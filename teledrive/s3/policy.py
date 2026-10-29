"""Bounded IAM-style S3 bucket policy engine (Phase L).

The document grammar is deliberately a strict subset of AWS bucket
policies.  Anything outside the subset is rejected at write time with a
400/501 — silently ignoring a clause would WIDEN authorization, which is
the one failure mode this engine must never have.

Precedence (implemented by :func:`evaluate`, highest first):

1. An explicit ``Deny`` statement that matches principal, action,
   resource and conditions denies the request.
2. Otherwise an explicit ``Allow`` statement that matches all four
   allows it and bypasses the Phase D ACL layer (AWS semantics).
3. Otherwise the decision is ``None``: the caller falls back to the ACL
   intersection gate.  A key without any stored ACL keeps the
   unrestricted baseline, so a deployment with no policy behaves
   exactly as it did before this phase.

Deny wins regardless of statement order, and conditions are evaluated
per statement (multiple operators/keys are ANDed; multiple values for a
positive operator are ORed; ``StringNotEquals``/``NotIpAddress`` require
that none of the values match).
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import (
    BigInteger, Column, ForeignKey, String, Table, Text, delete, insert,
    select, update,
)

from teledrive.s3.credentials import PERMISSIONS
from teledrive.storage.catalog import BucketCatalog, buckets, catalog_metadata

MAX_POLICY_BYTES = 20 * 1024
MAX_ABAC_BYTES = 20 * 1024
MAX_STATEMENTS = 50
MAX_SID = 128
MAX_JSON_DEPTH = 10
POLICY_VERSION = "2012-10-17"
CONDITION_OPERATORS = frozenset({
    "StringEquals", "StringLike", "StringNotEquals",
    "IpAddress", "NotIpAddress", "Bool",
    "NumericLessThan", "NumericLessThanEquals",
    "NumericGreaterThan", "NumericGreaterThanEquals",
})
# Only context keys the gateway actually populates.  A condition on an
# unknown key would be unevaluable; accepting it would either deny every
# request (safe but dishonest) or be ignored (unsafe).
_TAG_PREFIXES = ("s3:ExistingObjectTag/", "aws:PrincipalTag/")
CONDITION_KEYS = frozenset({
    "s3:prefix", "s3:max-keys", "s3:delimiter",
    "aws:SourceIp", "s3:x-amz-acl",
})
ABAC_TAG_PREFIXES = _TAG_PREFIXES

bucket_policy = Table(
    "storage_bucket_policy", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    Column("document", Text, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
    Column("updated_by", String(64), nullable=False),
)
bucket_abac = Table(
    "storage_bucket_abac", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
    Column("updated_by", String(64), nullable=False),
)


class PolicyError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _reject_constant(value):
    raise PolicyError("MalformedPolicy", f"Invalid JSON constant {value}")


def _no_duplicate_pairs(pairs):
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("MalformedPolicy", f"Duplicate JSON key {key}")
        result[key] = value
    return result


def _check_depth(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise PolicyError("MalformedPolicy", "Policy JSON nesting is too deep")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def _load_json(payload: bytes, *, limit: int, label: str):
    if len(payload) > limit:
        raise PolicyError("MalformedPolicy", f"{label} exceeds {limit} bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError("MalformedPolicy", f"{label} is not UTF-8") from exc
    try:
        document = json.loads(
            text, parse_constant=_reject_constant,
            object_pairs_hook=_no_duplicate_pairs,
        )
    except PolicyError:
        raise
    except ValueError as exc:
        raise PolicyError("MalformedPolicy", f"Invalid {label} JSON") from exc
    _check_depth(document)
    if not isinstance(document, dict):
        raise PolicyError("MalformedPolicy", f"{label} must be a JSON object")
    return document


def _string_list(value, *, field: str, maximum: int = 100,
                 max_length: int = 1024) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise PolicyError("MalformedPolicy", f"{field} must be a non-empty list")
    result = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > max_length:
            raise PolicyError("MalformedPolicy", f"Invalid {field} entry")
        result.append(item)
    return result


def _glob_match(pattern: str, value: str) -> bool:
    """Match an IAM glob (``*`` any run, ``?`` one character), LINEARLY.

    The previous implementation compiled the glob to a regex where every
    ``*`` became ``.*``. That is a classic catastrophic-backtracking shape:
    a 20-character pattern like ``*a*a*a...`` against a long key took > 5 s,
    single-threaded, on the event loop -- so one request from a credential
    that could write a bucket policy froze the whole application. This is a
    greedy two-pointer matcher with backtracking to the last star only: O(n)
    time, O(1) space, no regex, no cache, no depth limit.
    """
    if not isinstance(pattern, str) or not isinstance(value, str):
        return False
    p = v = 0
    star = -1
    mark = 0
    while v < len(value):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == value[v]):
            p += 1
            v += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = v
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            v = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _action_is_real(action: str) -> bool:
    if not action.startswith("s3:") or len(action) > 128:
        return False
    if re.fullmatch(r"s3:[A-Za-z0-9*?]+", action) is None:
        return False
    return any(_glob_match(action, permission)
               for permission in PERMISSIONS)


def _resource_pattern(raw: str, *, bucket: str) -> tuple[str, str | None]:
    prefix = "arn:aws:s3:::"
    if not raw.startswith(prefix):
        # Any other partition/service/account form is not representable
        # in this private single-account gateway.
        raise PolicyError(
            "MalformedPolicy",
            "Resource must be arn:aws:s3:::bucket[/key]", 400)
    remainder = raw[len(prefix):]
    if not remainder or remainder.startswith("/"):
        raise PolicyError("MalformedPolicy", "Resource ARN is incomplete")
    resource_bucket, slash, key_pattern = remainder.partition("/")
    if resource_bucket != bucket:
        raise PolicyError(
            "MalformedPolicy",
            "A bucket policy may only address its own bucket")
    if not slash:
        return bucket, None
    if not key_pattern or len(key_pattern.encode("utf-8")) > 1024:
        raise PolicyError("MalformedPolicy", "Invalid resource key pattern")
    if any(character in key_pattern for character in "\r\n\0"):
        raise PolicyError("MalformedPolicy", "Invalid resource key pattern")
    return bucket, key_pattern


def _condition_key(key: str) -> None:
    if key in CONDITION_KEYS:
        return
    for prefix in _TAG_PREFIXES:
        if key.startswith(prefix):
            suffix = key[len(prefix):]
            if suffix and len(suffix) <= 128 and "\0" not in suffix:
                return
    raise PolicyError(
        "MalformedPolicy",
        f"Unsupported condition key {key[:64]}", 400)


@dataclass(frozen=True)
class Condition:
    operator: str
    key: str
    values: tuple[str, ...]

    @property
    def negated(self) -> bool:
        return self.operator in {"StringNotEquals", "NotIpAddress"}


@dataclass(frozen=True)
class Statement:
    sid: str | None
    effect: str
    principals: frozenset[str]
    actions: tuple[str, ...]
    # The raw glob, not a compiled regex: matching is linear now.
    resources: tuple[tuple[str, str | None], ...]
    conditions: tuple[Condition, ...]

    def matches_action(self, action: str) -> bool:
        return any(_glob_match(pattern, action)
                   for pattern in self.actions)

    def matches_resource(self, resource_key: str) -> bool:
        for bucket, key_glob in self.resources:
            if key_glob is None:
                if resource_key == bucket:
                    return True
            elif resource_key.startswith(bucket + "/"):
                if _glob_match(key_glob, resource_key[len(bucket) + 1:]):
                    return True
        return False

    def matches_principal(self, principal: str | None) -> bool:
        return principal is not None and principal in self.principals


@dataclass(frozen=True)
class CompiledPolicy:
    bucket: str
    statements: tuple[Statement, ...]
    document: str
    updated_ns: int


def _parse_statement(raw, *, index: int, bucket: str) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyError("MalformedPolicy", "Each Statement must be an object")
    unknown = set(raw) - {"Sid", "Effect", "Principal", "Action",
                          "Resource", "Condition"}
    if unknown:
        raise PolicyError(
            "MalformedPolicy",
            f"Unsupported statement field {sorted(unknown)[0]}", 400)
    effect = raw.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise PolicyError("MalformedPolicy", "Effect must be Allow or Deny")
    sid = raw.get("Sid")
    if sid is not None and (not isinstance(sid, str) or len(sid) > MAX_SID):
        raise PolicyError("MalformedPolicy", "Sid must be at most 128 characters")

    principal = raw.get("Principal")
    if principal == "*":
        raise PolicyError(
            "NotImplemented",
            "Public (*) principals are not supported by this private gateway",
            501)
    if not isinstance(principal, dict) or set(principal) != {"CanonicalUser"}:
        unsupported = sorted(set(principal)) if isinstance(principal, dict) else []
        if any(name in {"AWS", "Service", "Federated"} for name in unsupported):
            raise PolicyError(
                "NotImplemented",
                "Only CanonicalUser principals are supported", 501)
        raise PolicyError(
            "MalformedPolicy",
            "Principal must be {CanonicalUser: [ids]}", 400)
    ids = principal["CanonicalUser"]
    if isinstance(ids, str):
        ids = [ids]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 100:
        raise PolicyError("MalformedPolicy", "CanonicalUser must be a list")
    principals = []
    for access_key in ids:
        if not isinstance(access_key, str) or not access_key \
                or len(access_key) > 64:
            raise PolicyError("MalformedPolicy", "Invalid CanonicalUser ID")
        principals.append(access_key)

    actions = _string_list(raw.get("Action"), field="Action",
                           maximum=200, max_length=128)
    if any(not _action_is_real(action) for action in actions):
        raise PolicyError(
            "MalformedPolicy", "Action is not a known S3 permission")
    resources = tuple(
        _resource_pattern(item, bucket=bucket)
        for item in _string_list(raw.get("Resource"), field="Resource",
                                 maximum=50, max_length=1024)
    )

    conditions: list[Condition] = []
    raw_conditions = raw.get("Condition")
    if raw_conditions is not None:
        if not isinstance(raw_conditions, dict) or not raw_conditions:
            raise PolicyError("MalformedPolicy",
                              "Condition must be a non-empty object")
        for operator, entries in raw_conditions.items():
            if operator not in CONDITION_OPERATORS:
                raise PolicyError(
                    "MalformedPolicy",
                    f"Unsupported condition operator {operator[:64]}", 400)
            if not isinstance(entries, dict) or not entries:
                raise PolicyError("MalformedPolicy",
                                  "Condition operator requires keys")
            for key, value in entries.items():
                _condition_key(key)
                values = _string_list(value, field="Condition value",
                                       maximum=50, max_length=1024)
                if operator == "Bool" and any(
                        item.lower() not in {"true", "false"}
                        for item in values):
                    raise PolicyError("MalformedPolicy",
                                      "Bool conditions require true/false")
                if operator.startswith("Numeric"):
                    for item in values:
                        try:
                            int(item)
                        except ValueError as exc:
                            raise PolicyError(
                                "MalformedPolicy",
                                "Numeric conditions require integers") from exc
                if operator in {"IpAddress", "NotIpAddress"}:
                    for item in values:
                        try:
                            ipaddress.ip_network(item, strict=False)
                        except ValueError as exc:
                            raise PolicyError(
                                "MalformedPolicy",
                                "IpAddress conditions require valid networks",
                            ) from exc
                conditions.append(Condition(operator, key, tuple(values)))
    return Statement(
        sid=sid, effect=effect, principals=frozenset(principals),
        actions=tuple(actions), resources=resources,
        conditions=tuple(conditions),
    )


def parse_policy(payload: bytes, *, bucket: str,
                 credential_store) -> CompiledPolicy:
    """Strictly validate a policy document and compile it.

    Every CanonicalUser ID must be an ACTIVE credential.  The parsed
    document is returned with a canonical JSON serialization that is
    what gets persisted, so re-reading is deterministic.
    """
    document = _load_json(payload, limit=MAX_POLICY_BYTES,
                          label="bucket policy")
    if set(document) != {"Version", "Statement"}:
        raise PolicyError(
            "MalformedPolicy",
            "Policy requires exactly Version and Statement", 400)
    if document.get("Version") != POLICY_VERSION:
        raise PolicyError("MalformedPolicy",
                          "Only Version 2012-10-17 is supported")
    raw_statements = document.get("Statement")
    if not isinstance(raw_statements, list) or not raw_statements:
        raise PolicyError("MalformedPolicy", "Statement must be a non-empty list")
    if len(raw_statements) > MAX_STATEMENTS:
        raise PolicyError("MalformedPolicy",
                          f"At most {MAX_STATEMENTS} statements are allowed")
    statements = tuple(
        _parse_statement(item, index=index, bucket=bucket)
        for index, item in enumerate(raw_statements)
    )
    sids = [statement.sid for statement in statements if statement.sid]
    if len(set(sids)) != len(sids):
        raise PolicyError("MalformedPolicy", "Sid values must be unique")
    for statement in statements:
        for access_key in statement.principals:
            if not credential_store.is_active(access_key):
                raise PolicyError(
                    "InvalidPrincipal",
                    "Policy principals must be active credentials", 400)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return CompiledPolicy(
        bucket=bucket, statements=statements, document=canonical,
        updated_ns=0,
    )


def _compile_stored(bucket: str, document: str, updated_ns: int) -> CompiledPolicy:
    """Compile an already-validated stored document (no credential store)."""
    parsed = json.loads(document)
    statements = tuple(
        _parse_statement(item, index=index, bucket=bucket)
        for index, item in enumerate(parsed["Statement"])
    )
    return CompiledPolicy(bucket=bucket, statements=statements,
                          document=document, updated_ns=updated_ns)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _context_values(context: dict, key: str) -> list[str] | None:
    value = context.get(key)
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _string_matches(operator: str, expected: str, actual: str) -> bool:
    if operator == "StringLike":
        return _glob_match(expected, actual)
    return expected == actual


def _condition_matches(condition: Condition, context: dict) -> bool:
    actual_values = _context_values(context, condition.key)
    if actual_values is None:
        # A missing key satisfies a negated condition and fails a
        # positive one (AWS semantics).
        return condition.negated
    operator = condition.operator
    if operator in {"StringEquals", "StringLike"}:
        return any(_string_matches(operator, expected, actual)
                   for expected in condition.values
                   for actual in actual_values)
    if operator == "StringNotEquals":
        return all(not _string_matches("StringEquals", expected, actual)
                   for expected in condition.values
                   for actual in actual_values)
    if operator in {"IpAddress", "NotIpAddress"}:
        matched = False
        for actual in actual_values:
            try:
                address = ipaddress.ip_address(actual)
            except ValueError:
                continue
            if any(address in ipaddress.ip_network(expected, strict=False)
                   for expected in condition.values):
                matched = True
                break
        return (not matched) if operator == "NotIpAddress" else matched
    if operator == "Bool":
        return any(actual.lower() == expected.lower()
                   for expected in condition.values
                   for actual in actual_values)
    if operator.startswith("Numeric"):
        try:
            numbers = [int(actual) for actual in actual_values]
        except ValueError:
            return False
        limits = [int(expected) for expected in condition.values]
        if operator == "NumericLessThan":
            return any(number < limit for number in numbers for limit in limits)
        if operator == "NumericLessThanEquals":
            return any(number <= limit for number in numbers for limit in limits)
        if operator == "NumericGreaterThan":
            return any(number > limit for number in numbers for limit in limits)
        return any(number >= limit for number in numbers for limit in limits)
    return False


def _conditions_match(conditions: tuple[Condition, ...],
                      context: dict) -> bool:
    return all(_condition_matches(condition, context)
               for condition in conditions)


def evaluate(statements, action: str, resource_key: str,
             principal: str | None, context: dict) -> str | None:
    """Return ``"deny"``, ``"allow"`` or ``None`` (no explicit decision).

    ``resource_key`` is the bucket name for bucket-level operations and
    ``bucket/key`` for object operations.  Deny always wins.
    """
    allowed = False
    denied = False
    for statement in statements:
        if not statement.matches_action(action):
            continue
        if not statement.matches_resource(resource_key):
            continue
        if not statement.matches_principal(principal):
            continue
        if not _conditions_match(statement.conditions, context):
            continue
        if statement.effect == "Deny":
            denied = True
        else:
            allowed = True
    if denied:
        return "deny"
    if allowed:
        return "allow"
    return None


# ---------------------------------------------------------------------------
# ABAC (Phase L4)
# ---------------------------------------------------------------------------

def parse_abac_document(payload: bytes) -> dict:
    """Validate a Get/PutBucketAbac document.

    Accepted shape::

        {"Status": "Enabled"|"Disabled",
         "Conditions": {"aws:PrincipalTag/<k>": ["v"],
                        "s3:ExistingObjectTag/<k>": ["v"]}}

    ``Conditions`` is optional.  When present and Status is Enabled the
    listed tag conditions become mandatory request conditions (the ABAC
    gate), evaluated with StringEquals semantics.  Unknown top-level or
    condition keys are rejected — never ignored.
    """
    document = _load_json(payload, limit=MAX_ABAC_BYTES, label="ABAC document")
    if not set(document) <= {"Status", "Conditions"}:
        raise PolicyError(
            "MalformedPolicy",
            "ABAC document allows only Status and Conditions", 400)
    if document.get("Status") not in {"Enabled", "Disabled"}:
        raise PolicyError("MalformedPolicy",
                          "ABAC Status must be Enabled or Disabled")
    conditions = document.get("Conditions")
    if conditions is not None:
        if not isinstance(conditions, dict) or not conditions:
            raise PolicyError("MalformedPolicy",
                              "ABAC Conditions must be a non-empty object")
        for key, value in conditions.items():
            if not any(key.startswith(prefix) and key[len(prefix):]
                       for prefix in ABAC_TAG_PREFIXES):
                raise PolicyError(
                    "MalformedPolicy",
                    "ABAC conditions require aws:PrincipalTag/* or "
                    "s3:ExistingObjectTag/* keys", 400)
            _string_list(value, field="ABAC condition value", maximum=50)
    return document


def evaluate_abac(abac: dict | None, context: dict) -> bool:
    """True when the ABAC gate passes (disabled/absent = pass)."""
    if not abac or abac.get("status") != "Enabled":
        return True
    conditions = (abac.get("document") or {}).get("Conditions") or {}
    for key, values in conditions.items():
        condition = Condition("StringEquals", key, tuple(values))
        if not _condition_matches(condition, context):
            return False
    return True


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------

class _CompiledCache:
    """Process-wide LRU keyed by (bucket, updated_ns).

    Stores are constructed per request, so the cache cannot live on the
    store instance.  ``updated_ns`` changes on every replace/delete, which
    invalidates older entries naturally.
    """

    def __init__(self, maximum: int = 512):
        self._items: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._maximum = maximum

    def get(self, key):
        with self._lock:
            value = self._items.get(key)
            if value is not None:
                self._items.move_to_end(key)
            return value

    def put(self, key, value):
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._maximum:
                self._items.popitem(last=False)

    def discard_bucket(self, bucket: str):
        with self._lock:
            for key in [item for item in self._items if item[0] == bucket]:
                del self._items[key]


_POLICY_CACHE = _CompiledCache()


class BucketPolicyStore:
    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)

    def _bucket_exists(self, name: str) -> None:
        if self.db.connection.execute(
                select(buckets.c.name).where(buckets.c.name == name)
        ).first() is None:
            raise FileNotFoundError("Bucket not found")

    def get(self, name: str) -> str | None:
        self._bucket_exists(name)
        return self.db.connection.execute(select(
            bucket_policy.c.document).where(
            bucket_policy.c.bucket == name)).scalar_one_or_none()

    def get_compiled(self, name: str) -> CompiledPolicy | None:
        self._bucket_exists(name)
        row = self.db.connection.execute(select(
            bucket_policy.c.document, bucket_policy.c.updated_ns).where(
            bucket_policy.c.bucket == name)).first()
        if row is None:
            return None
        cache_key = (name, int(row[1]))
        cached = _POLICY_CACHE.get(cache_key)
        if cached is not None:
            return cached
        compiled = _compile_stored(name, row[0], int(row[1]))
        _POLICY_CACHE.put(cache_key, compiled)
        return compiled

    def replace(self, name: str, compiled: CompiledPolicy,
                updated_by: str) -> int:
        updated_ns = time.time_ns()
        try:
            guard = self.db.connection.execute(
                update(buckets).where(buckets.c.name == name).values(
                    created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(bucket_policy).where(
                bucket_policy.c.bucket == name))
            self.db.connection.execute(insert(bucket_policy).values(
                bucket=name, document=compiled.document,
                updated_ns=updated_ns, updated_by=updated_by))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        _POLICY_CACHE.discard_bucket(name)
        return updated_ns

    def delete(self, name: str) -> None:
        self._bucket_exists(name)
        self.db.connection.execute(delete(bucket_policy).where(
            bucket_policy.c.bucket == name))
        self.db.commit()
        _POLICY_CACHE.discard_bucket(name)


class BucketAbacStore:
    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)

    def _bucket_exists(self, name: str) -> None:
        if self.db.connection.execute(
                select(buckets.c.name).where(buckets.c.name == name)
        ).first() is None:
            raise FileNotFoundError("Bucket not found")

    def get(self, name: str) -> dict | None:
        self._bucket_exists(name)
        row = self.db.connection.execute(select(
            bucket_abac.c.status, bucket_abac.c.document).where(
            bucket_abac.c.bucket == name)).first()
        if row is None:
            return None
        try:
            document = json.loads(row[1])
        except (TypeError, ValueError):
            document = {}
        return {"status": row[0], "document": document}

    def replace(self, name: str, document: dict, updated_by: str) -> None:
        try:
            guard = self.db.connection.execute(
                update(buckets).where(buckets.c.name == name).values(
                    created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(bucket_abac).where(
                bucket_abac.c.bucket == name))
            self.db.connection.execute(insert(bucket_abac).values(
                bucket=name, status=document["Status"],
                document=json.dumps(document, sort_keys=True,
                                    separators=(",", ":")),
                updated_ns=time.time_ns(), updated_by=updated_by))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
