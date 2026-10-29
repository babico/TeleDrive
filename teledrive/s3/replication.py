"""AWS-shaped bucket replication over the real cross-account engine.

This is **not** AWS cross-region replication and there is no IAM here.
A rule's ``Destination/Bucket`` names a configured TeleDrive credential
set (an MTProto account label), not an AWS bucket ARN or account id.
The storage engine already keeps a second Telegram copy of every chunk
in such an account (``storage_replica_chunks``) and re-sends missing
copies through the digest-verifying repair path. This module stores the
per-bucket rule set, parses/renders the AWS XML shape and exposes the
prefix-aware decision the engine consults before it replicates a chunk.

Semantics that differ from AWS, stated plainly:

* One replica per chunk. Enabled rules must therefore have disjoint
  prefixes; an object never matches two enabled rules. Disabled rules
  may overlap until they are enabled.
* A stored configuration is authoritative for its bucket. If it exists
  but no enabled rule matches the key, that object is not replicated —
  the operator-wide ``storage.replica_account`` default is *not* used.
  That fallback only applies to buckets with no configuration at all.
* ``Role`` is accepted and preserved as an opaque label with no
  authorization meaning. ``DeleteMarkerReplication``, replica
  modifications, storage classes, metrics/report and time-control
  options are rejected with 501 rather than silently ignored.

The table lives in ``catalog_metadata`` (like CORS/lifecycle). The
storage engine imports :func:`matching_destination` lazily, so the
engine has no hard dependency on this module at import time.
"""
from __future__ import annotations

import json
import time
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import (
    BigInteger, Column, ForeignKey, String, Table, Text, delete, inspect,
    insert, select, update,
)

from teledrive.storage.catalog import BucketCatalog, buckets, catalog_metadata

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_REPLICATION_XML_BYTES = 16 * 1024
MAX_RULES = 10
MAX_PREFIX_BYTES = 1024
MAX_DESTINATION_LENGTH = 255
DEFAULT_ROLE = "teledrive:replication"

replication_configs = Table(
    "storage_replication_configs", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    Column("role", String(2048)),
    Column("rules", Text, nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)

# AWS options with no honest backing in this engine. Raising 501 is the
# contract: an accepted-but-ignored option would silently break it.
_UNSUPPORTED_RULE = frozenset({
    "DeleteMarkerReplication", "ExistingObjectReplication",
    "SourceSelectionCriteria", "Priority", "ReplicateDelete",
    "ReplicaModifications",
})
_UNSUPPORTED_TOP = frozenset({
    "ReplicateDelete", "ReplicaModifications", "Metrics", "Report",
})
_UNSUPPORTED_DESTINATION = frozenset({
    "StorageClass", "Account", "AccessControlTranslation",
    "EncryptionConfiguration", "Metrics", "ReplicationTime",
})
_UNSUPPORTED_FILTER = frozenset({
    "And", "Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan",
})


class ReplicationError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def _name(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _scalar(node, label: str) -> str:
    if node.attrib or len(node):
        raise ReplicationError("MalformedXML", f"Invalid {label} element")
    return node.text or ""


def _prefixes(rule_node) -> list[str]:
    """One legacy Prefix or one Filter/Prefix; both means an ambiguous rule."""
    legacy = filter_node = None
    for element in rule_node:
        label = _name(element)
        if label == "Prefix":
            legacy = element
        elif label == "Filter":
            filter_node = element
    if legacy is not None and filter_node is not None:
        raise ReplicationError(
            "InvalidRequest", "Rule cannot set both Prefix and Filter")
    if legacy is not None:
        prefix = _scalar(legacy, "Prefix")
    elif filter_node is not None:
        if filter_node.attrib or len(filter_node) > 1:
            raise ReplicationError("MalformedXML", "Invalid replication Filter")
        prefix = ""
        for element in filter_node:
            label = _name(element)
            if label in _UNSUPPORTED_FILTER:
                raise ReplicationError(
                    "NotImplemented",
                    f"Replication Filter/{label} is not supported; "
                    "only a single Prefix filter is honoured", 501)
            if label != "Prefix":
                raise ReplicationError(
                    "MalformedXML", "Unexpected replication Filter element")
            prefix = _scalar(element, "Filter/Prefix")
    else:
        prefix = ""
    if len(prefix.encode("utf-8")) > MAX_PREFIX_BYTES:
        raise ReplicationError("InvalidRequest", "Replication prefix too long")
    if any(ord(character) < 32 for character in prefix):
        raise ReplicationError("InvalidRequest", "Replication prefix has control characters")
    return [prefix]


def _destination(destination, destinations: set[str] | None) -> str:
    if destination.attrib or len(destination) == 0:
        raise ReplicationError("MalformedXML", "Replication Rule requires a Destination")
    bucket = None
    for element in destination:
        label = _name(element)
        if label in _UNSUPPORTED_DESTINATION:
            raise ReplicationError(
                "NotImplemented",
                f"Destination/{label} is not supported; TeleDrive replication "
                "is a second Telegram copy, not an AWS storage destination", 501)
        if label != "Bucket":
            raise ReplicationError(
                "MalformedXML", "Unexpected replication Destination element")
        if bucket is not None:
            raise ReplicationError(
                "MalformedXML", "Duplicate replication Destination/Bucket")
        bucket = _scalar(element, "Destination/Bucket").strip()
    if not bucket:
        raise ReplicationError(
            "MalformedXML", "Replication Destination requires a Bucket")
    if len(bucket) > MAX_DESTINATION_LENGTH:
        raise ReplicationError("InvalidRequest", "Replication destination too long")
    if bucket.startswith("arn:"):
        raise ReplicationError(
            "NotImplemented",
            "AWS ARNs are not accepted; Destination/Bucket must name a "
            "configured TeleDrive credential set", 501)
    if destinations is not None and bucket not in destinations:
        raise ReplicationError(
            "InvalidRequest",
            "Destination/Bucket does not name a configured TeleDrive "
            "credential set")
    return bucket


def _parse_rule(node, destinations: set[str] | None, index: int) -> dict:
    if node.attrib:
        raise ReplicationError("MalformedXML", "Unexpected replication Rule attribute")
    seen: dict[str, object] = {}
    for element in node:
        label = _name(element)
        if label in _UNSUPPORTED_RULE:
            raise ReplicationError(
                "NotImplemented",
                f"Replication Rule/{label} is not supported", 501)
        if label not in {"ID", "Status", "Filter", "Prefix", "Destination"}:
            raise ReplicationError(
                "MalformedXML", "Unexpected replication Rule element")
        if label in seen:
            raise ReplicationError("MalformedXML", "Duplicate replication Rule field")
        seen[label] = element
    status = _scalar(seen["Status"], "Status") if "Status" in seen else ""
    if status not in {"Enabled", "Disabled"}:
        raise ReplicationError(
            "InvalidRequest", "Replication rule Status must be Enabled or Disabled")
    identity = _scalar(seen["ID"], "ID") if "ID" in seen else ""
    if "ID" in seen:
        if not identity or len(identity.encode("utf-8")) > 255:
            raise ReplicationError("InvalidRequest", "Invalid replication rule ID")
    else:
        identity = f"rule-{index + 1}"
    if "Destination" not in seen:
        raise ReplicationError(
            "MalformedXML", "Replication rule requires a Destination")
    return {
        "id": identity,
        "status": status,
        "prefixes": _prefixes(node),
        "destination": _destination(seen["Destination"], destinations),
    }


def validate_rules(rules: list[dict]) -> None:
    """Reject ambiguous rule sets the one-replica-per-chunk engine cannot honour."""
    identifiers = [rule["id"] for rule in rules]
    if len(set(identifiers)) != len(identifiers):
        raise ReplicationError("InvalidRequest", "Duplicate replication rule ID")
    enabled = [rule for rule in rules if rule["status"] == "Enabled"]
    for index, left in enumerate(enabled):
        for right in enabled[index + 1:]:
            for left_prefix in left["prefixes"]:
                for right_prefix in right["prefixes"]:
                    if (not left_prefix or not right_prefix
                            or left_prefix.startswith(right_prefix)
                            or right_prefix.startswith(left_prefix)):
                        raise ReplicationError(
                            "InvalidRequest",
                            "Enabled replication rules must have disjoint "
                            "prefixes: TeleDrive stores one replica per chunk")


def parse_replication_xml(payload: bytes,
                          destinations: set[str] | None = None) -> dict:
    """Parse a bounded, strict ``ReplicationConfiguration`` document.

    ``destinations`` is the set of configured TeleDrive credential labels;
    passing it rejects unknown targets at parse time. ``None`` is for
    structural tests and the store validates again before persisting.
    """
    if len(payload) > MAX_REPLICATION_XML_BYTES:
        raise ReplicationError("MalformedXML", "Replication XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ReplicationError("MalformedXML", "Invalid replication XML") from exc
    if _name(root) != "ReplicationConfiguration" or root.attrib:
        raise ReplicationError("MalformedXML", "Unexpected replication document")
    role = None
    rules: list[dict] = []
    top_seen: set[str] = set()
    for element in root:
        label = _name(element)
        if label != "Rule":
            if label in top_seen:
                raise ReplicationError(
                    "MalformedXML", "Duplicate replication configuration element")
            top_seen.add(label)
        if label == "Role":
            role = _scalar(element, "Role").strip()
            if len(role.encode("utf-8")) > 2048:
                raise ReplicationError("InvalidArgument", "Replication Role too long")
        elif label == "Rule":
            rules.append(_parse_rule(element, destinations, len(rules)))
        elif label in _UNSUPPORTED_TOP:
            raise ReplicationError(
                "NotImplemented",
                f"Replication {label} is not supported by the TeleDrive "
                "cross-account replica engine", 501)
        else:
            raise ReplicationError(
                "MalformedXML", "Unexpected replication configuration element")
    if not 1 <= len(rules) <= MAX_RULES:
        raise ReplicationError(
            "InvalidRequest", f"Replication requires 1..{MAX_RULES} rules")
    validate_rules(rules)
    return {"role": role or None, "rules": rules}


def replication_xml(config: dict) -> bytes:
    root = ET.Element("ReplicationConfiguration", xmlns=NAMESPACE)
    ET.SubElement(root, "Role").text = config.get("role") or DEFAULT_ROLE
    for rule in config["rules"]:
        node = ET.SubElement(root, "Rule")
        ET.SubElement(node, "ID").text = rule["id"]
        ET.SubElement(node, "Status").text = rule["status"]
        prefixes = rule["prefixes"] or [""]
        filter_node = ET.SubElement(node, "Filter")
        ET.SubElement(filter_node, "Prefix").text = prefixes[0]
        destination = ET.SubElement(node, "Destination")
        ET.SubElement(destination, "Bucket").text = rule["destination"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def rule_matches(rule: dict, key: str) -> bool:
    return any(key.startswith(prefix) for prefix in rule["prefixes"])


def matching_destination(db, bucket: str,
                         key: str) -> tuple[bool, str | None]:
    """Return ``(configuration_exists, destination)`` for one object.

    ``configuration_exists=True`` with a ``None`` destination means the
    bucket has a configuration but no enabled rule matches this key: the
    caller must NOT fall back to the operator-wide default.
    """
    if not inspect(db.engine).has_table(replication_configs.name):
        return False, None
    raw = db.connection.execute(select(replication_configs.c.rules).where(
        replication_configs.c.bucket == bucket)).scalar_one_or_none()
    if raw is None:
        return False, None
    try:
        rules = json.loads(raw)
        if not isinstance(rules, list):
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Corrupted replication configuration") from exc
    for rule in rules:
        if (not isinstance(rule, dict)
                or not {"id", "status", "prefixes", "destination"} <= set(rule)
                or rule["status"] not in {"Enabled", "Disabled"}
                or not isinstance(rule["prefixes"], list)
                or not isinstance(rule["destination"], str)
                or not all(isinstance(prefix, str) for prefix in rule["prefixes"])):
            raise RuntimeError("Corrupted replication configuration")
        if rule["status"] == "Enabled" and rule_matches(rule, key):
            return True, rule["destination"]
    return True, None


class BucketReplicationStore:
    """SQL-backed bucket replication configuration.

    ``destinations`` is an iterable or callable returning the configured
    TeleDrive credential labels; a destination outside that set is
    rejected so the API cannot point at an account that does not exist.
    """

    def __init__(self, catalog: BucketCatalog, destinations=None):
        self.catalog, self.db = catalog, catalog.db
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)
        self._destinations = destinations

    def destination_labels(self) -> set[str]:
        source = self._destinations
        if source is None:
            return set()
        values = source() if callable(source) else source
        return {str(value) for value in values or () if str(value)}

    def _bucket_exists(self, name: str) -> None:
        if self.db.connection.execute(
            select(buckets.c.name).where(buckets.c.name == name)
        ).first() is None:
            raise FileNotFoundError("Bucket not found")

    def get(self, name: str) -> dict | None:
        self._bucket_exists(name)
        row = self.db.connection.execute(select(
            replication_configs.c.role, replication_configs.c.rules,
            replication_configs.c.created_at, replication_configs.c.updated_at,
        ).where(replication_configs.c.bucket == name)).first()
        if row is None:
            return None
        try:
            rules = json.loads(row[1])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Corrupted replication configuration") from exc
        return {
            "role": row[0],
            "rules": rules,
            "created_at": int(row[2]),
            "updated_at": int(row[3]),
        }

    def replace(self, name: str, config: dict) -> None:
        """Validate and atomically replace the bucket's configuration."""
        destinations = self.destination_labels()
        if any(rule["destination"] not in destinations for rule in config["rules"]):
            raise ReplicationError(
                "InvalidRequest",
                "Destination/Bucket does not name a configured TeleDrive "
                "credential set")
        validate_rules(config["rules"])
        now = int(time.time())
        try:
            guard = self.db.connection.execute(update(buckets).where(
                buckets.c.name == name
            ).values(created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            existing = self.db.connection.execute(select(
                replication_configs.c.created_at).where(
                replication_configs.c.bucket == name)).scalar_one_or_none()
            self.db.connection.execute(delete(replication_configs).where(
                replication_configs.c.bucket == name))
            self.db.connection.execute(insert(replication_configs).values(
                bucket=name, role=config.get("role"),
                rules=json.dumps(config["rules"], ensure_ascii=False,
                                 sort_keys=True),
                created_at=int(existing) if existing is not None else now,
                updated_at=now,
            ))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise

    def delete(self, name: str) -> bool:
        """Remove the configuration; returns whether one existed (204 either way)."""
        try:
            guard = self.db.connection.execute(update(buckets).where(
                buckets.c.name == name
            ).values(created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            result = self.db.connection.execute(delete(replication_configs).where(
                replication_configs.c.bucket == name))
            self.db.commit()
            return result.rowcount > 0
        except BaseException:
            self.db.connection.rollback()
            raise
