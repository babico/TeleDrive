"""S3 Intelligent-Tiering configuration CRUD and the real access-tier gate.

This module implements the four aws S3 Intelligent-Tiering operations:

* ``PutBucketIntelligentTieringConfiguration``
* ``GetBucketIntelligentTieringConfiguration``
* ``DeleteBucketIntelligentTieringConfiguration``
* ``ListBucketIntelligentTieringConfigurations``

The request documents are strict and bounded: 16 KiB maximum, defusedxml,
bare or 2006-03-01 namespace, unknown elements rejected (400), unsupported
tier names rejected (501). The supported shape is the AWS Smart Tiering
document::

    <IntelligentTieringConfiguration>
      <Id>...</Id>
      <Filter><Prefix>...</Prefix>|<Tag><Key>..</Key><Value>..</Value></Tag></Filter>
      <Status>Enabled|Disabled</Status>
      <Tiering><Days>30</Days><AccessTier>ARCHIVE_ACCESS</AccessTier></Tiering>
    </IntelligentTieringConfiguration>

Honesty caveat — read this before calling it "Glacier"
-------------------------------------------------------
TeleDrive stores every object body as encrypted Telegram chunks. Changing
``storage_objects.storage_class`` to ``ARCHIVE_ACCESS`` or
``DEEP_ARCHIVE_ACCESS`` does **not** move, copy, compress or delete a single
Telegram byte, and there is no separate cold-storage backend. It is an
**access gate in our own SQL catalog** with the same observable read
behaviour as an AWS archived object:

* GetObject/HeadObject answer ``403 InvalidObjectState`` while gated.
* RestoreObject opens a bounded window (``restore_until_ns``) during which
  reads work normally; expiry closes the gate again.

The chunks stay on Telegram for the whole lifecycle. This is deliberately
NOT AWS Glacier and does not claim Glacier durability, retrieval pricing or
physical media management. It makes the S3 *API* honest: a tier label the
client can observe has a real consequence.

Scheduler policy
----------------
``TieringStore.apply_due`` evaluates enabled configurations against
``last_accessed_ns`` (falling back to object creation time when an object has
never been read):

* idle >= archive days -> ``ARCHIVE_ACCESS``
* idle >= deep days    -> ``DEEP_ARCHIVE_ACCESS``
* any access (idle < archive days) -> back to ``STANDARD`` and the restore
  window is cleared, so the next archive cycle starts clean.

The deep threshold is the DEEP_ARCHIVE_ACCESS ``Days`` value when supplied,
otherwise twice the ARCHIVE_ACCESS value. Each pass is bounded by an object
limit and every transition is a conditional SQL update, so concurrent or
repeated passes are idempotent.
"""
from __future__ import annotations

import json
import re
import threading
import time
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import (BigInteger, Column, MetaData, String, Table, Text,
                        delete, insert, select, update)

from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import objects

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_TIERING_XML_BYTES = 16 * 1024
ACCESS_TIERS = ("ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS")
STATUSES = ("Enabled", "Disabled")
NO_SUCH_CONFIGURATION = "NoSuchConfiguration"
_ARCHIVED_CLASSES = frozenset(ACCESS_TIERS)
_MAX_PREFIX_BYTES = 1024
_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")

tiering_metadata = MetaData()
tiering_configs = Table(
    "storage_tiering_configs", tiering_metadata,
    Column("bucket", String(63), primary_key=True),
    Column("config_id", String(64), primary_key=True),
    Column("document", Text, nullable=False),
    Column("created_ns", BigInteger, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
)

_ENSURED_ENGINES: set[int] = set()
_ENSURED_LOCK = threading.Lock()


class TieringError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def ensure_tiering_tables(engine) -> None:
    """Create the tiering table once per engine (never in a hot mutation)."""
    key = id(engine)
    with _ENSURED_LOCK:
        if key in _ENSURED_ENGINES:
            return
        tiering_metadata.create_all(engine, tables=[tiering_configs])
        _ENSURED_ENGINES.add(key)


# -- strict XML parser ----------------------------------------------------

def _name(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid(node, label: str) -> bool:
    return node.tag in {label, f"{{{NS}}}{label}"}


def _expect(node, label: str) -> None:
    if not _valid(node, label) or node.attrib:
        raise TieringError(
            "MalformedXML", f"Unexpected {_name(node)!r}; expected {label}")


def _leaf(node, label: str, *, maximum: int = _MAX_PREFIX_BYTES) -> str:
    _expect(node, label)
    if len(node):
        raise TieringError("MalformedXML", f"{label} must be a scalar")
    value = node.text or ""
    if len(value.encode("utf-8")) > maximum:
        raise TieringError("InvalidArgument", f"{label} is too long")
    return value


def _children(node, allowed: set[str]) -> dict[str, list]:
    grouped: dict[str, list] = {label: [] for label in allowed}
    for child in node:
        label = _name(child)
        if label not in allowed or not _valid(child, label):
            raise TieringError(
                "MalformedXML", f"Unsupported element {label!r}")
        grouped[label].append(child)
    return grouped


def _single(group: dict[str, list], label: str, *, required: bool = True):
    values = group[label]
    if len(values) > 1:
        raise TieringError("MalformedXML", f"Duplicate {label}")
    if not values:
        if required:
            raise TieringError("InvalidArgument", f"Missing {label}")
        return None
    return values[0]


def _config_id(value: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise TieringError(
            "InvalidArgument",
            "Id must be 1..64 characters of [A-Za-z0-9._-]")
    return value


def _prefix(value: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise TieringError("InvalidArgument", "Invalid Prefix") from exc
    if len(encoded) > _MAX_PREFIX_BYTES:
        raise TieringError("InvalidArgument", "Prefix is too long")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise TieringError("InvalidArgument", "Invalid Prefix")
    return value


def _filter(node) -> dict:
    """Parse the supported Filter subset: one Prefix or one Tag."""
    _expect(node, "Filter")
    if len(node) != 1:
        raise TieringError(
            "InvalidArgument", "Filter needs exactly one Prefix or Tag")
    child = node[0]
    label = _name(child)
    if label == "Prefix":
        return {"prefix": _prefix(_leaf(child, "Prefix")), "tag": None}
    if label == "Tag":
        _expect(child, "Tag")
        group = _children(child, {"Key", "Value"})
        key = _leaf(_single(group, "Key"), "Key", maximum=128)
        value = _leaf(_single(group, "Value"), "Value", maximum=256)
        if not key or key.lower().startswith("aws:"):
            raise TieringError("InvalidArgument", "Invalid tag key")
        return {"prefix": "", "tag": {"key": key, "value": value}}
    raise TieringError(
        "MalformedXML", f"Unsupported Filter form {label!r}; use Prefix or Tag")


def _days(node) -> int:
    raw = _leaf(node, "Days", maximum=5)
    if not raw.isascii() or not raw.isdigit():
        raise TieringError("InvalidArgument", "Days must be an integer")
    value = int(raw)
    if not 1 <= value <= 36500:
        raise TieringError(
            "InvalidArgument", "Days must be between 1 and 36500")
    return value


def _tiering(node) -> dict:
    _expect(node, "Tiering")
    group = _children(node, {"Days", "AccessTier"})
    days = _days(_single(group, "Days"))
    access_tier = _leaf(_single(group, "AccessTier"), "AccessTier",
                        maximum=32)
    if access_tier not in ACCESS_TIERS:
        raise TieringError(
            "NotImplemented",
            f"AccessTier {access_tier!r} cannot be honoured; only "
            "ARCHIVE_ACCESS and DEEP_ARCHIVE_ACCESS are implemented",
            501,
        )
    return {"days": days, "access_tier": access_tier}


def parse_document(payload: bytes, *,
                   expected_id: str | None = None) -> dict:
    """Parse one strict IntelligentTieringConfiguration document."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TieringError("MalformedXML", "Tiering configuration body required")
    if len(payload) > MAX_TIERING_XML_BYTES:
        raise TieringError(
            "MalformedXML", "Tiering configuration XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(bytes(payload))
    except (ET.ParseError, DefusedXmlException) as exc:
        raise TieringError(
            "MalformedXML", "Invalid tiering configuration XML") from exc
    if not _valid(root, "IntelligentTieringConfiguration") or root.attrib:
        raise TieringError(
            "MalformedXML", "Expected IntelligentTieringConfiguration")
    group = _children(root, {"Id", "Status", "Filter", "Tiering"})
    ident = _config_id(_leaf(_single(group, "Id"), "Id"))
    status = _leaf(_single(group, "Status"), "Status", maximum=16)
    if status not in STATUSES:
        raise TieringError("InvalidArgument", "Status must be Enabled or Disabled")
    filter_node = _single(group, "Filter", required=False)
    filter_value = (_filter(filter_node) if filter_node is not None
                    else {"prefix": "", "tag": None})
    if not group["Tiering"]:
        raise TieringError("InvalidArgument", "At least one Tiering is required")
    tiers = [_tiering(node) for node in group["Tiering"]]
    by_tier: dict[str, int] = {}
    for tier in tiers:
        if tier["access_tier"] in by_tier:
            raise TieringError(
                "InvalidArgument", "Duplicate AccessTier in Tiering list")
        by_tier[tier["access_tier"]] = tier["days"]
    archive_days = by_tier.get("ARCHIVE_ACCESS")
    deep_days = by_tier.get("DEEP_ARCHIVE_ACCESS")
    if archive_days is None:
        archive_days = deep_days
    if deep_days is None:
        deep_days = archive_days * 2
    if deep_days < archive_days:
        raise TieringError(
            "InvalidArgument",
            "DEEP_ARCHIVE_ACCESS Days cannot precede ARCHIVE_ACCESS Days")
    if expected_id is not None and ident != expected_id:
        raise TieringError(
            "InvalidArgument", "URL configuration id does not match document Id")
    return {
        "id": ident,
        "status": status,
        "filter": filter_value,
        "tiers": tiers,
        "archive_days": archive_days,
        "deep_days": deep_days,
    }


# -- serializers ----------------------------------------------------------

def config_xml(config: dict) -> bytes:
    """Serialize a stored configuration in the AWS document shape."""
    root = ET.Element("IntelligentTieringConfiguration", xmlns=NS)
    ET.SubElement(root, "Id").text = config["id"]
    filter_value = config.get("filter") or {}
    prefix = filter_value.get("prefix", "")
    tag = filter_value.get("tag")
    if prefix or tag:
        node = ET.SubElement(root, "Filter")
        if tag:
            tag_node = ET.SubElement(node, "Tag")
            ET.SubElement(tag_node, "Key").text = tag["key"]
            ET.SubElement(tag_node, "Value").text = tag["value"]
        else:
            ET.SubElement(node, "Prefix").text = prefix
    ET.SubElement(root, "Status").text = config["status"]
    for tier in config["tiers"]:
        node = ET.SubElement(root, "Tiering")
        ET.SubElement(node, "Days").text = str(tier["days"])
        ET.SubElement(node, "AccessTier").text = tier["access_tier"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def list_xml(configs: list[dict]) -> bytes:
    """AWS-shaped ListBucketIntelligentTieringConfigurationsResult."""
    root = ET.Element(
        "ListBucketIntelligentTieringConfigurationsResult", xmlns=NS)
    for config in configs:
        root.append(SafeET.fromstring(config_xml(config)))
    ET.SubElement(root, "IsTruncated").text = "false"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


# -- SQL store ------------------------------------------------------------

class TieringStore:
    """Read/write tiering configurations and apply the tiering policy."""

    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        ensure_tiering_tables(self.db.engine)

    def _bucket_exists(self, bucket: str) -> None:
        if bucket not in self.catalog.list_buckets():
            raise FileNotFoundError("Bucket not found")

    @staticmethod
    def _decode(raw: str) -> dict:
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Corrupted tiering configuration") from exc
        if not isinstance(value, dict) or value.get("id") in (None, ""):
            raise RuntimeError("Corrupted tiering configuration")
        return value

    def list(self, bucket: str) -> list[dict]:
        self._bucket_exists(bucket)
        rows = self.db.connection.execute(
            select(tiering_configs.c.document)
            .where(tiering_configs.c.bucket == bucket)
            .order_by(tiering_configs.c.config_id)).scalars().all()
        return [self._decode(raw) for raw in rows]

    def get(self, bucket: str, config_id: str) -> dict | None:
        self._bucket_exists(bucket)
        raw = self.db.connection.execute(
            select(tiering_configs.c.document).where(
                tiering_configs.c.bucket == bucket,
                tiering_configs.c.config_id == config_id,
            )).scalar_one_or_none()
        return None if raw is None else self._decode(raw)

    def put(self, bucket: str, config_id: str, config: dict, *,
            now_ns: int | None = None) -> dict:
        """PUT replaces the document for this (bucket, id)."""
        _config_id(config_id)
        if config.get("id") != config_id:
            raise TieringError(
                "InvalidArgument", "URL configuration id does not match document Id")
        self._bucket_exists(bucket)
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        data = json.dumps(config, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
        try:
            changed = self.db.connection.execute(update(tiering_configs).where(
                tiering_configs.c.bucket == bucket,
                tiering_configs.c.config_id == config_id,
            ).values(document=data, updated_ns=now_ns))
            if changed.rowcount == 0:
                self.db.connection.execute(insert(tiering_configs).values(
                    bucket=bucket, config_id=config_id, document=data,
                    created_ns=now_ns, updated_ns=now_ns,
                ))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        return config

    def delete(self, bucket: str, config_id: str) -> bool:
        """Idempotent delete; returns whether a row existed."""
        self._bucket_exists(bucket)
        removed = self.db.connection.execute(delete(tiering_configs).where(
            tiering_configs.c.bucket == bucket,
            tiering_configs.c.config_id == config_id,
        ))
        self.db.commit()
        return removed.rowcount > 0

    # -- scheduler -------------------------------------------------------
    def _conditions(self, bucket: str, config: dict) -> list:
        conditions = [objects.c.bucket == bucket, objects.c.status == "ready"]
        filter_value = config.get("filter") or {}
        prefix = filter_value.get("prefix") or ""
        if prefix:
            conditions.append(objects.c.object_key.startswith(
                prefix, autoescape=True))
        tag = filter_value.get("tag")
        if tag:
            from teledrive.s3.tagging import object_tags
            conditions.append(select(1).where(
                object_tags.c.object_id == objects.c.id,
                object_tags.c.tag_key == tag["key"],
                object_tags.c.tag_value == tag["value"],
            ).exists())
        return conditions

    def _transition(self, conditions: list, transition, target: str,
                    *, limit: int, clear_restore: bool = False) -> int:
        if limit <= 0:
            return 0
        identifiers = self.db.connection.execute(
            select(objects.c.id)
            .where(*conditions, transition)
            .order_by(objects.c.id).limit(limit)).scalars().all()
        if not identifiers:
            return 0
        values = {"storage_class": target}
        if clear_restore:
            values["restore_until_ns"] = None
        changed = self.db.connection.execute(
            update(objects).where(objects.c.id.in_(list(identifiers)))
            .values(**values))
        return int(changed.rowcount)

    def apply_due(self, *, now_ns: int, limit: int = 1000) -> int:
        """Apply enabled tiering configurations; returns changed objects."""
        if type(now_ns) is not int or now_ns < 0:
            raise ValueError("Invalid tiering clock")
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("Invalid tiering pass limit")
        rows = self.db.connection.execute(
            select(tiering_configs.c.bucket, tiering_configs.c.document)
            .order_by(tiering_configs.c.bucket,
                      tiering_configs.c.config_id)).all()
        changed = 0
        day_ns = 86_400_000_000_000
        try:
            for bucket, raw in rows:
                if changed >= limit:
                    break
                config = self._decode(raw)
                if config.get("status") != "Enabled":
                    continue
                if bucket not in self.catalog.list_buckets():
                    continue
                archive_days = config.get("archive_days")
                deep_days = config.get("deep_days")
                if (type(archive_days) is not int or type(deep_days) is not int
                        or archive_days < 1 or deep_days < archive_days):
                    raise RuntimeError("Corrupted tiering configuration")
                idle_ns = now_ns - _idle_expression()
                # Note: idle_ns is a SQL expression; thresholds are values.
                conditions = self._conditions(bucket, config)
                archive_ns = archive_days * day_ns
                deep_ns = deep_days * day_ns
                remaining = limit - changed
                # Deepest transition first: an object idle past the deep
                # threshold goes straight to DEEP_ARCHIVE_ACCESS.
                changed += self._transition(
                    conditions,
                    objects.c.storage_class.in_(("STANDARD", "ARCHIVE_ACCESS"))
                    & (idle_ns >= deep_ns),
                    "DEEP_ARCHIVE_ACCESS", limit=remaining - changed)
                changed += self._transition(
                    conditions,
                    (objects.c.storage_class == "STANDARD")
                    & (idle_ns >= archive_ns) & (idle_ns < deep_ns),
                    "ARCHIVE_ACCESS", limit=limit - changed)
                # Any access (idle below the archive threshold) resets to
                # STANDARD and clears the restore window.
                changed += self._transition(
                    conditions,
                    objects.c.storage_class.in_(tuple(_ARCHIVED_CLASSES))
                    & (idle_ns < archive_ns),
                    "STANDARD", limit=limit - changed, clear_restore=True)
            self.db.commit()
            return changed
        except BaseException:
            self.db.connection.rollback()
            raise


def _idle_expression():
    """Nanoseconds since the last successful read (creation when never read)."""
    from sqlalchemy import func
    return func.coalesce(objects.c.last_accessed_ns,
                         objects.c.created_at * 1_000_000_000)


def rows_for_runner(connection) -> list[dict]:
    """Snapshot all configurations (used by operators/tests)."""
    statement = select(
        tiering_configs.c.bucket, tiering_configs.c.config_id,
        tiering_configs.c.document, tiering_configs.c.updated_ns,
    ).order_by(tiering_configs.c.bucket, tiering_configs.c.config_id)
    return [dict(row) for row in connection.execute(statement).mappings().all()]
