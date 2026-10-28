"""S3 Metadata configuration backed by a REAL, queryable SQL journal.

AWS S3 Metadata exposes an AWS-managed Apache Iceberg "journal table" plus
optional inventory and annotation tables in S3 Tables. TeleDrive has no
Iceberg runtime and no S3 Tables bucket. Rather than fabricate one, this
module maps the API onto the only honest backing we have: the object
mutation journal that already lives in the same SQL database as the
catalog.

Honesty caveat (read before touching the GET responses)
-------------------------------------------------------
* The journal table is ``storage_metadata_journal``. Every row is a real
  object mutation committed in the SAME SQL transaction as the mutation it
  describes (publish, copy, form upload, multipart complete/abort, delete
  marker, version revocation, tag change, annotation change, rename).
* The response identifiers are deliberately **not** AWS ARNs. They are
  TeleDrive-shaped strings of the form ``teledrive:metadata:<bucket>`` and
  ``teledrive:metadata:<bucket>/journal``. They are stable, documented and
  obviously not ``arn:aws:s3tables:...``. ``TableBucketType`` is
  ``teledrive`` (AWS's enum is ``aws``/``customer``) for the same reason.
* The journal is created only for buckets that have a metadata
  configuration row, exactly as AWS creates the table only after
  ``CreateBucketMetadataConfiguration``. Deleting the configuration deletes
  the local journal rows with it (AWS leaves its managed table behind until
  the operator removes it manually; we prefer not to resurrect stale rows
  on re-create).
* ``InventoryTableConfiguration`` and ``AnnotationTableConfiguration`` are
  real boolean switches over this journal. They do NOT create a separate
  live inventory/annotation Iceberg table; annotation events are recorded
  in the same journal. This deviation is deliberate and documented rather
  than emulated with invented table metadata.
* SSE-KMS / S3 Tables encryption is not implemented. ``KmsKeyArn`` or an
  ``SseAlgorithm`` other than ``AES256`` fails with 501 — a local SQL table
  must not claim AWS-managed encryption it does not have.
* Retention is a real bounded cleanup: rows older than the configured
  ``RecordExpiration/Days`` window are deleted in batches. It is invoked
  lazily by ``Get`` and is also safe to call from a scheduler.

Error names
-----------
Verified offline against ``botocore``'s S3 service model (2006-03-01):
none of these nine operations declares an operation-specific error shape
(``m.operation_model(name).error_shapes`` is empty), and the model contains
no 409 response at all. The AWS API reference pages likewise publish no
error list for them. Behavior is therefore matched where AWS *is* explicit
— Create on an existing configuration conflicts, Update on a missing
configuration is 404 — using these codes:

* ``NoSuchConfiguration`` (404) for an absent configuration, matching the
  existing report-configuration family (also not modelled by botocore).
* ``BucketMetadataConfigurationAlreadyExists`` (409) for a duplicate
  Create. This name is a **TeleDrive code**, not an AWS-documented error
  name; it is documented here as *unverified* rather than presented as AWS.

Selectors and IAM action names WERE verified against the model:

    CreateBucketMetadataConfiguration      POST   ?metadataConfiguration
    CreateBucketMetadataTableConfiguration POST   ?metadataTable
    Get/DeleteBucketMetadataConfiguration  GET/DELETE ?metadataConfiguration
    Get/DeleteBucketMetadataTableConfiguration GET/DELETE ?metadataTable
    UpdateBucketMetadataJournalTableConfiguration     PUT ?metadataJournalTable
    UpdateBucketMetadataInventoryTableConfiguration   PUT ?metadataInventoryTable
    UpdateBucketMetadataAnnotationTableConfiguration  PUT ?metadataAnnotationTable

Both create/get/delete V1/V2 pairs share the single IAM action
``s3:CreateBucketMetadataTableConfiguration`` /
``s3:GetBucketMetadataTableConfiguration`` /
``s3:DeleteBucketMetadataTableConfiguration`` (confirmed in the AWS API
reference); the three Update operations have their own action names.
"""
from __future__ import annotations

import json
import logging
import threading
import weakref
import time
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import (BigInteger, Boolean, Column, Index, Integer,
                        MetaData, String, Table, Text, delete, func, insert,
                        select, update)
from sqlalchemy.exc import IntegrityError

from teledrive.storage.catalog import BucketCatalog

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_METADATA_XML_BYTES = 16 * 1024
MAX_DETAIL_BYTES = 1024
MAX_ROLE_BYTES = 2048
MAX_DESTINATION_BYTES = 2048
MAX_TABLE_NAME_BYTES = 255
DEFAULT_TRIM_BATCH = 500
MAX_TRIM_PER_CALL = 5000
MIN_RETENTION_DAYS = 7
MAX_RETENTION_DAYS = 2147483647

# The event vocabulary actually emitted by the catalog and its stores.
EVENTS = frozenset({
    "created", "deleted", "version_revoked", "tagged",
    "annotation_changed", "acl_changed", "restored", "renamed",
})
CONFIG_STATES = ("ENABLED", "DISABLED")
NO_SUCH_CONFIGURATION = "NoSuchConfiguration"
CONFIG_ALREADY_EXISTS = "BucketMetadataConfigurationAlreadyExists"

metadata_journal_metadata = MetaData()
metadata_journal = Table(
    "storage_metadata_journal", metadata_journal_metadata,
    # Integer (not BigInteger) so SQLite's rowid alias and MySQL's
    # AUTO_INCREMENT both assign the monotonic sequence without a default.
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("bucket", String(63), nullable=False),
    Column("object_key", String(1024), nullable=False),
    Column("version_id", String(80)),
    Column("event", String(32), nullable=False),
    Column("actor", String(64), nullable=False, default=""),
    Column("recorded_ns", BigInteger, nullable=False),
    # JSON detail is bounded; oversized details are replaced with a marker.
    Column("detail", Text, nullable=False),
)
Index("ix_storage_metadata_journal_bucket_seq",
      metadata_journal.c.bucket, metadata_journal.c.seq)
Index("ix_storage_metadata_journal_bucket_time",
      metadata_journal.c.bucket, metadata_journal.c.recorded_ns)

metadata_configs = Table(
    "storage_metadata_configs", metadata_journal_metadata,
    Column("bucket", String(63), primary_key=True),
    # 1 = CreateBucketMetadataTableConfiguration (V1 wire shape);
    # 2 = CreateBucketMetadataConfiguration (current V2 shape).
    Column("api_version", Integer, nullable=False, default=2),
    Column("journal_enabled", Boolean, nullable=False, default=True),
    Column("annotation_enabled", Boolean, nullable=False, default=False),
    Column("inventory_enabled", Boolean, nullable=False, default=False),
    # None means RecordExpiration Expiration=DISABLED. A value is days.
    Column("retention_days", Integer),
    Column("role", Text),
    # V1 client-supplied destination, retained as an opaque label for the
    # GET round-trip. It is never presented as a real S3 Tables ARN.
    Column("destination_label", Text),
    Column("table_name", String(MAX_TABLE_NAME_BYTES)),
    Column("created_ns", BigInteger, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
)

_ENSURED_ENGINES: "weakref.WeakSet" = weakref.WeakSet()
_ENSURED_LOCK = threading.Lock()
_LOGGER = logging.getLogger("teledrive.s3.metadata_journal")


class MetadataConfigurationError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def ensure_metadata_tables(engine) -> None:
    """Create both tables once per engine (idempotent).

    Called from application startup and from store constructors. It is NEVER
    called from a catalog mutation: issuing DDL on a separate connection while
    the caller's write transaction holds SQLite's lock deadlocks (the same
    failure mode Phase J fixed for the pending-tag journal).
    """
    with _ENSURED_LOCK:
        if engine in _ENSURED_ENGINES:
            return
        metadata_journal_metadata.create_all(
            engine, tables=[metadata_configs, metadata_journal])
        _ENSURED_ENGINES.add(engine)


# --------------------------------------------------------------------------
# Journal writer (same transaction, savepoint-isolated)
# --------------------------------------------------------------------------

def _bounded_detail(detail: dict | None) -> str:
    if not detail:
        return "{}"
    try:
        encoded = json.dumps(detail, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"))
    except (TypeError, ValueError):
        return '{"truncated":true}'
    if len(encoded.encode("utf-8")) > MAX_DETAIL_BYTES:
        keys = sorted(str(key) for key in detail)[:10]
        return json.dumps({"truncated": True, "keys": keys},
                          separators=(",", ":"))
    return encoded


def journal_event_uncommitted(connection, *, event: str, bucket: str,
                              object_key: str,
                              version_id: str | None = None,
                              actor: str = "",
                              detail: dict | None = None,
                              now_ns: int | None = None) -> bool:
    """Insert one journal row on the caller's EXISTING transaction.

    Returns whether a row was written. Nothing is written unless the bucket
    has an enabled metadata configuration, because no AWS metadata table
    exists before that configuration is created. The caller owns commit and
    rollback, so the row is durable exactly when the mutation is durable.
    """
    if (event not in EVENTS or not isinstance(bucket, str)
            or not isinstance(object_key, str)
            or (version_id is not None and not isinstance(version_id, str))
            or not isinstance(actor, str)):
        return False
    enabled = connection.execute(select(
        metadata_configs.c.journal_enabled,
        metadata_configs.c.annotation_enabled,
    ).where(metadata_configs.c.bucket == bucket)).first()
    if enabled is None or not enabled[0]:
        return False
    if event == "annotation_changed" and not enabled[1]:
        return False
    now_ns = time.time_ns() if now_ns is None else int(now_ns)
    connection.execute(insert(metadata_journal).values(
        bucket=bucket,
        object_key=object_key[:1024],
        version_id=(version_id[:80] if version_id is not None else None),
        event=event,
        actor=actor[:64],
        recorded_ns=now_ns,
        detail=_bounded_detail(detail),
    ))
    return True


def journal_event_safely(connection, **kwargs) -> bool:
    """Never let journal bookkeeping fail the catalog mutation.

    A SAVEPOINT confines any failure (missing tables on a legacy database,
    corrupt configuration) so the surrounding write transaction stays
    usable. On success the row commits with the caller's transaction.
    """
    try:
        with connection.begin_nested():
            return journal_event_uncommitted(connection, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive boundary
        _LOGGER.warning("metadata journal write skipped: %s",
                        type(exc).__name__)
        return False


# --------------------------------------------------------------------------
# Strict XML parsing
# --------------------------------------------------------------------------

def _name(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid(node, label: str) -> bool:
    return node.tag in {label, f"{{{NS}}}{label}"}


def _expect(node, label: str) -> None:
    if not _valid(node, label) or node.attrib:
        raise MetadataConfigurationError(
            "MalformedXML", f"Unexpected {_name(node)!r}; expected {label}")


def _leaf(node, label: str, *, maximum: int) -> str:
    _expect(node, label)
    if len(node):
        raise MetadataConfigurationError(
            "MalformedXML", f"{label} must be a scalar")
    value = node.text or ""
    if len(value.encode("utf-8")) > maximum:
        raise MetadataConfigurationError(
            "InvalidArgument", f"{label} is too long")
    return value


def _children(node, allowed: set[str]) -> dict[str, list]:
    grouped: dict[str, list] = {label: [] for label in allowed}
    for child in node:
        label = _name(child)
        if label not in allowed or not _valid(child, label):
            raise MetadataConfigurationError(
                "MalformedXML", f"Unsupported element {label!r}")
        grouped[label].append(child)
    return grouped


def _single(group: dict[str, list], label: str, *, required: bool = True):
    values = group[label]
    if len(values) > 1:
        raise MetadataConfigurationError("MalformedXML", f"Duplicate {label}")
    if not values:
        if required:
            raise MetadataConfigurationError(
                "InvalidArgument", f"Missing {label}")
        return None
    return values[0]


def _encryption(node) -> None:
    """Reject every encryption claim: this journal is a local SQL table."""
    _expect(node, "EncryptionConfiguration")
    fields = _children(node, {"KmsKeyArn", "SseAlgorithm"})
    kms = _single(fields, "KmsKeyArn", required=False)
    algorithm = _single(fields, "SseAlgorithm", required=False)
    if kms is not None or algorithm is not None:
        raise MetadataConfigurationError(
            "NotImplemented",
            "S3 Metadata table encryption (KMS/S3 Tables) is not implemented; "
            "TeleDrive stores the journal in its own SQL database", 501)


def _record_expiration(node) -> int | None:
    _expect(node, "RecordExpiration")
    fields = _children(node, {"Days", "Expiration"})
    expiration = _leaf(_single(fields, "Expiration"), "Expiration", maximum=16)
    if expiration not in CONFIG_STATES:
        raise MetadataConfigurationError(
            "InvalidArgument", "Expiration must be ENABLED or DISABLED")
    days_node = _single(fields, "Days", required=False)
    if expiration == "DISABLED":
        return None
    if days_node is None:
        raise MetadataConfigurationError(
            "InvalidArgument", "Days is required when Expiration is ENABLED")
    raw = _leaf(days_node, "Days", maximum=12)
    try:
        days = int(raw)
    except ValueError as exc:
        raise MetadataConfigurationError(
            "InvalidArgument", "Days must be an integer") from exc
    if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
        raise MetadataConfigurationError(
            "InvalidArgument",
            f"Days must be between {MIN_RETENTION_DAYS} and "
            f"{MAX_RETENTION_DAYS}")
    return days


def _configuration_state(node) -> bool:
    _expect(node, "ConfigurationState")
    if len(node):
        raise MetadataConfigurationError(
            "MalformedXML", "ConfigurationState must be a scalar")
    value = node.text or ""
    if value not in CONFIG_STATES:
        raise MetadataConfigurationError(
            "InvalidArgument", "ConfigurationState must be ENABLED or DISABLED")
    return value == "ENABLED"


def _journal_table(node) -> int | None:
    _expect(node, "JournalTableConfiguration")
    fields = _children(node, {"EncryptionConfiguration", "RecordExpiration"})
    encryption = _single(fields, "EncryptionConfiguration", required=False)
    if encryption is not None:
        _encryption(encryption)
    return _record_expiration(_single(fields, "RecordExpiration"))


def _inventory_table(node) -> bool:
    _expect(node, "InventoryTableConfiguration")
    fields = _children(node, {"ConfigurationState", "EncryptionConfiguration"})
    enabled = _configuration_state(_single(fields, "ConfigurationState"))
    encryption = _single(fields, "EncryptionConfiguration", required=False)
    if encryption is not None:
        _encryption(encryption)
    return enabled


def _annotation_table(node) -> tuple[bool, str]:
    _expect(node, "AnnotationTableConfiguration")
    fields = _children(node, {
        "ConfigurationState", "EncryptionConfiguration", "Role"})
    enabled = _configuration_state(_single(fields, "ConfigurationState"))
    encryption = _single(fields, "EncryptionConfiguration", required=False)
    if encryption is not None:
        _encryption(encryption)
    role_node = _single(fields, "Role", required=False)
    role = (_leaf(role_node, "Role", maximum=MAX_ROLE_BYTES)
            if role_node is not None else "")
    return enabled, role


def _root(payload: bytes, label: str):
    if not isinstance(payload, (bytes, bytearray)):
        raise MetadataConfigurationError(
            "MalformedXML", "Metadata configuration body required")
    if len(payload) > MAX_METADATA_XML_BYTES:
        raise MetadataConfigurationError(
            "MalformedXML", "Metadata configuration XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(bytes(payload))
    except (ET.ParseError, DefusedXmlException) as exc:
        raise MetadataConfigurationError(
            "MalformedXML", "Invalid metadata configuration XML") from exc
    if not _valid(root, label) or root.attrib:
        raise MetadataConfigurationError(
            "MalformedXML", f"Unexpected {label} document")
    return root


def parse_create_configuration(payload: bytes) -> dict:
    """Parse ``MetadataConfiguration`` used by CreateBucketMetadataConfiguration."""
    root = _root(payload, "MetadataConfiguration")
    fields = _children(root, {
        "JournalTableConfiguration", "InventoryTableConfiguration",
        "AnnotationTableConfiguration",
    })
    retention = _journal_table(_single(fields, "JournalTableConfiguration"))
    inventory = _single(fields, "InventoryTableConfiguration", required=False)
    annotation = _single(fields, "AnnotationTableConfiguration", required=False)
    inventory_enabled = _inventory_table(inventory) if inventory is not None else False
    annotation_enabled, role = (
        _annotation_table(annotation) if annotation is not None else (False, ""))
    return {
        "api_version": 2,
        "retention_days": retention,
        "inventory_enabled": inventory_enabled,
        "annotation_enabled": annotation_enabled,
        "role": role,
        "destination_label": "",
        "table_name": "",
    }


def parse_create_table_configuration(payload: bytes) -> dict:
    """Parse the V1 ``MetadataTableConfiguration`` create document."""
    root = _root(payload, "MetadataTableConfiguration")
    fields = _children(root, {"S3TablesDestination"})
    destination = _single(fields, "S3TablesDestination")
    _expect(destination, "S3TablesDestination")
    inner = _children(destination, {"TableBucketArn", "TableName"})
    arn = _leaf(_single(inner, "TableBucketArn"), "TableBucketArn",
                maximum=MAX_DESTINATION_BYTES)
    table_name = _leaf(_single(inner, "TableName"), "TableName",
                       maximum=MAX_TABLE_NAME_BYTES)
    if not arn or any(ord(char) < 33 or ord(char) == 127 for char in arn):
        raise MetadataConfigurationError(
            "InvalidArgument", "Invalid TableBucketArn")
    if not table_name or any(ord(char) < 33 or ord(char) == 127
                             for char in table_name):
        raise MetadataConfigurationError("InvalidArgument", "Invalid TableName")
    return {
        "api_version": 1,
        "retention_days": None,
        "inventory_enabled": False,
        "annotation_enabled": False,
        "role": "",
        # The client-supplied destination is retained as an OPAQUE label.
        # It is echoed only in the V1 destination result and is never
        # presented as a real, provisioned S3 Tables bucket.
        "destination_label": arn,
        "table_name": table_name,
    }


def parse_journal_update(payload: bytes) -> int | None:
    """Parse ``JournalTableConfiguration`` for the journal Update operation."""
    root = _root(payload, "JournalTableConfiguration")
    fields = _children(root, {"RecordExpiration"})
    return _record_expiration(_single(fields, "RecordExpiration"))


def parse_inventory_update(payload: bytes) -> bool:
    """Parse ``InventoryTableConfiguration`` for the inventory Update."""
    root = _root(payload, "InventoryTableConfiguration")
    fields = _children(root, {"ConfigurationState", "EncryptionConfiguration"})
    enabled = _configuration_state(_single(fields, "ConfigurationState"))
    encryption = _single(fields, "EncryptionConfiguration", required=False)
    if encryption is not None:
        _encryption(encryption)
    return enabled


def parse_annotation_update(payload: bytes) -> tuple[bool, str | None]:
    """Parse ``AnnotationTableConfiguration`` for the annotation Update."""
    root = _root(payload, "AnnotationTableConfiguration")
    fields = _children(root, {
        "ConfigurationState", "EncryptionConfiguration", "Role"})
    enabled = _configuration_state(_single(fields, "ConfigurationState"))
    encryption = _single(fields, "EncryptionConfiguration", required=False)
    if encryption is not None:
        _encryption(encryption)
    role_node = _single(fields, "Role", required=False)
    role = (_leaf(role_node, "Role", maximum=MAX_ROLE_BYTES)
            if role_node is not None else None)
    return enabled, role


# --------------------------------------------------------------------------
# Response rendering (TeleDrive identifiers, never AWS ARNs)
# --------------------------------------------------------------------------

def telemetry_table_ids(bucket: str) -> dict[str, str]:
    """Documented, non-AWS identifiers for the local journal table."""
    return {
        "bucket": f"teledrive:metadata:{bucket}",
        "journal": f"teledrive:metadata:{bucket}/journal",
        "inventory": f"teledrive:metadata:{bucket}/inventory",
        "annotation": f"teledrive:metadata:{bucket}/annotation",
    }


def _http_date(ns: int | None) -> str:
    if ns is None:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                         time.gmtime(int(ns) / 1_000_000_000))


def _append_stats(parent, stats: dict) -> None:
    """TeleDrive extension: real journal row statistics under the table."""
    node = ET.SubElement(parent, "TableStatistics")
    ET.SubElement(node, "RecordCount").text = str(stats.get("count", 0))
    ET.SubElement(node, "OldestRecordTimestamp").text = _http_date(
        stats.get("oldest_ns"))
    ET.SubElement(node, "NewestRecordTimestamp").text = _http_date(
        stats.get("newest_ns"))


def _state(value: bool) -> str:
    return "ENABLED" if value else "DISABLED"


def configuration_xml(bucket: str, config: dict, stats: dict) -> bytes:
    """V2 ``GetBucketMetadataConfiguration`` result derived from real data."""
    ids = telemetry_table_ids(bucket)
    root = ET.Element("GetBucketMetadataConfigurationResult", xmlns=NS)
    result = ET.SubElement(root, "MetadataConfigurationResult")
    destination = ET.SubElement(result, "DestinationResult")
    ET.SubElement(destination, "TableBucketArn").text = ids["bucket"]
    # AWS's enum is aws|customer. "teledrive" is explicit about the
    # substitution and cannot be mistaken for an AWS-managed table bucket.
    ET.SubElement(destination, "TableBucketType").text = "teledrive"
    ET.SubElement(destination, "TableNamespace").text = "teledrive_metadata"

    journal = ET.SubElement(result, "JournalTableConfigurationResult")
    expiration = ET.SubElement(journal, "RecordExpiration")
    days = config.get("retention_days")
    ET.SubElement(expiration, "Expiration").text = (
        "ENABLED" if days else "DISABLED")
    if days:
        ET.SubElement(expiration, "Days").text = str(days)
    ET.SubElement(journal, "TableArn").text = ids["journal"]
    ET.SubElement(journal, "TableName").text = "journal"
    ET.SubElement(journal, "TableStatus").text = "ACTIVE"
    _append_stats(journal, stats)

    inventory = ET.SubElement(result, "InventoryTableConfigurationResult")
    ET.SubElement(inventory, "ConfigurationState").text = _state(
        config.get("inventory_enabled", False))
    ET.SubElement(inventory, "TableArn").text = ids["inventory"]
    ET.SubElement(inventory, "TableName").text = "inventory"
    ET.SubElement(inventory, "TableStatus").text = "ACTIVE"
    _append_stats(inventory, stats)

    annotation = ET.SubElement(result, "AnnotationTableConfigurationResult")
    ET.SubElement(annotation, "ConfigurationState").text = _state(
        config.get("annotation_enabled", False))
    if config.get("role"):
        ET.SubElement(annotation, "Role").text = config["role"]
    ET.SubElement(annotation, "TableArn").text = ids["annotation"]
    ET.SubElement(annotation, "TableName").text = "annotation"
    ET.SubElement(annotation, "TableStatus").text = "ACTIVE"
    _append_stats(annotation, stats)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def table_configuration_xml(bucket: str, config: dict, stats: dict) -> bytes:
    """V1 ``GetBucketMetadataTableConfiguration`` result."""
    ids = telemetry_table_ids(bucket)
    root = ET.Element("GetBucketMetadataTableConfigurationResult", xmlns=NS)
    result = ET.SubElement(root, "MetadataTableConfigurationResult")
    destination = ET.SubElement(result, "S3TablesDestinationResult")
    ET.SubElement(destination, "TableArn").text = ids["journal"]
    ET.SubElement(destination, "TableBucketArn").text = ids["bucket"]
    ET.SubElement(destination, "TableName").text = (
        config.get("table_name") or "journal")
    ET.SubElement(destination, "TableNamespace").text = "teledrive_metadata"
    ET.SubElement(root, "Status").text = "ACTIVE"
    _append_stats(root, stats)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


# --------------------------------------------------------------------------
# Stores
# --------------------------------------------------------------------------

class MetadataJournalStore:
    """Read and trim ``storage_metadata_journal`` for one catalog."""

    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        ensure_metadata_tables(self.db.engine)

    def stats(self, bucket: str) -> dict:
        row = self.db.connection.execute(
            select(func.count(metadata_journal.c.seq),
                   func.min(metadata_journal.c.recorded_ns),
                   func.max(metadata_journal.c.recorded_ns))
            .where(metadata_journal.c.bucket == bucket)).one()
        return {"count": int(row[0] or 0),
                "oldest_ns": int(row[1]) if row[1] is not None else None,
                "newest_ns": int(row[2]) if row[2] is not None else None}

    def rows(self, bucket: str, *, limit: int = 1000) -> list[dict]:
        """Bounded inspection helper (never exposed by an S3 GET body)."""
        if not 1 <= limit <= 1000:
            raise ValueError("Invalid journal page limit")
        rows = self.db.connection.execute(
            select(metadata_journal.c.seq, metadata_journal.c.object_key,
                   metadata_journal.c.version_id, metadata_journal.c.event,
                   metadata_journal.c.actor, metadata_journal.c.recorded_ns,
                   metadata_journal.c.detail)
            .where(metadata_journal.c.bucket == bucket)
            .order_by(metadata_journal.c.seq).limit(limit)
        ).mappings().all()
        return [dict(row) for row in rows]

    def trim_expired(self, *, now_ns: int | None = None,
                     batch: int = DEFAULT_TRIM_BATCH) -> int:
        """Delete journal rows older than each bucket's retention window.

        Batched so a first run on a large journal cannot hold one enormous
        write lock. Returns the number of rows removed.
        """
        if not 1 <= batch <= MAX_TRIM_PER_CALL:
            raise ValueError("Invalid retention batch size")
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        deleted = 0
        configs = self.db.connection.execute(
            select(metadata_configs.c.bucket, metadata_configs.c.retention_days)
            .where(metadata_configs.c.retention_days.is_not(None))
        ).all()
        try:
            for bucket, days in configs:
                if not days:
                    continue
                cutoff = now_ns - int(days) * 86400 * 1_000_000_000
                while deleted < MAX_TRIM_PER_CALL:
                    expired = [int(row[0]) for row in self.db.connection.execute(
                        select(metadata_journal.c.seq)
                        .where(metadata_journal.c.bucket == bucket,
                               metadata_journal.c.recorded_ns < cutoff)
                        .order_by(metadata_journal.c.seq)
                        .limit(min(batch, MAX_TRIM_PER_CALL - deleted))
                    ).all()]
                    if not expired:
                        break
                    # A concrete IN list, not a LIMIT subquery: MySQL rejects
                    # ``DELETE ... WHERE seq IN (SELECT ... LIMIT n)``.
                    removed = self.db.connection.execute(
                        delete(metadata_journal).where(
                            metadata_journal.c.seq.in_(expired)))
                    deleted += int(removed.rowcount or 0)
                    self.db.commit()
                    if len(expired) < batch:
                        break
            return deleted
        except BaseException:
            self.db.connection.rollback()
            raise


class MetadataConfigurationStore:
    """CRUD for ``storage_metadata_configs`` with real journal statistics."""

    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        ensure_metadata_tables(self.db.engine)

    def _bucket_exists(self, bucket: str) -> None:
        if bucket not in self.catalog.list_buckets():
            raise FileNotFoundError("Bucket not found")

    def create(self, bucket: str, config: dict, *,
               now_ns: int | None = None) -> dict:
        """Create the configuration; 409 when one already exists."""
        self._bucket_exists(bucket)
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        try:
            self.db.connection.execute(insert(metadata_configs).values(
                bucket=bucket,
                api_version=int(config.get("api_version", 2)),
                journal_enabled=True,
                annotation_enabled=bool(config.get("annotation_enabled")),
                inventory_enabled=bool(config.get("inventory_enabled")),
                retention_days=config.get("retention_days"),
                role=config.get("role") or None,
                destination_label=config.get("destination_label") or None,
                table_name=config.get("table_name") or None,
                created_ns=now_ns,
                updated_ns=now_ns,
            ))
            self.db.commit()
        except IntegrityError as exc:
            self.db.connection.rollback()
            raise MetadataConfigurationError(
                CONFIG_ALREADY_EXISTS,
                "A metadata configuration already exists for this bucket",
                409,
            ) from exc
        except BaseException:
            self.db.connection.rollback()
            raise
        value = self.get(bucket)
        if value is None:  # pragma: no cover - insert/commit invariant
            raise RuntimeError("Metadata configuration vanished after insert")
        return value

    def get(self, bucket: str) -> dict | None:
        self._bucket_exists(bucket)
        row = self.db.connection.execute(select(
            metadata_configs.c.api_version,
            metadata_configs.c.journal_enabled,
            metadata_configs.c.annotation_enabled,
            metadata_configs.c.inventory_enabled,
            metadata_configs.c.retention_days,
            metadata_configs.c.role,
            metadata_configs.c.destination_label,
            metadata_configs.c.table_name,
            metadata_configs.c.created_ns,
            metadata_configs.c.updated_ns,
        ).where(metadata_configs.c.bucket == bucket)).first()
        if row is None:
            return None
        return {
            "bucket": bucket,
            "api_version": int(row[0]),
            "journal_enabled": bool(row[1]),
            "annotation_enabled": bool(row[2]),
            "inventory_enabled": bool(row[3]),
            "retention_days": int(row[4]) if row[4] is not None else None,
            "role": row[5] or "",
            "destination_label": row[6] or "",
            "table_name": row[7] or "",
            "created_ns": int(row[8]),
            "updated_ns": int(row[9]),
        }

    def get_with_stats(self, bucket: str, *, trim: bool = True) -> dict | None:
        """Configuration plus real journal stats; lazily applies retention."""
        config = self.get(bucket)
        if config is None:
            return None
        journals = MetadataJournalStore(self.catalog)
        if trim and config.get("retention_days"):
            journals.trim_expired()
        config["journal_stats"] = journals.stats(bucket)
        return config

    def delete(self, bucket: str) -> bool:
        """Delete the configuration and its local journal rows (idempotent)."""
        self._bucket_exists(bucket)
        try:
            removed = self.db.connection.execute(delete(metadata_configs).where(
                metadata_configs.c.bucket == bucket))
            self.db.connection.execute(delete(metadata_journal).where(
                metadata_journal.c.bucket == bucket))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        return removed.rowcount > 0

    def _require(self, bucket: str) -> None:
        if self.get(bucket) is None:
            raise MetadataConfigurationError(
                NO_SUCH_CONFIGURATION,
                "The specified metadata configuration does not exist", 404)

    def update_journal(self, bucket: str, retention_days: int | None, *,
                       now_ns: int | None = None) -> dict:
        """Update journal record expiration; 404 when the config is absent."""
        self._bucket_exists(bucket)
        self._require(bucket)
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        self.db.connection.execute(update(metadata_configs).where(
            metadata_configs.c.bucket == bucket).values(
                retention_days=retention_days, updated_ns=now_ns))
        self.db.commit()
        value = self.get(bucket)
        assert value is not None
        return value

    def update_inventory(self, bucket: str, enabled: bool, *,
                         now_ns: int | None = None) -> dict:
        """Enable/disable inventory-table state; 404 when config is absent."""
        self._bucket_exists(bucket)
        self._require(bucket)
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        self.db.connection.execute(update(metadata_configs).where(
            metadata_configs.c.bucket == bucket).values(
                inventory_enabled=bool(enabled), updated_ns=now_ns))
        self.db.commit()
        value = self.get(bucket)
        assert value is not None
        return value

    def update_annotation(self, bucket: str, enabled: bool,
                          role: str | None, *,
                          now_ns: int | None = None) -> dict:
        """Enable/disable annotation journaling; 404 when config is absent.

        ``role=None`` keeps the previously stored role (AWS treats Role as
        optional on this update) and an explicit empty string clears it.
        """
        self._bucket_exists(bucket)
        current = self.get(bucket)
        if current is None:
            raise MetadataConfigurationError(
                NO_SUCH_CONFIGURATION,
                "The specified metadata configuration does not exist", 404)
        if role is None:
            role = current.get("role") or ""
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        self.db.connection.execute(update(metadata_configs).where(
            metadata_configs.c.bucket == bucket).values(
                annotation_enabled=bool(enabled),
                role=role or None,
                updated_ns=now_ns))
        self.db.commit()
        value = self.get(bucket)
        assert value is not None
        return value
