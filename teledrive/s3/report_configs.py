"""Strict, bounded S3 storage-report configuration CRUD.

Three AWS "configuration" families share one SQL table:

* ``analytics``  Put/Get/Delete/ListBucketAnalyticsConfiguration
* ``inventory``  Put/Get/Delete/ListBucketInventoryConfiguration
* ``metrics``    Put/Get/Delete/ListBucketMetricsConfiguration

The XML parser is deliberately strict: 16 KiB maximum, defusedxml, namespace
checked, unknown elements rejected, duplicate ``Id`` elements rejected and
filter forms outside the implemented subset rejected (400) or declared
unsupported (501). Each stored document has an ``Id`` (1..64 characters,
``[A-Za-z0-9._-]``) that is also the ``?analytics&id=...`` query selector.

Honest backing notes

* ``inventory`` destinations are real buckets and the runner writes a real
  gzip CSV object (see ``report_runner.py``).
* ``analytics`` uses the same object-level data, emitted as JSON Lines. AWS
  exports Parquet; that deviation is recorded in the report object metadata
  and in the runner docstring.
* ``metrics`` has no ``Destination`` element in AWS (CloudWatch is the sink).
  TeleDrive has no CloudWatch channel, so the analyzed bucket itself is the
  destination and the runner writes a JSON metrics document under
  ``reports/metrics/<config-id>/``. CloudWatch is explicitly *not* claimed.
* ``schedule`` supports Daily and Weekly only. Continuous export is not an
  inventory feature; any other frequency is 501.

AWS error names (verified against the S3 API reference): all three GET
operations answer 404 ``NoSuchConfiguration`` when the requested ``id`` does
not exist. That name is used uniformly here with an explicit comment because
the inventory/metrics variants are easy to misremember as
``NoSuchInventoryConfiguration``/``NoSuchMetricsConfiguration``; they are not.
"""
from __future__ import annotations

import json
import re
import threading
import weakref
import time
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import (BigInteger, Column, MetaData, String, Table, Text,
                        delete, insert, select, update)

from teledrive.storage.catalog import BucketCatalog

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_REPORT_XML_BYTES = 16 * 1024
KINDS = ("analytics", "inventory", "metrics")
KIND_LABELS = {
    "analytics": "AnalyticsConfiguration",
    "inventory": "InventoryConfiguration",
    "metrics": "MetricsConfiguration",
}
LIST_LABELS = {
    "analytics": "ListBucketAnalyticsConfigurationsResult",
    "inventory": "ListBucketInventoryConfigurationsResult",
    "metrics": "ListBucketMetricsConfigurationsResult",
}
SCHEDULES = ("Daily", "Weekly")
FORMATS = ("CSV", "ORC", "Parquet")
NO_SUCH_CONFIGURATION = "NoSuchConfiguration"
_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_MAX_PREFIX_BYTES = 1024

report_metadata = MetaData()
report_configs = Table(
    "storage_report_configs", report_metadata,
    Column("bucket", String(63), primary_key=True),
    Column("kind", String(16), primary_key=True),
    Column("config_id", String(64), primary_key=True),
    Column("document", Text, nullable=False),
    Column("created_ns", BigInteger, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
    # Scheduler receipt. last_run_ns advances only after a report object is
    # really published; last_error records failures without pretending the
    # run happened. last_attempt_ns is a short lease so two workers cannot
    # generate the same due report concurrently.
    Column("last_run_ns", BigInteger),
    Column("last_attempt_ns", BigInteger),
    Column("last_error", Text),
)

_ENSURED_ENGINES: "weakref.WeakSet" = weakref.WeakSet()
_ENSURED_LOCK = threading.Lock()


class ReportConfigError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def ensure_report_tables(engine) -> None:
    """Create the report table once per engine (idempotent).

    Called from application startup and from the store constructor — never
    from a catalog mutation transaction (that path deadlocks SQLite).
    """
    with _ENSURED_LOCK:
        if engine in _ENSURED_ENGINES:
            return
        report_metadata.create_all(engine, tables=[report_configs])
        _ENSURED_ENGINES.add(engine)


def _name(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid(node, label: str) -> bool:
    return node.tag in {label, f"{{{NS}}}{label}"}


def _expect(node, label: str) -> None:
    if not _valid(node, label) or node.attrib:
        raise ReportConfigError(
            "MalformedXML", f"Unexpected {_name(node)!r}; expected {label}")


def _leaf(node, label: str, *, maximum: int = _MAX_PREFIX_BYTES) -> str:
    _expect(node, label)
    if len(node):
        raise ReportConfigError("MalformedXML", f"{label} must be a scalar")
    value = node.text or ""
    if len(value.encode("utf-8")) > maximum:
        raise ReportConfigError("InvalidArgument", f"{label} is too long")
    return value


def _children(node, allowed: set[str]) -> dict[str, list]:
    """Group child elements by local name; reject unknown or namespaced ones."""
    grouped: dict[str, list] = {label: [] for label in allowed}
    for child in node:
        label = _name(child)
        if label not in allowed or not _valid(child, label):
            raise ReportConfigError(
                "MalformedXML", f"Unsupported element {label!r}")
        grouped[label].append(child)
    return grouped


def _single(group: dict[str, list], label: str, *, required: bool = True):
    values = group[label]
    if len(values) > 1:
        raise ReportConfigError("MalformedXML", f"Duplicate {label}")
    if not values:
        if required:
            raise ReportConfigError("InvalidArgument", f"Missing {label}")
        return None
    return values[0]


def _config_id(value: str, label: str = "Id") -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ReportConfigError(
            "InvalidArgument",
            f"{label} must be 1..64 characters of [A-Za-z0-9._-]")
    return value


def _prefix(value: str, label: str = "Prefix") -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise ReportConfigError("InvalidArgument", f"Invalid {label}") from exc
    if len(encoded) > _MAX_PREFIX_BYTES:
        raise ReportConfigError("InvalidArgument", f"{label} is too long")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ReportConfigError("InvalidArgument", f"Invalid {label}")
    return value


def _tag(node) -> dict[str, str]:
    _expect(node, "Tag")
    group = _children(node, {"Key", "Value"})
    key = _leaf(_single(group, "Key"), "Key", maximum=128)
    value = _leaf(_single(group, "Value"), "Value", maximum=256)
    if not key or key.lower().startswith("aws:"):
        raise ReportConfigError("InvalidArgument", "Invalid tag key")
    return {"key": key, "value": value}


def _filter(node) -> dict:
    """Parse the supported Filter subset: Prefix, Tag, And(Prefix|Tag...)."""
    _expect(node, "Filter")
    if len(node) != 1:
        raise ReportConfigError("InvalidArgument", "Filter needs exactly one form")
    child = node[0]
    label = _name(child)
    if label == "Prefix":
        return {"prefix": _prefix(_leaf(child, "Prefix")), "tags": []}
    if label == "Tag":
        return {"prefix": "", "tags": [_tag(child)]}
    if label == "And":
        _expect(child, "And")
        if child.attrib:
            raise ReportConfigError("MalformedXML", "Unexpected And attributes")
        prefix = ""
        tags: list[dict[str, str]] = []
        for item in child:
            item_label = _name(item)
            if item_label == "Prefix":
                if prefix:
                    raise ReportConfigError(
                        "InvalidArgument", "Duplicate prefix in And filter")
                prefix = _prefix(_leaf(item, "Prefix"))
            elif item_label == "Tag":
                tags.append(_tag(item))
            elif item_label in {"ObjectSizeGreaterThan", "ObjectSizeLessThan"}:
                raise ReportConfigError(
                    "NotImplemented",
                    "Object-size report filters are not implemented", 501)
            else:
                raise ReportConfigError(
                    "MalformedXML", f"Unsupported filter element {item_label!r}")
        if not prefix and not tags:
            raise ReportConfigError("InvalidArgument", "Empty And filter")
        if len(tags) > 10:
            raise ReportConfigError("InvalidArgument", "At most 10 filter tags")
        if len({tag["key"] for tag in tags}) != len(tags):
            raise ReportConfigError("InvalidArgument", "Duplicate filter tag key")
        return {"prefix": prefix, "tags": tags}
    if label in {"ObjectSizeGreaterThan", "ObjectSizeLessThan"}:
        raise ReportConfigError(
            "NotImplemented", "Object-size report filters are not implemented",
            501)
    raise ReportConfigError("MalformedXML", f"Unsupported filter form {label!r}")


def _destination(node) -> dict:
    """Parse Destination/S3BucketDestination (analytics + inventory)."""
    _expect(node, "Destination")
    group = _children(node, {"S3BucketDestination"})
    bucket_node = _single(group, "S3BucketDestination")
    _expect(bucket_node, "S3BucketDestination")
    fields = _children(bucket_node, {"AccountId", "Bucket", "Format", "Prefix"})
    account = _single(fields, "AccountId", required=False)
    if account is not None:
        value = _leaf(account, "AccountId", maximum=12)
        if value and not value.isdigit():
            raise ReportConfigError("InvalidArgument", "Invalid AccountId")
    raw_bucket = _leaf(_single(fields, "Bucket"), "Bucket", maximum=255)
    if raw_bucket.startswith("arn:aws:s3:::"):
        raw_bucket = raw_bucket[len("arn:aws:s3:::"):]
    elif raw_bucket.startswith("arn:"):
        raise ReportConfigError(
            "InvalidArgument", "Only arn:aws:s3:::bucket destinations are supported")
    try:
        BucketCatalog.validate_bucket(raw_bucket)
    except ValueError as exc:
        raise ReportConfigError(
            "InvalidArgument", "Invalid destination bucket") from exc
    bucket = raw_bucket
    fmt = _leaf(_single(fields, "Format"), "Format", maximum=16)
    if fmt not in FORMATS:
        raise ReportConfigError("InvalidArgument", "Invalid report format")
    prefix_node = _single(fields, "Prefix", required=False)
    prefix = _prefix(_leaf(prefix_node, "Prefix")) if prefix_node is not None else ""
    return {"bucket": bucket, "prefix": prefix, "format": fmt}


def _parse_analytics(root) -> dict:
    group = _children(root, {"Id", "Filter", "StorageClassAnalysis"})
    ident = _config_id(_leaf(_single(group, "Id"), "Id"))
    filter_node = _single(group, "Filter", required=False)
    value = {"id": ident,
             "filter": _filter(filter_node) if filter_node is not None
             else {"prefix": "", "tags": []}}
    analysis = _single(group, "StorageClassAnalysis")
    _expect(analysis, "StorageClassAnalysis")
    export_group = _children(analysis, {"DataExport"})
    export = _single(export_group, "DataExport")
    _expect(export, "DataExport")
    export_fields = _children(export, {"OutputSchemaVersion", "Destination"})
    schema = _leaf(_single(export_fields, "OutputSchemaVersion"),
                   "OutputSchemaVersion", maximum=16)
    if schema != "V_1":
        raise ReportConfigError(
            "InvalidArgument", "OutputSchemaVersion must be V_1")
    destination = _destination(_single(export_fields, "Destination"))
    if destination["format"] != "CSV":
        # Analytics on AWS is CSV-only; accepting ORC/Parquet would be a lie.
        raise ReportConfigError(
            "NotImplemented",
            "Analytics export supports CSV only; ORC/Parquet is not implemented",
            501)
    value["destination"] = destination
    value["schedule"] = "Daily"   # analytics is a daily AWS report
    value["enabled"] = True
    return value


def _parse_inventory(root) -> dict:
    group = _children(root, {
        "Id", "IsEnabled", "Destination", "Schedule", "Filter",
        "IncludedObjectVersions", "OptionalFields",
    })
    ident = _config_id(_leaf(_single(group, "Id"), "Id"))
    enabled_text = _leaf(_single(group, "IsEnabled"), "IsEnabled", maximum=5)
    if enabled_text not in {"true", "false"}:
        raise ReportConfigError("InvalidArgument", "IsEnabled must be boolean")
    destination = _destination(_single(group, "Destination"))
    if destination["format"] != "CSV":
        raise ReportConfigError(
            "NotImplemented",
            "Inventory export supports CSV (gzip) only; ORC/Parquet is not "
            "implemented", 501)
    schedule_node = _single(group, "Schedule")
    _expect(schedule_node, "Schedule")
    frequency = _leaf(_single(_children(schedule_node, {"Frequency"}),
                              "Frequency"), "Frequency", maximum=16)
    if frequency not in SCHEDULES:
        raise ReportConfigError(
            "NotImplemented",
            "Only Daily and Weekly inventory schedules exist; continuous "
            "export is not implemented", 501)
    filter_node = _single(group, "Filter", required=False)
    prefix = ""
    if filter_node is not None:
        _expect(filter_node, "Filter")
        fields = _children(filter_node, {"Prefix"})
        if set(_name(child) for child in filter_node) != {"Prefix"}:
            raise ReportConfigError(
                "MalformedXML", "Inventory filters support Prefix only")
        prefix = _prefix(_leaf(_single(fields, "Prefix"), "Prefix"))
    versions = _leaf(_single(group, "IncludedObjectVersions"),
                     "IncludedObjectVersions", maximum=16)
    if versions not in {"All", "Current"}:
        raise ReportConfigError(
            "InvalidArgument", "IncludedObjectVersions must be All or Current")
    optional: list[str] = []
    optional_node = _single(group, "OptionalFields", required=False)
    if optional_node is not None:
        _expect(optional_node, "OptionalFields")
        allowed = {"Size", "LastModifiedDate", "StorageClass", "ETag"}
        known_unsupported = {
            "IsMultipartUploaded", "ReplicationStatus", "EncryptionStatus",
            "ObjectAccessControlList", "ObjectOwner", "ObjectLockRetainUntilDate",
            "ObjectLockMode", "ObjectLockLegalHoldStatus", "ChecksumAlgorithm",
        }
        for field in optional_node:
            label = _name(field)
            value = _leaf(field, label, maximum=64)
            if value in known_unsupported:
                raise ReportConfigError(
                    "NotImplemented",
                    f"Inventory OptionalFields/{value} is not implemented", 501)
            if value not in allowed:
                raise ReportConfigError(
                    "MalformedXML", f"Unsupported OptionalFields value {value!r}")
            if value in optional:
                raise ReportConfigError("InvalidArgument", "Duplicate optional field")
            optional.append(value)
    return {
        "id": ident,
        "enabled": enabled_text == "true",
        "destination": destination,
        "schedule": frequency,
        "filter": {"prefix": prefix, "tags": []},
        "included_object_versions": versions,
        "optional_fields": optional,
    }


def _parse_metrics(root) -> dict:
    # AWS MetricsConfiguration has no Destination and no Schedule: CloudWatch
    # is the sink. TeleDrive substitutes a real JSON document in the analyzed
    # bucket (see the module docstring); it never claims CloudWatch delivery.
    group = _children(root, {"Id", "Filter"})
    ident = _config_id(_leaf(_single(group, "Id"), "Id"))
    filter_node = _single(group, "Filter", required=False)
    filter_value = (_filter(filter_node) if filter_node is not None
                    else {"prefix": "", "tags": []})
    return {"id": ident, "filter": filter_value, "enabled": True,
            "schedule": "Daily"}


def parse_document(kind: str, payload: bytes, *,
                   expected_id: str | None = None) -> dict:
    """Parse one strict configuration document for the given report kind."""
    if kind not in KINDS:
        raise ReportConfigError("InvalidArgument", "Unknown report kind")
    if not isinstance(payload, (bytes, bytearray)):
        raise ReportConfigError("MalformedXML", "Report configuration body required")
    if len(payload) > MAX_REPORT_XML_BYTES:
        raise ReportConfigError(
            "MalformedXML", "Report configuration XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(bytes(payload))
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ReportConfigError(
            "MalformedXML", "Invalid report configuration XML") from exc
    label = KIND_LABELS[kind]
    if not _valid(root, label) or root.attrib:
        raise ReportConfigError("MalformedXML", f"Unexpected {label} document")
    parsed = {"analytics": _parse_analytics,
              "inventory": _parse_inventory,
              "metrics": _parse_metrics}[kind](root)
    if expected_id is not None and parsed["id"] != expected_id:
        raise ReportConfigError(
            "InvalidArgument", "URL configuration id does not match document Id")
    return parsed


def _append_filter(parent, filter_value: dict) -> None:
    prefix = filter_value.get("prefix", "")
    tags = filter_value.get("tags") or []
    if not prefix and not tags:
        return
    node = ET.SubElement(parent, "Filter")
    if tags and (prefix or len(tags) > 1):
        node = ET.SubElement(node, "And")
        if prefix:
            ET.SubElement(node, "Prefix").text = prefix
        for tag in tags:
            tag_node = ET.SubElement(node, "Tag")
            ET.SubElement(tag_node, "Key").text = tag["key"]
            ET.SubElement(tag_node, "Value").text = tag["value"]
        return
    if tags:
        tag_node = ET.SubElement(node, "Tag")
        ET.SubElement(tag_node, "Key").text = tags[0]["key"]
        ET.SubElement(tag_node, "Value").text = tags[0]["value"]
    else:
        ET.SubElement(node, "Prefix").text = prefix


def _append_destination(parent, destination: dict) -> None:
    dest = ET.SubElement(parent, "Destination")
    bucket = ET.SubElement(dest, "S3BucketDestination")
    ET.SubElement(bucket, "Bucket").text = "arn:aws:s3:::" + destination["bucket"]
    ET.SubElement(bucket, "Format").text = destination["format"]
    if destination.get("prefix"):
        ET.SubElement(bucket, "Prefix").text = destination["prefix"]


def config_xml(kind: str, config: dict) -> bytes:
    """Serialize one stored configuration in its AWS document shape."""
    root = ET.Element(KIND_LABELS[kind], xmlns=NS)
    ET.SubElement(root, "Id").text = config["id"]
    if kind == "inventory":
        ET.SubElement(root, "IsEnabled").text = (
            "true" if config.get("enabled", True) else "false")
        _append_destination(root, config["destination"])
        schedule = ET.SubElement(root, "Schedule")
        ET.SubElement(schedule, "Frequency").text = config.get("schedule", "Daily")
        prefix = config.get("filter", {}).get("prefix", "")
        if prefix:
            filter_node = ET.SubElement(root, "Filter")
            ET.SubElement(filter_node, "Prefix").text = prefix
        ET.SubElement(root, "IncludedObjectVersions").text = config.get(
            "included_object_versions", "Current")
        if config.get("optional_fields"):
            optional = ET.SubElement(root, "OptionalFields")
            for value in config["optional_fields"]:
                ET.SubElement(optional, "Field").text = value
    elif kind == "analytics":
        _append_filter(root, config.get("filter", {}))
        analysis = ET.SubElement(root, "StorageClassAnalysis")
        data_export = ET.SubElement(analysis, "DataExport")
        ET.SubElement(data_export, "OutputSchemaVersion").text = "V_1"
        _append_destination(data_export, config["destination"])
    else:
        _append_filter(root, config.get("filter", {}))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def list_xml(kind: str, configs: list[dict]) -> bytes:
    """AWS-shaped List* result; all ids are returned sorted, IsTruncated false."""
    root = ET.Element(LIST_LABELS[kind], xmlns=NS)
    for config in configs:
        document = SafeET.fromstring(config_xml(kind, config))
        root.append(document)
    ET.SubElement(root, "IsTruncated").text = "false"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class ReportConfigStore:
    """Read/write report configurations for one catalog."""

    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        ensure_report_tables(self.db.engine)

    def _bucket_exists(self, bucket: str) -> None:
        if bucket not in self.catalog.list_buckets():
            raise FileNotFoundError("Bucket not found")

    @staticmethod
    def _decode(kind: str, raw: str) -> dict:
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Corrupted report configuration") from exc
        if not isinstance(value, dict) or value.get("id") in (None, ""):
            raise RuntimeError("Corrupted report configuration")
        return value

    def list(self, bucket: str, kind: str) -> list[dict]:
        if kind not in KINDS:
            raise ReportConfigError("InvalidArgument", "Unknown report kind")
        self._bucket_exists(bucket)
        rows = self.db.connection.execute(
            select(report_configs.c.config_id, report_configs.c.document)
            .where(report_configs.c.bucket == bucket,
                   report_configs.c.kind == kind)
            .order_by(report_configs.c.config_id)).all()
        return [self._decode(kind, raw) for _ident, raw in rows]

    def get(self, bucket: str, kind: str, config_id: str) -> dict | None:
        if kind not in KINDS:
            raise ReportConfigError("InvalidArgument", "Unknown report kind")
        self._bucket_exists(bucket)
        raw = self.db.connection.execute(
            select(report_configs.c.document)
            .where(report_configs.c.bucket == bucket,
                   report_configs.c.kind == kind,
                   report_configs.c.config_id == config_id)).scalar_one_or_none()
        if raw is None:
            return None
        return self._decode(kind, raw)

    def put(self, bucket: str, kind: str, config_id: str, config: dict,
            *, now_ns: int | None = None) -> dict:
        """PUT replaces the document for this (bucket, kind, id)."""
        if kind not in KINDS:
            raise ReportConfigError("InvalidArgument", "Unknown report kind")
        _config_id(config_id)
        if config.get("id") != config_id:
            raise ReportConfigError(
                "InvalidArgument", "URL configuration id does not match document Id")
        self._bucket_exists(bucket)
        destination = config.get("destination")
        if destination is None and kind == "metrics":
            # Honest substitution for CloudWatch: the analyzed bucket is the
            # sink for the JSON metrics document.
            destination = {"bucket": bucket,
                           "prefix": f"reports/metrics/{config_id}",
                           "format": "JSON"}
            config = {**config, "destination": destination}
        if destination is not None:
            if destination["bucket"] not in self.catalog.list_buckets():
                raise ReportConfigError(
                    "InvalidArgument",
                    "The report destination bucket does not exist")
            _prefix(destination.get("prefix", ""))
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        data = json.dumps(config, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
        try:
            changed = self.db.connection.execute(update(report_configs).where(
                report_configs.c.bucket == bucket,
                report_configs.c.kind == kind,
                report_configs.c.config_id == config_id,
            ).values(document=data, updated_ns=now_ns))
            if changed.rowcount == 0:
                self.db.connection.execute(insert(report_configs).values(
                    bucket=bucket, kind=kind, config_id=config_id,
                    document=data, created_ns=now_ns, updated_ns=now_ns,
                    last_run_ns=None, last_attempt_ns=None, last_error=None,
                ))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        return config

    def delete(self, bucket: str, kind: str, config_id: str) -> bool:
        """Idempotent delete; returns whether a row existed."""
        if kind not in KINDS:
            raise ReportConfigError("InvalidArgument", "Unknown report kind")
        self._bucket_exists(bucket)
        removed = self.db.connection.execute(delete(report_configs).where(
            report_configs.c.bucket == bucket,
            report_configs.c.kind == kind,
            report_configs.c.config_id == config_id))
        self.db.commit()
        return removed.rowcount > 0


def rows_for_runner(connection) -> list[dict]:
    """Snapshot all configured reports, including scheduler receipts."""
    statement = select(
        report_configs.c.bucket, report_configs.c.kind,
        report_configs.c.config_id, report_configs.c.document,
        report_configs.c.last_run_ns, report_configs.c.last_attempt_ns,
    ).order_by(report_configs.c.bucket, report_configs.c.kind,
               report_configs.c.config_id)
    return [dict(row) for row in connection.execute(statement).mappings().all()]
