"""Real scheduled report generation for S3 analytics, inventory and metrics.

This module is the honest backing for the configuration CRUD in
``report_configs.py``. A due configuration produces a REAL object: bytes are
staged in the scratch directory, uploaded through
``TelegramObjectStorage.put_file`` (the same engine every S3 PUT uses) and
published with ``BucketCatalog.publish``. Nothing is written directly into a
filesystem pretending to be object storage.

Formats

* **Inventory** — gzip CSV with the fixed AWS inventory columns
  ``Bucket,Key,VersionId,IsLatest,Size,LastModifiedDate,ETag,StorageClass``.
  ``IncludedObjectVersions=All`` walks the real published-version journal, so
  historical versions are included with ``IsLatest`` false. ``Current`` uses
  live heads. ORC/Parquet never reach this module: they are rejected with 501
  at PUT time by ``report_configs``.
  Deviations: ``ETag`` carries the manifest SHA-256 (TeleDrive does not store
  an MD5), and all eight columns are always emitted. ``OptionalFields`` is
  validated at PUT time but cannot remove the fixed report columns.
* **Analytics** — JSON Lines, one object record per line. AWS exports Parquet;
  that is a documented deviation, recorded both here and in the report
  object's ``x-amz-meta-teledrive-report-*`` metadata. ``Filter`` prefix and
  tag rules are genuinely applied (tags are read from the object tag store).
* **Metrics** — a JSON document with real object counts and byte totals per
  storage class. All objects are ``STANDARD`` because TeleDrive has no tier
  assignment yet. There is NO S3 request counter in the codebase, so no
  request-count field is invented: the document says so explicitly and sets
  ``RequestCounters`` to ``null``. CloudWatch is not contacted or claimed;
  the analyzed bucket is the destination (``reports/metrics/<id>/``). Later
  runs therefore count earlier report objects like any other object; nothing
  is silently excluded from the metric (a customer prefix filter can be used
  to exclude them explicitly).

Bounds and receipts

* At most ``max_objects`` (default 100 000) objects are scanned and at most
  ``max_report_bytes`` (default 64 MiB) of uncompressed report data is
  emitted. Exceeding either writes a partial report with
  ``x-amz-meta-teledrive-report-truncated: true`` and an in-band
  ``Truncated: true`` field for JSON/JSONL. Partial reports are never
  presented as complete.
* ``last_run_ns`` advances ONLY after the report object is published. A
  failed run stores ``last_error`` and leaves ``last_run_ns`` untouched.
  ``last_attempt_ns`` is a short lease so concurrent workers cannot generate
  the same due report twice.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from sqlalchemy import or_, update

from teledrive.s3.object_metadata import ObjectMetadataStore
from teledrive.s3.report_configs import report_configs
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE

DAY_NS = 86400 * 1_000_000_000
WEEK_NS = 7 * DAY_NS
DEFAULT_MAX_OBJECTS = 100_000
DEFAULT_MAX_REPORT_BYTES = 64 * 1024 * 1024
DEFAULT_RETRY_AFTER_NS = 60 * 1_000_000_000
INVENTORY_COLUMNS = (
    "Bucket", "Key", "VersionId", "IsLatest", "Size", "LastModifiedDate",
    "ETag", "StorageClass",
)
STORAGE_CLASS = "STANDARD"


def _iso(ns: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                         time.gmtime(int(ns) / 1_000_000_000))


def _join_key(*parts: str) -> str:
    return "/".join(part.strip("/") for part in parts
                    if part is not None and part.strip("/"))


def _interval_ns(config: dict) -> int:
    if config.get("kind") == "inventory" and config.get("schedule") == "Weekly":
        return WEEK_NS
    return DAY_NS


def _is_due(config: dict, last_run_ns: int | None, now_ns: int) -> bool:
    if last_run_ns is None:
        return True
    return now_ns - int(last_run_ns) >= _interval_ns(config)


def _iter_current(catalog: BucketCatalog, bucket: str, prefix: str):
    after = None
    while True:
        page = catalog.list_objects(bucket, prefix=prefix, after=after,
                                    limit=1000)
        if not page:
            return
        for head in page:
            yield head
        after = page[-1].item.key
        if len(page) < 1000:
            return


def _iter_versions(catalog: BucketCatalog, bucket: str, prefix: str):
    key_marker = ""
    version_marker = ""
    while True:
        rows, more = catalog.list_bucket_versions(
            bucket, prefix=prefix, key_marker=key_marker,
            version_marker=version_marker, limit=1000,
        )
        if not rows:
            return
        for row in rows:
            yield row
        if not more:
            return
        key_marker = rows[-1]["key"]
        version_marker = rows[-1]["version_id"]


def _inventory_row(bucket: str, item: dict) -> list:
    return [
        bucket, item["key"], item["version_id"],
        "true" if item["is_latest"] else "false", item["size"],
        _iso(item["modified_ns"]), item.get("etag") or "", STORAGE_CLASS,
    ]


def build_inventory_report(catalog: BucketCatalog, bucket: str, config: dict, *,
                           max_objects: int, max_report_bytes: int):
    """Return (gzip CSV bytes, truncated flag, rows emitted)."""
    prefix = config.get("filter", {}).get("prefix", "")
    all_versions = config.get("included_object_versions", "Current") == "All"
    source = (_iter_versions(catalog, bucket, prefix) if all_versions
              else _iter_current(catalog, bucket, prefix))
    header = ",".join(INVENTORY_COLUMNS) + "\n"
    used = len(header.encode("utf-8"))
    lines = [header]
    count = 0
    truncated = False
    for raw in source:
        if count >= max_objects:
            truncated = True
            break
        if all_versions:
            if raw.get("is_delete_marker"):
                continue
            item = {
                "key": raw["key"], "version_id": raw["version_id"],
                "is_latest": raw["is_current"], "size": raw["size"],
                "modified_ns": raw["committed_ns"], "etag": raw["sha256"],
            }
        else:
            item = {
                "key": raw.item.key, "version_id": "",
                "is_latest": True, "size": raw.item.size,
                "modified_ns": int(raw.item.created_at) * 1_000_000_000,
                "etag": raw.item.sha256,
            }
        buffer = io.StringIO()
        csv.writer(buffer, lineterminator="\n").writerow(
            _inventory_row(bucket, item))
        line = buffer.getvalue()
        size = len(line.encode("utf-8"))
        if used + size > max_report_bytes:
            truncated = True
            break
        lines.append(line)
        used += size
        count += 1
    payload = gzip.compress("".join(lines).encode("utf-8"), mtime=0)
    return payload, truncated, count


def _tags_match(tag_store, object_id: str, wanted: list[dict]) -> bool:
    if not wanted:
        return True
    actual = {key: value for key, value in tag_store.get(object_id)}
    return all(actual.get(tag["key"]) == tag["value"] for tag in wanted)


def build_analytics_report(catalog: BucketCatalog, bucket: str, config: dict, *,
                           max_objects: int, max_report_bytes: int):
    """Return (JSON Lines bytes, truncated flag, rows emitted).

    One JSON object per line with the object-level fields AWS analytics
    exposes. Prefix/tag filters are applied against real catalog rows and the
    real object tag store. The JSON Lines/Parquet deviation is deliberate.
    """
    filter_value = config.get("filter", {})
    prefix = filter_value.get("prefix", "")
    wanted_tags = filter_value.get("tags") or []
    tag_store = None
    if wanted_tags:
        from teledrive.s3.tagging import ObjectTagStore
        tag_store = ObjectTagStore(catalog)
    lines: list[bytes] = []
    used = 0
    count = 0
    truncated = False
    for head in _iter_current(catalog, bucket, prefix):
        if count >= max_objects:
            truncated = True
            break
        if tag_store is not None and not _tags_match(
                tag_store, head.item.id, wanted_tags):
            continue
        record = {
            "Bucket": bucket,
            "Key": head.item.key,
            "VersionId": "",
            "IsLatest": True,
            "Size": head.item.size,
            "LastModifiedDate": _iso(int(head.item.created_at) * 1_000_000_000),
            "ETag": head.item.sha256 or "",
            "StorageClass": STORAGE_CLASS,
        }
        line = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        if used + len(line) > max_report_bytes:
            truncated = True
            break
        lines.append(line)
        used += len(line)
        count += 1
    if truncated:
        marker = json.dumps({"Truncated": True}).encode("utf-8") + b"\n"
        if used + len(marker) <= max_report_bytes:
            lines.append(marker)
    return b"".join(lines), truncated, count


def build_metrics_report(catalog: BucketCatalog, bucket: str, config: dict, *,
                         max_objects: int, max_report_bytes: int):
    """Return (JSON bytes, truncated flag, objects counted).

    Only real numbers are emitted. There is no S3 request counter in the
    codebase and none is invented; ``RequestCounters`` is null and the note
    says why. Storage-class totals are real (everything is STANDARD today).
    """
    filter_value = config.get("filter", {})
    prefix = filter_value.get("prefix", "")
    wanted_tags = filter_value.get("tags") or []
    tag_store = None
    if wanted_tags:
        from teledrive.s3.tagging import ObjectTagStore
        tag_store = ObjectTagStore(catalog)
    count = 0
    total_bytes = 0
    truncated = False
    for head in _iter_current(catalog, bucket, prefix):
        if count >= max_objects:
            truncated = True
            break
        if tag_store is not None and not _tags_match(
                tag_store, head.item.id, wanted_tags):
            continue
        count += 1
        total_bytes += int(head.item.size)
    document = {
        "Bucket": bucket,
        "ConfigurationId": config["id"],
        "GeneratedAt": _iso(time.time_ns()),
        "Filter": filter_value,
        "ObjectCount": count,
        "TotalBytes": total_bytes,
        "StorageClasses": [
            {"StorageClass": STORAGE_CLASS, "ObjectCount": count,
             "TotalBytes": total_bytes},
        ],
        # No request counter exists. Do not invent one.
        "RequestCounters": None,
        "Note": ("Request counters are unavailable: TeleDrive has no S3 "
                 "request counter. Object and byte metrics are computed from "
                 "the real catalog. This is not CloudWatch."),
        "Truncated": truncated,
    }
    payload = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > max_report_bytes:
        # The fixed document is tiny; clamp defensively rather than lie.
        document.update({"ObjectCount": 0, "TotalBytes": 0,
                         "StorageClasses": [], "Truncated": True})
        payload = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
        truncated = True
    return payload, truncated, count


async def _publish_report(catalog: BucketCatalog, transport, scratch, *,
                          destination_bucket: str, key: str, payload: bytes,
                          metadata: dict[str, str], now: int) -> str:
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise ValueError("Report payload is empty")
    scratch_dir = Path(scratch) if scratch is not None else Path(
        tempfile.gettempdir())
    scratch_dir.mkdir(parents=True, exist_ok=True)
    fd, pathname = tempfile.mkstemp(dir=scratch_dir, prefix="report-")
    staged = Path(pathname)
    try:
        with os.fdopen(fd, "wb") as sink:
            sink.write(payload)
            sink.flush()
            os.fsync(sink.fileno())
        engine = TelegramObjectStorage(
            catalog.manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE,
            scratch_directory=scratch_dir,
        )
        # Reports must be new objects even if identical bytes exist: the
        # filename timestamp is part of the delivery contract.
        stored = await engine.put_file(destination_bucket, key, staged,
                                       dedup=False)
        try:
            ObjectMetadataStore(catalog).attach_uncommitted(
                stored.id, metadata)
            catalog.publish(stored.id, now=int(now))
        except BaseException:
            catalog.db.connection.rollback()
            raise
        return stored.id
    finally:
        staged.unlink(missing_ok=True)


async def run_due_reports(catalog: BucketCatalog, now, *, transport,
                          scratch_directory=None,
                          max_objects: int = DEFAULT_MAX_OBJECTS,
                          max_report_bytes: int = DEFAULT_MAX_REPORT_BYTES,
                          retry_after_ns: int = DEFAULT_RETRY_AFTER_NS) -> dict:
    """Generate every due analytics/inventory/metrics report.

    ``now`` is seconds since the epoch, matching the lifecycle scheduler.
    Returns a summary dict; never raises for a single failed configuration
    (the failure is recorded in ``last_error``).
    """
    if type(max_objects) is not int or not 1 <= max_objects <= 1_000_000:
        raise ValueError("Invalid report object bound")
    if (type(max_report_bytes) is not int
            or not 1024 <= max_report_bytes <= 1024 * 1024 * 1024):
        raise ValueError("Invalid report size bound")
    if type(retry_after_ns) is not int or retry_after_ns < 0:
        raise ValueError("Invalid report retry lease")
    now_ns = int(now) * 1_000_000_000 if now < 10_000_000_000 else int(now)
    connection = catalog.db.connection
    rows = connection.execute(report_configs.select().order_by(
        report_configs.c.bucket, report_configs.c.kind,
        report_configs.c.config_id)).mappings().all()
    summary: dict = {"generated": [], "failed": [], "skipped": 0,
                     "objects": 0, "truncated": []}
    for row in rows:
        try:
            config = json.loads(row["document"])
        except (TypeError, ValueError):
            continue
        config = {**config, "kind": row["kind"], "_bucket": row["bucket"]}
        if not config.get("enabled", True):
            summary["skipped"] += 1
            continue
        if not _is_due(config, row["last_run_ns"], now_ns):
            summary["skipped"] += 1
            continue
        lease_cutoff = now_ns - retry_after_ns
        claim = update(report_configs).where(
            report_configs.c.bucket == row["bucket"],
            report_configs.c.kind == row["kind"],
            report_configs.c.config_id == row["config_id"],
            or_(report_configs.c.last_attempt_ns.is_(None),
                report_configs.c.last_attempt_ns <= lease_cutoff),
        ).values(last_attempt_ns=now_ns)
        try:
            claimed = connection.execute(claim)
            catalog.db.commit()
        except BaseException:
            connection.rollback()
            raise
        if claimed.rowcount != 1:
            summary["skipped"] += 1
            continue
        try:
            result = await _generate_one(
                catalog, transport, scratch_directory, config,
                max_objects=max_objects, max_report_bytes=max_report_bytes,
                now=int(now),
            )
            connection.execute(update(report_configs).where(
                report_configs.c.bucket == row["bucket"],
                report_configs.c.kind == row["kind"],
                report_configs.c.config_id == row["config_id"],
            ).values(last_run_ns=now_ns, last_attempt_ns=now_ns,
                     last_error=None))
            catalog.db.commit()
        except Exception as exc:
            try:
                connection.rollback()
            except Exception:
                pass
            message = f"{type(exc).__name__}: {exc}"[:1024]
            connection.execute(update(report_configs).where(
                report_configs.c.bucket == row["bucket"],
                report_configs.c.kind == row["kind"],
                report_configs.c.config_id == row["config_id"],
            ).values(last_error=message))
            catalog.db.commit()
            summary["failed"].append({
                "bucket": row["bucket"], "kind": row["kind"],
                "config_id": row["config_id"], "error": message,
            })
            continue
        summary["objects"] += result["objects"]
        summary["generated"].append(result)
        if result["truncated"]:
            summary["truncated"].append(result)
    return summary


async def _generate_one(catalog: BucketCatalog, transport, scratch,
                        config: dict, *, max_objects: int,
                        max_report_bytes: int, now: int) -> dict:
    # The runner injects the source bucket under "_bucket"; keep the check
    # explicit so a malformed document never silently targets the wrong one.
    bucket = config["_bucket"]
    kind = config["kind"]
    config_id = config["id"]
    destination = config["destination"]
    timestamp = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime(now))
    token = uuid4().hex[:8]
    common: dict[str, str] = {
        "x-amz-meta-teledrive-report-kind": kind,
        "x-amz-meta-teledrive-report-config-id": config_id,
        "x-amz-meta-teledrive-report-generated-at": _iso(now * 1_000_000_000),
    }
    if kind == "inventory":
        payload, truncated, objects = build_inventory_report(
            catalog, bucket, config, max_objects=max_objects,
            max_report_bytes=max_report_bytes)
        key = _join_key(destination["prefix"], bucket, config_id, "data",
                        f"{timestamp}-{token}.csv.gz")
        common.update({
            "x-amz-meta-teledrive-report-format": "csv-gzip",
            "x-amz-meta-teledrive-aws-format": "csv-gzip",
        })
    elif kind == "analytics":
        payload, truncated, objects = build_analytics_report(
            catalog, bucket, config, max_objects=max_objects,
            max_report_bytes=max_report_bytes)
        key = _join_key(destination["prefix"], bucket, config_id,
                        f"{timestamp}-{token}.jsonl")
        common.update({
            "x-amz-meta-teledrive-report-format": "jsonl",
            "x-amz-meta-teledrive-aws-format": "parquet",
            "x-amz-meta-teledrive-report-deviation":
                "AWS analytics exports Parquet; TeleDrive writes JSON Lines "
                "because no Parquet writer is available",
        })
    elif kind == "metrics":
        payload, truncated, objects = build_metrics_report(
            catalog, bucket, config, max_objects=max_objects,
            max_report_bytes=max_report_bytes)
        key = _join_key(destination["prefix"],
                        f"{timestamp}-{token}.json")
        common.update({
            "x-amz-meta-teledrive-report-format": "json",
            "x-amz-meta-teledrive-aws-format": "cloudwatch",
            "x-amz-meta-teledrive-report-deviation":
                "AWS metrics go to CloudWatch; TeleDrive writes a JSON "
                "document instead and does not claim CloudWatch delivery",
        })
    else:  # pragma: no cover - report_configs guarantees the kind
        raise ValueError("Unknown report kind")
    common["x-amz-meta-teledrive-report-truncated"] = (
        "true" if truncated else "false")
    object_id = await _publish_report(
        catalog, transport, scratch,
        destination_bucket=destination["bucket"], key=key, payload=payload,
        metadata=common, now=now)
    return {
        "bucket": bucket, "kind": kind, "config_id": config_id,
        "destination_bucket": destination["bucket"], "key": key,
        "object_id": object_id, "bytes": len(payload),
        "objects": objects, "truncated": truncated,
    }
