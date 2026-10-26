"""Phase N: real analytics/inventory/metrics report generation.

Every report is uploaded through the real storage engine to a deterministic
fake MTProto transport and published in the catalog. Tests read the bytes
back through the same engine, never from a filesystem shortcut.
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import json
from collections import namedtuple
from uuid import uuid4

import pytest

from tests.s3.test_s3_gateway import FakeTelegram
from teledrive.db import connect_database
from teledrive.s3.object_metadata import ObjectMetadataStore
from teledrive.s3.report_configs import ReportConfigStore, parse_document
from teledrive.s3.report_runner import (
    DAY_NS, INVENTORY_COLUMNS, run_due_reports,
)
from teledrive.s3.tagging import ObjectTagStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.manifest import ManifestStore

XMLNS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
Rig = namedtuple("Rig", "db catalog telegram engine store scratch")


def inventory_doc(body_id="inv", destination="report-dest", *,
                  frequency="Daily", versions="All", prefix=""):
    return (
        f"<InventoryConfiguration {XMLNS}><Id>{body_id}</Id>"
        "<IsEnabled>true</IsEnabled>"
        "<Destination><S3BucketDestination>"
        f"<Bucket>arn:aws:s3:::{destination}</Bucket><Format>CSV</Format>"
        "<Prefix>inventory</Prefix>"
        "</S3BucketDestination></Destination>"
        f"<Schedule><Frequency>{frequency}</Frequency></Schedule>"
        f"<Filter><Prefix>{prefix}</Prefix></Filter>"
        f"<IncludedObjectVersions>{versions}</IncludedObjectVersions>"
        "</InventoryConfiguration>"
    ).encode()


def analytics_doc(body_id="ana", destination="report-dest", *,
                  prefix="", tag=None):
    if tag:
        filter_xml = (
            "<Filter><And>"
            f"<Tag><Key>{tag[0]}</Key><Value>{tag[1]}</Value></Tag>"
            "</And></Filter>")
    elif prefix:
        filter_xml = f"<Filter><Prefix>{prefix}</Prefix></Filter>"
    else:
        filter_xml = ""
    return (
        f"<AnalyticsConfiguration {XMLNS}><Id>{body_id}</Id>{filter_xml}"
        "<StorageClassAnalysis><DataExport>"
        "<OutputSchemaVersion>V_1</OutputSchemaVersion>"
        "<Destination><S3BucketDestination>"
        f"<Bucket>arn:aws:s3:::{destination}</Bucket><Format>CSV</Format>"
        "</S3BucketDestination></Destination>"
        "</DataExport></StorageClassAnalysis></AnalyticsConfiguration>"
    ).encode()


def metrics_doc(body_id="met", *, prefix=""):
    return (
        f"<MetricsConfiguration {XMLNS}><Id>{body_id}</Id>"
        f"<Filter><Prefix>{prefix}</Prefix></Filter></MetricsConfiguration>"
    ).encode()


def configure(rig, kind, config_id, body):
    config = parse_document(kind, body, expected_id=config_id)
    rig.store.put("report-source", kind, config_id, config)


@pytest.fixture
def rig(tmp_path):
    db = connect_database(str(tmp_path / "reports.db"))
    telegram = FakeTelegram()
    catalog = BucketCatalog(ManifestStore(db))
    catalog.create_bucket("report-source", 1)
    catalog.create_bucket("report-dest", 2)
    engine = TelegramObjectStorage(
        catalog.manifests, telegram, chunk_size=1024,
        scratch_directory=tmp_path)
    store = ReportConfigStore(catalog)
    rig = Rig(db, catalog, telegram, engine, store, tmp_path)
    try:
        yield rig
    finally:
        db.close()


def put_version(rig, key, payload, now):
    """Publish one real version through the storage engine."""
    source = rig.scratch / f"src-{uuid4().hex}"
    source.write_bytes(payload)
    try:
        stored = asyncio.run(
            rig.engine.put_file("report-source", key, source, dedup=False))
        rig.catalog.publish(stored.id, now=now)
        return stored.id
    finally:
        source.unlink(missing_ok=True)


def read_object(rig, bucket, key):
    head = rig.catalog.get(bucket, key)
    chunks = asyncio.run(_collect(rig.engine.iter_bytes(head.item.id)))
    return b"".join(chunks), head


async def _collect(iterator):
    return [chunk async for chunk in iterator]


def report_heads(rig, bucket="report-dest"):
    return [head.item for head in rig.catalog.list_objects(bucket)]


def generate(rig, now, **kwargs):
    kwargs.setdefault("transport", rig.telegram)
    kwargs.setdefault("scratch_directory", rig.scratch)
    return asyncio.run(run_due_reports(rig.catalog, now, **kwargs))


def test_inventory_all_includes_historical_versions(rig):
    old_id = put_version(rig, "data/a.bin", b"a" * 10, 100)
    new_id = put_version(rig, "data/a.bin", b"a" * 20, 200)
    put_version(rig, "other.txt", b"z" * 5, 300)
    configure(rig, "inventory", "inv", inventory_doc(versions="All"))
    summary = generate(rig, 1000)
    assert summary["failed"] == []
    entry = summary["generated"][0]
    assert entry["objects"] == 3
    payload, head = read_object(rig, "report-dest", entry["key"])
    assert head.item.key.endswith(".csv.gz")
    text = gzip.decompress(payload).decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert tuple(rows[0].keys()) == INVENTORY_COLUMNS
    versions = {row["VersionId"]: row for row in rows
                if row["Key"] == "data/a.bin"}
    assert set(versions) == {old_id, new_id}
    assert versions[new_id]["IsLatest"] == "true"
    assert versions[old_id]["IsLatest"] == "false"
    assert versions[old_id]["Size"] == "10"
    assert all(row["StorageClass"] == "STANDARD" for row in rows)
    metadata = ObjectMetadataStore(rig.catalog).get(head.item.id)
    assert metadata["x-amz-meta-teledrive-report-truncated"] == "false"
    assert metadata["x-amz-meta-teledrive-report-format"] == "csv-gzip"


def test_inventory_current_only_excludes_history(rig):
    put_version(rig, "data/a.bin", b"old", 100)
    current_id = put_version(rig, "data/a.bin", b"newer", 200)
    configure(rig, "inventory", "cur", inventory_doc(body_id="cur", versions="Current"))
    entry = generate(rig, 1000)["generated"][0]
    payload, _ = read_object(rig, "report-dest", entry["key"])
    rows = list(csv.DictReader(io.StringIO(
        gzip.decompress(payload).decode("utf-8"))))
    assert len(rows) == 1
    assert rows[0]["VersionId"] == ""
    assert rows[0]["IsLatest"] == "true"
    assert rows[0]["Size"] == str(len(b"newer"))
    assert rows[0]["ETag"] == rig.catalog.get(
        "report-source", "data/a.bin").item.sha256
    assert current_id


def test_inventory_prefix_filter_is_real(rig):
    put_version(rig, "keep/a.txt", b"a", 100)
    put_version(rig, "skip/b.txt", b"b", 100)
    configure(rig, "inventory", "prefixed",
              inventory_doc(body_id="prefixed", prefix="keep/"))
    entry = generate(rig, 1000)["generated"][0]
    payload, _ = read_object(rig, "report-dest", entry["key"])
    rows = list(csv.DictReader(io.StringIO(
        gzip.decompress(payload).decode("utf-8"))))
    assert [row["Key"] for row in rows] == ["keep/a.txt"]


def test_analytics_json_lines_and_documented_deviation(rig):
    put_version(rig, "data/a.bin", b"abc", 100)
    put_version(rig, "other.txt", b"defg", 100)
    configure(rig, "analytics", "ana", analytics_doc(prefix="data/"))
    entry = generate(rig, 1000)["generated"][0]
    payload, head = read_object(rig, "report-dest", entry["key"])
    records = [json.loads(line) for line in payload.decode().splitlines()]
    assert len(records) == 1
    assert records[0]["Key"] == "data/a.bin"
    assert records[0]["Size"] == 3
    assert records[0]["StorageClass"] == "STANDARD"
    metadata = ObjectMetadataStore(rig.catalog).get(head.item.id)
    assert metadata["x-amz-meta-teledrive-report-format"] == "jsonl"
    assert metadata["x-amz-meta-teledrive-aws-format"] == "parquet"
    assert "Parquet" in metadata["x-amz-meta-teledrive-report-deviation"]


def test_analytics_tag_filter_reads_real_tags(rig):
    put_version(rig, "data/blue.bin", b"b", 100)
    put_version(rig, "data/red.bin", b"r", 100)
    ObjectTagStore(rig.catalog).replace_current(
        "report-source", "data/blue.bin", [("team", "blue")])
    configure(rig, "analytics", "tagged",
              analytics_doc(body_id="tagged", tag=("team", "blue")))
    entry = generate(rig, 1000)["generated"][0]
    payload, _ = read_object(rig, "report-dest", entry["key"])
    records = [json.loads(line) for line in payload.decode().splitlines()]
    assert [record["Key"] for record in records] == ["data/blue.bin"]


def test_metrics_computes_real_counts_and_bytes(rig):
    put_version(rig, "data/a.bin", b"a" * 10, 100)
    put_version(rig, "data/b.bin", b"b" * 25, 100)
    configure(rig, "metrics", "met", metrics_doc(prefix="data/"))
    entry = generate(rig, 1000)["generated"][0]
    assert entry["destination_bucket"] == "report-source"
    payload, _ = read_object(rig, "report-source", entry["key"])
    document = json.loads(payload)
    assert document["ObjectCount"] == 2
    assert document["TotalBytes"] == 35
    assert document["StorageClasses"] == [{
        "StorageClass": "STANDARD", "ObjectCount": 2, "TotalBytes": 35}]
    # No request counter exists; the gap is documented, not invented.
    assert document["RequestCounters"] is None
    assert "no S3 request counter" in document["Note"]
    assert document["Truncated"] is False


def test_report_generation_is_idempotent_via_last_run(rig):
    put_version(rig, "data/a.bin", b"a", 100)
    configure(rig, "inventory", "inv", inventory_doc())
    first = generate(rig, 1000)
    assert len(first["generated"]) == 1
    before = len(report_heads(rig))
    second = generate(rig, 1010)
    assert second["generated"] == []
    assert second["skipped"] == 1
    assert len(report_heads(rig)) == before
    from teledrive.s3.report_configs import report_configs
    row = rig.db.connection.execute(
        report_configs.select()).mappings().one()
    assert row["last_run_ns"] == 1000 * 1_000_000_000
    assert row["last_error"] is None


class FailingTelegram(FakeTelegram):
    async def upload(self, path, *, object_id, ordinal, checksum):
        raise RuntimeError("telegram unavailable")


def test_failed_run_records_error_without_advancing_last_run(rig):
    put_version(rig, "data/a.bin", b"a", 100)
    configure(rig, "inventory", "inv", inventory_doc())
    failed = generate(rig, 1000, transport=FailingTelegram())
    assert failed["generated"] == []
    assert len(failed["failed"]) == 1
    from teledrive.s3.report_configs import report_configs
    row = rig.db.connection.execute(
        report_configs.select()).mappings().one()
    assert row["last_run_ns"] is None
    assert "telegram unavailable" in row["last_error"]
    # A later attempt (past the lease) succeeds and only then advances.
    retried = generate(rig, 2000)
    assert len(retried["generated"]) == 1
    row = rig.db.connection.execute(
        report_configs.select()).mappings().one()
    assert row["last_run_ns"] == 2000 * 1_000_000_000
    assert row["last_error"] is None


def test_object_bound_writes_partial_report_with_truncation_marker(rig):
    for index in range(3):
        put_version(rig, f"data/{index}.bin", b"x", 100)
    configure(rig, "inventory", "inv", inventory_doc())
    summary = generate(rig, 1000, max_objects=2)
    entry = summary["generated"][0]
    assert entry["truncated"] is True
    payload, head = read_object(rig, "report-dest", entry["key"])
    rows = list(csv.DictReader(io.StringIO(
        gzip.decompress(payload).decode("utf-8"))))
    assert len(rows) == 2
    metadata = ObjectMetadataStore(rig.catalog).get(head.item.id)
    assert metadata["x-amz-meta-teledrive-report-truncated"] == "true"


def test_analytics_truncation_is_in_band(rig):
    for index in range(3):
        put_version(rig, f"data/{index}.bin", b"x", 100)
    configure(rig, "analytics", "ana", analytics_doc(prefix="data/"))
    entry = generate(rig, 1000, max_objects=1)["generated"][0]
    payload, head = read_object(rig, "report-dest", entry["key"])
    lines = payload.decode().splitlines()
    assert json.loads(lines[-1]) == {"Truncated": True}
    metadata = ObjectMetadataStore(rig.catalog).get(head.item.id)
    assert metadata["x-amz-meta-teledrive-report-truncated"] == "true"


def test_weekly_schedule_waits_a_week(rig):
    put_version(rig, "data/a.bin", b"a", 100)
    configure(rig, "inventory", "weekly",
              inventory_doc(body_id="weekly", frequency="Weekly"))
    assert len(generate(rig, 1000)["generated"]) == 1
    assert generate(rig, 1000 + DAY_NS // 1_000_000_000)["generated"] == []
    assert len(generate(
        rig, 1000 + 8 * DAY_NS // 1_000_000_000)["generated"]) == 1


def test_reports_are_real_engine_objects_not_filesystem_files(rig):
    put_version(rig, "data/a.bin", b"a", 100)
    configure(rig, "inventory", "inv", inventory_doc())
    entry = generate(rig, 1000)["generated"][0]
    # The report is visible through the catalog and readable via Telegram
    # chunks; the scratch file used for staging was removed.
    head = rig.catalog.get("report-dest", entry["key"])
    assert head.item.size == entry["bytes"]
    assert rig.telegram.uploads >= 2
    assert not list(rig.scratch.glob("report-*"))
    assert not list(rig.scratch.glob("*.csv.gz"))
