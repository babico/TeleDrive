"""Real SQL catalog tests for immutable version pointers and bucket behavior."""
from __future__ import annotations

from hashlib import sha256

import pytest

from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore


@pytest.fixture
def catalog(tmp_path):
    db = connect_database(str(tmp_path / "catalog.sqlite"))
    manifests = ManifestStore(db)
    try:
        yield BucketCatalog(manifests), manifests
    finally:
        db.close()


def ready(manifests, bucket, key, data, now):
    ident = manifests.begin(bucket, key, len(data), now)
    # Empty files are the only ones that can be published with no remote chunks.
    assert data == b""
    manifests.finish(ident, sha256(data).hexdigest(), now + 1)
    return ident


def test_bucket_crud_and_validation(catalog):
    cat, _ = catalog
    cat.create_bucket("my-bucket", 1)
    cat.create_bucket("other-123", 2)
    assert cat.list_buckets() == ["my-bucket", "other-123"]
    with pytest.raises(ValueError, match="already exists"):
        cat.create_bucket("my-bucket", 3)
    for name in ["UPPER", "a", "192.168.1.1", "-bad", "bad..name",
                 "a" * 64, "bad_.name", "bad.-name"]:
        with pytest.raises(ValueError):
            cat.create_bucket(name, 4)
    cat.delete_bucket("my-bucket")
    assert cat.list_buckets() == ["other-123"]


def test_atomic_publish_and_overwrite_keeps_old_manifest(catalog):
    cat, manifests = catalog
    cat.create_bucket("backup-store", 10)
    first = ready(manifests, "backup-store", "folder/foo.txt", b"", 11)
    head = cat.publish(first, now=12, expected_generation=0)
    assert head.generation == 1
    assert cat.get("backup-store", "folder/foo.txt").item.id == first
    second = ready(manifests, "backup-store", "folder/foo.txt", b"", 20)
    head = cat.publish(second, now=21, expected_generation=1)
    assert head.generation == 2 and head.item.id == second
    assert manifests.get(first).id == first
    with pytest.raises(ValueError, match="precondition"):
        cat.publish(first, now=22, expected_generation=1)
    assert cat.get("backup-store", "folder/foo.txt").item.id == second


def test_list_pagination_unicode_and_literal_prefix(catalog):
    cat, manifests = catalog
    cat.create_bucket("backup-store", 10)
    for i, key in enumerate(["prefix%literal", "prefix_a", "prefix_b",
                             "quotes/\"hello\"", "ümlaut", "prefix/z"]):
        item = ready(manifests, "backup-store", key, b"", i + 20)
        cat.publish(item, now=i + 20)
    first_page = cat.list_objects("backup-store", prefix="prefix", limit=2)
    assert [row.item.key for row in first_page] == ["prefix%literal", "prefix/z"]
    second_page = cat.list_objects("backup-store", prefix="prefix",
                                   after=first_page[-1].item.key, limit=2)
    assert [row.item.key for row in second_page] == ["prefix_a", "prefix_b"]
    assert [x.item.key for x in cat.list_objects("backup-store", prefix="prefix%")] == [
        "prefix%literal",
    ]
    assert [x.item.key for x in cat.list_objects("backup-store", prefix="prefix_")] == [
        "prefix_a", "prefix_b",
    ]


def test_delete_unlinks_only_current_pointer_and_cannot_destroy_history(catalog):
    cat, manifests = catalog
    cat.create_bucket("backup-store", 1)
    ident = ready(manifests, "backup-store", "test", b"", 2)
    cat.publish(ident, now=3)
    assert cat.remove_current("backup-store", "test", expected_generation=1)
    assert not cat.remove_current("backup-store", "test")
    with pytest.raises(FileNotFoundError):
        cat.get("backup-store", "test")
    assert manifests.get(ident).id == ident
    with pytest.raises(ValueError, match="history"):
        cat.delete_bucket("backup-store")


def test_uncommitted_object_cannot_be_published(catalog):
    cat, manifests = catalog
    cat.create_bucket("backup-store", 1)
    ident = manifests.begin("backup-store", "pending", 55, 2)
    with pytest.raises(FileNotFoundError):
        cat.publish(ident, now=3)
    assert cat.list_objects("backup-store") == []


def test_invalid_key_size_fails_before_catalog_write(catalog):
    cat, manifests = catalog
    cat.create_bucket("backup-store", 1)
    for key in ["", "ü" * 600]:
        ident = ready(manifests, "backup-store", key, b"", 2) if key else None
        if ident:
            with pytest.raises(ValueError, match="UTF-8"):
                cat.publish(ident, now=3)


def test_generation_guard_prevents_lost_update(catalog):
    cat, manifests = catalog
    cat.create_bucket("backup-store", 1)
    ids = [ready(manifests, "backup-store", "same", b"", i * 10 + 1) for i in range(3)]
    assert cat.publish(ids[0], now=5).generation == 1
    assert cat.publish(ids[1], now=6, expected_generation=1).generation == 2
    with pytest.raises(ValueError, match="precondition"):
        cat.publish(ids[2], now=7, expected_generation=1)
    assert cat.get("backup-store", "same").item.id == ids[1]


def test_catalog_metadata_survives_restart(tmp_path):
    url = str(tmp_path / "state.db")
    one = connect_database(url)
    try:
        manifests = ManifestStore(one)
        cat = BucketCatalog(manifests)
        cat.create_bucket("persisted-bucket", 1)
        ident = ready(manifests, "persisted-bucket", "some/key", b"", 2)
        cat.publish(ident, now=3)
    finally:
        one.close()
    two = connect_database(url)
    try:
        cat = BucketCatalog(ManifestStore(two))
        assert cat.get("persisted-bucket", "some/key").item.id == ident
    finally:
        two.close()


def test_deleting_a_bucket_clears_every_governance_row(catalog):
    """Re-creating a bucket must not revive the old one's rights.

    Every governance surface is keyed by the bucket NAME, so a surviving row
    silently re-attaches to the new bucket: an old policy (including a
    Deny), ABAC gates, an SSE default, replication rules, tiering rules
    (which would make new objects answer 403 until restored), webhook and
    logging targets, report schedules, an old quota, an account pin and
    — worst — a public share link that keeps working against new keys.
    """
    from sqlalchemy import text

    cat, _ = catalog
    bucket = "revive-bucket"
    cat.create_bucket(bucket, 1)
    conn = cat.db.connection

    rows = [
        ("storage_bucket_acl_grants", "bucket"),
        ("storage_bucket_policy", "bucket"),
        ("storage_bucket_abac", "bucket"),
        ("storage_bucket_encryption", "bucket"),
        ("storage_replication_configs", "bucket"),
        ("storage_tiering_configs", "bucket"),
        ("storage_report_configs", "bucket"),
        ("storage_notification_configs", "bucket"),
        ("storage_logging_configs", "bucket"),
        ("bucket_quotas", "bucket"),
        ("bucket_account_pins", "bucket"),
        ("share_links", "bucket"),
    ]
    inserted = []
    for table, column in rows:
        if not conn.dialect.has_table(conn, table):
            continue
        cols = {c["name"] for c in
                __import__("sqlalchemy").inspect(conn.engine).get_columns(table)}
        if column not in cols:
            continue
        payload = {column: bucket}
        # Fill any other required column with a harmless default.
        for name in cols:
            if name == column:
                continue
            if name in ("id", "token"):
                payload[name] = f"probe-{table}-{name}"
            elif name in ("created_at", "updated_at", "created_ns",
                          "updated_ns", "committed_ns", "removed_ns"):
                payload[name] = 1
            elif name in ("permission",):
                payload[name] = "READ"
            elif name in ("grantee", "owner", "config_id", "kind", "event"):
                payload[name] = "probe"
            elif name in ("rules", "document", "tags", "payload"):
                payload[name] = "{}"
            elif name in ("max_size_bytes", "max_objects"):
                payload[name] = 1
            elif name in ("account", "channel"):
                payload[name] = "probe"
            elif name in ("enabled", "public_read", "revoked"):
                payload[name] = 0
            elif name in ("password_salt", "password_hash", "prefix",
                          "destination", "mode", "key_md5", "digest_kind"):
                payload[name] = None
        try:
            conn.execute(text(
                f"INSERT INTO {table} ({', '.join(payload)}) "
                f"VALUES ({', '.join(':' + k for k in payload)})"  # nosec B608
            ), payload)
        except Exception:
            conn.rollback()
            continue
        inserted.append(table)
    conn.commit()
    assert inserted, "no governance table accepted a probe row"

    cat.delete_bucket(bucket)

    leftover = {}
    for table in inserted:
        count = conn.execute(text(
            f"SELECT COUNT(*) FROM {table} WHERE bucket = :b"  # nosec B608
        ), {"b": bucket}).scalar_one()
        if count:
            leftover[table] = count
    assert leftover == {}, f"orphaned governance rows: {leftover}"
    assert bucket not in cat.list_buckets()

    # Re-creating the name must start from a clean slate.
    cat.create_bucket(bucket, 2)
    for table in inserted:
        count = conn.execute(text(
            f"SELECT COUNT(*) FROM {table} WHERE bucket = :b"  # nosec B608
        ), {"b": bucket}).scalar_one()
        assert count == 0, table
