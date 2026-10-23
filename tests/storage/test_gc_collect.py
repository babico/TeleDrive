"""Physical GC of logically-deleted objects: fail-closed candidates,
owner-gated execution, journaling and alias protection."""
from __future__ import annotations

import time
from hashlib import sha256

import pytest
from sqlalchemy import text

from tests.s3.test_s3_admin import admin
from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.manifest import ChunkReference, ManifestStore


class FakeTransport:
    def __init__(self):
        self.deleted: list[tuple[str, int, int]] = []

    async def delete(self, reference):
        self.deleted.append((reference.account, reference.chat_id,
                             reference.message_id))


_message_seq = [5000]


def _publish(cat, key, *, size, now, account="acct-a", chat=-100):
    """begin -> one chunk -> finish -> publish; returns object id."""
    _message_seq[0] += 1
    oid = cat.manifests.begin("gcx", key, size, now)
    cat.manifests.append(oid, ChunkReference(
        ordinal=0, offset=0, size=size, sha256=sha256(b"x").hexdigest(),
        account=account, chat_id=chat, message_id=_message_seq[0]), now)
    cat.manifests.finish(oid, sha256(b"x").hexdigest(), now)
    cat.publish(oid, now=now)
    return oid, _message_seq[0]


@pytest.fixture
def store(admin):
    client, url, _ = admin
    db = connect_database(url)
    try:
        cat = BucketCatalog(ManifestStore(db))
        cat.create_bucket("gcx", int(time.time()))
        yield cat
    finally:
        db.close()


def test_metrics_and_candidates_split_scopes(store):
    cat = store
    old = int(time.time()) - 48 * 3600
    # Live object.
    live, _ = _publish(cat, "live.txt", size=100, now=old)
    # Historical version of a LIVE key: retained, never a candidate.
    _publish(cat, "hist.txt", size=110, now=old)
    hist_head, _ = _publish(cat, "hist.txt", size=111, now=old)
    # Deleted via delete marker: candidate only in scope=deleted.
    marker_target, _ = _publish(cat, "gone.txt", size=120, now=old)
    cat.delete_marker("gcx", "gone.txt")
    # Explicitly revoked version: candidate in revoked AND deleted.
    revoked, _ = _publish(cat, "revoked.txt", size=130, now=old)
    cat.delete_version("gcx", "revoked.txt", revoked)
    # Unlinked head (REST delete): candidate only in scope=deleted.
    unlinked, _ = _publish(cat, "unlinked.txt", size=140, now=old)
    cat.remove_current("gcx", "unlinked.txt")

    gcx = RetainedMediaGC(cat.manifests.db)
    metrics = gcx.metrics()
    assert metrics["logical_objects"] == 2  # live + hist head
    assert metrics["physical_objects"] == 6
    assert metrics["retained_objects"] == 4
    assert metrics["logical_bytes"] == 100 + 111
    assert metrics["physical_bytes"] == 100 + 110 + 111 + 120 + 130 + 140

    revoked_ids = {c["object_id"] for c in gcx.candidates(scope="revoked")}
    deleted_ids = {c["object_id"] for c in gcx.candidates(scope="deleted")}
    assert revoked_ids == {revoked}
    assert deleted_ids == {marker_target, revoked, unlinked}
    assert live not in deleted_ids and hist_head not in deleted_ids

    # A dedup alias pointing at the revoked object fences its media.
    from teledrive.storage.manifest import object_aliases
    cat.manifests.db.connection.execute(
        object_aliases.insert().values(
            object_id=live, source_object_id=revoked))
    cat.manifests.db.commit()
    assert gcx.candidates(scope="revoked") == []


def test_collect_requires_the_owner_gate(store):
    cat = store
    old = int(time.time()) - 48 * 3600
    revoked, _ = _publish(cat, "revoked.txt", size=10, now=old)
    cat.delete_version("gcx", "revoked.txt", revoked)
    gcx = RetainedMediaGC(cat.manifests.db)
    transport = FakeTransport()
    with pytest.raises(PermissionError):
        import asyncio
        asyncio.run(gcx.collect(transport, scope="revoked"))
    assert transport.deleted == []


def test_collect_executes_journals_and_hides_versions(store):
    cat = store
    old = int(time.time()) - 48 * 3600
    gone, gone_message = _publish(cat, "gone.txt", size=120, now=old)
    cat.delete_marker("gcx", "gone.txt")
    live, _ = _publish(cat, "live.txt", size=100, now=old)

    gcx = RetainedMediaGC(cat.manifests.db)
    gcx.set_enabled(True, by="owner-test")
    assert gcx.state()["enabled"] is True
    transport = FakeTransport()

    candidates = gcx.candidates(scope="deleted")
    assert [c["object_id"] for c in candidates] == [gone]

    import asyncio
    report = asyncio.run(gcx.collect(transport, scope="deleted",
                                     chunk_refs=candidates))
    assert [r["object_id"] for r in report["collected"]] == [gone]
    assert report["skipped"] == [] and report["failed"] == []
    # Exactly the retained object's Telegram message was deleted.
    assert transport.deleted == [("acct-a", -100, gone_message)]

    db = cat.manifests.db.connection
    remaining = db.execute(text(
        "SELECT COUNT(*) FROM storage_chunks WHERE object_id = :oid"),
        {"oid": gone}).scalar_one()
    assert remaining == 0
    status = db.execute(text(
        "SELECT status FROM storage_objects WHERE id = :oid"),
        {"oid": gone}).scalar_one()
    assert status == "gc-collected"
    hidden = db.execute(text(
        "SELECT COUNT(*) FROM storage_removed_versions WHERE object_id = :oid"),
        {"oid": gone}).scalar_one()
    assert hidden == 1
    journal = db.execute(text(
        "SELECT chunk_count, bytes, scope FROM storage_gc_collected "
        "WHERE object_id = :oid"), {"oid": gone}).one()
    assert journal == (1, 120, "deleted")

    # The live object was untouched; metrics reflect the collection.
    live_chunks = db.execute(text(
        "SELECT COUNT(*) FROM storage_chunks WHERE object_id = :oid"),
        {"oid": live}).scalar_one()
    assert live_chunks == 1
    metrics = gcx.metrics()
    assert metrics["logical_objects"] == 1
    assert metrics["physical_objects"] == 1
    assert metrics["collected_objects"] == 1
    assert metrics["collected_bytes"] == 120


def test_web_endpoints_fence_the_toggle_and_confirm(admin):
    client, _, _ = admin
    auth = ("testadmin", "secure-auth-password")
    status = client.get("/api/v1/admin/storage/gc", auth=auth)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["state"]["enabled"] is False
    assert "logical_bytes" in body["metrics"]

    # Enabling requires the typed confirmation.
    denied = client.put("/api/v1/admin/storage/gc", auth=auth,
                        headers={"x-teledrive-csrf": "1"},
                        json={"enabled": True})
    assert denied.status_code == 422
    allowed = client.put("/api/v1/admin/storage/gc", auth=auth,
                         headers={"x-teledrive-csrf": "1"},
                         json={"enabled": True, "confirm": "PHYSICAL-GC"})
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["state"]["enabled"] is True

    # Dry-run preview works without touching Telegram.
    preview = client.post("/api/v1/admin/storage/gc/collect", auth=auth,
                          headers={"x-teledrive-csrf": "1"},
                          json={"scope": "deleted", "dry_run": True})
    assert preview.status_code == 200, preview.text
    assert preview.json()["dry_run"] is True

    # Execution demands its own confirmation even with GC enabled.
    unconfirmed = client.post("/api/v1/admin/storage/gc/collect", auth=auth,
                              headers={"x-teledrive-csrf": "1"},
                              json={"scope": "deleted", "dry_run": False})
    assert unconfirmed.status_code == 422

    # Restore the OFF state for other suites.
    client.put("/api/v1/admin/storage/gc", auth=auth,
               headers={"x-teledrive-csrf": "1"},
               json={"enabled": False})
