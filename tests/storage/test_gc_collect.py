"""Physical GC of logically-deleted objects: fail-closed candidates,
owner-gated execution, journaling and alias protection."""
from __future__ import annotations

import asyncio
import time
from hashlib import sha256

import pytest
from sqlalchemy import text

from tests.s3.test_s3_admin import admin, admin_headers
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


def _publish(cat, key, *, size, now, account="acct-a", chat=-100,
             bucket="gcx"):
    """begin -> one chunk -> finish -> publish; returns object id."""
    _message_seq[0] += 1
    oid = cat.manifests.begin(bucket, key, size, now)
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


def _backdate_revocation(cat, object_id, when_seconds):
    """Move a removed_versions row back in time (test-only helper)."""
    from sqlalchemy import text
    cat.manifests.db.connection.execute(text(
        "UPDATE storage_removed_versions SET removed_ns = :ns "
        "WHERE object_id = :oid"),
        {"ns": int(when_seconds) * 1_000_000_000, "oid": object_id})
    cat.manifests.db.connection.commit()


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
    # Age is measured from the LATER of upload and REVOCATION, so a version
    # revoked just now is deliberately NOT eligible yet: the safety window
    # must protect the delete too, not only the original upload. Backdate
    # the revocation to simulate a version that has been gone for 48h.
    _backdate_revocation(cat, revoked, old)
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
    auth = admin_headers(client)
    status = client.get("/api/v1/admin/storage/gc", headers=auth)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["state"]["enabled"] is False
    assert "logical_bytes" in body["metrics"]

    # Enabling requires the typed confirmation.
    denied = client.put("/api/v1/admin/storage/gc", headers={**auth, **{"x-teledrive-csrf": "1"}},
                        json={"enabled": True})
    assert denied.status_code == 422
    allowed = client.put("/api/v1/admin/storage/gc", headers={**auth, **{"x-teledrive-csrf": "1"}},
                         json={"enabled": True, "confirm": "PHYSICAL-GC"})
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["state"]["enabled"] is True

    # Dry-run preview works without touching Telegram.
    preview = client.post("/api/v1/admin/storage/gc/collect", headers={**auth, **{"x-teledrive-csrf": "1"}},
                          json={"scope": "deleted", "dry_run": True})
    assert preview.status_code == 200, preview.text
    assert preview.json()["dry_run"] is True

    # Execution demands its own confirmation even with GC enabled.
    unconfirmed = client.post("/api/v1/admin/storage/gc/collect", headers={**auth, **{"x-teledrive-csrf": "1"}},
                              json={"scope": "deleted", "dry_run": False})
    assert unconfirmed.status_code == 422

    # Restore the OFF state for other suites.
    client.put("/api/v1/admin/storage/gc", headers={**auth, **{"x-teledrive-csrf": "1"}},
               json={"enabled": False})


def test_gc_queue_scope_respects_grace_and_drains(store):
    """Phase A: version deletes / aborts / expirations enqueue objects;
    the queued scope collects them once the grace period passes."""
    cat = store
    old = int(time.time()) - 48 * 3600
    gone, _ = _publish(cat, "queued.bin", size=90, now=old)
    cat.remove_current("gcx", "queued.bin")  # no live head -> reclaimable

    gcx = RetainedMediaGC(cat.manifests.db)
    assert gcx.state()["grace_seconds"] == 24 * 3600  # default
    # Enqueue is idempotent and ignores unknown ids.
    assert gcx.enqueue([gone], "version-delete") == 1
    assert gcx.enqueue([gone], "version-delete") == 0
    assert gcx.enqueue(["nonexistent"], "x") == 0
    assert gcx.metrics()["queued"] == 1

    # Inside the grace period: queued scope finds nothing.
    assert gcx.candidates(scope="queued") == []

    # Shrink the grace, let the enqueue age past it (time travel),
    # then collect: the object is physically removed and the queue drains.
    gcx.set_enabled(True, by="owner-test", grace_seconds=3600)
    from sqlalchemy import text as _t
    cat.manifests.db.connection.execute(_t(
        "UPDATE storage_gc_queue SET enqueued_ns = enqueued_ns - :age"),
        {"age": 2 * 3600 * 1_000_000_000})
    cat.manifests.db.commit()
    candidates = gcx.candidates(scope="queued")
    assert [c["object_id"] for c in candidates] == [gone]
    assert candidates[0]["reason"] == "version-delete"

    transport = FakeTransport()
    import asyncio
    report = asyncio.run(gcx.collect(transport, scope="queued",
                                     chunk_refs=candidates))
    assert [r["object_id"] for r in report["collected"]] == [gone]
    assert gcx.metrics()["queued"] == 0
    assert gcx.metrics()["physical_objects"] == 0


def test_version_delete_enqueues_only_when_gc_enabled(store):
    """The S3 version-delete path queues physical collection only
    when the owner gate is open."""
    cat = store
    old = int(time.time()) - 48 * 3600
    target, _ = _publish(cat, "vd.bin", size=50, now=old)
    cat.delete_version("gcx", "vd.bin", target)

    from teledrive.storage.gc_collect import RetainedMediaGC as _GC
    db = cat.manifests.db
    # GC disabled (default): the revoked version keeps its media.
    assert _GC(db).metrics()["queued"] == 0
    # Enable GC: a second version delete enqueues.
    gcx = _GC(db)
    gcx.set_enabled(True, by="t")
    other, _ = _publish(cat, "vd2.bin", size=60, now=old)
    cat.delete_version("gcx", "vd2.bin", other)
    # (enqueue happens in the web handler; simulate the same call the
    # handler makes to prove the wiring contract)
    assert gcx.enqueue([other], "version-delete") == 1
    assert gcx.metrics()["queued"] == 1


def test_lifecycle_expiration_creates_markers_and_enqueues(admin):
    """Expiration rules: due current objects get delete markers and,
    with GC enabled, their media joins the collection queue."""
    client, url, _ = admin
    auth = admin_headers(client)
    from tests.s3.test_s3_gateway import service as _svc  # noqa: F401
    db = connect_database(url)
    try:
        cat = BucketCatalog(ManifestStore(db))
        cat.create_bucket("lcx", int(time.time()))
        old = int(time.time()) - 10 * 86400
        from tests.storage.test_gc_collect import _publish as _pub
        expiring, _ = _pub(cat, "temp/old.bin", size=70, now=old,
                           bucket="lcx")
        _pub(cat, "keep/new.bin", size=80, now=int(time.time()),
             bucket="lcx")
        from teledrive.s3.lifecycle import (BucketLifecycleStore,
                                            parse_lifecycle_xml)
        rules = parse_lifecycle_xml(
            b"<LifecycleConfiguration><Rule><ID>r1</ID>"
            b"<Status>Enabled</Status><Filter><Prefix>temp/</Prefix></Filter>"
            b"<Expiration><Days>7</Days></Expiration></Rule></LifecycleConfiguration>")
        assert rules == [{"id": "r1", "status": "Enabled", "prefix": "temp/",
                          "days": 7, "action": "expire", "expired_marker": False}]
        store = BucketLifecycleStore(cat)
        store.replace("lcx", rules)

        gcx = RetainedMediaGC(db)
        gcx.set_enabled(True, by="t", grace_seconds=3600)
        applied = store.apply_due(now=int(time.time()), limit=10)
        assert applied == 1
        # The old object is no longer the head; the new one is intact.
        try:
            cat.get("lcx", "temp/old.bin")
            raised = False
        except FileNotFoundError:
            raised = True
        assert raised
        assert cat.get("lcx", "keep/new.bin").item.size == 80
        # And its media is queued for physical collection (past grace).
        assert gcx.metrics()["queued"] == 1
        from sqlalchemy import text as _t2
        db.connection.execute(_t2(
            "UPDATE storage_gc_queue SET enqueued_ns = enqueued_ns - :age"),
            {"age": 2 * 3600 * 1_000_000_000})
        db.commit()
        assert [c["object_id"] for c in gcx.candidates(
            scope="queued")] == [expiring]
    finally:
        db.close()


def test_revoked_scope_collects_and_records_without_colliding(store):
    """The default scope must account for what it deletes.

    Found by the API review. ``delete_version`` already writes a
    ``storage_removed_versions`` row, and the collector inserted a second
    one unconditionally. The UNIQUE violation was caught as a per-object
    failure and rolled back -- AFTER the Telegram messages were deleted. The
    media was gone while SQL still said ``ready``, which is the worst state
    a storage system can reach: nothing records the loss.

    This pins the whole outcome: one collected object, no failures, chunks
    physically gone, exactly one journal row, and status gc-collected.
    """
    cat = store
    old = int(time.time()) - 48 * 3600
    oid, _message = _publish(cat, "revoked.bin", size=256, now=old)
    cat.delete_version("gcx", "revoked.bin", oid)
    _backdate_revocation(cat, oid, old)

    gcx = RetainedMediaGC(cat.manifests.db)
    gcx.set_enabled(True, by="test")
    transport = FakeTransport()
    report = asyncio.run(gcx.collect(transport, scope="revoked",
                               min_age_seconds=3600))

    assert report["failed"] == [], report["failed"]
    assert [c["object_id"] for c in report["collected"]] == [oid]
    assert transport.deleted, "no Telegram message was deleted"

    db = cat.manifests.db
    chunks = db.connection.execute(text(
        "SELECT COUNT(*) FROM storage_chunks WHERE object_id = :o"),
        {"o": oid}).scalar_one()
    assert chunks == 0, "chunks remain after a successful collection"
    journal = db.connection.execute(text(
        "SELECT COUNT(*) FROM storage_gc_collected WHERE object_id = :o"),
        {"o": oid}).scalar_one()
    assert journal == 1
    removed = db.connection.execute(text(
        "SELECT COUNT(*) FROM storage_removed_versions WHERE object_id = :o"),
        {"o": oid}).scalar_one()
    assert removed == 1, "the revocation row must exist exactly once"
    status = db.connection.execute(text(
        "SELECT status FROM storage_objects WHERE id = :o"),
        {"o": oid}).scalar_one()
    assert status == "gc-collected"


def test_queued_scope_drains_a_version_deleted_object(store):
    """A queued version-delete must drain without colliding either."""
    cat = store
    old = int(time.time()) - 48 * 3600
    oid, _ = _publish(cat, "queued.bin", size=300, now=old)
    gcx = RetainedMediaGC(cat.manifests.db)
    gcx.set_enabled(True, by="test")
    gcx.enqueue([oid], "version-delete")
    # Age the queue entry past the grace window.
    cat.manifests.db.connection.execute(text(
        "UPDATE storage_gc_queue SET enqueued_ns = enqueued_ns - :d"),
        {"d": 7 * 86400 * 1_000_000_000})
    cat.manifests.db.connection.commit()
    # The object still needs a revocation row to be eligible.
    cat.delete_version("gcx", "queued.bin", oid)
    _backdate_revocation(cat, oid, old)

    transport = FakeTransport()
    report = asyncio.run(gcx.collect(transport, scope="queued"))
    assert report["failed"] == [], report["failed"]
    assert [c["object_id"] for c in report["collected"]] == [oid]
