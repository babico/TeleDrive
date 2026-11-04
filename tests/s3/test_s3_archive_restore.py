"""Handoff 08: physical archive bytes, real restores and the fences.

The failure matrix this module pins (SQLite unit plus the real-backend
matrix for the worker races):

* cold backend unavailable, corrupted archive, partial upload,
  interrupted read - every fault fails closed and leaves a recoverable
  object, never a permanently unreadable one;
* lost ACK / retry after SQL commit - idempotent queueing, exactly one
  staged copy, AWS-shaped 409 on a duplicate request;
* two workers restoring one version - the durable lease admits exactly
  one winner;
* restart between archive-verified and source-deletion - the phase-C GC
  fence collects only independently verified archives;
* expired restore cache - the staged copy clears, archive data never;
* mixed SSE-C/envelope objects archive as stored ciphertext and restore
  to exact plaintext;
* dedup aliases and replicated bytes archive and restore through the
  content resolution;
* COMPLIANCE lock and HEAD/GET/read conditions keep their gates.

Never uses owner original data: the fake Telegram transport holds the
bytes for every case.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time

import pytest
from sqlalchemy import select, update

import web.s3 as gateway
# The plain SQLite `service` fixture; the worker-race cases use the
# real-backend matrix through `backend_service` where contention matters.
from tests.s3.test_s3_gateway import backend_service, service, signed
from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore, objects
from teledrive.storage.cold_store import (
    ArchiveStore, ColdBlobStore, archive_deletion_permitted, archive_row,
)

BUCKET = "archive-bucket"
KEY = "cold/data.bin"
DAY_NS = 86_400_000_000_000


@pytest.fixture
def cold(service, monkeypatch, tmp_path):
    """A per-test cold-archive root, resolved by the gateway at call time."""
    root = tmp_path / "cold-archive"
    monkeypatch.setenv("TELEDRIVE_COLD_ARCHIVE_DIR", str(root))
    return root


def _open(service):
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _bucket(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200


def _seed(service, body=b"cold-bytes-payload", key=KEY):
    _bucket(service)
    put = signed(service, "PUT", f"/{BUCKET}/{key}", body)
    assert put.status_code == 200, put.text
    return put.headers["x-amz-version-id"]


def _label(service, version_id, klass="ARCHIVE_ACCESS"):
    db = service[3]()
    try:
        db.connection.execute(update(objects).where(
            objects.c.id == version_id).values(storage_class=klass))
        db.commit()
    finally:
        db.close()


def _enqueue(service, root, *version_ids):
    db, catalog = _open(service)
    try:
        store = ArchiveStore(catalog, ColdBlobStore(root))
        assert store.enqueue_archive(list(version_ids)) == len(version_ids)
    finally:
        db.close()


def _archive_pass(service, root, transport=None, **kwargs):
    db, catalog = _open(service)
    try:
        store = ArchiveStore(catalog, ColdBlobStore(root))
        return asyncio.run(store.run_archive_pass(
            transport if transport is not None else service[2],
            scratch_directory=None, **kwargs))
    finally:
        db.close()


def _restore_pass(service, root, **kwargs):
    db, catalog = _open(service)
    try:
        store = ArchiveStore(catalog, ColdBlobStore(root))
        return store.run_restore_pass(**kwargs)
    finally:
        db.close()


def _row(service, version_id):
    db = service[3]()
    try:
        return archive_row(db, version_id)
    finally:
        db.close()


def _sql(service, statement, params=None):
    db = service[3]()
    try:
        db.connection.execute(statement, params or {})
        db.commit()
    finally:
        db.close()


def _expire_window(service, version_id):
    _sql(service, update(objects).where(objects.c.id == version_id)
         .values(restore_until_ns=time.time_ns() - 1))


def _full_archive(service, root, version_id):
    """Label + enqueue + run the worker until the row is ARCHIVED."""
    _label(service, version_id)
    _enqueue(service, root, version_id)
    report = _archive_pass(service, root)
    assert report["archived"] == [version_id], report
    row = _row(service, version_id)
    assert row["state"] == "ARCHIVED"
    blob = ColdBlobStore(root)
    assert blob.verify_archive(
        version_id,
        *_receipt(service, version_id))
    return blob


def _receipt(service, version_id):
    """(whole_sha256, stored_bytes) straight from the SQL row."""
    from teledrive.storage.cold_store import archive_versions
    db = service[3]()
    try:
        row = db.connection.execute(select(
            archive_versions.c.whole_sha256,
            archive_versions.c.stored_bytes).where(
            archive_versions.c.object_id == version_id)).one()
        return row[0], row[1]
    finally:
        db.close()


class DeletingTransport:
    """The fake Telegram plus the delete() the GC collector calls."""

    def __init__(self, inner):
        self.inner = inner
        self.deleted = []

    async def upload(self, *args, **kwargs):
        return await self.inner.upload(*args, **kwargs)

    async def download(self, *args, **kwargs):
        return await self.inner.download(*args, **kwargs)

    async def verify_target(self):
        await self.inner.verify_target()

    async def delete(self, reference):
        self.deleted.append(reference)


# ---------------------------------------------------------------------------
# The core round trip
# ---------------------------------------------------------------------------

def test_archive_and_restore_round_trip_with_whole_sha256(service, cold):
    body = b"archived-payload-" * 64
    version = _seed(service, body=body)
    blob = _full_archive(service, cold, version)

    # The sealed manifest carries the receipt and lineage, never secrets.
    manifest = blob.read_manifest(version)
    assert manifest["object_id"] == version
    assert manifest["bucket"] == BUCKET and manifest["key"] == KEY
    assert manifest["size"] == len(body)
    assert manifest["sha256_plaintext"] == hashlib.sha256(body).hexdigest()
    assert manifest["verified"] == {"algorithm": "sha256", "readback": True,
                                    "at_ns": manifest["verified"]["at_ns"]}
    assert manifest["chunk_lineage"][0]["size"] == len(body)
    text = json.dumps(manifest)
    for banned in ("wrapped_key", "key_wrap", "envelope_aad",
                   "customer-key", "secret"):
        assert banned not in text
    assert blob.staged_exists(version) is False

    # Gated until restored; RestoreObject queues the real retrieval.
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "GET", path).status_code == 403
    restore = signed(service, "POST", f"{path}?restore",
                     b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert restore.status_code == 202, restore.text
    # While the work is pending: 403 + ongoing-request="true".
    head = signed(service, "HEAD", path)
    assert head.status_code == 403
    assert head.headers.get("x-amz-restore") == 'ongoing-request="true"'
    get = signed(service, "GET", path)
    assert get.status_code == 403
    assert get.headers.get("x-amz-restore") == 'ongoing-request="true"'
    # A duplicate request while pending is the AWS conflict.
    again = signed(service, "POST", f"{path}?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert again.status_code == 409
    assert b"RestoreAlreadyInProgress" in again.content

    # The worker copies cold -> staging and only then opens the window.
    report = _restore_pass(service, cold)
    assert report["restored"] == [version], report
    get = signed(service, "GET", path)
    assert get.status_code == 200, get.text
    assert get.content == body
    head = signed(service, "HEAD", path)
    assert head.status_code == 200
    assert 'ongoing-request="false"' in head.headers.get("x-amz-restore", "")
    assert "expiry-date" in head.headers.get("x-amz-restore", "")
    # Ranged reads are served from the staged copy, byte-exact.
    rng = signed(service, "GET", path,
                 extra_headers={"Range": "bytes=2-5"})
    assert rng.status_code == 206 and rng.content == body[2:6]
    assert blob.staged_exists(version) is True

    # Expiry clears the staged copy, never the archive data.
    _expire_window(service, version)
    assert signed(service, "GET", path).status_code == 403
    assert blob.staged_exists(version) is False
    assert blob.archive_path(version).is_file()
    assert blob.read_manifest(version)["state"] == "ARCHIVED"
    assert blob.verify_archive(version, *_receipt(service, version))

    # Nothing is permanently unreadable: a fresh restore works again.
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    assert signed(service, "GET", path).content == body
    # The Telegram hot copy is untouched by every step above.
    assert service[2].uploads == 1


def test_label_without_archive_keeps_the_hot_copy_window(service, cold):
    """No archive row: RestoreObject keeps today's immediate window."""
    body = b"window-gate-only"
    version = _seed(service, body=body)
    _label(service, version)
    path = f"/{BUCKET}/{KEY}"
    restore = signed(service, "POST", f"{path}?restore",
                     b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert restore.status_code == 202
    # Reads re-open immediately: the hot copy is authoritative.
    assert signed(service, "GET", path).content == body
    again = signed(service, "POST", f"{path}?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert again.status_code == 409


def test_restore_before_archive_verification_uses_the_hot_copy(
        service, cold):
    """A restore accepted while the row is still HOT/ARCHING is served by
    the hot copy - there is nothing to retrieve from cold storage yet."""
    body = b"not-yet-archived"
    version = _seed(service, body=body)
    _label(service, version)
    _enqueue(service, cold, version)
    assert _row(service, version)["state"] == "HOT"
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert signed(service, "GET", path).content == body


def test_standard_object_restore_stays_invalid_object_state(service, cold):
    _seed(service)
    reply = signed(service, "POST", f"/{BUCKET}/{KEY}?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert reply.status_code == 403
    assert b"InvalidObjectState" in reply.content


# ---------------------------------------------------------------------------
# Failure matrix
# ---------------------------------------------------------------------------

def test_missing_cold_backend_fails_the_archive_pass(service, cold,
                                                     tmp_path):
    version = _seed(service)
    _label(service, version)
    _enqueue(service, cold, version)
    # A cold root that cannot exist (a file where a directory is needed).
    broken = tmp_path / "not-a-directory"
    broken.write_text("occupied", encoding="ascii")
    db, catalog = _open(service)
    try:
        store = ArchiveStore(catalog, ColdBlobStore(broken))
        report = asyncio.run(store.run_archive_pass(
            service[2], scratch_directory=None))
    finally:
        db.close()
    assert report["failed"] == [version], report
    row = _row(service, version)
    assert row["state"] in ("HOT", "ARCHIVING")
    assert row["error"]
    # The same object collects nothing while the archive is unverified.
    db = service[3]()
    try:
        assert archive_deletion_permitted(db, version) is False
    finally:
        db.close()
    # The backend coming back lets the same request complete.
    report = _archive_pass(service, cold)
    assert report["archived"] == [version], report


def test_corrupted_archive_fails_closed_and_recovers(service, cold):
    body = b"corruptible-archive-body"
    version = _seed(service, body=body)
    blob = _full_archive(service, cold, version)
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    # Corrupt the cold bytes after sealing.
    blob.archive_path(version).write_bytes(b"tampered" * 32)
    report = _restore_pass(service, cold)
    assert report["failed"] == [version], report
    row = _row(service, version)
    assert row["state"] == "ARCHIVED"
    assert row["error"]
    # No window ever opened: the object stays gated, not half-restored.
    assert signed(service, "GET", path).status_code == 403
    # A corrupt archive also blocks GC deletion of the hot source.
    db = service[3]()
    try:
        assert archive_deletion_permitted(db, version) is False
    finally:
        db.close()
    # Re-archiving from the still-present hot copy repairs everything.
    _rearchive(service, cold, version)
    assert _archive_pass(service, cold)["archived"] == [version]
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    assert signed(service, "GET", path).content == body


def _expire_lease(service, version_id):
    from teledrive.storage.cold_store import archive_versions
    _sql(service, update(archive_versions).where(
        archive_versions.c.object_id == version_id
    ).values(lease_until_ns=time.time_ns() - 1))


def _hold_lease(service, version_id, seconds=900):
    from teledrive.storage.cold_store import archive_versions
    _sql(service, update(archive_versions).where(
        archive_versions.c.object_id == version_id
    ).values(lease_until_ns=time.time_ns() + seconds * 1_000_000_000,
             lease_owner="dead-worker"))


def _rearchive(service, root, version_id):
    db, catalog = _open(service)
    try:
        assert ArchiveStore(
            catalog, ColdBlobStore(root)).request_rearchive(version_id)
    finally:
        db.close()


def test_partial_upload_is_resumable_after_lease_expiry(
        service, cold, monkeypatch):
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 256)
    body = bytes(range(256)) * 8  # 8 chunks
    version = _seed(service, body=body)
    _label(service, version)
    _enqueue(service, cold, version)

    inner = service[2]
    state = {"downloads": 0}

    class FlakyTransport:
        async def upload(self, *args, **kwargs):
            return await inner.upload(*args, **kwargs)

        async def verify_target(self):
            await inner.verify_target()

        async def download(self, reference, destination):
            state["downloads"] += 1
            if state["downloads"] > 2:
                raise IOError("connection lost mid-download")
            return await inner.download(reference, destination)

    report = _archive_pass(service, cold, transport=FlakyTransport())
    assert report["failed"] == [version], report
    row = _row(service, version)
    assert row["state"] in ("HOT", "ARCHIVING")
    # A crashed worker (one that never released) holds the row until the
    # durable lease expires; a healthy pass cannot steal it.
    _hold_lease(service, version)
    report = _archive_pass(service, cold)
    assert report == {"archived": [], "failed": [], "skipped": []}, report
    _expire_lease(service, version)
    # A restart resumes and completes the SAME sealed receipt.
    report = _archive_pass(service, cold)
    assert report["archived"] == [version], report
    blob = ColdBlobStore(cold)
    manifest = blob.read_manifest(version)
    assert len(manifest["chunk_lineage"]) == 8
    assert manifest["stored_bytes"] == len(body)
    assert blob.verify_archive(version, *_receipt(service, version))


def test_crash_between_blob_write_and_sql_commit_is_idempotent(
        service, cold):
    """Restart with the blob sealed but the CAS never committed."""
    body = b"sealed-but-uncommitted"
    version = _seed(service, body=body)
    blob = _full_archive(service, cold, version)
    receipt = _receipt(service, version)
    # Simulate the crash: roll the row back to an interrupted claim.
    from teledrive.storage.cold_store import archive_versions
    _sql(service, update(archive_versions).where(
        archive_versions.c.object_id == version
    ).values(state="ARCHIVING", whole_sha256=None, manifest=None,
             lease_until_ns=time.time_ns() - 1))
    report = _archive_pass(service, cold)
    assert report["archived"] == [version], report
    # The re-run reproduced the identical sealed bytes.
    assert _receipt(service, version) == receipt
    assert blob.verify_archive(version, *receipt)


def test_retry_after_commit_leaves_one_staged_copy(service, cold):
    body = b"retry-after-commit"
    version = _seed(service, body=body)
    _full_archive(service, cold, version)
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    # A lost 202 ACK makes the client retry: the AWS-shaped conflict.
    again = signed(service, "POST", f"{path}?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert again.status_code == 409
    assert _restore_pass(service, cold)["restored"] == [version]
    # Re-running the committed work changes nothing.
    report = _restore_pass(service, cold)
    assert report["restored"] == [] and report["skipped"] == []
    assert signed(service, "GET", path).content == body


def test_interrupted_read_from_staging_recovers_from_the_archive(
        service, cold):
    body = b"staged-read-interrupted" * 16
    version = _seed(service, body=body)
    blob = _full_archive(service, cold, version)
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    # Damage the staged copy after verification: the read must fail
    # closed (never serve wrong bytes) with the staged-copy error.
    staged = blob.staged_path(version)
    staged.write_bytes(staged.read_bytes()[:4])
    from teledrive.storage.cold_store import ColdStoreError
    with pytest.raises(ColdStoreError):
        signed(service, "GET", path)
    # The archive data is the recovery source: expire, re-restore, serve.
    _expire_window(service, version)
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    assert signed(service, "GET", path).content == body


def test_staging_cache_is_bounded_and_eviction_closes_the_window(
        service, cold):
    versions = []
    for index in range(3):
        version = _seed(service, body=f"bounded-{index}".encode() * 8,
                        key=f"cold/bounded-{index}.bin")
        versions.append(version)
        _full_archive(service, cold, version)
        assert signed(service, "POST",
                      f"/{BUCKET}/cold/bounded-{index}.bin?restore",
                      b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                      ).status_code == 202
        assert _restore_pass(service, cold, limit=1)["restored"] == [version]
    blob = ColdBlobStore(cold)
    assert all(blob.staged_exists(v) for v in versions)
    # Order the restorations so the eviction target is deterministic.
    from teledrive.storage.cold_store import archive_versions
    for offset, version in enumerate(versions):
        _sql(service, update(archive_versions).where(
            archive_versions.c.object_id == version
        ).values(restored_ns=time.time_ns() + offset * 1000))
    db, catalog = _open(service)
    try:
        store = ArchiveStore(catalog, ColdBlobStore(cold))
        settled = store.purge_expired(max_staged=2)
    finally:
        db.close()
    assert settled == 1
    assert _row(service, versions[0])["state"] == "ARCHIVED"
    assert blob.staged_exists(versions[0]) is False
    assert blob.staged_exists(versions[1]) and blob.staged_exists(versions[2])
    # The evicted restore's window closed with the copy.
    assert signed(service, "GET", "/{}/cold/bounded-0.bin".format(BUCKET)
                  ).status_code == 403
    assert signed(service, "GET", "/{}/cold/bounded-2.bin".format(BUCKET)
                  ).status_code == 200
    # Archive data survived every eviction.
    for version in versions:
        assert blob.verify_archive(version, *_receipt(service, version))


# ---------------------------------------------------------------------------
# Version addressing
# ---------------------------------------------------------------------------

def test_restore_targets_the_selected_generation_never_the_head(
        service, cold):
    first = _seed(service, body=b"first-generation", key=KEY)
    second = _seed(service, body=b"second-generation", key=KEY)
    assert second != first
    _full_archive(service, cold, first)
    _full_archive(service, cold, second)
    path = f"/{BUCKET}/{KEY}"
    # Restore the HISTORICAL version by VersionId.
    assert signed(service, "POST", f"{path}?restore&versionId={first}",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [first]
    restored = signed(service, "GET", f"{path}?versionId={first}")
    assert restored.status_code == 200
    assert restored.content == b"first-generation"
    # The current HEAD (also archived, NOT restored) stays gated: the
    # restore never leaked into the head's generation.
    assert signed(service, "GET", path).status_code == 403
    head = signed(service, "HEAD", path)
    assert head.status_code == 403
    # Restoring the head afterwards is its own request.
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [second]
    assert signed(service, "GET", path).content == b"second-generation"


# ---------------------------------------------------------------------------
# Encryption mixes
# ---------------------------------------------------------------------------

def _ssec_headers(raw: bytes) -> dict[str, str]:
    return {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key":
            base64.b64encode(raw).decode("ascii"),
        "x-amz-server-side-encryption-customer-key-md5":
            base64.b64encode(hashlib.md5(
                raw, usedforsecurity=False).digest()).decode("ascii"),
    }


def test_ssec_object_archives_as_ciphertext_and_restores_exact(
        service, cold):
    _bucket(service)
    raw = bytes((index * 7 + 3) % 256 for index in range(32))
    body = b"ssec-archive-body" * 24
    put = signed(service, "PUT", f"/{BUCKET}/{KEY}", body,
                 extra_headers=_ssec_headers(raw))
    assert put.status_code == 200, put.text
    version = put.headers["x-amz-version-id"]
    blob = _full_archive(service, cold, version)
    # The archived bytes are the STORED ciphertext, not plaintext.
    manifest = blob.read_manifest(version)
    assert manifest["encryption"]["mode"] == "SSE-C"
    assert manifest["stored_bytes"] > len(body)
    assert blob.archive_path(version).read_bytes() != body
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    # A read without the customer key never yields plaintext.
    missing = signed(service, "GET", path)
    assert missing.status_code == 400
    assert b"customer key" in missing.content
    # The correct key decrypts the staged copy byte-exactly.
    restored = signed(service, "GET", path, extra_headers=_ssec_headers(raw))
    assert restored.status_code == 200
    assert restored.content == body
    rng = signed(service, "GET", path, extra_headers={
        **_ssec_headers(raw), "Range": "bytes=3-9"})
    assert rng.status_code == 206 and rng.content == body[3:10]


def test_envelope_object_archive_restore_round_trip(service, cold,
                                                     monkeypatch):
    _bucket(service)
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    body = b"envelope-archive-body" * 20
    put = signed(service, "PUT", f"/{BUCKET}/{KEY}", body,
                 extra_headers={
                     "x-amz-server-side-encryption": "AES256"})
    assert put.status_code == 200, put.text
    assert put.headers.get("x-amz-server-side-encryption") == "AES256"
    version = put.headers["x-amz-version-id"]
    blob = _full_archive(service, cold, version)
    manifest = blob.read_manifest(version)
    assert manifest["encryption"]["mode"] == "SSE-S3"
    assert "wrapped_key" not in json.dumps(manifest)
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    restored = signed(service, "GET", path)
    assert restored.status_code == 200, restored.text
    assert restored.content == body
    assert restored.headers.get("x-amz-server-side-encryption") == "AES256"


# ---------------------------------------------------------------------------
# Aliases, replicas, tiering integration
# ---------------------------------------------------------------------------

def test_dedup_alias_version_archives_and_restores(service, cold):
    body = b"alias-source-payload" * 12
    _seed(service, body=body, key="cold/source.bin")
    copy = signed(service, "PUT", f"/{BUCKET}/cold/alias.bin", b"",
                  extra_headers={
                      "x-amz-copy-source": f"{BUCKET}/cold/source.bin"})
    assert copy.status_code == 200, copy.text
    db, catalog = _open(service)
    try:
        alias_version = catalog.get(BUCKET, "cold/alias.bin").item.id
        from teledrive.storage.manifest import object_aliases
        assert db.connection.execute(select(
            object_aliases.c.source_object_id).where(
            object_aliases.c.object_id == alias_version)).first() is not None
    finally:
        db.close()
    _full_archive(service, cold, alias_version)
    path = f"/{BUCKET}/cold/alias.bin"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [alias_version]
    restored = signed(service, "GET", path)
    assert restored.status_code == 200
    assert restored.content == body


def test_replicated_bytes_archive_and_restore(service, cold):
    body = b"replicated-payload" * 10
    version = _seed(service, body=body, key="cold/replicated.bin")
    db, catalog = _open(service)
    try:
        content_id = catalog.manifests.resolve_content_id(version)
        catalog.manifests.append_replica(
            content_id, 0, "replica-account", -100999, 4242, int(time.time()))
    finally:
        db.close()
    _full_archive(service, cold, version)
    path = "/{}/cold/replicated.bin".format(BUCKET)
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    assert _restore_pass(service, cold)["restored"] == [version]
    assert signed(service, "GET", path).content == body
    # The replica reference survived untouched.
    from teledrive.storage.manifest import replica_chunks
    db = service[3]()
    try:
        assert db.connection.execute(select(
            replica_chunks.c.message_id).where(
            replica_chunks.c.object_id == version)).scalar_one() == 4242
    finally:
        db.close()


def test_tiering_scheduler_enqueues_and_resets(service, cold):
    from teledrive.s3.tiering import TieringStore
    version = _seed(service)
    document = (
        '<IntelligentTieringConfiguration '
        'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        "<Id>t</Id><Filter><Prefix>cold/</Prefix></Filter>"
        "<Status>Enabled</Status>"
        "<Tiering><Days>1</Days><AccessTier>ARCHIVE_ACCESS</AccessTier>"
        "</Tiering></IntelligentTieringConfiguration>").encode()
    assert signed(service, "PUT",
                  f"/{BUCKET}?intelligent-tiering&id=t",
                  document).status_code == 200
    _sql(service, update(objects).where(objects.c.id == version)
         .values(created_at=int(time.time()) - 6 * 86400))
    db, catalog = _open(service)
    try:
        changed = TieringStore(catalog).apply_due(now_ns=time.time_ns())
    finally:
        db.close()
    assert changed >= 1
    row = _row(service, version)
    assert row is not None and row["state"] == "HOT"
    assert _archive_pass(service, cold)["archived"] == [version]
    # An access resets the tier and settles any restore state.
    _sql(service, update(objects).where(objects.c.id == version)
         .values(last_accessed_ns=time.time_ns()))
    db, catalog = _open(service)
    try:
        TieringStore(catalog).apply_due(now_ns=time.time_ns())
    finally:
        db.close()
    assert signed(service, "GET", f"/{BUCKET}/{KEY}").status_code == 200
    assert not ColdBlobStore(cold).staged_exists(version)


# ---------------------------------------------------------------------------
# Phase C: the GC fence
# ---------------------------------------------------------------------------

def _prepare_gc(service, version_id, *, bucket=BUCKET):
    """Revoke a noncurrent version and queue it for collection."""
    from teledrive.storage.gc_collect import RetainedMediaGC
    db, catalog = _open(service)
    try:
        gcx = RetainedMediaGC(db)
        gcx.set_enabled(True, by="test", grace_seconds=3600)
        row = db.connection.execute(select(
            objects.c.object_key).where(
            objects.c.id == version_id)).scalar_one()
        assert catalog.delete_version(bucket, row, version_id)
        gcx.enqueue([version_id], "archive-fence-test")
        from teledrive.storage.gc_collect import gc_queue
        db.connection.execute(update(gc_queue).values(
            enqueued_ns=gc_queue.c.enqueued_ns - 2 * 3600 * 1_000_000_000))
        db.commit()
        transport = DeletingTransport(service[2])
        report = asyncio.run(gcx.collect(transport, scope="queued"))
        return report, transport
    finally:
        db.close()


def test_gc_collects_only_independently_verified_archives(service, cold):
    # Distinct payloads: identical bytes would dedup the second PUT into
    # an alias of the first, and the alias fence (correctly) protects it.
    keep = _seed(service, body=b"gc-fence-verified-payload",
                 key="cold/gc-keep.bin")
    pending = _seed(service, body=b"gc-fence-pending-payload",
                    key="cold/gc-pending.bin")
    # keep: fully verified archive. pending: enqueued but never run.
    _full_archive(service, cold, keep)
    _label(service, pending)
    _enqueue(service, cold, pending)

    report, transport = _prepare_gc(service, keep)
    assert [entry["object_id"] for entry in report["collected"]] == [keep]
    # The verified archive permitted deletion; the Telegram messages went.
    assert any(reference.message_id for reference in transport.deleted)
    from teledrive.storage.manifest import chunks
    db = service[3]()
    try:
        assert db.connection.execute(select(
            chunks.c.object_id).where(
            chunks.c.object_id == keep)).first() is None
    finally:
        db.close()
    # An unverified (ARCHIVING) archive blocks deletion.
    report, transport = _prepare_gc(service, pending)
    assert report["collected"] == []
    assert [entry["object_id"] for entry in report["skipped"]] == [pending]
    from teledrive.storage.manifest import chunks as chunks2
    db = service[3]()
    try:
        assert db.connection.execute(select(
            chunks2.c.object_id).where(
            chunks2.c.object_id == pending)).first() is not None
    finally:
        db.close()


def test_corrupt_archive_blocks_gc_deletion(service, cold):
    body = b"corrupt-gc-payload"
    version = _seed(service, body=body, key="cold/gc-corrupt.bin")
    blob = _full_archive(service, cold, version)
    blob.archive_path(version).write_bytes(b"gone" * 64)
    report, _transport = _prepare_gc(service, version)
    assert report["collected"] == []
    assert [entry["object_id"] for entry in report["skipped"]] == [version]


def test_compliance_lock_beats_gc_even_archived(service, cold):
    body = b"locked-gc-payload"
    version = _seed(service, body=body, key="cold/gc-locked.bin")
    _full_archive(service, cold, version)
    # Revoke first (an active COMPLIANCE lock refuses the revocation
    # itself), then lock the revoked version: the collector must still
    # refuse to touch its media.
    db, catalog = _open(service)
    try:
        row = db.connection.execute(select(
            objects.c.object_key).where(
            objects.c.id == version)).scalar_one()
        assert catalog.delete_version(BUCKET, row, version)
        catalog.set_retention(version, mode="COMPLIANCE",
                              until_ns=time.time_ns() + DAY_NS)
        from teledrive.storage.gc_collect import RetainedMediaGC, gc_queue
        gcx = RetainedMediaGC(db)
        gcx.set_enabled(True, by="test", grace_seconds=3600)
        gcx.enqueue([version], "archive-fence-test")
        db.connection.execute(update(gc_queue).values(
            enqueued_ns=gc_queue.c.enqueued_ns - 2 * 3600 * 1_000_000_000))
        db.commit()
        transport = DeletingTransport(service[2])
        report = asyncio.run(gcx.collect(transport, scope="queued"))
    finally:
        db.close()
    assert report["collected"] == []
    assert [entry["object_id"] for entry in report["skipped"]] == [version]
    assert transport.deleted == []


# ---------------------------------------------------------------------------
# Worker races (the real-backend matrix: [sqlite] plus every configured
# DB_TEST_*_URL, exactly like tests/s3/test_s3_retry_race_matrix.py)
# ---------------------------------------------------------------------------

def test_two_workers_restore_one_version(backend_service, monkeypatch,
                                         tmp_path):
    service = backend_service
    root = tmp_path / "cold-archive"
    monkeypatch.setenv("TELEDRIVE_COLD_ARCHIVE_DIR", str(root))
    body = b"contended-restore-body"
    version = _seed(service, body=body)
    _full_archive(service, root, version)
    path = f"/{BUCKET}/{KEY}"
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    results: list[dict] = []
    errors: list[BaseException] = []

    def worker():
        db = None
        try:
            db, catalog = _open(service)
            store = ArchiveStore(catalog, ColdBlobStore(root))
            results.append(store.run_restore_pass(limit=1))
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)
        finally:
            if db is not None:
                db.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors
    restored = [entry for report in results for entry in report["restored"]]
    # Exactly one winner; the loser skipped the claimed row.
    assert sorted(restored) == [version]
    assert sum(len(report["restored"]) for report in results) == 1
    row = _row(service, version)
    assert row["state"] == "RESTORED_TEMP"
    assert signed(service, "GET", path).content == body


def test_two_workers_archive_one_version(backend_service, monkeypatch,
                                         tmp_path):
    service = backend_service
    root = tmp_path / "cold-archive"
    monkeypatch.setenv("TELEDRIVE_COLD_ARCHIVE_DIR", str(root))
    body = b"contended-archive-body"
    version = _seed(service, body=body)
    _label(service, version)
    _enqueue(service, root, version)
    results: list[dict] = []
    errors: list[BaseException] = []

    def worker():
        db = None
        try:
            db, catalog = _open(service)
            store = ArchiveStore(catalog, ColdBlobStore(root))
            results.append(asyncio.run(store.run_archive_pass(
                service[2], scratch_directory=None)))
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)
        finally:
            if db is not None:
                db.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors
    archived = [entry for report in results for entry in report["archived"]]
    assert sorted(archived) == [version]
    assert sum(len(report["archived"]) for report in results) == 1
    assert _row(service, version)["state"] == "ARCHIVED"
