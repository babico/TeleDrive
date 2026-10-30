"""Retry and multiworker-race columns of the per-operation matrix.

Two independent questions, one file:

* **retry** — the same logical request arrives twice (a client retry after a
  timeout, or a replay). The operation must either be idempotent or answer a
  clean conflict, and the second attempt must never publish a second object,
  lose chunk accounting, or resurrect deleted state.
* **multiworker race** — two independent ``Database``/store instances (two
  separate connections, exactly as two processes would have) act at the same
  time. A ``threading.Barrier`` (or an equivalent event gate that pauses a
  real code path) forces the interleaving; every case asserts exactly one
  winner and the negative: never two heads, never a double publish, never a
  stale delete removing the NEW object.

HTTP retries use the shared ``service`` fixture (fresh request = fresh
connection). Races run at the catalog/store level because that is where two
processes actually contend; the gateway adds no extra concurrency primitive
of its own. Physical GC is not an S3 operation, so it is a standalone case.

Every table is keyed by manifest operation name; the meta-test fails if a name
stops being ``supported``.
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import hashlib
import json
import shutil
import tempfile
import threading
import time
from pathlib import Path
from xml.etree import ElementTree as StdET

import pytest
from defusedxml import ElementTree as ET
from sqlalchemy import func, select, text

import web.s3 as gateway
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, part, setup, xml_text
from teledrive.db import connect_database
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.multipart import MultipartError, MultipartStore, uploads
from teledrive.s3.policy import bucket_policy
from teledrive.storage.catalog import BucketCatalog, heads, published_versions
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.gc import StorageGCInventory
from teledrive.storage.gc_collect import RetainedMediaGC, gc_collected, gc_leases
from teledrive.storage.manifest import (
    ChunkReference, ManifestStore, chunks, object_aliases, objects,
)

B = "/retry-bucket"
BUCKET = "retry-bucket"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

# manifest operation -> the retry contract this file proves.
RETRY_CASES = {
    "PutObject":
        "replaying identical bytes dedups to one physical payload, advances "
        "the generation exactly once and leaves no orphaned chunks",
    "CompleteMultipartUpload":
        "the same part list replays to the committed object; a different "
        "list is refused instead of silently re-published",
    "DeleteObject":
        "a second DELETE is not an error and cannot resurrect the payload",
    "DeleteObjects":
        "the same batch again reports NoSuchVersion per entry, never a "
        "resurrection and never a second delete",
    "PutBucketPolicy":
        "re-writing the same document keeps one row; a conflicting document "
        "replaces it (last write wins) and the decision follows the database",
    "CopyObject":
        "a repeated copy advances the generation, keeps one head and leaves "
        "the alias resolving to the original bytes",
    "AbortMultipartUpload":
        "a second abort is effect-idempotent: the session stays dead and "
        "nothing is published",
}

# manifest operation -> the race contract this file proves.
RACE_CASES = {
    "PutObject":
        "two create-if-absent publications of different bytes: exactly one "
        "winner, generation 1, one head, the loser gets a conflict",
    "CompleteMultipartUpload":
        "two concurrent completes of one upload: one published object, one "
        "clean 409 loser, no second object and no orphaned part chunks",
    "DeleteObject":
        "a stale delete racing a publish never removes the NEW object, even "
        "when a re-publish reuses the same generation number",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fresh(connection):
    """A new Database plus catalog, as a second process would open it."""
    db = connection()
    return db, BucketCatalog(ManifestStore(db))


def _keyhash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _stage(catalog, bucket, key, payload, *, message_id, now=None):
    """begin -> one journaled chunk -> finish. No publish yet."""
    now = int(time.time()) if now is None else now
    digest = hashlib.sha256(payload).hexdigest()
    oid = catalog.manifests.begin(bucket, key, len(payload), now)
    catalog.manifests.append(oid, ChunkReference(
        ordinal=0, offset=0, size=len(payload), sha256=digest,
        account="mtproto-user", chat_id=-1001234567890,
        message_id=message_id), now)
    catalog.manifests.finish(oid, digest, now)
    return oid


def _publish(catalog, bucket, key, payload, *, message_id, now=None):
    oid = _stage(catalog, bucket, key, payload,
                 message_id=message_id, now=now)
    catalog.publish(oid, now=int(time.time()) if now is None else now)
    return oid


def _head_row(db, bucket, key):
    return db.connection.execute(select(
        heads.c.object_id, heads.c.generation).where(
        heads.c.bucket == bucket, heads.c.key_hash == _keyhash(key))).first()


def _head_rows(db, bucket, key):
    return db.connection.execute(select(
        heads.c.object_id, heads.c.generation).where(
        heads.c.bucket == bucket, heads.c.key_hash == _keyhash(key))).all()


def _published_count(db, bucket, key):
    return db.connection.execute(
        select(func.count()).select_from(published_versions.join(
            objects, published_versions.c.object_id == objects.c.id,
        )).where(objects.c.bucket == bucket,
                 objects.c.object_key == key)).scalar_one()


def _chunk_count(db, object_id):
    return db.connection.execute(select(func.count()).select_from(
        chunks).where(chunks.c.object_id == object_id)).scalar_one()


def _batch_delete(service, bucket, entries):
    """entries: list of (key, version_id|None)."""
    root = StdET.Element("Delete")
    for key, version_id in entries:
        node = StdET.SubElement(root, "Object")
        StdET.SubElement(node, "Key").text = key
        if version_id is not None:
            StdET.SubElement(node, "VersionId").text = version_id
    body = StdET.tostring(root)
    return signed(service, "POST", f"/{bucket}?delete", body, extra_headers={
        "Content-MD5": base64.b64encode(
            hashlib.md5(body, usedforsecurity=False).digest()).decode()})


def _policy(other_key: str, effect: str) -> bytes:
    statement = {
        "Effect": effect,
        "Principal": {"CanonicalUser": [other_key]},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*",
    }
    return json.dumps({"Version": "2012-10-17",
                       "Statement": [statement]}).encode()


# ---------------------------------------------------------------------------
# 1. PutObject retry
# ---------------------------------------------------------------------------

def case_put_object_retry(service):
    _client, _creds, telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    payload = b"identical-retry-payload" * 11

    first = signed(service, "PUT", f"{B}/retry.bin", payload)
    assert first.status_code == 200, first.text
    first_version = first.headers["x-amz-version-id"]
    uploads_after_first = telegram.uploads

    second = signed(service, "PUT", f"{B}/retry.bin", payload)
    assert second.status_code == 200, second.text
    second_version = second.headers["x-amz-version-id"]
    assert second_version != first_version, "a replay must create a new version"
    # Content-addressed dedup: the identical bytes are not sent again, so no
    # duplicate physical payload exists to leak.
    assert telegram.uploads == uploads_after_first, (
        "an identical byte-for-byte retry re-uploaded Telegram media")

    db, catalog = _fresh(connection)
    try:
        head = catalog.get(BUCKET, "retry.bin")
        assert head.item.id == second_version
        assert head.generation == 2, (
            f"a retry must advance the generation once, got {head.generation}")
        assert len(_head_rows(db, BUCKET, "retry.bin")) == 1

        # The first version is the physical base; the second is a GC-aware
        # alias of it. Exactly one chunk row exists, and no chunk is orphaned
        # on the alias.
        assert _chunk_count(db, first_version) == 1
        assert _chunk_count(db, second_version) == 0
        assert db.connection.execute(select(func.count()).select_from(
            chunks)).scalar_one() == 1
        alias = db.connection.execute(select(
            object_aliases.c.source_object_id).where(
            object_aliases.c.object_id == second_version)).scalar_one()
        assert alias == first_version

        inventory = StorageGCInventory(catalog.manifests).inspect()
        assert inventory.total_telegram_messages == 1
        assert inventory.copy_aliases == 1
        rooted = [item for item in inventory.protected_chunks
                  if item.owner_object_id == first_version]
        assert len(rooted) == 1 and rooted[0].copied_aliases == 1

        gcx = RetainedMediaGC(db)
        gcx.set_enabled(True, by="test")
        # Negative: a live head is never a physical candidate, and neither is
        # the alias. Nothing was orphaned by the replay.
        for scope in ("deleted", "revoked", "queued"):
            assert {row["object_id"] for row in gcx.candidates(
                scope=scope, min_age_seconds=3600)} == set()
        assert gcx.metrics()["physical_objects"] == 1
    finally:
        db.close()

    read = signed(service, "GET", f"{B}/retry.bin")
    assert read.status_code == 200 and read.content == payload


# ---------------------------------------------------------------------------
# 2. CompleteMultipartUpload retry
# ---------------------------------------------------------------------------

def case_complete_multipart_retry(service):
    _client, _creds, telegram, connection, _key = service
    setup(service)
    uid = begin(service)
    first_bytes = b"m" * (5 * 1024 * 1024)
    tail = b"tail" * 5
    etag1 = part(service, uid, 1, first_bytes)
    etag2 = part(service, uid, 2, tail)
    uploads_before = telegram.uploads

    first = complete(service, uid, [(1, etag1), (2, etag2)])
    assert first.status_code == 200, first.text
    etag = xml_text(first, "ETag")
    assert telegram.uploads == uploads_before, "Complete must not re-upload"

    # Same logical request again: the committed result, not a second object.
    replay = complete(service, uid, [(1, etag1), (2, etag2)])
    assert replay.status_code == 200, replay.text
    assert xml_text(replay, "ETag") == etag
    assert telegram.uploads == uploads_before

    # A different part list is NOT an equivalent replay.
    different = complete(service, uid, [(1, etag1)])
    assert different.status_code in (400, 409), different.text
    assert xml_text(different, "Code") == "InvalidPart"

    db, catalog = _fresh(connection)
    try:
        assert _published_count(db, "backup-bucket", "asset.bin") == 1
        head = catalog.get("backup-bucket", "asset.bin")
        assert head.generation == 1
        assert len(_head_rows(db, "backup-bucket", "asset.bin")) == 1
        # The refused replay did not publish a second object: exactly one
        # published version exists for the key (the staged part manifests are
        # not published versions).
        assert _published_count(db, "backup-bucket", "asset.bin") == 1
        # The staged part chunks were physically re-owned by the final object
        # exactly once, not duplicated.
        assert _chunk_count(db, head.item.id) == 2
        assert db.connection.execute(select(func.count()).select_from(
            chunks)).scalar_one() == 2
    finally:
        db.close()

    body = signed(service, "GET", "/backup-bucket/asset.bin")
    assert body.status_code == 200 and body.content == first_bytes + tail


# ---------------------------------------------------------------------------
# 3. DeleteObject retry
# ---------------------------------------------------------------------------

def case_delete_object_retry(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    put = signed(service, "PUT", f"{B}/gone.bin", b"delete-me-once")
    assert put.status_code == 200
    payload_id = put.headers["x-amz-version-id"]

    first = signed(service, "DELETE", f"{B}/gone.bin")
    assert first.status_code == 204
    assert signed(service, "GET", f"{B}/gone.bin").status_code == 404

    # Retry: still 204, still no bytes able to come back.
    second = signed(service, "DELETE", f"{B}/gone.bin")
    assert second.status_code == 204
    assert signed(service, "GET", f"{B}/gone.bin").status_code == 404
    assert signed(service, "HEAD", f"{B}/gone.bin").status_code == 404

    db, catalog = _fresh(connection)
    try:
        with pytest.raises(FileNotFoundError):
            catalog.get(BUCKET, "gone.bin")
        head = _head_row(db, BUCKET, "gone.bin")
        assert head is not None, "the tombstone head must survive the retry"
        assert head[0] != payload_id
        assert len(_head_rows(db, BUCKET, "gone.bin")) == 1
        # The payload's bytes are retained for GC, never resurrected as a
        # readable object, and the retry did not double-delete them.
        assert _chunk_count(db, payload_id) == 1
        listed = signed(service, "GET", f"{B}?list-type=2")
        assert b"gone.bin" not in listed.content
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 4. DeleteObjects retry
# ---------------------------------------------------------------------------

def case_delete_objects_retry(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    put = signed(service, "PUT", f"{B}/batch.bin", b"batch-retry")
    assert put.status_code == 200
    version_id = put.headers["x-amz-version-id"]

    first = _batch_delete(service, BUCKET, [("batch.bin", version_id)])
    assert first.status_code == 200, first.text
    root = ET.fromstring(first.content)
    assert root.findtext(f"{NS}Deleted/{NS}Key") == "batch.bin"

    # The same batch again: the version is already gone, so AWS-shaped
    # per-entry NoSuchVersion, never a second delete and never a resurrection.
    replay = _batch_delete(service, BUCKET, [("batch.bin", version_id)])
    assert replay.status_code == 200, replay.text
    root = ET.fromstring(replay.content)
    assert root.findtext(f"{NS}Error/{NS}Code") == "NoSuchVersion"
    assert root.find(f"{NS}Deleted") is None

    assert signed(service, "GET", f"{B}/batch.bin").status_code == 404
    db, catalog = _fresh(connection)
    try:
        with pytest.raises(FileNotFoundError):
            catalog.get(BUCKET, "batch.bin")
        assert _head_row(db, BUCKET, "batch.bin") is None
        # One deleted-version record, not two, and the payload is retained as
        # the recovery journal (physical GC is disabled here).
        assert db.connection.execute(select(func.count()).select_from(
            objects).where(objects.c.id == version_id)).scalar_one() == 1
        assert _chunk_count(db, version_id) == 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 5. PutBucketPolicy retry
# ---------------------------------------------------------------------------

def case_put_bucket_policy_retry(service):
    _client, _creds, _telegram, connection, key = service
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", f"{B}/policy.bin",
                  b"policy-bytes").status_code == 200

    db, _catalog = _fresh(connection)
    try:
        other = S3CredentialStore(db, key).create(
            "retry-policy-reader", ["s3:GetObject"])
    finally:
        db.close()

    allow = _policy(other.access_key, "Allow")
    deny = _policy(other.access_key, "Deny")

    # Same document twice: a replace, never a duplicate row.
    assert signed(service, "PUT", f"{B}?policy", allow).status_code == 204
    assert signed(service, "PUT", f"{B}?policy", allow).status_code == 204
    db, _catalog = _fresh(connection)
    try:
        rows = db.connection.execute(select(
            bucket_policy.c.document).where(
            bucket_policy.c.bucket == BUCKET)).scalars().all()
        assert len(rows) == 1, (
            "the same policy retry produced duplicate rows")
        assert json.loads(rows[0]) == json.loads(allow), (
            "the same policy retry stored a diverging document")
    finally:
        db.close()
    assert signed(service, "GET", f"{B}/policy.bin",
                  access=other.access_key,
                  secret=other.secret_key).status_code == 200

    # Conflicting document: last write wins, and the decision follows it.
    assert signed(service, "PUT", f"{B}?policy", deny).status_code == 204
    db, _catalog = _fresh(connection)
    try:
        rows = db.connection.execute(select(
            bucket_policy.c.document).where(
            bucket_policy.c.bucket == BUCKET)).scalars().all()
        assert len(rows) == 1
        assert json.loads(rows[0]) == json.loads(deny)
    finally:
        db.close()
    denied = signed(service, "GET", f"{B}/policy.bin",
                    access=other.access_key, secret=other.secret_key)
    assert denied.status_code == 403, denied.text
    # The read-back is the exact stored document, not a stale compiled cache.
    stored = signed(service, "GET", f"{B}?policy")
    assert stored.status_code == 200
    assert stored.json() == json.loads(deny)

    # Back to Allow: exactly one row, decision flips again.
    assert signed(service, "PUT", f"{B}?policy", allow).status_code == 204
    db, _catalog = _fresh(connection)
    try:
        assert db.connection.execute(select(func.count()).select_from(
            bucket_policy).where(
            bucket_policy.c.bucket == BUCKET)).scalar_one() == 1
    finally:
        db.close()
    assert signed(service, "GET", f"{B}/policy.bin",
                  access=other.access_key,
                  secret=other.secret_key).status_code == 200


# ---------------------------------------------------------------------------
# 6. CopyObject retry
# ---------------------------------------------------------------------------

def case_copy_object_retry(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", "/retry-origin").status_code == 200
    assert signed(service, "PUT", B).status_code == 200
    payload = b"copy-retry-payload"
    source = signed(service, "PUT", "/retry-origin/source.bin", payload)
    assert source.status_code == 200
    source_id = source.headers["x-amz-version-id"]

    headers = {"x-amz-copy-source": "/retry-origin/source.bin"}
    first = signed(service, "PUT", f"{B}/copy.bin", extra_headers=headers)
    assert first.status_code == 200, first.text
    second = signed(service, "PUT", f"{B}/copy.bin", extra_headers=headers)
    assert second.status_code == 200, second.text

    db, catalog = _fresh(connection)
    try:
        head = catalog.get(BUCKET, "copy.bin")
        assert head.generation == 2, (
            f"a repeated copy must advance the generation, got {head.generation}")
        rows = _head_rows(db, BUCKET, "copy.bin")
        assert len(rows) == 1 and rows[0][0] == head.item.id
        assert _published_count(db, BUCKET, "copy.bin") == 2
        # The head is a copy alias of the one physical source payload.
        alias = db.connection.execute(select(
            object_aliases.c.source_object_id).where(
            object_aliases.c.object_id == head.item.id)).scalar_one()
        assert alias == source_id
        assert _chunk_count(db, head.item.id) == 0
        assert _chunk_count(db, source_id) == 1
        inventory = StorageGCInventory(catalog.manifests).inspect()
        assert inventory.copy_aliases == 2
        assert inventory.total_telegram_messages == 1
    finally:
        db.close()

    body = signed(service, "GET", f"{B}/copy.bin")
    assert body.status_code == 200 and body.content == payload
    assert signed(service, "GET", "/retry-origin/source.bin").content == payload


# ---------------------------------------------------------------------------
# 7. AbortMultipartUpload retry
# ---------------------------------------------------------------------------

def case_abort_multipart_retry(service):
    _client, _creds, _telegram, connection, _key = service
    setup(service)
    uid = begin(service)
    part(service, uid, 1, b"staged-to-abort")

    first = signed(service, "DELETE", f"/backup-bucket/asset.bin?uploadId={uid}")
    assert first.status_code == 204, first.text

    # Second abort: effect-idempotent. AWS answers NoSuchUpload for an upload
    # id that no longer exists; a 204 would be equally acceptable, so the
    # contract asserted here is the STATE, not the status code.
    second = signed(service, "DELETE", f"/backup-bucket/asset.bin?uploadId={uid}")
    assert second.status_code in (204, 404), second.text

    assert signed(service, "GET",
                  f"/backup-bucket/asset.bin?uploadId={uid}").status_code == 404
    assert part_retry_status(service, uid) == 404
    assert complete(service, uid, [(1, '"x"')]).status_code in (400, 404)
    assert signed(service, "HEAD", "/backup-bucket/asset.bin").status_code == 404

    db, catalog = _fresh(connection)
    try:
        state = db.connection.execute(select(uploads.c.state).where(
            uploads.c.id == uid)).scalar_one()
        assert state == "aborted"
        assert _head_row(db, "backup-bucket", "asset.bin") is None
        assert _published_count(db, "backup-bucket", "asset.bin") == 0
    finally:
        db.close()


def part_retry_status(service, uid):
    return signed(service, "PUT",
                  f"/backup-bucket/asset.bin?partNumber=2&uploadId={uid}",
                  b"late").status_code


# ---------------------------------------------------------------------------
# 8. PutObject race: create-if-absent, two writers, one winner
# ---------------------------------------------------------------------------

def test_put_object_race_exactly_one_winner(service):
    _client, _creds, telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200

    db_a, cat_a = _fresh(connection)
    db_b, cat_b = _fresh(connection)
    try:
        oid_a = _stage(cat_a, BUCKET, "race.bin", b"writer-a", message_id=88001)
        oid_b = _stage(cat_b, BUCKET, "race.bin", b"writer-b", message_id=88002)
        # The fake transport is keyed by message id; the staged manifests were
        # written straight to SQL, so make their payloads readable over HTTP.
        telegram.parts["file-88001"] = b"writer-a"
        telegram.parts["file-88002"] = b"writer-b"
        barrier = threading.Barrier(2, timeout=15)

        def publish(catalog, oid):
            barrier.wait()
            try:
                head = catalog.publish(oid, now=int(time.time()),
                                       expected_generation=0)
                return "won", head.generation
            except ValueError as exc:
                return "conflict", str(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [f.result(timeout=30) for f in (
                pool.submit(publish, cat_a, oid_a),
                pool.submit(publish, cat_b, oid_b),
            )]
    finally:
        db_a.close()
        db_b.close()

    outcomes = [outcome for outcome, _ in results]
    assert sorted(outcomes) == ["conflict", "won"], results
    winner_generation = next(value for outcome, value in results
                             if outcome == "won")
    assert winner_generation == 1

    db, catalog = _fresh(connection)
    try:
        rows = _head_rows(db, BUCKET, "race.bin")
        assert len(rows) == 1, f"two concurrent publishers produced {len(rows)} heads"
        assert rows[0][1] == 1
        assert _published_count(db, BUCKET, "race.bin") == 1
        head = catalog.get(BUCKET, "race.bin")
        assert head.item.id in (oid_a, oid_b)
        # Negative: the loser's staged chunk is still accounted for, never
        # silently dropped and never attached to the winner.
        assert _chunk_count(db, oid_a) == 1
        assert _chunk_count(db, oid_b) == 1
        assert db.connection.execute(select(func.count()).select_from(
            chunks)).scalar_one() == 2
        inventory = StorageGCInventory(catalog.manifests).inspect()
        assert inventory.total_telegram_messages == 2
        # Only the winner is a logical (head) object; the loser is retained
        # staging, not a second published object.
        assert inventory.total_manifests == 2
    finally:
        db.close()

    body = signed(service, "GET", f"{B}/race.bin")
    assert body.status_code == 200
    assert body.content in (b"writer-a", b"writer-b")


# ---------------------------------------------------------------------------
# 9. CompleteMultipartUpload race: one publisher, one clean loser
# ---------------------------------------------------------------------------

class _AttemptGatedTelegram:
    """Forward to the fake, but hold the winner in a real code path.

    The winner reaches ``download`` while holding the completion lease. The
    gate blocks that download until the other worker has attempted (and lost)
    the claim, so the interleaving is deterministic rather than timing-based.
    """

    def __init__(self, inner, attempted: threading.Event):
        self._inner = inner
        self._attempted = attempted

    async def download(self, reference, destination):
        if not self._attempted.wait(15):
            raise AssertionError(
                "the losing completion never reached its claim")
        return await self._inner.download(reference, destination)

    async def upload(self, path, *, object_id, ordinal, checksum):
        return await self._inner.upload(
            path, object_id=object_id, ordinal=ordinal, checksum=checksum)

    async def verify_target(self):
        return await self._inner.verify_target()


def test_complete_multipart_race_one_publish(service):
    _client, _creds, telegram, connection, _key = service
    setup(service)
    uid = begin(service)
    first_bytes = b"r" * (5 * 1024 * 1024)
    tail = b"race-tail"
    etag1 = part(service, uid, 1, first_bytes).strip('"')
    etag2 = part(service, uid, 2, tail).strip('"')
    owner = service[1].access_key
    attempted = threading.Event()
    barrier = threading.Barrier(2, timeout=15)
    scratch_root = Path(tempfile.mkdtemp(prefix="s3-mpu-race-"))
    scratch = scratch_root / "mpu-race"
    scratch.mkdir()

    def run_complete() -> tuple[str, object]:
        db, catalog = _fresh(connection)
        try:
            mpu = MultipartStore(catalog)
            engine = TelegramObjectStorage(
                catalog.manifests,
                _AttemptGatedTelegram(telegram, attempted),
                chunk_size=gateway.RECOMMENDED_CHUNK_SIZE,
                scratch_directory=scratch,
            )
            barrier.wait()
            try:
                finished = asyncio.run(mpu.complete(
                    uid, "backup-bucket", "asset.bin", owner,
                    [(1, etag1), (2, etag2)], engine))
                return "won", finished.object_id
            except MultipartError as exc:
                return "lost", (exc.code, exc.status, str(exc))
            finally:
                # Only a worker whose completion has already RETURNED can set
                # this; the winner is still blocked inside download().
                attempted.set()
        finally:
            db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result(timeout=60) for f in (
            pool.submit(run_complete), pool.submit(run_complete))]
    shutil.rmtree(scratch_root, ignore_errors=True)

    outcomes = [outcome for outcome, _ in results]
    assert sorted(outcomes) == ["lost", "won"], results
    loser = next(value for outcome, value in results if outcome == "lost")
    # A loser that reaches the claim answers 409 OperationAborted; one that
    # observes the `completing` state first answers 404 NoSuchUpload. Both are
    # clean fail-closed answers (never a second publish); the exact code
    # depends only on where the interleaving lands.
    assert loser[0] in ("OperationAborted", "NoSuchUpload"), loser
    assert loser[1] in (404, 409), loser

    db, catalog = _fresh(connection)
    try:
        assert db.connection.execute(select(uploads.c.state).where(
            uploads.c.id == uid)).scalar_one() == "completed"
        assert _published_count(db, "backup-bucket", "asset.bin") == 1
        head = _head_row(db, "backup-bucket", "asset.bin")
        assert head is not None
        # Negative: the loser did not publish a second object, and the two
        # staged part chunks belong to exactly one final (head) object.
        assert _chunk_count(db, head[0]) == 2
        assert db.connection.execute(select(func.count()).select_from(
            chunks)).scalar_one() == 2
    finally:
        db.close()

    body = signed(service, "GET", "/backup-bucket/asset.bin")
    assert body.status_code == 200 and body.content == first_bytes + tail


# ---------------------------------------------------------------------------
# 10. DeleteObject vs PutObject: remove_current fences on object id
# ---------------------------------------------------------------------------

class _PausingCatalog(BucketCatalog):
    """Pause ``remove_current``'s read so a publish can land in between."""

    def __init__(self, manifests, paused: threading.Event,
                 resume: threading.Event):
        super().__init__(manifests)
        self._paused = paused
        self._resume = resume

    def get(self, bucket: str, key: str):
        head = super().get(bucket, key)
        self._paused.set()
        assert self._resume.wait(15), "the racing publish never completed"
        return head


def test_delete_versus_publish_never_removes_the_new_object(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200

    # --- phase 1: a genuine barrier race, invariant after the interleaving ---
    db0, cat0 = _fresh(connection)
    try:
        old_id = _publish(cat0, BUCKET, "race-del.bin", b"old",
                          message_id=88101)
    finally:
        db0.close()
    service[2].parts["file-88101"] = b"old"
    service[2].parts["file-88102"] = b"new"

    db_del, cat_del = _fresh(connection)
    db_new, cat_new = _fresh(connection)
    try:
        new_id = _stage(cat_new, BUCKET, "race-del.bin", b"new",
                        message_id=88102)
        barrier = threading.Barrier(2, timeout=15)

        def delete_worker():
            barrier.wait()
            try:
                return "deleted", cat_del.remove_current(
                    BUCKET, "race-del.bin", expected_object_id=old_id)
            except ValueError as exc:
                return "refused", str(exc)

        def publish_worker():
            barrier.wait()
            try:
                cat_new.publish(new_id, now=int(time.time()))
                return "published", new_id
            except ValueError as exc:
                return "refused", str(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [f.result(timeout=30) for f in (
                pool.submit(delete_worker), pool.submit(publish_worker))]
    finally:
        db_del.close()
        db_new.close()

    db, catalog = _fresh(connection)
    try:
        head = _head_row(db, BUCKET, "race-del.bin")
        # The invariant: if the NEW object was ever published, it is still the
        # head. A stale delete must never remove it. When the delete wins
        # first, the publish may legitimately fail and leave no head.
        assert head is None or head[0] == new_id, (
            "a racing DELETE removed the NEW object")
        assert head is None or head[0] != old_id
        assert len(_head_rows(db, BUCKET, "race-del.bin")) <= 1
    finally:
        db.close()
    assert sorted(outcome for outcome, _ in results) in (
        ["deleted", "published"], ["deleted", "refused"],
        ["published", "refused"]), results

    # --- phase 2: the exact ABA window the object-id fence closes ----------
    # A delete reads generation 1 of object A, then A is unlinked and object B
    # is published at the SAME generation (publish restarts at 1 when the head
    # is absent). A generation-only unlink would delete B here.
    db_seed, cat_seed = _fresh(connection)
    try:
        a_id = _publish(cat_seed, BUCKET, "aba.bin", b"A", message_id=88103)
    finally:
        db_seed.close()
    service[2].parts["file-88103"] = b"A"
    service[2].parts["file-88104"] = b"B"

    paused, resume = threading.Event(), threading.Event()
    db_slow, cat_slow = _fresh(connection)
    slow = _PausingCatalog(cat_slow.manifests, paused, resume)
    db_fast, cat_fast = _fresh(connection)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                lambda: slow.remove_current(
                    BUCKET, "aba.bin", expected_object_id=a_id))
            assert paused.wait(15), "the stale delete never read the head"

            # A is unlinked, then B is published with no precondition, so B
            # gets generation 1 -- identical to the snapshot the delete holds.
            assert cat_fast.remove_current(
                BUCKET, "aba.bin", expected_object_id=a_id) is True
            b_id = _publish(cat_fast, BUCKET, "aba.bin", b"B", message_id=88104)
            head_before = _head_row(db_fast, BUCKET, "aba.bin")
            assert head_before is not None and head_before[0] == b_id
            assert head_before[1] == 1, (
                "the ABA window requires the new object to reuse generation 1")

            resume.set()
            with pytest.raises(ValueError):
                future.result(timeout=30)
    finally:
        resume.set()
        db_slow.close()
        db_fast.close()

    db, catalog = _fresh(connection)
    try:
        head = catalog.get(BUCKET, "aba.bin")
        assert head.item.id == b_id, "a stale same-generation delete removed B"
        assert head.generation == 1
        assert len(_head_rows(db, BUCKET, "aba.bin")) == 1
        assert _chunk_count(db, b_id) == 1
    finally:
        db.close()
    assert signed(service, "GET", f"{B}/aba.bin").content == b"B"


# ---------------------------------------------------------------------------
# 11. Physical GC race: the durable lease picks exactly one collector
# ---------------------------------------------------------------------------

class _CountingTransport:
    def __init__(self):
        self.deleted: list[tuple[str, int, int]] = []
        self._lock = threading.Lock()

    async def delete(self, reference):
        with self._lock:
            self.deleted.append((reference.account, reference.chat_id,
                                 reference.message_id))


def test_two_gc_collectors_delete_exactly_once(service):
    _client, _creds, _telegram, connection, _key = service
    db, catalog = _fresh(connection)
    try:
        catalog.create_bucket("gc-race-bucket", int(time.time()))
        now = int(time.time())
        oid = _publish(catalog, "gc-race-bucket", "gc.bin",
                       b"collect-me-once", message_id=88201, now=now - 7200)
        assert catalog.delete_version("gc-race-bucket", "gc.bin", oid) is True
        db.connection.execute(
            objects.update().where(objects.c.id == oid).values(
                updated_at=now - 7200))
        db.connection.execute(
            text("UPDATE storage_removed_versions SET removed_ns = :ns "
                 "WHERE object_id = :oid"),
            {"ns": (now - 7200) * 1_000_000_000, "oid": oid})
        db.commit()
        RetainedMediaGC(db).set_enabled(True, by="test")
    finally:
        db.close()

    transport = _CountingTransport()
    barrier = threading.Barrier(2, timeout=15)

    def collect():
        db2, _catalog2 = _fresh(connection)
        try:
            gcx = RetainedMediaGC(db2)
            barrier.wait()
            return asyncio.run(gcx.collect(
                transport, scope="revoked", min_age_seconds=3600))
        finally:
            db2.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        reports = [f.result(timeout=60) for f in (
            pool.submit(collect), pool.submit(collect))]

    collected = [item for report in reports for item in report["collected"]]
    skipped = [item for report in reports for item in report["skipped"]]
    assert [item["object_id"] for item in collected] == [oid], (
        "exactly one collector must report the object as collected")
    assert len(transport.deleted) == 1, (
        f"two collectors physically deleted the same media "
        f"{len(transport.deleted)} times")
    # The other collector either lost the lease (skipped) or found the object
    # already collected; both are the same observable outcome.
    if skipped:
        assert skipped[0]["object_id"] == oid

    db, _catalog = _fresh(connection)
    try:
        assert db.connection.execute(select(objects.c.status).where(
            objects.c.id == oid)).scalar_one() == "gc-collected"
        assert db.connection.execute(select(func.count()).select_from(
            gc_collected).where(gc_collected.c.object_id == oid)
        ).scalar_one() == 1
        assert _chunk_count(db, oid) == 0
        # The lease is released, not left claiming a collected object.
        assert db.connection.execute(select(func.count()).select_from(
            gc_leases).where(gc_leases.c.object_id == oid)).scalar_one() == 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# table / meta contract
# ---------------------------------------------------------------------------

RETRY_HANDLERS = {
    "PutObject": case_put_object_retry,
    "CompleteMultipartUpload": case_complete_multipart_retry,
    "DeleteObject": case_delete_object_retry,
    "DeleteObjects": case_delete_objects_retry,
    "PutBucketPolicy": case_put_bucket_policy_retry,
    "CopyObject": case_copy_object_retry,
    "AbortMultipartUpload": case_abort_multipart_retry,
}

RACE_HANDLERS = {
    "PutObject": test_put_object_race_exactly_one_winner,
    "CompleteMultipartUpload": test_complete_multipart_race_one_publish,
    "DeleteObject": test_delete_versus_publish_never_removes_the_new_object,
}


def test_the_tables_name_only_supported_operations():
    """A renamed/removed operation must fail here, not test nothing."""
    manifest = json.loads(
        (Path(__file__).resolve().parents[2]
         / "teledrive/s3/operation_manifest.json").read_text())
    supported = {op["name"] for op in manifest["operations"]
                 if op.get("status") == "supported"}
    stale = sorted((set(RETRY_CASES) | set(RACE_CASES)) - supported)
    assert not stale, (
        f"retry/race table names non-supported operations: {stale}")
    assert set(RETRY_CASES) == set(RETRY_HANDLERS), (
        "every retry case needs exactly one handler")
    assert set(RACE_CASES) == set(RACE_HANDLERS), (
        "every race case needs exactly one handler")


@pytest.mark.parametrize("operation", sorted(RETRY_CASES))
def test_operation_survives_a_retry(service, operation):
    RETRY_HANDLERS[operation](service)


@pytest.mark.parametrize("operation", sorted(RACE_CASES))
def test_operation_survives_a_multiworker_race(service, operation):
    RACE_HANDLERS[operation](service)
