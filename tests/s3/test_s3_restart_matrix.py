"""Crash/restart column of the per-operation matrix in `docs/S3_SPECS.md`.

"Crash/restart" means: the process dies between two observable steps, a NEW
connection and a new store/catalog are opened against the SAME database, and
the operation must either resume safely or fail closed. The contract every
case pins:

* no half-object is ever published as a live head,
* accounted bytes/chunks are never lost or double-counted,
* deleted state never resurrects,
* a stale in-process cache never outvotes the database.

A restart is simulated the only honest way available in one interpreter:
close the ``Database`` and call ``connect_database`` again for every
assertion, then build a NEW ``ManifestStore`` / ``BucketCatalog`` /
``MultipartStore`` on that connection. HTTP assertions use a fresh client
request (the gateway opens a new connection per request). The one genuinely
process-wide cache (compiled bucket policy) is explicitly discarded where a
real process death would drop it.

The table is keyed by manifest operation name, and the meta-test fails if a
name stops being `supported`. Physical GC is not an S3 operation, so it is a
standalone case below rather than a table entry.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from defusedxml import ElementTree as ET

import pytest
from sqlalchemy import func, select, text, update

from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, part, setup, xml_text
from teledrive.db import connect_database
from teledrive.s3.multipart import (
    MultipartError, MultipartStore, completion_leases,
)
from teledrive.s3.policy import _POLICY_CACHE, bucket_policy
from teledrive.storage.catalog import (
    BucketCatalog, heads, published_versions,
)
from teledrive.storage.gc import StorageGCInventory
from teledrive.storage.gc_collect import RetainedMediaGC, gc_collected, gc_leases
from teledrive.storage.manifest import (
    ChunkReference, ManifestStore, chunks, object_aliases, objects,
)

B = "/restart-bucket"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

# manifest operation -> the restart contract this file proves for it.
CASES = {
    "PutObject":
        "chunks+ready manifest without a published version: invisible head, "
        "GC-audited, never collected as if it were published",
    "CompleteMultipartUpload":
        "a live `completing` lease is not silently completed; recovery must "
        "fence it, and a replay still yields exactly one published object",
    "UploadPart":
        "staged parts survive a restart and Complete still publishes once",
    "DeleteObject":
        "a committed delete marker survives; a re-publish gets a new object "
        "id and a fresh generation",
    "DeleteObjects":
        "a committed version delete survives; a re-publish cannot be killed "
        "by a stale ABA precondition",
    "CopyObject":
        "an alias copy survives; the alias resolves and protects the source "
        "media from physical GC",
    "PutBucketPolicy":
        "the decision is read from the database, not a stale compiled cache",
    "PutObjectLockConfiguration":
        "the one-way lock config survives and applies retention to new "
        "objects published after the restart",
    "RestoreObject":
        "an open restore window survives; the archive gate honours it and "
        "still closes on expiry",
    "RenameObject":
        "a committed rename has one head, not two, after the restart",
    "AbortMultipartUpload":
        "a committed abort cannot be completed or listed after the restart",
}

BUCKET = "restart-bucket"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fresh(connection):
    """Open a new Database and catalog, exactly as a restarted process would.

    Callers own the Database and must close it; nothing here reuses the old
    connection or an old store instance.
    """
    db = connection()
    return db, BucketCatalog(ManifestStore(db))


def _keyhash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _publish(catalog, bucket, key, payload, *, message_id, now=None):
    """begin -> one journaled chunk -> finish -> publish; returns object id."""
    now = int(time.time()) if now is None else now
    digest = hashlib.sha256(payload).hexdigest()
    oid = catalog.manifests.begin(bucket, key, len(payload), now)
    catalog.manifests.append(oid, ChunkReference(
        ordinal=0, offset=0, size=len(payload), sha256=digest,
        account="mtproto-user", chat_id=-1001234567890,
        message_id=message_id), now)
    catalog.manifests.finish(oid, digest, now)
    catalog.publish(oid, now=now)
    return oid


def _batch_delete(service, bucket, key, version_id):
    body = (f"<Delete><Object><Key>{key}</Key>"
            f"<VersionId>{version_id}</VersionId></Object></Delete>").encode()
    import base64
    return signed(service, "POST", f"/{bucket}?delete", body, extra_headers={
        "Content-MD5": base64.b64encode(
            hashlib.md5(body, usedforsecurity=False).digest()).decode()})


def _object_row(db, object_id):
    return db.connection.execute(select(
        objects.c.id, objects.c.bucket, objects.c.object_key,
        objects.c.status, objects.c.size,
    ).where(objects.c.id == object_id)).first()


def _head_row(db, bucket, key):
    return db.connection.execute(select(
        heads.c.object_id, heads.c.generation).where(
        heads.c.bucket == bucket, heads.c.key_hash == _keyhash(key))).first()


def _published_count(db, bucket, key):
    return db.connection.execute(
        select(func.count()).select_from(published_versions.join(
            objects, published_versions.c.object_id == objects.c.id,
        )).where(objects.c.bucket == bucket,
                 objects.c.object_key == key)).scalar_one()


# ---------------------------------------------------------------------------
# 1. PutObject: ready-but-unpublished staging after a crash
# ---------------------------------------------------------------------------

def case_put_object_ready_unpublished(service):
    """The exact shape of the historical bug: READY + chunks, no publish.

    A new process must not mistake the manifest for a live head or a
    published version, but its chunks must still be visible to the GC audit
    so the bytes are accounted for and never silently lost. It is also NOT a
    physical candidate: only proven-published payloads may be collected.
    """
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200

    db, catalog = _fresh(connection)
    try:
        now = int(time.time())
        payload = b"staged-but-never-published"
        oid = catalog.manifests.begin(BUCKET, "orphan.bin", len(payload), now)
        catalog.manifests.append(oid, ChunkReference(
            ordinal=0, offset=0, size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            account="mtproto-user", chat_id=-1001234567890,
            message_id=90001), now)
        catalog.manifests.finish(
            oid, hashlib.sha256(payload).hexdigest(), now)
    finally:
        db.close()  # crash between manifest completion and publish

    db2, catalog2 = _fresh(connection)
    try:
        # Not a live head, not a readable object, not a published version.
        with pytest.raises(FileNotFoundError):
            catalog2.get(BUCKET, "orphan.bin")
        assert signed(service, "HEAD", f"{B}/orphan.bin").status_code == 404
        assert catalog2.list_versions(BUCKET, "orphan.bin", limit=10) == []
        assert _published_count(db2, BUCKET, "orphan.bin") == 0
        assert _head_row(db2, BUCKET, "orphan.bin") is None

        # The chunks are still accounted for, and the object is discoverable
        # by the read-only GC audit (not silently dropped).
        assert db2.connection.execute(select(func.count()).select_from(
            chunks).where(chunks.c.object_id == oid)).scalar_one() == 1
        inventory = StorageGCInventory(catalog2.manifests).inspect()
        audit = [item for item in inventory.protected_chunks
                 if item.owner_object_id == oid]
        assert len(audit) == 1
        assert audit[0].message_count == 1
        assert audit[0].live_heads == 0
        assert audit[0].retained_history is True
        assert inventory.total_telegram_messages == 1

        gcx = RetainedMediaGC(db2)
        gcx.set_enabled(True, by="test")
        metrics = gcx.metrics()
        assert metrics["physical_objects"] == 1
        assert metrics["logical_objects"] == 0
        assert metrics["retained_bytes"] == len(payload)
        # Fail-closed: an unpublished staging object must never be treated
        # as a reclaimable *published* candidate. Its chunks are visible to
        # the audit above, but `gc_collect` only deletes proven-published
        # payloads; a dedicated staging-reclaim path does not exist today.
        # (Whether such a path should exist is unverified here: this test
        # asserts the observable audit state, not a reclaim guarantee.)
        assert oid not in {
            row["object_id"] for row in gcx.candidates(
                scope="deleted", min_age_seconds=3600)}
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# 2. CompleteMultipartUpload: a `completing` upload with a live lease
# ---------------------------------------------------------------------------

def case_complete_multipart_live_lease(service):
    """A crash after the state change must not let a new process complete it.

    The lease and the `completing` state commit together. A new process sees
    them, refuses stale recovery while the lease is live, and refuses a plain
    Complete. Only an explicit fenced recovery may reopen it, and then a
    replay must reuse the SAME published object.
    """
    _client, _creds, _telegram, connection, _key = service
    setup(service)
    uid = begin(service)
    etag = part(service, uid, 1, b"multipart-restart-payload")

    db, mpu = _fresh_mpu(connection)
    try:
        token = mpu._claim_completion(uid, int(time.time()), 120)
        assert token
    finally:
        db.close()  # the completing process dies

    db2, mpu2 = _fresh_mpu(connection)
    try:
        # Live lease: not stale, not recoverable, not silently completable.
        assert mpu2.stale_completions(min_age_seconds=60) == []
        assert mpu2.recover_stale_completion(
            uid, dry_run=False, min_age_seconds=3600) is False
        reply = complete(service, uid, [(1, etag)])
        assert reply.status_code != 200, (
            "a new process silently completed an upload whose writer may "
            f"still be alive: {reply.status_code}")
        assert _published_count(db2, "backup-bucket", "asset.bin") == 0
        assert signed(service, "HEAD",
                      "/backup-bucket/asset.bin").status_code == 404
    finally:
        db2.close()

    # The writer is now genuinely gone: age only the DURABLE lease, which is
    # the same clock the recovery path uses.
    db3, mpu3 = _fresh_mpu(connection)
    try:
        db3.connection.execute(update(completion_leases).where(
            completion_leases.c.upload_id == uid).values(
            lease_until=int(time.time()) - 7200))
        db3.commit()
        assert mpu3.recover_stale_completion(
            uid, dry_run=True, min_age_seconds=3600) is True
        assert mpu3.recover_stale_completion(
            uid, dry_run=False, min_age_seconds=3600) is True
    finally:
        db3.close()

    first = complete(service, uid, [(1, etag)])
    assert first.status_code == 200, first.text
    first_etag = xml_text(first, "ETag")

    db4, _catalog4 = _fresh(connection)
    try:
        # Exactly one object, one head and one published version.
        assert _published_count(db4, "backup-bucket", "asset.bin") == 1
        # The staged part manifests are READY objects too; only one of them
        # may be published and own the head.
        head = _head_row(db4, "backup-bucket", "asset.bin")
        assert head is not None
        first_version = head[0]
    finally:
        db4.close()

    # A replay is idempotent: same object, still one published object.
    replay = complete(service, uid, [(1, etag)])
    assert replay.status_code == 200, replay.text
    assert xml_text(replay, "ETag") == first_etag
    # A different selection is not an equivalent replay and must not publish.
    other = complete(service, uid, [(2, etag)])
    assert other.status_code in (400, 404), other.text
    assert signed(service, "GET",
                  "/backup-bucket/asset.bin").content == \
        b"multipart-restart-payload"

    db5, _catalog5 = _fresh(connection)
    try:
        assert _published_count(db5, "backup-bucket", "asset.bin") == 1
        head = _head_row(db5, "backup-bucket", "asset.bin")
        assert head is not None and head[0] == first_version
    finally:
        db5.close()


# ---------------------------------------------------------------------------
# 3. UploadPart / ListParts: staged parts survive
# ---------------------------------------------------------------------------

def case_upload_part_survives(service):
    _client, _creds, telegram, connection, _key = service
    setup(service)
    uid = begin(service)
    payload = b"staged-part-across-a-restart" * 7
    etag = part(service, uid, 1, payload)
    uploads_before = telegram.uploads

    db, mpu = _fresh_mpu(connection)
    try:
        stored = mpu.list_parts(uid, "backup-bucket", "asset.bin",
                                service[1].access_key)
        assert [(row[0], row[2]) for row in stored] == [
            (1, etag.strip('"'))]
    finally:
        db.close()  # restart

    listed = signed(service, "GET", f"/backup-bucket/asset.bin?uploadId={uid}")
    assert listed.status_code == 200, listed.text
    root = ET.fromstring(listed.content)
    assert [node.findtext(NS + "PartNumber")
            for node in root.findall(NS + "Part")] == ["1"]

    done = complete(service, uid, [(1, etag)])
    assert done.status_code == 200, done.text
    assert signed(service, "GET", "/backup-bucket/asset.bin").content == payload
    # Complete never re-uploads the staged bytes.
    assert telegram.uploads == uploads_before

    # Negative: the upload is finished, so a later listing cannot resurrect it
    # and no second object was created.
    assert signed(service, "GET",
                  f"/backup-bucket/asset.bin?uploadId={uid}").status_code == 404
    db2, _catalog2 = _fresh(connection)
    try:
        assert _published_count(db2, "backup-bucket", "asset.bin") == 1
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# 4. DeleteObject: delete marker survives; re-publish is fresh
# ---------------------------------------------------------------------------

def case_delete_object_survives(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", f"{B}/gone.bin", b"old-bytes").status_code == 200

    db, catalog = _fresh(connection)
    try:
        old_id = catalog.get(BUCKET, "gone.bin").item.id
        old_generation = catalog.get(BUCKET, "gone.bin").generation
    finally:
        db.close()

    assert signed(service, "DELETE", f"{B}/gone.bin").status_code == 204

    db2, catalog2 = _fresh(connection)
    try:
        # Restart: the delete did not evaporate.
        with pytest.raises(FileNotFoundError):
            catalog2.get(BUCKET, "gone.bin")
        assert signed(service, "GET", f"{B}/gone.bin").status_code == 404
        assert signed(service, "HEAD", f"{B}/gone.bin").status_code == 404
        listing = signed(service, "GET", f"{B}?list-type=2")
        assert b"gone.bin" not in listing.content
        # The marker is the current head; it is not the deleted payload.
        head = _head_row(db2, BUCKET, "gone.bin")
        assert head is not None and head[0] != old_id
    finally:
        db2.close()

    # Re-publish after the restart: a new object id AND a fresh generation.
    assert signed(service, "PUT", f"{B}/gone.bin", b"new-bytes").status_code == 200
    db3, catalog3 = _fresh(connection)
    try:
        head = catalog3.get(BUCKET, "gone.bin")
        assert head.item.id != old_id
        assert head.generation > old_generation
        assert signed(service, "GET", f"{B}/gone.bin").content == b"new-bytes"
        # Negative: the old object id can never unlink the new head.
        with pytest.raises(ValueError):
            catalog3.remove_current(BUCKET, "gone.bin",
                                    expected_object_id=old_id)
        assert catalog3.get(BUCKET, "gone.bin").item.id == head.item.id
    finally:
        db3.close()


# ---------------------------------------------------------------------------
# 5. DeleteObjects: committed batch version delete + ABA fence
# ---------------------------------------------------------------------------

def case_delete_objects_survives(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    put = signed(service, "PUT", f"{B}/batch.bin", b"batch-old")
    assert put.status_code == 200
    version_id = put.headers["x-amz-version-id"]

    reply = _batch_delete(service, BUCKET, "batch.bin", version_id)
    assert reply.status_code == 200, reply.text
    assert signed(service, "GET", f"{B}/batch.bin").status_code == 404

    db, catalog = _fresh(connection)
    try:
        # Restart: gone means gone, and the revoked manifest is retained (its
        # chunks are the recovery journal, not silently dropped).
        with pytest.raises(FileNotFoundError):
            catalog.get(BUCKET, "batch.bin")
        assert _head_row(db, BUCKET, "batch.bin") is None
        assert _object_row(db, version_id)[3] == "ready"
    finally:
        db.close()

    republished = signed(service, "PUT", f"{B}/batch.bin", b"batch-new")
    assert republished.status_code == 200
    db2, catalog2 = _fresh(connection)
    try:
        head = catalog2.get(BUCKET, "batch.bin")
        assert head.item.id != version_id
        # The head was unlinked, so publish() restarts the counter at 1 --
        # exactly the ABA shape a generation-only delete gets wrong.
        assert head.generation == 1
        # Negative: the stale version id cannot delete the newer object.
        with pytest.raises(ValueError):
            catalog2.remove_current(BUCKET, "batch.bin",
                                    expected_object_id=version_id)
        assert catalog2.get(BUCKET, "batch.bin").item.id == head.item.id
        assert signed(service, "GET", f"{B}/batch.bin").content == b"batch-new"
        # Both manifests still account for their own chunk.
        for identifier in (version_id, head.item.id):
            assert db2.connection.execute(select(func.count()).select_from(
                chunks).where(chunks.c.object_id == identifier)
            ).scalar_one() == 1
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# 6. CopyObject: alias survives, and protects the source from GC
# ---------------------------------------------------------------------------

def case_copy_object_alias_survives(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", "/restart-origin").status_code == 200
    assert signed(service, "PUT", B).status_code == 200
    payload = b"copied-payload-survives-restart"
    assert signed(service, "PUT", "/restart-origin/source.bin",
                  payload).status_code == 200
    copy = signed(service, "PUT", f"{B}/copy.bin", extra_headers={
        "x-amz-copy-source": "/restart-origin/source.bin"})
    assert copy.status_code == 200, copy.text

    db, catalog = _fresh(connection)
    try:
        source_id = catalog.get("restart-origin", "source.bin").item.id
        clone_id = catalog.get(BUCKET, "copy.bin").item.id
    finally:
        db.close()

    db2, catalog2 = _fresh(connection)
    try:
        # Restart: the alias resolves to real bytes and the physical reference
        # is still visible as an alias, not as a second chunk row.
        assert signed(service, "GET", f"{B}/copy.bin").content == payload
        clone = catalog2.get(BUCKET, "copy.bin")
        assert clone.item.id == clone_id and clone.item.id != source_id
        alias = db2.connection.execute(select(
            object_aliases.c.source_object_id).where(
            object_aliases.c.object_id == clone_id)).scalar_one()
        assert alias == source_id
        assert db2.connection.execute(select(func.count()).select_from(
            chunks).where(chunks.c.object_id == source_id)).scalar_one() == 1
        assert db2.connection.execute(select(func.count()).select_from(
            chunks).where(chunks.c.object_id == clone_id)).scalar_one() == 0

        inventory = StorageGCInventory(catalog2.manifests).inspect()
        assert inventory.copy_aliases == 1
        rooted = [item for item in inventory.protected_chunks
                  if item.owner_object_id == source_id]
        assert len(rooted) == 1 and rooted[0].copied_aliases == 1
        assert rooted[0].message_count == 1

        # Negative: revoke the source version; the surviving alias must keep
        # the source's Telegram media out of physical collection.
        now_seconds = int(time.time())
        assert catalog2.delete_version(
            "restart-origin", "source.bin", source_id) is True
        db2.connection.execute(update(objects).where(
            objects.c.id == source_id).values(updated_at=now_seconds - 7200))
        db2.connection.execute(text(
            "UPDATE storage_removed_versions SET removed_ns = :ns "
            "WHERE object_id = :oid"),
            {"ns": (now_seconds - 7200) * 1_000_000_000, "oid": source_id})
        db2.commit()
        gcx = RetainedMediaGC(db2)
        gcx.set_enabled(True, by="test")
        assert source_id not in {
            row["object_id"] for row in gcx.candidates(
                scope="revoked", min_age_seconds=3600)}
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# 7. PutBucketPolicy: the cache must never outvote the database
# ---------------------------------------------------------------------------

def case_bucket_policy_from_database(service):
    from teledrive.s3.credentials import S3CredentialStore

    _client, _creds, _telegram, connection, key = service
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", f"{B}/policy.bin", b"policy-bytes").status_code == 200

    db, _catalog = _fresh(connection)
    try:
        other = S3CredentialStore(db, key).create("restart-policy-reader",
                                                  ["s3:GetObject"])
    finally:
        db.close()

    def statement(effect: str) -> dict:
        return {
            "Effect": effect,
            "Principal": {"CanonicalUser": [other.access_key]},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        }

    allow = json.dumps({"Version": "2012-10-17",
                        "Statement": [statement("Allow")]}).encode()
    deny = json.dumps({"Version": "2012-10-17",
                       "Statement": [statement("Deny")]}).encode()
    assert signed(service, "PUT", f"{B}?policy", allow).status_code == 204
    # Populate the in-process compiled cache through a real request.
    assert signed(service, "GET", f"{B}/policy.bin",
                  access=other.access_key,
                  secret=other.secret_key).status_code == 200

    # Another process replaces the stored policy directly in SQL. This
    # process's cache still holds the Allow entry keyed by the OLD updated_ns.
    db2, _catalog2 = _fresh(connection)
    try:
        db2.connection.execute(bucket_policy.delete().where(
            bucket_policy.c.bucket == BUCKET))
        db2.connection.execute(bucket_policy.insert().values(
            bucket=BUCKET, document=deny.decode(),
            updated_ns=time.time_ns(), updated_by="other-process"))
        db2.commit()
        assert db2.connection.execute(select(func.count()).select_from(
            bucket_policy).where(bucket_policy.c.bucket == BUCKET)
        ).scalar_one() == 1
    finally:
        db2.close()

    # No sleep, no local invalidation: the decision must come from the DB.
    denied = signed(service, "GET", f"{B}/policy.bin",
                    access=other.access_key, secret=other.secret_key)
    assert denied.status_code == 403, denied.text
    assert b"bucket policy" in denied.content

    # Simulate process death: an in-process cache does not survive it.
    _POLICY_CACHE.discard_bucket(BUCKET)
    still_denied = signed(service, "GET", f"{B}/policy.bin",
                          access=other.access_key, secret=other.secret_key)
    assert still_denied.status_code == 403

    # Remove the policy in SQL: the restarted process must not resurrect the
    # cached Deny either.
    db3, _catalog3 = _fresh(connection)
    try:
        db3.connection.execute(bucket_policy.delete().where(
            bucket_policy.c.bucket == BUCKET))
        db3.commit()
    finally:
        db3.close()
    _POLICY_CACHE.discard_bucket(BUCKET)
    allowed_again = signed(service, "GET", f"{B}/policy.bin",
                           access=other.access_key, secret=other.secret_key)
    assert allowed_again.status_code == 200, allowed_again.text
    # And the read-back is honest about "no policy".
    assert signed(service, "GET", f"{B}?policy").status_code == 404


# ---------------------------------------------------------------------------
# 8. PutObjectLockConfiguration: persisted one-way state applies after restart
# ---------------------------------------------------------------------------

def _lock_config(days: int, mode: str = "COMPLIANCE") -> bytes:
    return (f'<ObjectLockConfiguration '
            f'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
            f"<Rule><DefaultRetention><Mode>{mode}</Mode>"
            f"<Days>{days}</Days></DefaultRetention></Rule>"
            f"</ObjectLockConfiguration>").encode()


def case_object_lock_configuration_after_restart(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    configured = signed(service, "PUT", f"{B}?object-lock", _lock_config(30))
    assert configured.status_code == 200, configured.text

    # Restart: close every store/connection this process holds.
    db, _catalog = _fresh(connection)
    try:
        assert db.connection.execute(text(
            "SELECT object_lock_enabled FROM storage_buckets WHERE name = :b"),
            {"b": BUCKET}).scalar_one() in (1, True)
    finally:
        db.close()

    read = signed(service, "GET", f"{B}?object-lock")
    assert read.status_code == 200, read.text
    assert b"<Mode>COMPLIANCE</Mode>" in read.content

    # A post-restart publish must apply the DB's default retention.
    put = signed(service, "PUT", f"{B}/locked.bin", b"locked-after-restart")
    assert put.status_code == 200
    retention = signed(service, "GET", f"{B}/locked.bin?retention")
    assert retention.status_code == 200, retention.text
    assert b"<Mode>COMPLIANCE</Mode>" in retention.content
    # Negative: the one-way lock cannot be shortened or disabled after the
    # restart, and the retained version refuses deletion.
    assert signed(service, "PUT", f"{B}?object-lock",
                  _lock_config(1)).status_code == 400
    version = put.headers["x-amz-version-id"]
    assert signed(service, "DELETE",
                  f"{B}/locked.bin?versionId={version}").status_code == 403


# ---------------------------------------------------------------------------
# 9. RestoreObject: the archive gate reads the persisted window
# ---------------------------------------------------------------------------

def case_restore_window_survives(service):
    _client, _creds, telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    put = signed(service, "PUT", f"{B}/cold.bin", b"cold-payload")
    assert put.status_code == 200
    version = put.headers["x-amz-version-id"]

    db, _catalog = _fresh(connection)
    try:
        db.connection.execute(update(objects).where(
            objects.c.id == version).values(storage_class="ARCHIVE_ACCESS"))
        db.commit()
    finally:
        db.close()

    assert signed(service, "GET", f"{B}/cold.bin").status_code == 403
    restore = signed(service, "POST", f"{B}/cold.bin?restore",
                     b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert restore.status_code == 202, restore.text

    # Restart: the window is a SQL row, so a new process must honour it.
    db2, _catalog2 = _fresh(connection)
    try:
        assert db2.connection.execute(select(
            objects.c.restore_until_ns).where(
            objects.c.id == version)).scalar_one() > time.time_ns()
    finally:
        db2.close()
    body = signed(service, "GET", f"{B}/cold.bin")
    assert body.status_code == 200, body.text
    assert body.content == b"cold-payload"
    head = signed(service, "HEAD", f"{B}/cold.bin")
    assert head.status_code == 200
    assert 'ongoing-request="false"' in head.headers.get("x-amz-restore", "")
    # Negative: a still-open window refuses a duplicate restore (it is not
    # reset or duplicated by the restart).
    again = signed(service, "POST", f"{B}/cold.bin?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert again.status_code == 409, again.text
    assert b"RestoreAlreadyInProgress" in again.content

    # Expiry closes the gate from the database, not process memory.
    db3, _catalog3 = _fresh(connection)
    try:
        db3.connection.execute(update(objects).where(
            objects.c.id == version).values(
            restore_until_ns=time.time_ns() - 1))
        db3.commit()
    finally:
        db3.close()
    assert signed(service, "GET", f"{B}/cold.bin").status_code == 403
    assert signed(service, "HEAD", f"{B}/cold.bin").status_code == 403
    # The archived payload never moved or duplicated.
    assert telegram.uploads == 1


# ---------------------------------------------------------------------------
# 10. RenameObject: one head after an atomic move
# ---------------------------------------------------------------------------

def case_rename_object_atomic(service):
    _client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", f"{B}/before.bin", b"rename-payload").status_code == 200
    renamed = signed(service, "PUT", f"{B}/after.bin?renameObject",
                     extra_headers={
                         "x-amz-rename-source": f"{BUCKET}/before.bin"})
    assert renamed.status_code == 200, renamed.text

    db2, catalog2 = _fresh(connection)
    try:
        # Restart: the move is one SQL transaction, so exactly one head.
        assert signed(service, "GET", f"{B}/after.bin").content == b"rename-payload"
        assert signed(service, "GET", f"{B}/before.bin").status_code == 404
        moved = catalog2.get(BUCKET, "after.bin")
        with pytest.raises(FileNotFoundError):
            catalog2.get(BUCKET, "before.bin")
        # Negative: no second head and no second chunk row.
        assert db2.connection.execute(select(func.count()).select_from(
            heads).where(heads.c.bucket == BUCKET)).scalar_one() == 1
        assert db2.connection.execute(select(func.count()).select_from(
            chunks).where(chunks.c.object_id == moved.item.id)
        ).scalar_one() == 1
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# 11. AbortMultipartUpload: an abort is not undone by a restart
# ---------------------------------------------------------------------------

def case_abort_multipart_survives(service):
    _client, _creds, _telegram, connection, _key = service
    setup(service)
    uid = begin(service)
    part(service, uid, 1, b"aborted-part")
    aborted = signed(service, "DELETE", f"/backup-bucket/asset.bin?uploadId={uid}")
    assert aborted.status_code == 204, aborted.text

    db, mpu = _fresh_mpu(connection)
    try:
        # Negative: the aborted upload cannot come back as active.
        with pytest.raises(MultipartError):
            mpu.require(uid, "backup-bucket", "asset.bin",
                        service[1].access_key)
        with pytest.raises(MultipartError):
            mpu.list_parts(uid, "backup-bucket", "asset.bin",
                           service[1].access_key)
    finally:
        db.close()

    assert signed(service, "GET",
                  f"/backup-bucket/asset.bin?uploadId={uid}").status_code == 404
    done = complete(service, uid, [(1, '"x"')])
    assert done.status_code in (400, 404), done.text
    assert signed(service, "HEAD", "/backup-bucket/asset.bin").status_code == 404
    db2, _catalog2 = _fresh(connection)
    try:
        assert _published_count(db2, "backup-bucket", "asset.bin") == 0
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# Physical GC is not an S3 operation, so it is not in the manifest table.
# ---------------------------------------------------------------------------

def _fresh_mpu(connection):
    db = connection()
    return db, MultipartStore(BucketCatalog(ManifestStore(db)))


class _RecordingTransport:
    def __init__(self):
        self.deleted: list[tuple[str, int, int]] = []

    async def delete(self, reference):
        self.deleted.append((reference.account, reference.chat_id,
                             reference.message_id))


def test_physical_gc_resumes_a_dead_collectors_lease_exactly_once(service):
    """A collector dies holding a durable lease.

    The lease is the only thing that stops two collectors double-deleting the
    same Telegram messages. A new collector must respect the live lease, then
    resume the object once the lease expires, and collect it exactly once.
    """
    _client, _creds, _telegram, connection, _key = service
    db, catalog = _fresh(connection)
    try:
        catalog.create_bucket(BUCKET, int(time.time()))
        now = int(time.time())
        payload = b"physical-gc-across-restart"
        oid = _publish(catalog, BUCKET, "gc.bin", payload,
                       message_id=70001, now=now - 7200)
        assert catalog.delete_version(BUCKET, "gc.bin", oid) is True
        db.connection.execute(update(objects).where(
            objects.c.id == oid).values(updated_at=now - 7200))
        db.connection.execute(text(
            "UPDATE storage_removed_versions SET removed_ns = :ns "
            "WHERE object_id = :oid"),
            {"ns": (now - 7200) * 1_000_000_000, "oid": oid})
        db.commit()

        gcx = RetainedMediaGC(db)
        gcx.set_enabled(True, by="test")
        # A collector that died just now still holds the claim.
        db.connection.execute(gc_leases.insert().values(
            object_id=oid, claimed_ns=time.time_ns(),
            owner="dead-collector"))
        db.commit()
    finally:
        db.close()

    # New process, same database.
    db2, _catalog2 = _fresh(connection)
    try:
        gcx2 = RetainedMediaGC(db2)
        transport = _RecordingTransport()
        report = asyncio.run(gcx2.collect(
            transport, scope="revoked", min_age_seconds=3600))
        assert report["collected"] == []
        assert [item["object_id"] for item in report["skipped"]] == [oid]
        assert transport.deleted == [], "a live GC lease was ignored"
        assert _object_row(db2, oid)[3] == "ready"

        # The lease expires: a restarted collector resumes the exact object.
        db2.connection.execute(update(gc_leases).where(
            gc_leases.c.object_id == oid).values(
            claimed_ns=time.time_ns() - 1000 * 1_000_000_000))
        db2.commit()
        gcx3 = RetainedMediaGC(db2)
        report = asyncio.run(gcx3.collect(
            transport, scope="revoked", min_age_seconds=3600))
        assert [item["object_id"] for item in report["collected"]] == [oid]
        assert len(transport.deleted) == 1
        assert _object_row(db2, oid)[3] == "gc-collected"
        assert db2.connection.execute(select(func.count()).select_from(
            chunks).where(chunks.c.object_id == oid)).scalar_one() == 0
        assert db2.connection.execute(select(func.count()).select_from(
            gc_collected).where(gc_collected.c.object_id == oid)
        ).scalar_one() == 1

        # Exactly once: a second collector has nothing left to do.
        report = asyncio.run(RetainedMediaGC(db2).collect(
            transport, scope="revoked", min_age_seconds=3600))
        assert report["collected"] == []
        assert len(transport.deleted) == 1
        assert db2.connection.execute(select(func.count()).select_from(
            gc_collected).where(gc_collected.c.object_id == oid)
        ).scalar_one() == 1
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# table / meta contract
# ---------------------------------------------------------------------------

HANDLERS = {
    "PutObject": case_put_object_ready_unpublished,
    "CompleteMultipartUpload": case_complete_multipart_live_lease,
    "UploadPart": case_upload_part_survives,
    "DeleteObject": case_delete_object_survives,
    "DeleteObjects": case_delete_objects_survives,
    "CopyObject": case_copy_object_alias_survives,
    "PutBucketPolicy": case_bucket_policy_from_database,
    "PutObjectLockConfiguration": case_object_lock_configuration_after_restart,
    "RestoreObject": case_restore_window_survives,
    "RenameObject": case_rename_object_atomic,
    "AbortMultipartUpload": case_abort_multipart_survives,
}


def test_the_table_names_only_supported_operations():
    """A renamed/removed operation must fail here, not test nothing."""
    from pathlib import Path

    manifest = json.loads(
        (Path(__file__).resolve().parents[2]
         / "teledrive/s3/operation_manifest.json").read_text())
    supported = {op["name"] for op in manifest["operations"]
                 if op.get("status") == "supported"}
    stale = sorted(set(CASES) - supported)
    assert not stale, f"restart table names non-supported operations: {stale}"
    assert set(CASES) == set(HANDLERS), (
        "every restart case needs exactly one handler")


@pytest.mark.parametrize("operation", sorted(CASES))
def test_operation_survives_a_crash_and_restart(service, operation):
    HANDLERS[operation](service)
