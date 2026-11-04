"""Retry column for the object- and service-level operations.

Companion of ``tests/s3/test_s3_evidence_retry_config.py``: the same
logical request sent twice through the signed gateway (a client retry
after a timeout), for the nine open retry cells that are not config
family writes. The contract pinned per operation:

* **CreateBucket** — us-east-1 semantics: re-creating an owned bucket
  answers 200 again and keeps exactly one bucket row;
* **DeleteBucket** — the replay is a clean 404, never a resurrection;
* **RenameObject** — the replay is a clean 404 (the source is gone)
  and the move stays exactly one head;
* **UpdateObjectEncryption** — the replayed rotation is refused
  because the source key is no longer current; the object is unchanged
  and a rotation with the *current* key still works;
* **CreateMultipartUpload** — a replay opens a distinct session (AWS
  semantics: there is no idempotency token); both sessions are
  independently usable and cleanly abortable, and nothing is torn;
* **UploadPart / UploadPartCopy** — the replay replaces the part slot
  (last write wins): exactly one parts row, one published object after
  Complete, and the superseded staging is never visible;
* **RestoreObject** — the replay is a clean 409
  ``RestoreAlreadyInProgress`` and does not reset the window;
* **DeleteObjectAnnotation** — the replayed DELETE stays 204 with no
  resurrected row.
"""
from __future__ import annotations

import time
from urllib.parse import quote

from sqlalchemy import func, select, update

from teledrive.s3.annotations import AnnotationStore
from teledrive.s3.multipart import MultipartStore, parts as part_rows
from teledrive.storage.catalog import BucketCatalog, heads
from teledrive.storage.manifest import ManifestStore, objects
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, part, setup, xml_text
from tests.s3.test_s3_sse_c import (
    COPY_PREFIX, KEY_A, KEY_B, make_bucket, ssec_headers,
)

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def _fresh(service):
    """A new Database + catalog, as a second process would open them."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _keyhash(catalog, key: str) -> str:
    return catalog._keyhash(key)


def _head_rows(service, bucket, key):
    db, catalog = _fresh(service)
    try:
        return db.connection.execute(select(
            heads.c.object_id, heads.c.generation).where(
            heads.c.bucket == bucket,
            heads.c.key_hash == _keyhash(catalog, key))).all()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Service lifecycle
# ---------------------------------------------------------------------------

def test_replayed_create_bucket_is_idempotent(service):
    """AWS us-east-1 semantics: re-creating an owned bucket answers 200."""
    first = signed(service, "PUT", "/retry-created")
    assert first.status_code == 200, first.text
    replay = signed(service, "PUT", "/retry-created")
    assert replay.status_code == 200, replay.text

    db, catalog = _fresh(service)
    try:
        names = catalog.list_buckets()
        assert names.count("retry-created") == 1, (
            "a replayed CreateBucket left more than one bucket row")
    finally:
        db.close()
    assert signed(service, "HEAD", "/retry-created").status_code == 200


def test_replayed_delete_bucket_stays_dead(service):
    assert signed(service, "PUT", "/retry-deleted").status_code == 200
    assert signed(service, "DELETE", "/retry-deleted").status_code == 204
    replay = signed(service, "DELETE", "/retry-deleted")
    assert replay.status_code == 404, (
        "a replayed DeleteBucket must be a clean 404, not a second delete "
        f"of state that may already belong to someone else: {replay.text}")

    db, catalog = _fresh(service)
    try:
        assert "retry-deleted" not in catalog.list_buckets(), (
            "a replayed DeleteBucket resurrected the bucket")
    finally:
        db.close()
    assert signed(service, "HEAD", "/retry-deleted").status_code == 404


# ---------------------------------------------------------------------------
# RenameObject
# ---------------------------------------------------------------------------

def test_replayed_rename_object_is_a_clean_conflict(service):
    assert signed(service, "PUT", "/retry-rename").status_code == 200
    assert signed(service, "PUT", "/retry-rename/source.bin",
                  b"rename-once").status_code == 200
    headers = {"x-amz-rename-source": "/retry-rename/source.bin"}
    first = signed(service, "PUT", "/retry-rename/destination.bin?renameObject",
                   extra_headers=headers)
    assert first.status_code == 200, first.text

    # The same logical request again: the source no longer exists, so a
    # clean 404 — never a second head, never a resurrection.
    replay = signed(service, "PUT",
                    "/retry-rename/destination.bin?renameObject",
                    extra_headers=headers)
    assert replay.status_code == 404, replay.text

    assert signed(service, "GET",
                  "/retry-rename/destination.bin").content == b"rename-once"
    assert signed(service, "GET",
                  "/retry-rename/source.bin").status_code == 404
    assert len(_head_rows(service, "retry-rename", "destination.bin")) == 1
    assert _head_rows(service, "retry-rename", "source.bin") == []


# ---------------------------------------------------------------------------
# UpdateObjectEncryption (SSE-C key rotation)
# ---------------------------------------------------------------------------

def test_replayed_update_object_encryption_is_a_clean_conflict(service):
    make_bucket(service)
    payload = b"rotate-me-once"
    assert signed(service, "PUT", "/sse-bucket/rotate.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    rotate = {**ssec_headers(KEY_B), **ssec_headers(KEY_A, prefix=COPY_PREFIX)}
    first = signed(service, "PUT", "/sse-bucket/rotate.bin?encryption", b"",
                   extra_headers=rotate)
    assert first.status_code == 200, first.text

    # The identical request again: the stored key is now KEY_B, so the
    # replayed source key no longer matches — a clean refusal, and the
    # object is exactly as the first rotation left it.
    replay = signed(service, "PUT", "/sse-bucket/rotate.bin?encryption", b"",
                    extra_headers=rotate)
    assert replay.status_code == 400, replay.text
    kept = signed(service, "GET", "/sse-bucket/rotate.bin",
                  extra_headers=ssec_headers(KEY_B))
    assert kept.status_code == 200 and kept.content == payload
    stale = signed(service, "GET", "/sse-bucket/rotate.bin",
                   extra_headers=ssec_headers(KEY_A))
    assert stale.status_code == 400

    # The state is not broken: rotating with the CURRENT key still works.
    back = {**ssec_headers(KEY_A), **ssec_headers(KEY_B, prefix=COPY_PREFIX)}
    again = signed(service, "PUT", "/sse-bucket/rotate.bin?encryption", b"",
                   extra_headers=back)
    assert again.status_code == 200, again.text
    final = signed(service, "GET", "/sse-bucket/rotate.bin",
                   extra_headers=ssec_headers(KEY_A))
    assert final.status_code == 200 and final.content == payload


# ---------------------------------------------------------------------------
# Multipart creates
# ---------------------------------------------------------------------------

def test_replayed_create_multipart_upload_opens_a_clean_second_session(
        service):
    """AWS semantics: every CreateMultipartUpload opens a new session.

    A client retry therefore produces a second, independent upload id —
    there is no idempotency token on this API. The contract pinned here
    is that nothing is torn: both sessions are listed and usable, the
    completed one publishes exactly one object, and the abandoned
    replay aborts cleanly without publishing anything.
    """
    setup(service)
    first_id = begin(service)
    replay_id = begin(service)
    assert first_id != replay_id, "a replay must not reuse the upload id"

    db, mpu = _fresh_mpu(service)
    try:
        active = {row[0] for row in mpu.list_uploads(
            "backup-bucket", service[1].access_key)[0]}
        assert {first_id, replay_id} <= active, (
            "a replayed CreateMultipartUpload lost a session")
    finally:
        db.close()

    # The first session completes and publishes exactly one object.
    etag = part(service, first_id, 1, b"first-session-payload")
    done = complete(service, first_id, [(1, etag)])
    assert done.status_code == 200, done.text
    assert signed(service, "GET",
                  "/backup-bucket/asset.bin").content == b"first-session-payload"

    # The abandoned replay aborts cleanly and stays dead.
    assert signed(service, "DELETE",
                  f"/backup-bucket/asset.bin?uploadId={replay_id}"
                  ).status_code == 204
    assert signed(service, "GET",
                  f"/backup-bucket/asset.bin?uploadId={replay_id}"
                  ).status_code == 404

    db, mpu = _fresh_mpu(service)
    try:
        active = {row[0] for row in mpu.list_uploads(
            "backup-bucket", service[1].access_key)[0]}
        assert replay_id not in active
        assert db.connection.execute(select(
            func.count()).select_from(part_rows).where(
            part_rows.c.upload_id == replay_id)).scalar_one() == 0
    finally:
        db.close()


def test_replayed_upload_part_replaces_the_slot(service):
    setup(service)
    uid = begin(service)
    payload = b"part-retry-payload" * 3

    first = part(service, uid, 1, payload)
    replay = signed(service, "PUT",
                    f"/backup-bucket/asset.bin?partNumber=1&uploadId={uid}",
                    payload)
    assert replay.status_code == 200, replay.text
    assert replay.headers["etag"] == first, (
        "an identical part replay changed the part ETag")

    db, mpu = _fresh_mpu(service)
    try:
        stored = mpu.list_parts_page(uid, "backup-bucket", "asset.bin",
                                      service[1].access_key)[0]
        assert [(row[0], row[2]) for row in stored] == [
            (1, first.strip('"'))], (
            "a part replay left more than one parts row")
    finally:
        db.close()

    # Last write wins: a different payload for the same slot replaces it.
    replaced = b"part-retry-payload-replaced" * 3
    second = part(service, uid, 1, replaced)
    assert second != first
    done = complete(service, uid, [(1, second)])
    assert done.status_code == 200, done.text
    assert signed(service, "GET",
                  "/backup-bucket/asset.bin").content == replaced


def test_replayed_upload_part_copy_replaces_the_slot(service):
    setup(service)
    source = b"p" * (5 * 1024 * 1024 + 7)
    assert signed(service, "PUT", "/backup-bucket/source.bin",
                  source).status_code == 200
    uid = begin(service, key="copied.bin")
    url = f"/backup-bucket/copied.bin?partNumber=1&uploadId={uid}"
    headers = {"x-amz-copy-source": "/backup-bucket/source.bin"}

    first = signed(service, "PUT", url, extra_headers=headers)
    assert first.status_code == 200, first.text
    etag = f'"{xml_text(first, "ETag")}"'
    replay = signed(service, "PUT", url, extra_headers=headers)
    assert replay.status_code == 200, replay.text
    assert f'"{xml_text(replay, "ETag")}"' == etag, (
        "an identical part-copy replay changed the part ETag")

    db, mpu = _fresh_mpu(service)
    try:
        stored = mpu.list_parts_page(uid, "backup-bucket", "copied.bin",
                                      service[1].access_key)[0]
        assert [(row[0], row[2]) for row in stored] == [
            (1, etag.strip('"'))], (
            "a part-copy replay left more than one parts row")
    finally:
        db.close()

    done = complete(service, uid, [(1, etag)], key="copied.bin")
    assert done.status_code == 200, done.text
    body = signed(service, "GET", "/backup-bucket/copied.bin")
    assert body.status_code == 200 and body.content == source


def _fresh_mpu(service):
    db, catalog = _fresh(service)
    return db, MultipartStore(catalog)


# ---------------------------------------------------------------------------
# RestoreObject
# ---------------------------------------------------------------------------

def test_replayed_restore_object_is_a_clean_conflict(service):
    assert signed(service, "PUT", "/retry-restore").status_code == 200
    put = signed(service, "PUT", "/retry-restore/cold.bin", b"cold-retry")
    assert put.status_code == 200
    version = put.headers["x-amz-version-id"]

    # Archive the version the way the tiering scheduler does.
    db, _catalog = _fresh(service)
    try:
        db.connection.execute(update(objects).where(
            objects.c.id == version).values(storage_class="ARCHIVE_ACCESS"))
        db.commit()
    finally:
        db.close()
    assert signed(service, "GET", "/retry-restore/cold.bin").status_code == 403

    request = b"<RestoreRequest><Days>1</Days></RestoreRequest>"
    first = signed(service, "POST", "/retry-restore/cold.bin?restore", request)
    assert first.status_code == 202, first.text

    # The same logical request again: a clean 409, never a second window.
    replay = signed(service, "POST", "/retry-restore/cold.bin?restore",
                    request)
    assert replay.status_code == 409, replay.text
    assert b"RestoreAlreadyInProgress" in replay.content

    # The original window is intact: the object reads through the gate.
    body = signed(service, "GET", "/retry-restore/cold.bin")
    assert body.status_code == 200 and body.content == b"cold-retry"
    db, _catalog = _fresh(service)
    try:
        assert db.connection.execute(select(
            objects.c.restore_until_ns).where(
            objects.c.id == version)).scalar_one() > time.time_ns(), (
            "the replayed restore reset or dropped the window")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# DeleteObjectAnnotation
# ---------------------------------------------------------------------------

def test_replayed_delete_object_annotation_stays_dead(service):
    assert signed(service, "PUT", "/annotations").status_code == 200
    assert signed(service, "PUT", "/annotations/doc.txt",
                  b"annotated-payload").status_code == 200
    name = quote("summary", safe="")
    assert signed(
        service, "PUT",
        f"/annotations/doc.txt?annotation&annotationName={name}",
        b"retry-me").status_code == 200

    path = f"/annotations/doc.txt?annotation&annotationName={name}"
    assert signed(service, "DELETE", path).status_code == 204
    assert signed(service, "DELETE", path).status_code == 204  # client retry

    db, catalog = _fresh(service)
    try:
        object_id = db.connection.execute(select(
            heads.c.object_id).where(
            heads.c.bucket == "annotations",
            heads.c.key_hash == _keyhash(catalog, "doc.txt"))).scalar_one()
        store = AnnotationStore(catalog)
        assert store.get(object_id, "summary") is None, (
            "a replayed annotation DELETE resurrected a row")
        assert store.count(object_id) == 0
    finally:
        db.close()
    assert signed(service, "GET", path).status_code == 404
