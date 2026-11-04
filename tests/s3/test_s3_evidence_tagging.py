"""Per-operation evidence for the bucket and object tagging family.

Fills three columns of the evidence matrix in
``docs/reference/s3-evidence.md`` for the six tagging operations
(Get/Put/Delete for bucket tags and for object tags):

* **retry** — replaying a PUT keeps exactly one tag set (last write
  wins, row-for-row), and a replayed DELETE stays 204 with an empty
  set and no resurrected rows;
* **crash-restart** — stored tags are read back through a NEW
  ``Database``/store pair, exactly as a restarted process would open
  them;
* **race** — two concurrent replacements of the same tag set leave
  exactly one winner's tags, never a merge of both and never duplicate
  rows.

Normal / auth-failure / malformed / over-limit for this family are
proven in ``tests/s3/test_s3_tagging.py``; the global unsigned sweep
covers the missing-credential column for every operation.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select

from teledrive.s3.tagging import (
    BucketTagStore, ObjectTagStore, bucket_tags, object_tags,
)
from teledrive.storage.catalog import BucketCatalog, heads
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_tagging import create, extract_tags, tag_xml

BUCKET = "backup-bucket"
KEY = "file.bin"
PATH = f"/{BUCKET}/{KEY}?tagging"
BUCKET_PATH = f"/{BUCKET}?tagging"


def _object_id(connection):
    db = connection()
    try:
        return db.connection.execute(select(heads.c.object_id).where(
            heads.c.bucket == BUCKET,
            heads.c.key_hash == BucketCatalog(ManifestStore(db))._keyhash(
                KEY))).scalar_one()
    finally:
        db.close()


def _bucket_tag_rows(connection, bucket=BUCKET):
    db = connection()
    try:
        return db.connection.execute(select(
            func.count()).select_from(bucket_tags).where(
            bucket_tags.c.bucket == bucket)).scalar_one()
    finally:
        db.close()


def test_replayed_bucket_tag_puts_keep_one_row_and_delete_stays_dead(service):
    """Retry column for PutBucketTagging / DeleteBucketTagging."""
    create(service)
    tags = [("env", "evidence"), ("suite", "matrix")]
    assert signed(service, "PUT", BUCKET_PATH,
                  tag_xml(tags)).status_code == 200
    assert signed(service, "PUT", BUCKET_PATH,
                  tag_xml(tags)).status_code == 200  # client retry
    assert _bucket_tag_rows(service[3]) == len(tags), (
        "a replayed bucket-tag PUT changed the stored row count")

    replaced = [("env", "replaced")]
    assert signed(service, "PUT", BUCKET_PATH,
                  tag_xml(replaced)).status_code == 200
    assert _bucket_tag_rows(service[3]) == len(replaced), (
        "a replacing bucket-tag PUT left rows from the previous set")

    assert signed(service, "DELETE", BUCKET_PATH).status_code == 204
    assert signed(service, "DELETE", BUCKET_PATH).status_code == 204
    assert _bucket_tag_rows(service[3]) == 0, (
        "a replayed bucket-tag DELETE resurrected rows")
    # AWS answers 404 NoSuchTagSet for a deleted bucket tag set.
    cleared = signed(service, "GET", BUCKET_PATH)
    assert cleared.status_code == 404
    assert b"NoSuchTagSet" in cleared.content


def test_replayed_object_tag_puts_keep_one_row_and_delete_stays_dead(service):
    """Retry column for PutObjectTagging / DeleteObjectTagging."""
    create(service)
    object_id = _object_id(service[3])

    def rows():
        db = service[3]()
        try:
            return db.connection.execute(select(
                func.count()).select_from(object_tags).where(
                object_tags.c.object_id == object_id)).scalar_one()
        finally:
            db.close()

    tags = [("env", "evidence")]
    assert signed(service, "PUT", PATH, tag_xml(tags)).status_code == 200
    assert signed(service, "PUT", PATH, tag_xml(tags)).status_code == 200
    assert rows() == len(tags), "a replayed object-tag PUT changed the rows"

    replaced = [("env", "replaced"), ("extra", "row")]
    assert signed(service, "PUT", PATH, tag_xml(replaced)).status_code == 200
    assert rows() == len(replaced), (
        "a replacing object-tag PUT left rows from the previous set")

    assert signed(service, "DELETE", PATH).status_code == 204
    assert signed(service, "DELETE", PATH).status_code == 204
    assert rows() == 0, "a replayed object-tag DELETE resurrected rows"


def test_bucket_and_object_tags_survive_a_restart(service):
    """Crash-restart column: a fresh Database/store reads the same tags."""
    create(service)
    bucket_tags_written = [("env", "evidence")]
    object_tags_written = [("layer", "object")]
    assert signed(service, "PUT", BUCKET_PATH,
                  tag_xml(bucket_tags_written)).status_code == 200
    assert signed(service, "PUT", PATH,
                  tag_xml(object_tags_written)).status_code == 200
    object_id = _object_id(service[3])

    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        assert BucketTagStore(catalog).get(BUCKET) == bucket_tags_written, (
            "the bucket tags vanished after a restart")
        assert ObjectTagStore(catalog).get(object_id) == object_tags_written, (
            "the object tags vanished after a restart")
    finally:
        db.close()

    # The gateway opens a new connection per request; both reads agree.
    assert b"evidence" in signed(service, "GET", BUCKET_PATH).content
    assert b"object" in signed(service, "GET", PATH).content


def test_concurrent_bucket_tag_replacements_leave_one_set(service):
    """Race column: two writers, one bucket — one winner's tag set."""
    create(service)
    assert signed(service, "PUT", BUCKET_PATH,
                  tag_xml([("seed", "yes")])).status_code == 200

    connection = service[3]
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    writers = (
        [("writer", "a"), ("shared", "a")],
        [("writer", "b"), ("shared", "b")],
    )

    def writer(tags) -> None:
        db = connection()
        try:
            store = BucketTagStore(BucketCatalog(ManifestStore(db)))
            barrier.wait(timeout=10)
            store.replace(BUCKET, tags)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(tags,))
               for tags in writers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert not failures, failures

    # Exactly one writer's set is stored — never a merge, never duplicates.
    db = connection()
    try:
        stored = BucketTagStore(BucketCatalog(ManifestStore(db))).get(BUCKET)
    finally:
        db.close()
    assert sorted(stored) in [sorted(w) for w in writers], (
        f"the stored bucket tags are neither writer's set: {stored}")
    assert _bucket_tag_rows(connection) == len(stored)
    assert stored[0][1] == stored[1][1], (
        "tags from both writers leaked into one set")


def test_concurrent_object_tag_replacements_leave_one_set(service):
    """Race column: two writers, one object version — one winner's set."""
    create(service)
    object_id = _object_id(service[3])
    writers = (
        [("writer", "a")],
        [("writer", "b")],
    )
    connection = service[3]
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []

    def writer(tags) -> None:
        db = connection()
        try:
            store = ObjectTagStore(BucketCatalog(ManifestStore(db)))
            barrier.wait(timeout=10)
            store.replace_published(BUCKET, KEY, object_id, tags)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(tags,))
               for tags in writers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    # The head-row CAS fence may answer one writer with a clean 409
    # OperationAborted; that is the designed contract, not a failure.
    failures = [exc for exc in failures
                if not (isinstance(exc, Exception)
                        and "OperationAborted" in str(exc))]
    assert not failures, failures

    db = connection()
    try:
        stored = ObjectTagStore(BucketCatalog(ManifestStore(db))).get(
            object_id)
    finally:
        db.close()
    assert stored in writers, (
        f"the stored object tags are neither writer's set: {stored}")
