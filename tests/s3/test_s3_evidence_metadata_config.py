"""Per-operation evidence for the S3 Metadata configuration family.

Fills four columns of the evidence matrix in
``docs/reference/s3-evidence.md`` for the nine metadata configuration
operations (V2 ``?metadataConfiguration`` and V1 ``?metadataTable``
create/get/delete, plus the three ``?metadata*Table`` update selectors):

* **auth-failure** — a validly signed credential WITHOUT the operation's
  own permission is refused 403 ``AccessDenied`` for every one of the
  nine operations, while a credential holding the permission is not;
* **retry** — replaying a create is a clean 409 with still exactly one
  SQL row, replaying an update keeps one row (last write wins), and a
  replayed delete stays dead;
* **crash-restart** — the configuration and its journal rows are read
  back through a NEW ``Database``/store pair, exactly as a restarted
  process would open them;
* **race** — two concurrent journal-retention updates leave exactly one
  configuration row holding exactly one of the two written values.

Normal / malformed / over-limit for this family are proven in
``tests/s3/test_s3_metadata_journal.py`` (which also proves the
auth-failure denial for ``CreateBucketMetadataConfiguration`` and
``UpdateBucketMetadataJournalTableConfiguration``); the global unsigned
sweep covers the missing-credential column for every operation.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.metadata_journal import (
    MetadataConfigurationStore, MetadataJournalStore, metadata_configs,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_metadata_journal import (
    annotation_update, create_body, inventory_update, journal_update,
    make_bucket, table_body,
)

BUCKET = "meta-evidence"

# (method, selector, the permission the gateway requires).
OPERATIONS = [
    ("POST", "metadataConfiguration",
     "s3:CreateBucketMetadataTableConfiguration"),
    ("GET", "metadataConfiguration",
     "s3:GetBucketMetadataTableConfiguration"),
    ("DELETE", "metadataConfiguration",
     "s3:DeleteBucketMetadataTableConfiguration"),
    ("POST", "metadataTable", "s3:CreateBucketMetadataTableConfiguration"),
    ("GET", "metadataTable", "s3:GetBucketMetadataTableConfiguration"),
    ("DELETE", "metadataTable", "s3:DeleteBucketMetadataTableConfiguration"),
    ("PUT", "metadataJournalTable",
     "s3:UpdateBucketMetadataJournalTableConfiguration"),
    ("PUT", "metadataInventoryTable",
     "s3:UpdateBucketMetadataInventoryTableConfiguration"),
    ("PUT", "metadataAnnotationTable",
     "s3:UpdateBucketMetadataAnnotationTableConfiguration"),
]

UPDATE_BODIES = {
    "metadataJournalTable": lambda: journal_update(14),
    "metadataInventoryTable": lambda: inventory_update("ENABLED"),
    "metadataAnnotationTable": lambda: annotation_update("ENABLED"),
}


def _scoped(service, name, permissions):
    db = service[3]()
    try:
        return S3CredentialStore(db, service[4]).create(name, permissions)
    finally:
        db.close()


def _request(service, method, selector, credential, body=b""):
    return signed(service, method, f"/{BUCKET}?{selector}", body,
                  access=credential.access_key,
                  secret=credential.secret_key)


def _config_rows(connection, bucket=BUCKET):
    db = connection()
    try:
        return db.connection.execute(select(
            func.count()).select_from(metadata_configs).where(
            metadata_configs.c.bucket == bucket)).scalar_one()
    finally:
        db.close()


def _fresh_store(connection):
    db = connection()
    return db, MetadataConfigurationStore(BucketCatalog(ManifestStore(db)))


@pytest.mark.parametrize("method,selector,permission", OPERATIONS,
                         ids=[op[1] + ":" + op[0] for op in OPERATIONS])
def test_each_operation_denies_a_credential_without_its_permission(
        service, method, selector, permission):
    """Every one of the nine operations refuses a missing scope."""
    make_bucket(service, BUCKET)
    # The update operations mutate an existing configuration; the others
    # are exercised against a bucket with no configuration yet.
    if selector in UPDATE_BODIES:
        assert signed(service, "POST", f"/{BUCKET}?metadataConfiguration",
                      create_body()).status_code == 200
    body = UPDATE_BODIES[selector]() if selector in UPDATE_BODIES else (
        create_body() if method == "POST" else b"")

    outsider = _scoped(service, "metadata-outsider", ["s3:GetObject"])
    denied = _request(service, method, selector, outsider, body)
    assert denied.status_code == 403, denied.text
    assert b"AccessDenied" in denied.content
    if selector in UPDATE_BODIES:
        # A denied update must not have changed the stored configuration.
        stored = signed(service, "GET", f"/{BUCKET}?metadataConfiguration")
        assert b"DISABLED" in stored.content

    holder = _scoped(service, "metadata-holder", [permission])
    allowed = _request(service, method, selector, holder, body)
    assert allowed.status_code != 403, allowed.text


@pytest.mark.parametrize("selector", ["metadataConfiguration", "metadataTable"])
def test_replayed_create_is_a_clean_conflict_with_one_row(service, selector):
    """Retry column: a create replay is 409, never a second row."""
    make_bucket(service, BUCKET)
    body = (create_body() if selector == "metadataConfiguration"
            else table_body("retry-table"))
    first = signed(service, "POST", f"/{BUCKET}?{selector}", body)
    assert first.status_code == 200, first.text
    replay = signed(service, "POST", f"/{BUCKET}?{selector}", body)
    assert replay.status_code == 409, replay.text
    assert _config_rows(service[3]) == 1, (
        "a replayed create left more than one configuration row")


def test_replayed_update_keeps_one_row_and_last_write_wins(service):
    """Retry column: the same journal update twice is still one row."""
    make_bucket(service, BUCKET)
    assert signed(service, "POST", f"/{BUCKET}?metadataConfiguration",
                  create_body()).status_code == 200
    for _ in range(2):
        reply = signed(service, "PUT", f"/{BUCKET}?metadataJournalTable",
                       journal_update(30))
        assert reply.status_code == 200, reply.text
    assert _config_rows(service[3]) == 1
    db, store = _fresh_store(service[3])
    try:
        assert store.get(BUCKET)["retention_days"] == 30
    finally:
        db.close()


def test_replayed_delete_stays_dead(service):
    """Retry column: a second delete cannot resurrect the configuration."""
    make_bucket(service, BUCKET)
    assert signed(service, "POST", f"/{BUCKET}?metadataConfiguration",
                  create_body()).status_code == 200
    path = f"/{BUCKET}?metadataConfiguration"
    assert signed(service, "DELETE", path).status_code == 204
    replay = signed(service, "DELETE", path)
    assert replay.status_code == 204, replay.text
    assert _config_rows(service[3]) == 0
    assert signed(service, "GET", path).status_code == 404


def test_configuration_and_journal_survive_a_restart(service):
    """Crash-restart column: a fresh Database/store reads the same state."""
    make_bucket(service, BUCKET)
    assert signed(service, "POST", f"/{BUCKET}?metadataConfiguration",
                  create_body(days=14)).status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/journaled.bin",
                  b"evidence-bytes").status_code == 200

    db, store = _fresh_store(service[3])
    try:
        config = store.get(BUCKET)
        assert config is not None, "the configuration vanished after a restart"
        assert config["retention_days"] == 14
        records = MetadataJournalStore(
            BucketCatalog(ManifestStore(db))).stats(BUCKET)
        assert records["count"] >= 1, (
            "the journal rows vanished after a restart")
    finally:
        db.close()

    reply = signed(service, "GET", f"/{BUCKET}?metadataConfiguration")
    assert reply.status_code == 200
    assert b"14" in reply.content


def test_concurrent_journal_updates_leave_one_consistent_row(service):
    """Race column: two writers, one bucket — one row, one written value."""
    make_bucket(service, BUCKET)
    assert signed(service, "POST", f"/{BUCKET}?metadataConfiguration",
                  create_body()).status_code == 200

    connection = service[3]
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    days_values = (7, 90)

    def writer(days: int) -> None:
        db = connection()
        try:
            store = MetadataConfigurationStore(
                BucketCatalog(ManifestStore(db)))
            barrier.wait(timeout=10)
            store.update_journal(BUCKET, days)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(days,))
               for days in days_values]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert not failures, failures

    assert _config_rows(service[3]) == 1, (
        "concurrent journal updates left more than one configuration row")
    db, store = _fresh_store(service[3])
    try:
        assert store.get(BUCKET)["retention_days"] in days_values
    finally:
        db.close()
