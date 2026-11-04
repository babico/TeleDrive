"""Per-operation evidence for the bucket website family.

Fills three columns of the evidence matrix in
``docs/reference/s3-evidence.md`` for the three website operations
(Get/Put/DeleteBucketWebsite):

* **retry** — replaying a PUT keeps exactly one SQL row (last write
  wins), and a replayed DELETE stays 204 with no resurrected row;
* **crash-restart** — the stored configuration is read back through a
  NEW ``Database``/store pair, exactly as a restarted process would
  open it;
* **race** — two concurrent replacements leave exactly one stored
  configuration, never two rows and never a torn write.

Normal / auth-failure / malformed / over-limit for this family are
proven in ``tests/s3/test_s3_website.py``; the global unsigned sweep
covers the missing-credential column for every operation.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select

from teledrive.s3.website import WebsiteConfigStore, website_configs
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_website import create_bucket, website_xml_body

BUCKET = "site-evidence"
PATH = f"/{BUCKET}?website"


def _rows(connection, bucket=BUCKET):
    db = connection()
    try:
        return db.connection.execute(select(
            func.count()).select_from(website_configs).where(
            website_configs.c.bucket == bucket)).scalar_one()
    finally:
        db.close()


def test_replayed_website_puts_keep_one_row_and_delete_stays_dead(service):
    """Retry column for PutBucketWebsite / DeleteBucketWebsite."""
    create_bucket(service, BUCKET)
    first = website_xml_body("index.html", "404.html")
    assert signed(service, "PUT", PATH, first).status_code == 200
    assert signed(service, "PUT", PATH, first).status_code == 200  # retry
    assert _rows(service[3]) == 1, (
        "a replayed website PUT left more than one row")

    replaced = website_xml_body("home.html")
    assert signed(service, "PUT", PATH, replaced).status_code == 200
    assert _rows(service[3]) == 1
    stored = signed(service, "GET", PATH)
    assert stored.status_code == 200
    assert b"home.html" in stored.content
    assert b"404.html" not in stored.content

    assert signed(service, "DELETE", PATH).status_code == 204
    assert signed(service, "DELETE", PATH).status_code == 204
    assert _rows(service[3]) == 0, "a replayed website DELETE resurrected a row"
    assert signed(service, "GET", PATH).status_code == 404


def test_website_configuration_survives_a_restart(service):
    """Crash-restart column: a fresh Database/store reads the same config."""
    create_bucket(service, BUCKET)
    assert signed(service, "PUT", PATH,
                  website_xml_body("index.html", "err.html")).status_code == 200

    db = service[3]()
    try:
        stored = WebsiteConfigStore(BucketCatalog(ManifestStore(db))).get(
            BUCKET)
        assert stored == {"index_document": "index.html",
                          "error_document": "err.html",
                          "enabled": True}, (
            "the website configuration vanished after a restart")
    finally:
        db.close()

    reply = signed(service, "GET", PATH)
    assert reply.status_code == 200
    assert b"err.html" in reply.content


def test_concurrent_website_puts_leave_one_configuration(service):
    """Race column: two writers, one bucket — one stored configuration."""
    create_bucket(service, BUCKET)
    assert signed(service, "PUT", PATH,
                  website_xml_body("seed.html")).status_code == 200

    connection = service[3]
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    indexes = ("writer-a.html", "writer-b.html")

    def writer(index: str) -> None:
        db = connection()
        try:
            store = WebsiteConfigStore(BucketCatalog(ManifestStore(db)))
            barrier.wait(timeout=10)
            store.replace(BUCKET, {"index_document": index,
                                   "error_document": None,
                                   "enabled": True})
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(index,))
               for index in indexes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert not failures, failures

    assert _rows(service[3]) == 1, (
        "concurrent website PUTs left more than one row")
    stored = signed(service, "GET", PATH)
    assert stored.status_code == 200
    assert (b"writer-a.html" in stored.content) != (
        b"writer-b.html" in stored.content), (
        "the stored configuration is neither writer's, or both leaked in")
