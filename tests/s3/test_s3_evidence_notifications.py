"""Per-operation evidence for the notification and logging family.

Fills four columns of the evidence matrix in
``docs/reference/s3-evidence.md`` for the six notification / logging
configuration operations:

* **auth-failure** — the ``?notificationConfiguration`` alias operations
  (``GetBucketNotificationConfiguration`` /
  ``PutBucketNotificationConfiguration``) refuse a validly signed
  credential without their own scope, like the primary selector already
  proves in ``tests/s3/test_s3_notifications.py``;
* **over-limit** — a body one byte past the enforced limit is refused
  for the notification PUT (both selectors) and the logging PUT, and a
  rejected write never replaces the stored configuration;
* **retry** — replaying a PUT keeps exactly one SQL row (last write
  wins) and a replayed disable stays disabled;
* **crash-restart** — the stored configuration is read back through a
  NEW ``Database``/store pair, exactly as a restarted process would;
* **race** — two concurrent replacements leave exactly one stored
  configuration, never a torn write.

Normal / malformed / auth-failure for the primary ``?notification`` and
``?logging`` selectors are proven in ``tests/s3/test_s3_notifications.py``;
the global unsigned sweep covers the missing-credential column for every
operation, and the global over-limit sweep covers the primary
``?notification`` selector.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.notifications import (
    MAX_LOGGING_XML_BYTES, MAX_NOTIFICATION_XML_BYTES, NotificationStore,
    logging_configs, notification_configs,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_notifications import (
    ALLOWED, logging_payload, notification_payload,
)

BUCKET = "notify-evidence"


def _scoped(service, name, permissions):
    db = service[3]()
    try:
        return S3CredentialStore(db, service[4]).create(name, permissions)
    finally:
        db.close()


def _rows(connection, table, bucket=BUCKET):
    db = connection()
    try:
        return db.connection.execute(select(
            func.count()).select_from(table).where(
            table.c.bucket == bucket)).scalar_one()
    finally:
        db.close()


def _fresh_store(service):
    db = service[3]()
    return db, NotificationStore(BucketCatalog(ManifestStore(db)),
                                  master_key=service[4])


def test_the_alias_selectors_enforce_their_own_permissions(service, monkeypatch):
    """Auth-failure column for the ``?notificationConfiguration`` pair."""
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    reader = _scoped(service, "alias-reader", ["s3:GetBucketNotification"])
    writer = _scoped(service, "alias-writer", ["s3:PutBucketNotification"])
    outsider = _scoped(service, "alias-outsider", ["s3:GetObject"])
    alias = f"/{BUCKET}?notificationConfiguration"
    body = notification_payload(events=("s3:ObjectCreated:Put",))

    denied_read = signed(service, "GET", alias,
                         access=outsider.access_key,
                         secret=outsider.secret_key)
    assert denied_read.status_code == 403, denied_read.text
    assert b"AccessDenied" in denied_read.content
    assert signed(service, "GET", alias, access=reader.access_key,
                  secret=reader.secret_key).status_code == 200

    denied_write = signed(service, "PUT", alias, body,
                          access=reader.access_key,
                          secret=reader.secret_key)
    assert denied_write.status_code == 403, denied_write.text
    assert b"AccessDenied" in denied_write.content
    assert signed(service, "PUT", alias, body,
                  access=writer.access_key,
                  secret=writer.secret_key).status_code == 200


@pytest.mark.parametrize("selector", ["notification",
                                      "notificationConfiguration"])
def test_an_over_limit_notification_body_is_refused_and_keeps_the_config(
        service, monkeypatch, selector):
    """Over-limit column, beyond the global sweep: the config survives."""
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    path = f"/{BUCKET}?{selector}"
    good = notification_payload(events=("s3:ObjectCreated:Put",))
    assert signed(service, "PUT", path, good).status_code == 200
    before = signed(service, "GET", path).content

    oversized = b"<NotificationConfiguration>" + \
        b" " * MAX_NOTIFICATION_XML_BYTES
    assert len(oversized) > MAX_NOTIFICATION_XML_BYTES
    reply = signed(service, "PUT", path, oversized)

    assert reply.status_code in (400, 413), reply.text
    assert signed(service, "GET", path).content == before, (
        "an over-limit body replaced the stored notification configuration")
    assert _rows(service[3], notification_configs) == 1


def test_an_over_limit_logging_body_is_refused_and_keeps_the_config(service, monkeypatch):
    """Over-limit column: the logging limit is proven per operation."""
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", "/log-target").status_code == 200
    path = f"/{BUCKET}?logging"
    assert signed(service, "PUT", path, logging_payload()).status_code == 200
    before = signed(service, "GET", path).content

    oversized = b"<BucketLoggingStatus>" + b" " * MAX_LOGGING_XML_BYTES
    assert len(oversized) > MAX_LOGGING_XML_BYTES
    reply = signed(service, "PUT", path, oversized)

    assert reply.status_code in (400, 413), reply.text
    assert signed(service, "GET", path).content == before, (
        "an over-limit body replaced the stored logging configuration")
    assert _rows(service[3], logging_configs) == 1


def test_replayed_puts_keep_one_row_and_last_write_wins(service, monkeypatch):
    """Retry column for PutBucketNotification(PutBucketNotificationConfiguration)."""
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    path = f"/{BUCKET}?notification"
    first = notification_payload(events=("s3:ObjectCreated:Put",),
                                 prefix="alpha/")
    second = notification_payload(events=("s3:ObjectRemoved:Delete",),
                                  prefix="beta/")

    assert signed(service, "PUT", path, first).status_code == 200
    assert signed(service, "PUT", path, first).status_code == 200  # retry
    assert _rows(service[3], notification_configs) == 1, (
        "a replayed notification PUT left more than one row")

    assert signed(service, "PUT", f"/{BUCKET}?notificationConfiguration",
                  second).status_code == 200  # the alias replaces too
    assert _rows(service[3], notification_configs) == 1
    stored = signed(service, "GET", path)
    assert b"beta/" in stored.content and b"alpha/" not in stored.content

    # A replayed disable stays disabled: the row is gone after the first
    # disable (the AWS empty-document form) and stays gone after the
    # replay; the read side reports the empty configuration, 200.
    import xml.etree.ElementTree as ET
    disable = ET.tostring(ET.Element("NotificationConfiguration"))
    assert signed(service, "PUT", path, disable).status_code == 200
    assert _rows(service[3], notification_configs) == 0
    assert signed(service, "PUT", path, disable).status_code == 200
    assert _rows(service[3], notification_configs) == 0
    assert list(ET.fromstring(
        signed(service, "GET", path).content)) == []


def test_replayed_logging_puts_keep_one_row(service):
    """Retry column for PutBucketLogging."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", "/log-target").status_code == 200
    path = f"/{BUCKET}?logging"
    body = logging_payload()
    assert signed(service, "PUT", path, body).status_code == 200
    assert signed(service, "PUT", path, body).status_code == 200  # retry
    assert _rows(service[3], logging_configs) == 1, (
        "a replayed logging PUT left more than one row")
    stored = signed(service, "GET", path)
    assert b"log-target" in stored.content


def test_configurations_survive_a_restart(service, monkeypatch):
    """Crash-restart column: a fresh Database/store reads the same state."""
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", "/log-target").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}?notification",
                  notification_payload(events=("s3:ObjectCreated:Put",),
                                       prefix="durable/")).status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}?logging",
                  logging_payload()).status_code == 200

    db, store = _fresh_store(service)
    try:
        config = store.get_config(BUCKET)
        assert config is not None, (
            "the notification configuration vanished after a restart")
        assert config["filter_prefix"] == "durable/"
        assert store.get_logging(BUCKET) == {
            "target_bucket": "log-target",
            "target_prefix": "logs/",
            "enabled": True,
        }
    finally:
        db.close()

    notification = signed(service, "GET", f"/{BUCKET}?notification")
    assert notification.status_code == 200 and b"durable/" in notification.content
    logging_read = signed(service, "GET", f"/{BUCKET}?logging")
    assert logging_read.status_code == 200
    assert b"log-target" in logging_read.content


def test_concurrent_notification_puts_leave_one_configuration(service, monkeypatch):
    """Race column: two writers, one bucket — one stored configuration."""
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}?notification",
                  notification_payload(events=("s3:ObjectCreated:Put",),
                                       prefix="seed/")).status_code == 200

    connection = service[3]
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    prefixes = ("race-a/", "race-b/")

    def writer(prefix: str) -> None:
        db = connection()
        try:
            store = NotificationStore(BucketCatalog(ManifestStore(db)),
                                      master_key=service[4])
            barrier.wait(timeout=10)
            store.replace_config(BUCKET, {
                "destination": f"{ALLOWED}/events",
                "events": ["s3:ObjectCreated:Put"],
                "filter_prefix": prefix,
                "filter_suffix": "",
                "enabled": True,
                "secret": None,
            })
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(prefix,))
               for prefix in prefixes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert not failures, failures

    assert _rows(service[3], notification_configs) == 1, (
        "concurrent notification PUTs left more than one row")
    stored = signed(service, "GET", f"/{BUCKET}?notification")
    assert (b"race-a/" in stored.content) != (
        b"race-b/" in stored.content), (
        "the stored configuration is neither writer's, or both leaked in")
