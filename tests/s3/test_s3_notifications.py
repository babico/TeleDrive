"""Phase F: metadata-backed bucket notifications, outbox delivery and logging.

Real SQLite, AWS SigV4 and the deterministic fake Telegram transport. Webhook
HTTP is never contacted: a fake sender exercises the retry state machine and
verifies the HMAC contract locally.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from urllib.parse import quote
from xml.etree import ElementTree as ET

import pytest

from starlette.datastructures import QueryParams

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.notifications import (
    MAX_ATTEMPTS, NotificationDelivery, NotificationStore,
    destination_is_approved, logging_xml, notification_xml,
    parse_logging_xml, parse_notification_xml,
)
from teledrive.s3.route_guard import S3QueryError, validate_s3_query
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
ALLOWED = "https://hooks.example.com"


def notification_payload(*, endpoint=f"{ALLOWED}/events",
                         events=("s3:ObjectCreated:*",), prefix=None,
                         suffix=None, secret=None):
    root = ET.Element("NotificationConfiguration")
    node = ET.SubElement(root, "WebhookConfiguration")
    ET.SubElement(node, "Endpoint").text = endpoint
    for event in events:
        ET.SubElement(node, "Event").text = event
    if prefix is not None or suffix is not None:
        s3_key = ET.SubElement(ET.SubElement(node, "Filter"), "S3Key")
        for name, value in (("prefix", prefix), ("suffix", suffix)):
            if value is not None:
                rule = ET.SubElement(s3_key, "FilterRule")
                ET.SubElement(rule, "Name").text = name
                ET.SubElement(rule, "Value").text = value
    if secret is not None:
        ET.SubElement(node, "Secret").text = secret
    return ET.tostring(root)


def logging_payload(target="log-target", prefix="logs/", *,
                    grants=False):
    root = ET.Element("BucketLoggingStatus")
    enabled = ET.SubElement(root, "LoggingEnabled")
    ET.SubElement(enabled, "TargetBucket").text = target
    ET.SubElement(enabled, "TargetPrefix").text = prefix
    if grants:
        ET.SubElement(enabled, "TargetGrants")
    return ET.tostring(root)


def create(service, name="notify-bucket"):
    assert signed(service, "PUT", "/" + name).status_code == 200


def begin(svc, key="asset.bin"):
    response = signed(svc, "POST", "/notify-bucket/"
                      + quote(key, safe="/") + "?uploads")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    return root.findtext(NS + "UploadId")


def put_part(svc, upload_id, number, payload, key="asset.bin"):
    response = signed(
        svc, "PUT",
        f"/notify-bucket/{key}?partNumber={number}&uploadId={upload_id}",
        payload,
    )
    assert response.status_code == 200, response.text
    return response.headers["etag"]


def complete(svc, upload_id, selection, key="asset.bin"):
    root = ET.Element("CompleteMultipartUpload")
    for number, etag in selection:
        node = ET.SubElement(root, "Part")
        ET.SubElement(node, "PartNumber").text = str(number)
        ET.SubElement(node, "ETag").text = etag
    return signed(svc, "POST",
                  f"/notify-bucket/{key}?uploadId={upload_id}",
                  ET.tostring(root))


def store_for(service):
    db = service[3]()
    catalog = BucketCatalog(ManifestStore(db))
    return db, catalog, NotificationStore(catalog, master_key=service[4])


def test_notification_config_round_trip_and_secret_never_returned(
    service, monkeypatch,
):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    path = "/notify-bucket?notification"
    assert signed(service, "GET", path).status_code == 200
    body = notification_payload(
        events=("s3:ObjectCreated:Put", "s3:ObjectRemoved:*"),
        prefix="in/", suffix=".bin", secret="a" * 32,
    )
    assert signed(service, "PUT", path, body).status_code == 200
    response = signed(service, "GET", path)
    assert response.status_code == 200
    root = ET.fromstring(response.content)
    node = root.find(NS + "WebhookConfiguration")
    assert node.findtext(NS + "Endpoint") == f"{ALLOWED}/events"
    assert [event.text for event in node.findall(NS + "Event")] == [
        "s3:ObjectCreated:Put", "s3:ObjectRemoved:*",
    ]
    assert b"Secret" not in response.content
    assert node.findtext(
        f"{NS}Filter/{NS}S3Key/{NS}FilterRule/{NS}Value") == "in/"

    db, _, store = store_for(service)
    try:
        config = store.get_config("notify-bucket")
        assert config["filter_prefix"] == "in/"
        assert config["filter_suffix"] == ".bin"
        assert config["secret"] is None
        raw = db.connection.exec_driver_sql(
            "SELECT encrypted_secret FROM storage_notification_configs"
        ).scalar_one()
        assert raw and raw != "a" * 32
    finally:
        db.close()

    # `notificationConfiguration` is the same AWS operation alias.
    alias = signed(service, "GET", "/notify-bucket?notificationConfiguration")
    assert alias.status_code == 200
    assert b"WebhookConfiguration" in alias.content

    # An empty document is the AWS way to disable notifications.
    empty = ET.tostring(ET.Element("NotificationConfiguration"))
    assert signed(service, "PUT", path, empty).status_code == 200
    assert list(ET.fromstring(signed(service, "GET", path).content)) == []


@pytest.mark.parametrize("payload,status", [
    (b"<NotificationConfiguration><WebhookConfiguration>",
     400),
    (b'<!DOCTYPE x [<!ENTITY a "x">]><NotificationConfiguration>&a;'
     b"</NotificationConfiguration>", 400),
    (b"<WrongRoot/>", 400),
    (notification_payload(events=("s3:ObjectCreated:Put",)).replace(
        b"Endpoint", b"Unknown"), 400),
    (notification_payload(events=("s3:ObjectCreated:Put",
                                  "s3:ObjectCreated:Put")), 400),
    (notification_payload(events=("s3:ObjectRemoved:Restore",)), 400),
    (notification_payload(endpoint="ftp://hooks.example.com/events"), 400),
    (notification_payload(secret="short"), 400),
    (b"<NotificationConfiguration><TopicConfiguration/></"
     b"NotificationConfiguration>", 501),
    (b"<NotificationConfiguration><QueueConfiguration/></"
     b"NotificationConfiguration>", 501),
])
def test_strict_notification_xml_fails_closed_and_preserves_state(
    service, monkeypatch, payload, status,
):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    path = "/notify-bucket?notification"
    good = notification_payload(events=("s3:ObjectCreated:Put",))
    assert signed(service, "PUT", path, good).status_code == 200
    reply = signed(service, "PUT", path, payload)
    assert reply.status_code == status, reply.text
    assert b"WebhookConfiguration" in signed(service, "GET", path).content
    assert service[2].uploads == 0


def test_notification_destination_must_be_owner_approved(service, monkeypatch):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    path = "/notify-bucket?notification"
    denied = signed(service, "PUT", path, notification_payload(
        endpoint="https://evil.example.net/events"))
    assert denied.status_code == 403, denied.text
    assert b"AccessDenied" in denied.content
    assert list(ET.fromstring(signed(service, "GET", path).content)) == []
    # An allowlisted path prefix is narrower than the whole origin.
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS",
                       ALLOWED + "/approved")
    assert signed(service, "PUT", path, notification_payload(
        endpoint=f"{ALLOWED}/approved/events")).status_code == 200
    assert signed(service, "PUT", path, notification_payload(
        endpoint=f"{ALLOWED}/other/events")).status_code == 403
    assert destination_is_approved(f"{ALLOWED}/approved/events",
                                   (ALLOWED + "/approved",))
    assert not destination_is_approved(f"{ALLOWED}/approvedness",
                                       (ALLOWED + "/approved",))


def test_event_filtering_and_outbox_rows_for_every_covered_mutation(
    service, monkeypatch,
):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    path = "/notify-bucket?notification"
    body = notification_payload(
        events=("s3:ObjectCreated:*", "s3:ObjectRemoved:*"),
        prefix="in/",
    )
    assert signed(service, "PUT", path, body).status_code == 200

    assert signed(service, "PUT", "/notify-bucket/in/put.bin",
                  b"payload").status_code == 200
    assert signed(service, "PUT", "/notify-bucket/out/ignored.bin",
                  b"ignored").status_code == 200
    copy = signed(service, "PUT", "/notify-bucket/in/copy.bin", extra_headers={
        "x-amz-copy-source": "/notify-bucket/in/put.bin",
    })
    assert copy.status_code == 200, copy.text

    upload_id = begin(service, "in/multipart.bin")
    etag = put_part(service, upload_id, 1, os.urandom(5 * 1024 * 1024),
                    "in/multipart.bin")
    done = complete(service, upload_id, [(1, etag)], "in/multipart.bin")
    assert done.status_code == 200, done.text

    marker = signed(service, "DELETE", "/notify-bucket/in/put.bin")
    assert marker.status_code == 204
    version = signed(service, "PUT", "/notify-bucket/in/versioned.bin",
                     b"versioned").headers["x-amz-version-id"]
    assert signed(
        service, "DELETE",
        f"/notify-bucket/in/versioned.bin?versionId={version}",
    ).status_code == 204

    aborted = begin(service, "in/aborted.bin")
    assert signed(
        service, "DELETE",
        f"/notify-bucket/in/aborted.bin?uploadId={aborted}",
    ).status_code == 204

    db, _, store = store_for(service)
    try:
        rows = store.outbox_rows("notify-bucket")
    finally:
        db.close()
    events = [row["event_type"] for row in rows]
    assert events == [
        "s3:ObjectCreated:Put",
        "s3:ObjectCreated:Copy",
        "s3:ObjectCreated:CompleteMultipartUpload",
        "s3:ObjectRemoved:DeleteMarkerCreated",
        "s3:ObjectCreated:Put",
        "s3:ObjectRemoved:Delete",
        "s3:ObjectRemoved:Delete",
    ]
    assert all(row["object_key"].startswith("in/") for row in rows)
    assert rows[0]["version_id"]


def test_partial_event_subscription_skips_unmatched_mutations(
    service, monkeypatch,
):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    body = notification_payload(events=("s3:ObjectCreated:Copy",))
    assert signed(service, "PUT", "/notify-bucket?notification",
                  body).status_code == 200
    assert signed(service, "PUT", "/notify-bucket/plain.bin",
                  b"plain").status_code == 200
    assert signed(service, "PUT", "/notify-bucket/from.bin",
                  b"source").status_code == 200
    db, _, store = store_for(service)
    try:
        assert store.outbox_rows("notify-bucket") == []
    finally:
        db.close()
    copied = signed(service, "PUT", "/notify-bucket/copied.bin", extra_headers={
        "x-amz-copy-source": "/notify-bucket/from.bin",
    })
    assert copied.status_code == 200
    db, _, store = store_for(service)
    try:
        rows = store.outbox_rows("notify-bucket")
    finally:
        db.close()
    assert [row["event_type"] for row in rows] == ["s3:ObjectCreated:Copy"]


class FakeSender:
    def __init__(self, failures=0):
        self.failures = failures
        self.calls = []

    def send(self, destination, body, headers):
        self.calls.append((destination, body, dict(headers)))
        if self.failures:
            self.failures -= 1
            raise OSError("simulated webhook outage")


def _enqueue(store, event="s3:ObjectCreated:Put", key="in/event.bin", *,
             now_ns=None):
    from teledrive.s3.notifications import enqueue_event_safely
    assert enqueue_event_safely(
        store.db.connection, event_type=event, bucket="notify-bucket",
        object_key=key, version_id="version-1", now_ns=now_ns,
    ) == 1
    store.db.commit()


def test_retry_backoff_signature_and_exhaustion(service, monkeypatch):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    db, catalog, store = store_for(service)
    sender = FakeSender(failures=1)
    try:
        store.replace_config("notify-bucket", {
            "id": "", "destination": f"{ALLOWED}/events",
            "events": ["s3:ObjectCreated:*"], "filter_prefix": "",
            "filter_suffix": "", "enabled": True, "secret": "s" * 32,
        })
        now = time.time_ns()
        _enqueue(store, now_ns=now)
        delivery = NotificationDelivery(
            catalog, master_key=service[4], sender=sender)
        first = delivery.deliver_due(now_ns=now)
        assert (first.claimed, first.retried, first.delivered) == (1, 1, 0)
        row = store.outbox_rows("notify-bucket")[0]
        assert row["attempts"] == 1
        assert row["delivered_ns"] is None
        assert row["next_retry_ns"] > now
        # Not due yet: no second HTTP attempt.
        assert delivery.deliver_due(now_ns=now).claimed == 0
        second = delivery.deliver_due(now_ns=row["next_retry_ns"] + 1)
        assert (second.claimed, second.delivered) == (1, 1)
        row = store.outbox_rows("notify-bucket")[0]
        assert row["delivered_ns"] is not None and row["last_error"] is None

        destination, body, headers = sender.calls[-1]
        assert destination == f"{ALLOWED}/events"
        timestamp = headers["X-TeleDrive-Timestamp"]
        expected = hmac.new(
            ("s" * 32).encode(), timestamp.encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        assert headers["X-TeleDrive-Signature"] == "sha256=" + expected
        assert headers["X-TeleDrive-Event"] == "s3:ObjectCreated:Put"

        # Bounded attempts: a permanently failing destination terminates.
        _enqueue(store, key="in/never.bin", now_ns=now)
        always = FakeSender(failures=1000)
        exhausted = NotificationDelivery(
            catalog, master_key=service[4], sender=always)
        horizon = now
        result = None
        for _ in range(MAX_ATTEMPTS + 2):
            result = exhausted.deliver_due(now_ns=horizon)
            if result.claimed == 0:
                break
            horizon += 2 * 3600 * 1_000_000_000
        assert result is not None
        rows = [row for row in store.outbox_rows("notify-bucket")
                if row["object_key"] == "in/never.bin"]
        assert rows[0]["attempts"] == MAX_ATTEMPTS
        assert rows[0]["delivered_ns"] is not None
        assert "abandoned" in rows[0]["last_error"]
        assert len(always.calls) == MAX_ATTEMPTS
    finally:
        db.close()


def test_logging_config_round_trip_and_validation(service):
    create(service)
    assert signed(service, "PUT", "/log-target").status_code == 200
    path = "/notify-bucket?logging"
    empty = signed(service, "GET", path)
    assert empty.status_code == 200
    assert list(ET.fromstring(empty.content)) == []

    assert signed(service, "PUT", path, logging_payload()).status_code == 200
    response = signed(service, "GET", path)
    assert response.status_code == 200
    root = ET.fromstring(response.content)
    assert root.findtext(f"{NS}LoggingEnabled/{NS}TargetBucket") == "log-target"
    assert root.findtext(f"{NS}LoggingEnabled/{NS}TargetPrefix") == "logs/"
    db, _, store = store_for(service)
    try:
        assert store.get_logging("notify-bucket") == {
            "target_bucket": "log-target", "target_prefix": "logs/",
            "enabled": True,
        }
    finally:
        db.close()

    missing = signed(service, "PUT", path, logging_payload("absent-bucket"))
    assert missing.status_code == 400
    assert b"InvalidTargetBucketForLogging" in missing.content
    assert signed(service, "PUT", path, logging_payload(
        grants=True)).status_code == 501
    # A rejected write never replaces the real stored configuration.
    assert signed(service, "GET", path).content == response.content

    disable = ET.tostring(ET.Element("BucketLoggingStatus"))
    assert signed(service, "PUT", path, disable).status_code == 200
    assert list(ET.fromstring(signed(service, "GET", path).content)) == []


def test_notification_and_logging_permissions_are_separate(service, monkeypatch):
    monkeypatch.setenv("TELEDRIVE_NOTIFICATION_DESTINATIONS", ALLOWED)
    create(service)
    assert signed(service, "PUT", "/log-target").status_code == 200
    db = service[3]()
    try:
        keys = S3CredentialStore(db, service[4])
        notifier = keys.create("notification-writer",
                               ["s3:PutBucketNotification"])
        reader = keys.create("notification-reader",
                             ["s3:GetBucketNotification"])
        logger = keys.create("logging-writer", ["s3:PutBucketLogging"])
        log_reader = keys.create("logging-reader", ["s3:GetBucketLogging"])
        object_only = keys.create("object-only", ["s3:PutObject"])
    finally:
        db.close()

    notification = "/notify-bucket?notification"
    body = notification_payload(events=("s3:ObjectCreated:Put",))
    assert signed(service, "PUT", notification, body,
                  access=object_only.access_key,
                  secret=object_only.secret_key).status_code == 403
    assert signed(service, "PUT", notification, body,
                  access=notifier.access_key,
                  secret=notifier.secret_key).status_code == 200
    assert signed(service, "GET", notification,
                  access=notifier.access_key,
                  secret=notifier.secret_key).status_code == 403
    assert signed(service, "GET", notification,
                  access=reader.access_key,
                  secret=reader.secret_key).status_code == 200

    logging = "/notify-bucket?logging"
    assert signed(service, "PUT", logging, logging_payload(),
                  access=object_only.access_key,
                  secret=object_only.secret_key).status_code == 403
    assert signed(service, "PUT", logging, logging_payload(),
                  access=logger.access_key,
                  secret=logger.secret_key).status_code == 200
    assert signed(service, "GET", logging,
                  access=logger.access_key,
                  secret=logger.secret_key).status_code == 403
    assert signed(service, "GET", logging,
                  access=log_reader.access_key,
                  secret=log_reader.secret_key).status_code == 200


def test_route_guard_allows_get_put_and_rejects_fake_delete():
    for selector in ("notification", "notificationConfiguration", "logging"):
        params = QueryParams({selector: ""})
        validate_s3_query("GET", "bucket", False, params)
        validate_s3_query("PUT", "bucket", False, params)
        with pytest.raises(S3QueryError) as denied:
            validate_s3_query("DELETE", "bucket", False, params)
        assert denied.value.status == 501


def test_xml_renderers_are_idempotent_and_never_emit_secrets():
    config = {
        "id": "events", "destination": f"{ALLOWED}/events",
        "events": ["s3:ObjectCreated:*"], "filter_prefix": "in/",
        "filter_suffix": ".bin", "enabled": True, "secret": "hidden",
    }
    rendered = notification_xml(config)
    assert b"hidden" not in rendered
    assert parse_notification_xml(rendered) == {
        "id": "events", "destination": f"{ALLOWED}/events",
        "events": ["s3:ObjectCreated:*"], "filter_prefix": "in/",
        "filter_suffix": ".bin", "secret": None, "enabled": True,
    }
    logging = {"target_bucket": "logs", "target_prefix": "prefix/",
               "enabled": True}
    assert parse_logging_xml(logging_xml(logging)) == logging
