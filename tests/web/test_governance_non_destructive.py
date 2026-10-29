"""A governance save must not silently destroy state it was not asked about.

Found by the seventh review wave: the website PUT defaulted an omitted
``public_read`` to False, so editing the index document unpublished a live
site; a notification save dropped the stored HMAC secret; and an object-lock
save could erase the retention period or downgrade COMPLIANCE.
"""
from __future__ import annotations

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore

BUCKET = "gov-bucket"


def _store(service):
    return S3CredentialStore(service[3](), service[4])


def test_notification_save_preserves_the_stored_secret(service):
    """The gateway must store the HMAC secret it was given.

    ``notification_xml`` never emitted <Secret>, so every governance save
    replaced the config with an UNSIGNED webhook and answered 200.
    """
    from teledrive.s3.notifications import (
        NotificationStore, notification_xml, parse_notification_xml)

    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    config = {
        "id": "", "destination": "https://example.invalid/hook",
        "events": ["s3:ObjectCreated:*"], "filter_prefix": "",
        "filter_suffix": "", "secret": "a" * 32, "enabled": True,
    }
    # A server-side write carries the secret; the GET renderer does not.
    assert b"a" * 32 in notification_xml(config, include_secret=True)
    assert b"a" * 32 not in notification_xml(config)
    assert parse_notification_xml(
        notification_xml(config, include_secret=True))["secret"] == "a" * 32
    assert parse_notification_xml(notification_xml(config))["secret"] is None

    db = service[3]()
    try:
        catalog = __import__(
            "teledrive.storage.catalog", fromlist=["BucketCatalog"]
        ).BucketCatalog(__import__(
            "teledrive.storage.manifest", fromlist=["ManifestStore"]
        ).ManifestStore(db))
        store = NotificationStore(catalog, master_key=service[4])
        store.replace_config(BUCKET, config)
        stored = store.get_config(BUCKET, include_secret=True)
        assert stored["secret"] == "a" * 32, "the webhook secret was dropped"
        # The GET-facing read never carries it.
        assert store.get_config(BUCKET)["secret"] is None
    finally:
        db.close()


def test_object_lock_cannot_downgrade_compliance_or_erase_the_period(service):
    """A WORM configuration must not become weaker through the UI."""
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    body = (
        "<ObjectLockConfiguration>"
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
        "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days>"
        "</DefaultRetention></Rule>"
        "</ObjectLockConfiguration>"
    ).encode()
    assert signed(service, "PUT", f"/{BUCKET}?object-lock",
                  body).status_code in (200, 204)

    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        before = catalog.object_lock_config(BUCKET)
    finally:
        db.close()
    assert before["default_mode"] == "COMPLIANCE"
    assert int(before["default_days"]) == 30

    # A GOVERNANCE/days=1 write must be refused (mode downgrade AND shortening).
    weaker = (
        "<ObjectLockConfiguration>"
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
        "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days>"
        "</DefaultRetention></Rule>"
        "</ObjectLockConfiguration>"
    ).encode()
    refused = signed(service, "PUT", f"/{BUCKET}?object-lock", weaker)
    assert refused.status_code in (400, 403, 409), refused.text
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        after = catalog.object_lock_config(BUCKET)
    finally:
        db.close()
    assert after["default_mode"] == "COMPLIANCE"
    assert int(after["default_days"]) == 30


def test_suspended_versioning_cannot_delete_a_retained_head(service):
    """A legal hold or a retention window forbids the suspended-branch delete.

    The explicit-version path fenced this; the suspended branch removed the
    head with no check, so on a lock-enabled bucket set to Suspended an
    ordinary DELETE hid a COMPLIANCE-retained object.
    """
    from sqlalchemy import text
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/worm.bin",
                  b"immutable").status_code == 200
    db = service[3]()
    try:
        oid = db.connection.execute(text(
            "SELECT object_id FROM storage_object_heads WHERE bucket = :b"),
            {"b": BUCKET}).scalar_one()
        db.connection.execute(text(
            "UPDATE storage_objects SET retention_mode = 'COMPLIANCE', "
            "retention_until_ns = :u WHERE id = :o"),
            {"u": __import__("time").time_ns() + 3600 * 10**9, "o": oid})
        db.connection.execute(text(
            "UPDATE storage_buckets SET versioning_state = 'Suspended' "
            "WHERE name = :b"), {"b": BUCKET})
        db.connection.commit()
    finally:
        db.close()

    denied = signed(service, "DELETE", f"/{BUCKET}/worm.bin")
    assert denied.status_code == 403, denied.text
    still_there = signed(service, "GET", f"/{BUCKET}/worm.bin")
    assert still_there.status_code == 200
    assert still_there.content == b"immutable"
