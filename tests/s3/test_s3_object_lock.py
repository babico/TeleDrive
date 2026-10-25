"""Phase C: object lock — retention and legal hold with real SQL state,
enforced on version deletes, batch deletes and physical GC."""
from __future__ import annotations

import time

import pytest

from tests.s3.test_s3_admin import admin  # noqa: F401
from tests.s3.test_s3_gateway import service, signed


def _put_lock_config(service, bucket, mode="COMPLIANCE", days=None):
    days_xml = f"<Days>{days}</Days>" if days else ""
    body = (f'<ObjectLockConfiguration '
            f'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
            f"<Rule><DefaultRetention><Mode>{mode}</Mode>{days_xml}"
            f"</DefaultRetention></Rule>"
            f"</ObjectLockConfiguration>").encode()
    return signed(service, "PUT", f"/{bucket}?object-lock", body)


def _put_retention(service, path, mode, until_iso):
    body = (f'<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Mode>{mode}</Mode>"
            f"<RetainUntilDate>{until_iso}</RetainUntilDate>"
            f"</Retention>").encode()
    return signed(service, "PUT", f"{path}?retention", body)


def _put_legal_hold(service, path, status):
    body = (f'<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Status>{status}</Status></LegalHold>").encode()
    return signed(service, "PUT", f"{path}?legal-hold", body)


def test_bucket_object_lock_configuration_roundtrip(service):
    assert signed(service, "PUT", "/lock-bucket").status_code == 200
    # Unconfigured: honest 404.
    empty = signed(service, "GET", "/lock-bucket?object-lock")
    assert empty.status_code == 404
    assert b"ObjectLockConfigurationNotFoundError" in empty.content
    # Configure with a default retention.
    configured = _put_lock_config(service, "lock-bucket", days=30)
    assert configured.status_code == 200, configured.text
    read = signed(service, "GET", "/lock-bucket?object-lock")
    assert read.status_code == 200, read.text
    assert b"<Mode>COMPLIANCE</Mode>" in read.content
    assert b"<Days>30</Days>" in read.content
    # The default can only be extended, never shortened (one-way).
    shortened = _put_lock_config(service, "lock-bucket", days=10)
    assert shortened.status_code == 400
    extended = _put_lock_config(service, "lock-bucket", days=60)
    assert extended.status_code == 200
    # Invalid modes fail closed.
    bad = _put_lock_config(service, "lock-bucket", mode="WAT", days=30)
    assert bad.status_code == 400


def test_retention_blocks_version_delete_and_gc(service):
    assert signed(service, "PUT", "/lock-bucket").status_code == 200
    assert signed(service, "PUT", "/lock-bucket/worm.bin", b"locked-payload"
                  ).status_code == 200
    version = signed(service, "GET", "/lock-bucket/worm.bin"
                     ).headers.get("x-amz-version-id")
    # No retention yet: 404 on read.
    assert signed(service, "GET", "/lock-bucket/worm.bin?retention"
                  ).status_code == 404
    # Set a COMPLIANCE retention ending in the future.
    until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    applied = _put_retention(service, "/lock-bucket/worm.bin",
                             "COMPLIANCE", until)
    assert applied.status_code == 200, applied.text
    state = signed(service, "GET", "/lock-bucket/worm.bin?retention")
    assert state.status_code == 200
    assert b"<Mode>COMPLIANCE</Mode>" in state.content
    assert until[:10].encode() in state.content

    # Explicit version delete is refused while retained.
    denied = signed(service, "DELETE",
                    f"/lock-bucket/worm.bin?versionId={version}")
    assert denied.status_code == 403, denied.text
    assert b"retention" in denied.content.lower()
    # The object is still fully readable.
    assert signed(service, "GET", "/lock-bucket/worm.bin"
                  ).content == b"locked-payload"

    # COMPLIANCE retention cannot be shortened or removed.
    earlier = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() + 60))
    shortened = _put_retention(service, "/lock-bucket/worm.bin",
                               "COMPLIANCE", earlier)
    assert shortened.status_code in (400, 403)

    # The GC collector never touches retained media.
    from tests.s3.test_s3_gateway import service as _s  # noqa: F401
    connection = service[3]()
    try:
        from teledrive.storage.gc_collect import RetainedMediaGC
        gcx = RetainedMediaGC(connection)
        gcx.set_enabled(True, by="test")
        gcx.enqueue([version], "version-delete")
        from sqlalchemy import text
        connection.connection.execute(text(
            "UPDATE storage_gc_queue SET enqueued_ns = "
            "enqueued_ns - 7200000000000"))
        connection.commit()
        candidates = gcx.candidates(scope="queued")
        # The queue scope filters retained objects out entirely.
        assert version not in [c["object_id"] for c in candidates]
    finally:
        connection.close()


def test_legal_hold_roundtrip_and_delete_fence(service):
    assert signed(service, "PUT", "/lock-bucket").status_code == 200
    assert signed(service, "PUT", "/lock-bucket/hold.bin", b"held"
                  ).status_code == 200
    version = signed(service, "GET", "/lock-bucket/hold.bin"
                     ).headers.get("x-amz-version-id")
    assert b"<Status>OFF</Status>" in signed(
        service, "GET", "/lock-bucket/hold.bin?legal-hold").content
    assert _put_legal_hold(service, "/lock-bucket/hold.bin", "ON").status_code == 200
    assert b"<Status>ON</Status>" in signed(
        service, "GET", "/lock-bucket/hold.bin?legal-hold").content
    # Version delete refused while held.
    denied = signed(service, "DELETE",
                    f"/lock-bucket/hold.bin?versionId={version}")
    assert denied.status_code == 403
    # Releasing the hold unblocks the delete.
    assert _put_legal_hold(service, "/lock-bucket/hold.bin", "OFF").status_code == 200
    allowed = signed(service, "DELETE",
                     f"/lock-bucket/hold.bin?versionId={version}")
    assert allowed.status_code == 204


def test_bucket_default_lock_applies_on_publish(service):
    assert signed(service, "PUT", "/lock-bucket").status_code == 200
    assert _put_lock_config(service, "lock-bucket", mode="GOVERNANCE",
                            days=1).status_code == 200
    assert signed(service, "PUT", "/lock-bucket/fresh.bin",
                  b"auto-locked").status_code == 200
    version = signed(service, "GET", "/lock-bucket/fresh.bin"
                     ).headers.get("x-amz-version-id")
    # The default retention is materialized on the new version.
    state = signed(service, "GET", "/lock-bucket/fresh.bin?retention")
    assert state.status_code == 200, state.text
    assert b"<Mode>GOVERNANCE</Mode>" in state.content
    # Retained: an explicit version delete is fenced.
    denied = signed(service, "DELETE",
                    f"/lock-bucket/fresh.bin?versionId={version}")
    assert denied.status_code == 403


def test_lifecycle_expiration_skips_locked_objects(admin):
    """Retention fences the lifecycle evaluator too."""
    client, url, _ = admin
    from teledrive.db import connect_database
    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    from tests.storage.test_gc_collect import _publish
    from teledrive.s3.lifecycle import (BucketLifecycleStore,
                                        parse_lifecycle_xml)
    db = connect_database(url)
    try:
        cat = BucketCatalog(ManifestStore(db))
        cat.create_bucket("locklcx", int(time.time()))
        old = int(time.time()) - 10 * 86400
        locked, _ = _publish(cat, "temp/locked.bin", size=70, now=old,
                             bucket="locklcx")
        _publish(cat, "temp/free.bin", size=80, now=old, bucket="locklcx")
        cat.set_retention(locked, mode="COMPLIANCE",
                          until_ns=time.time_ns() + 3600 * 1_000_000_000)
        rules = parse_lifecycle_xml(
            b"<LifecycleConfiguration><Rule><ID>r</ID>"
            b"<Status>Enabled</Status><Filter><Prefix>temp/</Prefix></Filter>"
            b"<Expiration><Days>7</Days></Expiration></Rule>"
            b"</LifecycleConfiguration>")
        BucketLifecycleStore(cat).replace("locklcx", rules)
        applied = BucketLifecycleStore(cat).apply_due(
            now=int(time.time()), limit=10)
        assert applied == 1  # only the unlocked object expired
        try:
            cat.get("locklcx", "temp/locked.bin")
            locked_ok = True
        except FileNotFoundError:
            locked_ok = False
        assert locked_ok
        try:
            cat.get("locklcx", "temp/free.bin")
            raise AssertionError("unlocked object should have expired")
        except FileNotFoundError:
            pass
    finally:
        db.close()
