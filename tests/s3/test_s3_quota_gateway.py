"""Bucket-quota enforcement on every S3 upload path.

The gate must run before Telegram work begins: an over-quota request may
stage scratch bytes, but it must never reach the transport and must answer
the S3 413 EntityTooLarge shape.
"""
from __future__ import annotations

import time
from xml.etree import ElementTree as ET

from teledrive.storage.quota import set_bucket_quota
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, part, setup
from tests.s3.test_s3_post_policy import make_form, post


def _quota(service, bucket, *, max_size_bytes=None, max_objects=None):
    db = service[3]()
    try:
        set_bucket_quota(db, bucket, max_size_bytes, max_objects,
                         int(time.time()))
    finally:
        db.close()


def _code(response):
    return ET.fromstring(response.content).findtext("Code")


def test_over_quota_put_is_413_before_any_telegram_upload(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    _quota(service, "backup-bucket", max_size_bytes=4)
    before = service[2].uploads
    response = signed(service, "PUT", "/backup-bucket/too-big.bin", b"12345")
    assert response.status_code == 413, response.text
    assert _code(response) == "EntityTooLarge"
    assert service[2].uploads == before
    assert signed(service, "HEAD", "/backup-bucket/too-big.bin").status_code == 404


def test_over_quota_browser_post_is_413_before_any_telegram_upload(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    _quota(service, "backup-bucket", max_size_bytes=4)
    payload = b"12345"
    before = service[2].uploads
    response = post(service, payload, make_form(service, payload))
    assert response.status_code == 413, response.text
    assert _code(response) == "EntityTooLarge"
    assert service[2].uploads == before


def test_over_quota_complete_is_413_before_assembly(service):
    setup(service)
    upload_id = begin(service)
    payload = b"p" * (5 * 1024 * 1024)
    etag = part(service, upload_id, 1, payload)
    _quota(service, "backup-bucket", max_size_bytes=1024)
    before = service[2].uploads
    response = complete(service, upload_id, [(1, etag)])
    assert response.status_code == 413, response.text
    assert _code(response) == "EntityTooLarge"
    assert service[2].uploads == before
    assert signed(service, "HEAD", "/backup-bucket/asset.bin").status_code == 404
