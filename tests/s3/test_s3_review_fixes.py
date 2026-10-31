"""Regression tests for the S3 API review findings (wave A).

Each test names the failure mode it pins: an exception class that was not
imported, an unbound CORS variable, checksum declarations the gateway
acknowledged without verifying, and HTTP semantics (If-Range, max-keys,
Allow) that AWS clients rely on.
"""
from __future__ import annotations

import base64
import hashlib
import zlib
from xml.etree import ElementTree as ET

from sqlalchemy import select, update

import web.s3 as gateway
from teledrive.s3.checksums import crc32c
from teledrive.s3.multipart import MultipartStore, parts
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore, object_encryption
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, part, setup

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def _catalog(service):
    return BucketCatalog(ManifestStore(service[3]()))


def _acl_body(service):
    from web.s3_gateway.xml import _canned_private_acl_xml
    return _canned_private_acl_xml(service[1].access_key)


def test_corrupt_envelope_wrapped_key_is_an_xml_400(service, monkeypatch):
    """A tampered envelope marker must be a clean S3 error, never a 500."""
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    put = signed(service, "PUT", "/review-bucket/envelope.bin", b"secret",
                 extra_headers={"x-amz-server-side-encryption": "AES256"})
    assert put.status_code == 200, put.text

    catalog = _catalog(service)
    try:
        item = catalog.get("review-bucket", "envelope.bin").item
        catalog.db.connection.execute(
            update(object_encryption)
            .where(object_encryption.c.object_id == item.id)
            .values(wrapped_key="not-valid-base64%%"))
        catalog.db.commit()
    finally:
        catalog.db.close()

    response = signed(service, "GET", "/review-bucket/envelope.bin")
    assert response.status_code == 400, response.text
    assert ET.fromstring(response.content).findtext("Code") == "InvalidRequest"


def test_bucket_list_with_origin_does_not_hit_unbound_cors_match(service):
    """GET / has no bucket, so the CORS lookup never runs; it must still 200."""
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    response = signed(service, "GET", "/",
                      extra_headers={"Origin": "https://console.example.com"})
    assert response.status_code == 200, response.text
    assert b"ListAllMyBucketsResult" in response.content


def test_put_object_acl_verifies_correct_and_wrong_content_md5(service):
    """Correct Content-MD5 must not be rejected as BadDigest."""
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    assert signed(service, "PUT", "/review-bucket/md5.bin", b"x").status_code == 200
    body = _acl_body(service)
    correct = base64.b64encode(
        hashlib.md5(body, usedforsecurity=False).digest()).decode()
    accepted = signed(service, "PUT", "/review-bucket/md5.bin?acl", body,
                      extra_headers={"Content-MD5": correct})
    assert accepted.status_code == 200, accepted.text

    rejected = signed(service, "PUT", "/review-bucket/md5.bin?acl", body,
                      extra_headers={
                          "Content-MD5": base64.b64encode(b"0" * 16).decode()})
    assert rejected.status_code == 400, rejected.text
    assert ET.fromstring(rejected.content).findtext("Code") == "BadDigest"


def test_put_object_acl_verifies_crc32_and_crc32c(service):
    """Every declared CRC is checked on object-level control bodies too."""
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    assert signed(service, "PUT", "/review-bucket/crc.bin", b"x").status_code == 200
    body = _acl_body(service)
    for header, value in (
        ("x-amz-checksum-crc32", zlib.crc32(body) & 0xffffffff),
        ("x-amz-checksum-crc32c", crc32c(body)),
    ):
        encoded = base64.b64encode(value.to_bytes(4, "big")).decode()
        accepted = signed(service, "PUT", "/review-bucket/crc.bin?acl", body,
                          extra_headers={header: encoded})
        assert accepted.status_code == 200, (header, accepted.text)
        rejected = signed(service, "PUT", "/review-bucket/crc.bin?acl", body,
                          extra_headers={
                              header: base64.b64encode(b"\0\0\0\0").decode()})
        assert rejected.status_code == 400, (header, rejected.text)
        assert ET.fromstring(rejected.content).findtext("Code") == "BadDigest"


def test_if_range_mismatch_serves_full_body_and_match_applies_range(service):
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    payload = b"0123456789"
    assert signed(service, "PUT", "/review-bucket/range.bin",
                  payload).status_code == 200
    head = signed(service, "HEAD", "/review-bucket/range.bin")
    etag = head.headers["etag"]

    stale = signed(service, "GET", "/review-bucket/range.bin",
                   extra_headers={"Range": "bytes=0-2",
                                  "If-Range": '"0000000000000000"'})
    assert stale.status_code == 200, stale.text
    assert stale.content == payload

    fresh = signed(service, "GET", "/review-bucket/range.bin",
                   extra_headers={"Range": "bytes=0-2", "If-Range": etag})
    assert fresh.status_code == 206, fresh.text
    assert fresh.content == payload[:3]

    by_date = signed(service, "GET", "/review-bucket/range.bin",
                     extra_headers={"Range": "bytes=0-2",
                                    "If-Range": head.headers["last-modified"]})
    assert by_date.status_code == 206, by_date.text
    assert by_date.content == payload[:3]


def test_max_keys_zero_is_empty_page_and_large_value_is_clamped(service):
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    for key in ("a.bin", "b.bin"):
        assert signed(service, "PUT", f"/review-bucket/{key}", b"x").status_code == 200

    empty = signed(service, "GET", "/review-bucket?list-type=2&max-keys=0")
    assert empty.status_code == 200, empty.text
    root = ET.fromstring(empty.content)
    assert root.findtext(NS + "KeyCount") == "0"
    assert root.findtext(NS + "IsTruncated") == "false"
    assert root.findall(NS + "Contents") == []

    empty_v1 = signed(service, "GET", "/review-bucket?max-keys=0")
    assert empty_v1.status_code == 200, empty_v1.text
    assert ET.fromstring(empty_v1.content).findall(NS + "Contents") == []

    clamped = signed(service, "GET", "/review-bucket?list-type=2&max-keys=5000")
    assert clamped.status_code == 200, clamped.text
    assert ET.fromstring(clamped.content).findtext(NS + "MaxKeys") == "1000"

    versions_zero = signed(service, "GET", "/review-bucket?versions&max-keys=0")
    assert versions_zero.status_code == 200, versions_zero.text
    versions_root = ET.fromstring(versions_zero.content)
    assert versions_root.findtext(NS + "IsTruncated") == "false"
    assert versions_root.findall(NS + "Version") == []

    versions_clamped = signed(
        service, "GET", "/review-bucket?versions&max-keys=5000")
    assert versions_clamped.status_code == 200, versions_clamped.text
    assert ET.fromstring(versions_clamped.content).findtext(
        NS + "MaxKeys") == "1000"


def test_delete_marker_read_405_advertises_delete(service):
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    assert signed(service, "PUT", "/review-bucket/tombstone.bin",
                  b"old").status_code == 200
    marker = signed(service, "DELETE",
                    "/review-bucket/tombstone.bin").headers["x-amz-version-id"]
    response = signed(
        service, "GET", f"/review-bucket/tombstone.bin?versionId={marker}")
    assert response.status_code == 405, response.text
    assert response.headers.get("allow") == "DELETE"


def test_zero_part_complete_is_malformed_xml(service):
    setup(service)
    upload_id = begin(service)
    response = signed(
        service, "POST", f"/backup-bucket/asset.bin?uploadId={upload_id}",
        b"<CompleteMultipartUpload></CompleteMultipartUpload>")
    assert response.status_code == 400, response.text
    assert ET.fromstring(response.content).findtext("Code") == "MalformedXML"


def test_response_header_overrides_apply_to_get_and_head(service):
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    assert signed(service, "PUT", "/review-bucket/override.bin",
                  b"body").status_code == 200
    query = (
        "?response-content-type=text%2Fplain"
        "&response-content-disposition=attachment%3B%20filename%3D%22a.txt%22"
        "&response-cache-control=no-store"
        "&response-content-encoding=identity"
        "&response-content-language=en"
        "&response-expires=Wed%2C%2021%20Oct%202015%2007%3A28%3A00%20GMT"
    )
    got = signed(service, "GET", "/review-bucket/override.bin" + query)
    assert got.status_code == 200, got.text
    assert got.headers["content-type"] == "text/plain"
    assert got.headers["content-disposition"] == 'attachment; filename="a.txt"'
    assert got.headers["cache-control"] == "no-store"
    assert got.headers["content-encoding"] == "identity"
    assert got.headers["content-language"] == "en"
    assert got.headers["expires"] == "Wed, 21 Oct 2015 07:28:00 GMT"

    head = signed(service, "HEAD", "/review-bucket/override.bin" + query)
    assert head.status_code == 200
    assert head.headers["content-type"] == "text/plain"
    assert head.headers["cache-control"] == "no-store"

    # Unknown query parameters still fail closed.
    unknown = signed(service, "GET",
                     "/review-bucket/override.bin?response-content-length=1")
    assert unknown.status_code == 501, unknown.text

    # A control character would turn the override into header injection.
    injected = signed(
        service, "GET",
        "/review-bucket/override.bin"
        "?response-content-type=text%2Fplain%0D%0AX-Evil%3A%201")
    assert injected.status_code == 400, injected.text
    assert "x-evil" not in injected.headers


def test_envelope_object_returns_checksum_with_checksum_mode(service, monkeypatch):
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    payload = b"checksummed-envelope"
    put = signed(service, "PUT", "/review-bucket/checksum.bin", payload,
                 extra_headers={"x-amz-server-side-encryption": "AES256"})
    assert put.status_code == 200, put.text
    response = signed(
        service, "GET", "/review-bucket/checksum.bin",
        extra_headers={"x-amz-checksum-mode": "ENABLED"})
    assert response.status_code == 200, response.text
    assert response.headers["x-amz-checksum-sha256"] == base64.b64encode(
        hashlib.sha256(payload).digest()).decode()


def test_object_tagging_verifies_crc32(service):
    assert signed(service, "PUT", "/review-bucket").status_code == 200
    assert signed(service, "PUT", "/review-bucket/tag.bin", b"x").status_code == 200
    body = (b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value>"
            b"</Tag></TagSet></Tagging>")
    actual = base64.b64encode(
        (zlib.crc32(body) & 0xffffffff).to_bytes(4, "big")).decode()
    accepted = signed(service, "PUT", "/review-bucket/tag.bin?tagging", body,
                      extra_headers={"x-amz-checksum-crc32": actual})
    assert accepted.status_code == 200, accepted.text
    rejected = signed(service, "PUT", "/review-bucket/tag.bin?tagging", body,
                      extra_headers={
                          "x-amz-checksum-crc32":
                              base64.b64encode(b"\0\0\0\0").decode()})
    assert rejected.status_code == 400, rejected.text
    assert ET.fromstring(rejected.content).findtext("Code") == "BadDigest"


def test_complete_accepts_unsigned_payload_with_signed_content_md5(service):
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.config import Config
    from botocore.credentials import Credentials

    setup(service)
    upload_id = begin(service)
    etag = part(service, upload_id, 1, b"tail")
    body = (b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
            b"<ETag>" + etag.encode() + b"</ETag></Part>"
            b"</CompleteMultipartUpload>")
    path = f"/backup-bucket/asset.bin?uploadId={upload_id}"

    def unsigned_complete(md5_header):
        credentials = service[1]
        request = AWSRequest(
            method="POST", url="http://localhost:9000" + path, data=body,
            headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD",
                     "Content-MD5": md5_header})
        # S3SigV4Auth reads payload_signing_enabled from the client config;
        # with an integrity header present this is the real
        # "UNSIGNED-PAYLOAD + signed Content-MD5" wire shape.
        request.context["client_config"] = Config(
            s3={"payload_signing_enabled": False})
        S3SigV4Auth(Credentials(credentials.access_key,
                                credentials.secret_key),
                    "s3", "us-east-1").add_auth(request)
        return service[0].request("POST", path, content=body,
                                  headers=dict(request.headers))

    wrong = unsigned_complete(base64.b64encode(b"0" * 16).decode())
    assert wrong.status_code == 400, wrong.text
    assert ET.fromstring(wrong.content).findtext("Code") == "BadDigest"

    correct = unsigned_complete(base64.b64encode(
        hashlib.md5(body, usedforsecurity=False).digest()).decode())
    assert correct.status_code == 200, correct.text


def test_record_part_cas_loser_rechecks_and_retries(service, monkeypatch):
    """A stale part CAS must not silently acknowledge the losing write."""
    setup(service)
    upload_id = begin(service)
    first_etag = part(service, upload_id, 1, b"first").strip('"')
    second_etag = part(service, upload_id, 2, b"second").strip('"')

    catalog = _catalog(service)
    try:
        rows = catalog.db.connection.execute(
            select(parts.c.number, parts.c.object_id).where(
                parts.c.upload_id == upload_id)).all()
        identifiers = {number: object_id for number, object_id in rows}
        winning_id = identifiers[2]
        # A competing UploadPart has already replaced slot 1 while our
        # reader still believes it holds the original object.
        catalog.db.connection.execute(update(parts).where(
            parts.c.upload_id == upload_id, parts.c.number == 1,
        ).values(object_id=winning_id, etag=second_etag))
        catalog.db.commit()
    finally:
        catalog.db.close()

    loser = _catalog(service)
    try:
        store = MultipartStore(loser)
        original_read = MultipartStore._part_object_id
        reads = {"count": 0}

        def stale_then_real(self, identifier, number):
            reads["count"] += 1
            if reads["count"] == 1:
                return identifiers[1]
            return original_read(self, identifier, number)

        monkeypatch.setattr(MultipartStore, "_part_object_id", stale_then_real)
        store.record_part(upload_id, "backup-bucket", "asset.bin",
                          service[1].access_key, number=1,
                          object_id=identifiers[1], etag=first_etag)
    finally:
        loser.db.close()

    check = _catalog(service)
    try:
        stored = check.db.connection.execute(
            select(parts.c.object_id, parts.c.etag).where(
                parts.c.upload_id == upload_id, parts.c.number == 1)).one()
    finally:
        check.db.close()
    assert stored.object_id == identifiers[1]
    assert stored.etag == first_etag
    assert reads["count"] == 2
