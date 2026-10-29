"""Gates that must not depend on WHICH API a client uses.

Found by the sixth review wave: multipart completion skipped the bucket's
default object lock, the public website served archived and SSE-C objects,
and an over-long Range header escaped as a 500.
"""
from __future__ import annotations

import json

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore

BUCKET = "gate-bucket"


def _store(service):
    return S3CredentialStore(service[3](), service[4])


def test_bucket_default_lock_applies_to_multipart_complete(service):
    """A WORM guarantee must not depend on the write API.

    ``catalog.publish`` applies the bucket's DefaultRetention for a single
    PUT; ``MultipartStore.complete`` never did, so a bucket configured for
    GOVERNANCE retention accepted an unprotected object through the
    multipart API -- verified: PUT object answered GET ?retention 200,
    multipart object answered 404 and DELETE ?versionId 204.
    """
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    lock = {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
    }
    body = (
        "<ObjectLockConfiguration>"
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
        "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days>"
        "</DefaultRetention></Rule>"
        "</ObjectLockConfiguration>"
    ).encode()
    put = signed(service, "PUT", f"/{BUCKET}?object-lock", body)
    assert put.status_code in (200, 204), put.text

    created = signed(service, "POST", f"/{BUCKET}/mp.bin?uploads")
    assert created.status_code == 200, created.text
    upload_id = created.text.split("<UploadId>")[1].split("</UploadId>")[0]
    part = signed(service, "PUT",
                  f"/{BUCKET}/mp.bin?partNumber=1&uploadId={upload_id}",
                  b"x" * (5 * 1024 * 1024))
    assert part.status_code == 200, part.text
    etag = part.headers["etag"]
    complete = signed(
        service, "POST", f"/{BUCKET}/mp.bin?uploadId={upload_id}",
        f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
        f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>".encode())
    assert complete.status_code == 200, complete.text

    retained = signed(service, "GET", f"/{BUCKET}/mp.bin?retention")
    assert retained.status_code == 200, (
        "multipart completion bypassed the bucket's default retention")
    assert "GOVERNANCE" in retained.text


def test_public_site_refuses_sse_c_and_archived_objects(service):
    """The public site is a read surface, so it obeys the same read gate.

    It did not: an SSE-C object returned 200 with Content-Length and zero
    body bytes (a client reads that as a successful empty page) and an
    ARCHIVE_ACCESS object streamed normally instead of InvalidObjectState.
    """
    from sqlalchemy import text
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    website = (
        "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix>"
        "</IndexDocument></WebsiteConfiguration>").encode()
    assert signed(service, "PUT", f"/{BUCKET}?website",
                  website).status_code in (200, 204)
    from sqlalchemy import text as _text
    db = service[3]()
    try:
        db.connection.execute(_text(
            "UPDATE storage_buckets SET public_read = :v WHERE name = :b"),
            {"v": True, "b": BUCKET})
        db.connection.commit()
    finally:
        db.close()

    assert signed(service, "PUT", f"/{BUCKET}/cold.html",
                  b"cold-bytes").status_code == 200
    db = service[3]()
    try:
        oid = db.connection.execute(text(
            "SELECT object_id FROM storage_object_heads WHERE bucket = :b"),
            {"b": BUCKET}).scalar_one()
        db.connection.execute(text(
            "UPDATE storage_objects SET storage_class = 'ARCHIVE_ACCESS', "
            "restore_until_ns = NULL WHERE id = :o"), {"o": oid})
        db.connection.commit()
    finally:
        db.close()

    served = signed(service, "GET", f"/site/{BUCKET}/cold.html")
    # The public surface never explains why: uniform 404.
    assert served.status_code == 404
    assert b"cold-bytes" not in served.content


def test_an_over_long_range_header_is_416_not_500(service):
    """int() refuses a 5000-digit literal; the ValueError escaped as a 500."""
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/r.bin", b"0123456789").status_code == 200
    response = signed(service, "GET", f"/{BUCKET}/r.bin",
                      extra_headers={"range": "bytes=" + "9" * 5000 + "-"})
    assert response.status_code == 416, response.text
