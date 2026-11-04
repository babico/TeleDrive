"""Auth-failure evidence for the S3 operations the matrix left open.

The per-operation matrix in ``docs/reference/s3-evidence.md`` requires,
for the auth-failure column, a test that sends a *validly signed*
request whose credential deliberately lacks the operation's OWN
permission scope and asserts the operation-specific 403 ``AccessDenied``
— the unsigned sweep is the floor, not the cell.

Every test here mints a second credential through the admin-facing
``S3CredentialStore`` (exactly like ``tests/s3/test_s3_permissions.py``),
gives it a neighbouring scope but never the operation's own, signs the
request with SigV4, and then proves both halves of the contract:

* the answer is 403 ``AccessDenied`` (not 401, not a generic deny), and
* the operation's state was NOT mutated — the bucket/object/upload/
  lock/encryption configuration is byte-identical afterwards, and zero
  bytes reached Telegram.

Filling the 19 open auth-failure cells: the object-lock family
(GetObjectLockConfiguration, PutObjectLockConfiguration,
GetObjectRetention, PutObjectRetention, GetObjectLegalHold,
PutObjectLegalHold) and the service/multipart basics (CreateBucket,
HeadBucket, DeleteBucket, ListObjects, HeadObject,
CreateMultipartUpload, UploadPartCopy, ListParts,
CompleteMultipartUpload, AbortMultipartUpload and the bucket-encryption
trio).
"""
from __future__ import annotations

import re
import time

from tests.s3.test_s3_gateway import service, signed  # noqa: F401
from teledrive.s3.credentials import S3CredentialStore

XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

# The SSE-C-less empty rule document is the one valid bucket encryption
# configuration (tests/s3/test_s3_sse_c.py pins the same shape).
EMPTY_ENCRYPTION_CONFIG = (
    b"<ServerSideEncryptionConfiguration "
    b"xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>")


def scoped(service, permissions):
    """A second, correctly issued credential with exactly these scopes."""
    connection = service[3]()
    try:
        store = S3CredentialStore(connection, service[4])
        return store.create("evidence-authfail", list(permissions))
    finally:
        connection.close()


def as_credential(service, credential, method, path, body=b"",
                  extra_headers=None):
    return signed(service, method, path, body,
                  access=credential.access_key,
                  secret=credential.secret_key,
                  extra_headers=extra_headers)


def _denied(reply):
    assert reply.status_code == 403, (reply.status_code, reply.text[:300])
    assert b"AccessDenied" in reply.content, reply.text[:300]
    return reply


def _make_bucket(service, name):
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


def _put_object(service, bucket, key, payload=b"authfail-payload"):
    reply = signed(service, "PUT", f"/{bucket}/{key}", payload)
    assert reply.status_code == 200, reply.text
    return payload


def _start_upload(service, bucket, key):
    reply = signed(service, "POST", f"/{bucket}/{key}?uploads")
    assert reply.status_code == 200, reply.text
    match = re.search(rb"<UploadId>([^<]+)</UploadId>", reply.content)
    assert match, reply.text
    return match.group(1).decode()


def _iso_later(seconds=3600):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() + seconds))


def _put_lock_config(service, bucket, mode="COMPLIANCE", days=1):
    body = (f'<ObjectLockConfiguration xmlns="{XMLNS}">'
            f"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
            f"<Rule><DefaultRetention><Mode>{mode}</Mode>"
            f"<Days>{days}</Days></DefaultRetention></Rule>"
            f"</ObjectLockConfiguration>").encode()
    reply = signed(service, "PUT", f"/{bucket}?object-lock", body)
    assert reply.status_code == 200, reply.text


def _put_retention(service, path, mode="GOVERNANCE"):
    body = (f'<Retention xmlns="{XMLNS}"><Mode>{mode}</Mode>'
            f"<RetainUntilDate>{_iso_later()}</RetainUntilDate>"
            f"</Retention>").encode()
    reply = signed(service, "PUT", f"{path}?retention", body)
    assert reply.status_code == 200, reply.text


def _put_legal_hold(service, path, status="ON"):
    body = (f'<LegalHold xmlns="{XMLNS}"><Status>{status}</Status>'
            f"</LegalHold>").encode()
    reply = signed(service, "PUT", f"{path}?legal-hold", body)
    assert reply.status_code == 200, reply.text


# ---------------------------------------------------------------------------
# The object-lock family (gap 4): the scopes live in
# teledrive/s3/credentials.py PERMISSIONS as s3:Get/PutBucketObjectLock-
# Configuration and s3:Get/PutObjectRetention / s3:Get/PutObjectLegalHold.
# ---------------------------------------------------------------------------

def test_put_object_lock_configuration_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-lock-bucket")
    other = scoped(service, ["s3:GetBucketObjectLockConfiguration"])
    body = (f'<ObjectLockConfiguration xmlns="{XMLNS}">'
            f"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
            f"</ObjectLockConfiguration>").encode()
    _denied(as_credential(service, other, "PUT",
                          f"/{bucket}?object-lock", body))
    # Nothing was stored: the read side still says "no configuration".
    assert signed(service, "GET",
                  f"/{bucket}?object-lock").status_code == 404


def test_get_object_lock_configuration_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-lock-bucket")
    _put_lock_config(service, bucket)
    other = scoped(service, ["s3:PutBucketObjectLockConfiguration"])
    _denied(as_credential(service, other, "GET", f"/{bucket}?object-lock"))
    # The configuration is untouched and still readable by its owner.
    state = signed(service, "GET", f"/{bucket}?object-lock")
    assert state.status_code == 200
    assert b"<ObjectLockEnabled>Enabled</ObjectLockEnabled>" in state.content


def test_put_object_retention_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-lock-bucket")
    _put_object(service, bucket, "locked.bin")
    path = f"/{bucket}/locked.bin"
    other = scoped(service, ["s3:GetObjectRetention"])
    body = (f'<Retention xmlns="{XMLNS}"><Mode>COMPLIANCE</Mode>'
            f"<RetainUntilDate>{_iso_later()}</RetainUntilDate>"
            f"</Retention>").encode()
    _denied(as_credential(service, other, "PUT", f"{path}?retention", body))
    # No retention was applied.
    assert signed(service, "GET", f"{path}?retention").status_code == 404


def test_get_object_retention_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-lock-bucket")
    _put_object(service, bucket, "locked.bin")
    path = f"/{bucket}/locked.bin"
    _put_retention(service, path)
    other = scoped(service, ["s3:PutObjectRetention"])
    _denied(as_credential(service, other, "GET", f"{path}?retention"))
    # The stored retention is unchanged.
    state = signed(service, "GET", f"{path}?retention")
    assert state.status_code == 200
    assert b"<Mode>GOVERNANCE</Mode>" in state.content


def test_put_object_legal_hold_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-lock-bucket")
    _put_object(service, bucket, "locked.bin")
    path = f"/{bucket}/locked.bin"
    other = scoped(service, ["s3:GetObjectLegalHold"])
    body = (f'<LegalHold xmlns="{XMLNS}"><Status>ON</Status>'
            f"</LegalHold>").encode()
    _denied(as_credential(service, other, "PUT", f"{path}?legal-hold", body))
    # No hold was applied.
    state = signed(service, "GET", f"{path}?legal-hold")
    assert state.status_code == 200 and b"<Status>OFF</Status>" in state.content


def test_get_object_legal_hold_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-lock-bucket")
    _put_object(service, bucket, "locked.bin")
    path = f"/{bucket}/locked.bin"
    _put_legal_hold(service, path, "ON")
    other = scoped(service, ["s3:PutObjectLegalHold"])
    _denied(as_credential(service, other, "GET", f"{path}?legal-hold"))
    # The hold survives.
    state = signed(service, "GET", f"{path}?legal-hold")
    assert state.status_code == 200 and b"<Status>ON</Status>" in state.content


# ---------------------------------------------------------------------------
# Service and bucket basics (gap 5).
# ---------------------------------------------------------------------------

def test_create_bucket_requires_its_own_scope(service):
    other = scoped(service, ["s3:ListAllMyBuckets"])
    _denied(as_credential(service, other, "PUT", "/auth-deny-bucket"))
    # The bucket was not created.
    listing = signed(service, "GET", "/")
    assert listing.status_code == 200
    assert b"auth-deny-bucket" not in listing.content
    assert signed(service, "HEAD", "/auth-deny-bucket").status_code == 404


def test_head_bucket_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-head-bucket")
    other = scoped(service, ["s3:CreateBucket"])
    reply = as_credential(service, other, "HEAD", f"/{bucket}")
    assert reply.status_code == 403
    # The bucket itself is untouched.
    assert signed(service, "HEAD", f"/{bucket}").status_code == 200


def test_delete_bucket_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-delete-bucket")
    other = scoped(service, ["s3:CreateBucket"])
    _denied(as_credential(service, other, "DELETE", f"/{bucket}"))
    # The bucket still exists.
    assert signed(service, "HEAD", f"/{bucket}").status_code == 200


def test_list_objects_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-list-bucket")
    _put_object(service, bucket, "listed.bin")
    other = scoped(service, ["s3:ListAllMyBuckets"])
    _denied(as_credential(service, other, "GET", f"/{bucket}"))
    # The V1 listing still works for the owner and names the object.
    listing = signed(service, "GET", f"/{bucket}")
    assert listing.status_code == 200 and b"listed.bin" in listing.content


def test_head_object_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-headobj-bucket")
    payload = _put_object(service, bucket, "headed.bin")
    other = scoped(service, ["s3:ListBucket"])
    reply = as_credential(service, other, "HEAD", f"/{bucket}/headed.bin")
    assert reply.status_code == 403
    # The object is intact.
    assert signed(service, "GET", f"/{bucket}/headed.bin").content == payload


# ---------------------------------------------------------------------------
# Multipart basics (gap 5). CreateMultipartUpload, UploadPartCopy and
# CompleteMultipartUpload ride the s3:PutObject scope; ListParts rides
# s3:GetObject; AbortMultipartUpload rides s3:DeleteObject.
# ---------------------------------------------------------------------------

def test_create_multipart_upload_requires_put_object_scope(service):
    bucket = _make_bucket(service, "auth-mpu-bucket")
    other = scoped(service, ["s3:GetObject"])
    _denied(as_credential(service, other, "POST",
                          f"/{bucket}/denied.bin?uploads"))
    # No multipart session was allocated.
    listing = signed(service, "GET", f"/{bucket}?uploads")
    assert listing.status_code == 200
    assert b"<Upload>" not in listing.content


def test_upload_part_copy_requires_put_object_scope(service):
    bucket = _make_bucket(service, "auth-mpucopy-bucket")
    _put_object(service, bucket, "source.bin")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    other = scoped(service, ["s3:GetObject"])
    _denied(as_credential(service, other, "PUT",
                          f"/{bucket}/assembled.bin?uploadId={upload_id}"
                          f"&partNumber=1",
                          extra_headers={
                              "x-amz-copy-source": f"/{bucket}/source.bin"}))
    # No part was staged for the upload.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200 and b"<Part>" not in parts.content


def test_list_parts_requires_get_object_scope(service):
    bucket = _make_bucket(service, "auth-listparts-bucket")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    other = scoped(service, ["s3:PutObject"])
    _denied(as_credential(service, other, "GET",
                          f"/{bucket}/assembled.bin?uploadId={upload_id}"))
    # The upload is intact and still listable by its owner.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200


def test_complete_multipart_upload_requires_put_object_scope(service):
    bucket = _make_bucket(service, "auth-complete-bucket")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    body = (f'<CompleteMultipartUpload xmlns="{XMLNS}">'
            f"<Part><PartNumber>1</PartNumber>"
            f"<ETag>\"00000000000000000000000000000000\"</ETag>"
            f"</Part></CompleteMultipartUpload>").encode()
    other = scoped(service, ["s3:GetObject"])
    _denied(as_credential(service, other, "POST",
                          f"/{bucket}/assembled.bin?uploadId={upload_id}",
                          body))
    # The upload was neither completed nor consumed...
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200
    # ...and no object was published.
    assert signed(service, "GET",
                  f"/{bucket}/assembled.bin").status_code == 404


def test_abort_multipart_upload_requires_delete_object_scope(service):
    bucket = _make_bucket(service, "auth-abort-bucket")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    other = scoped(service, ["s3:PutObject"])
    _denied(as_credential(service, other, "DELETE",
                          f"/{bucket}/assembled.bin?uploadId={upload_id}"))
    # The upload survived the unauthorized abort.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200


# ---------------------------------------------------------------------------
# The bucket-encryption trio (gap 5): s3:Get/Put/DeleteBucketEncryption.
# ---------------------------------------------------------------------------

def test_get_bucket_encryption_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-encryption-bucket")
    other = scoped(service, ["s3:PutBucketEncryption"])
    _denied(as_credential(service, other, "GET", f"/{bucket}?encryption"))


def test_put_bucket_encryption_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-encryption-bucket")
    other = scoped(service, ["s3:GetBucketEncryption"])
    _denied(as_credential(service, other, "PUT", f"/{bucket}?encryption",
                          EMPTY_ENCRYPTION_CONFIG))
    # Nothing was stored.
    assert signed(service, "GET",
                  f"/{bucket}?encryption").status_code == 404


def test_delete_bucket_encryption_requires_its_own_scope(service):
    bucket = _make_bucket(service, "auth-encryption-bucket")
    configured = signed(service, "PUT", f"/{bucket}?encryption",
                        EMPTY_ENCRYPTION_CONFIG)
    assert configured.status_code == 200, configured.text
    other = scoped(service, ["s3:GetBucketEncryption"])
    _denied(as_credential(service, other, "DELETE", f"/{bucket}?encryption"))
    # The configuration survives the unauthorized delete.
    assert signed(service, "GET",
                  f"/{bucket}?encryption").status_code == 200
