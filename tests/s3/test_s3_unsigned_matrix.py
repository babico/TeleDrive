"""Every supported S3 operation refuses an UNSIGNED request.

This is the "missing / auth-failed" column of the per-operation matrix in
`docs/S3_SPECS.md`, applied generically instead of per-operation: one table
maps each supported manifest operation to the AWS-shaped request that names
it, and the sweep sends that request with **no** Authorization header.

The contract for every entry:

* the gateway answers 401 or 403 (never 2xx, never a redirect to 2xx),
* no object or bucket in the fixture changes,
* zero bytes reach Telegram.

The table is keyed by manifest name, so the pair of meta-assertions below
make it impossible to add a supported operation without deciding what its
unauthenticated request looks like. An operation that genuinely has no
request shape (none do) must be listed in `EXPLICITLY_EXEMPT` with a reason.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.s3.test_s3_gateway import service, signed

ROOT = Path(__file__).resolve().parents[2]
B = "/auth-bucket"
K = "/auth-bucket/asset.bin"

# manifest operation name -> the AWS-shaped request that addresses it.
# Every entry is sent UNSIGNED, so only the selector/method matters.
REQUESTS: dict[str, tuple[str, str]] = {
    # -- service / bucket lifecycle ------------------------------------------
    "CreateBucket": ("PUT", "/auth-bucket-new"),
    "HeadBucket": ("HEAD", B),
    "DeleteBucket": ("DELETE", "/auth-bucket-empty"),
    "ListBuckets": ("GET", "/"),
    "GetBucketLocation": ("GET", f"{B}?location"),
    # -- listing -------------------------------------------------------------
    "ListObjects": ("GET", B),
    "ListObjectsV2": ("GET", f"{B}?list-type=2"),
    "ListObjectVersions": ("GET", f"{B}?versions"),
    "ListMultipartUploads": ("GET", f"{B}?uploads"),
    "ListDirectoryBuckets": ("GET", "/?x-id=ListDirectoryBuckets"),
    # -- objects -------------------------------------------------------------
    "PutObject": ("PUT", K),
    "GetObject": ("GET", K),
    "HeadObject": ("HEAD", K),
    "DeleteObject": ("DELETE", K),
    "DeleteObjects": ("POST", f"{B}?delete"),
    "CopyObject": ("PUT", "/auth-bucket/copy.bin"),
    "GetObjectAttributes": ("GET", f"{K}?attributes"),
    "RenameObject": ("PUT", "/auth-bucket/renamed.bin?renameObject"),
    "SelectObjectContent": ("POST", f"{K}?select&select-type=2"),
    "UpdateObjectEncryption": ("PUT", K),
    # -- multipart -----------------------------------------------------------
    "CreateMultipartUpload": ("POST", f"{K}?uploads"),
    "UploadPart": ("PUT", f"{K}?partNumber=1&uploadId=missing"),
    "UploadPartCopy": ("PUT", f"{K}?partNumber=1&uploadId=missing"),
    "ListParts": ("GET", f"{K}?uploadId=missing"),
    "CompleteMultipartUpload": ("POST", f"{K}?uploadId=missing"),
    "AbortMultipartUpload": ("DELETE", f"{K}?uploadId=missing"),
    # -- bucket tagging / cors / versioning ----------------------------------
    "GetBucketTagging": ("GET", f"{B}?tagging"),
    "PutBucketTagging": ("PUT", f"{B}?tagging"),
    "DeleteBucketTagging": ("DELETE", f"{B}?tagging"),
    "GetObjectTagging": ("GET", f"{K}?tagging"),
    "PutObjectTagging": ("PUT", f"{K}?tagging"),
    "DeleteObjectTagging": ("DELETE", f"{K}?tagging"),
    "GetBucketCors": ("GET", f"{B}?cors"),
    "PutBucketCors": ("PUT", f"{B}?cors"),
    "DeleteBucketCors": ("DELETE", f"{B}?cors"),
    "GetBucketVersioning": ("GET", f"{B}?versioning"),
    "PutBucketVersioning": ("PUT", f"{B}?versioning"),
    # -- public access block / lifecycle -------------------------------------
    "GetPublicAccessBlock": ("GET", f"{B}?publicAccessBlock"),
    "PutPublicAccessBlock": ("PUT", f"{B}?publicAccessBlock"),
    "DeletePublicAccessBlock": ("DELETE", f"{B}?publicAccessBlock"),
    "GetBucketLifecycle": ("GET", f"{B}?lifecycle"),
    "PutBucketLifecycle": ("PUT", f"{B}?lifecycle"),
    "GetBucketLifecycleConfiguration": ("GET", f"{B}?lifecycle"),
    "PutBucketLifecycleConfiguration": ("PUT", f"{B}?lifecycle"),
    "DeleteBucketLifecycle": ("DELETE", f"{B}?lifecycle"),
    # -- ACL / ownership -----------------------------------------------------
    "GetBucketAcl": ("GET", f"{B}?acl"),
    "PutBucketAcl": ("PUT", f"{B}?acl"),
    "GetObjectAcl": ("GET", f"{K}?acl"),
    "PutObjectAcl": ("PUT", f"{K}?acl"),
    "GetBucketOwnershipControls": ("GET", f"{B}?ownershipControls"),
    "PutBucketOwnershipControls": ("PUT", f"{B}?ownershipControls"),
    "DeleteBucketOwnershipControls": ("DELETE", f"{B}?ownershipControls"),
    # -- policy --------------------------------------------------------------
    "GetBucketPolicy": ("GET", f"{B}?policy"),
    "PutBucketPolicy": ("PUT", f"{B}?policy"),
    "DeleteBucketPolicy": ("DELETE", f"{B}?policy"),
    "GetBucketPolicyStatus": ("GET", f"{B}?policyStatus"),
    # -- encryption / object lock --------------------------------------------
    "GetBucketEncryption": ("GET", f"{B}?encryption"),
    "PutBucketEncryption": ("PUT", f"{B}?encryption"),
    "DeleteBucketEncryption": ("DELETE", f"{B}?encryption"),
    "GetObjectLockConfiguration": ("GET", f"{B}?object-lock"),
    "PutObjectLockConfiguration": ("PUT", f"{B}?object-lock"),
    "GetObjectRetention": ("GET", f"{K}?retention"),
    "PutObjectRetention": ("PUT", f"{K}?retention"),
    "GetObjectLegalHold": ("GET", f"{K}?legal-hold"),
    "PutObjectLegalHold": ("PUT", f"{K}?legal-hold"),
    # -- replication / restore -----------------------------------------------
    "GetBucketReplication": ("GET", f"{B}?replication"),
    "PutBucketReplication": ("PUT", f"{B}?replication"),
    "DeleteBucketReplication": ("DELETE", f"{B}?replication"),
    "RestoreObject": ("POST", f"{K}?restore"),
    # -- website / notification / logging ------------------------------------
    "GetBucketWebsite": ("GET", f"{B}?website"),
    "PutBucketWebsite": ("PUT", f"{B}?website"),
    "DeleteBucketWebsite": ("DELETE", f"{B}?website"),
    "GetBucketNotification": ("GET", f"{B}?notification"),
    "GetBucketNotificationConfiguration": ("GET", f"{B}?notification"),
    "PutBucketNotification": ("PUT", f"{B}?notification"),
    "PutBucketNotificationConfiguration": ("PUT", f"{B}?notification"),
    "GetBucketLogging": ("GET", f"{B}?logging"),
    "PutBucketLogging": ("PUT", f"{B}?logging"),
    # -- analytics / inventory / metrics / intelligent tiering ---------------
    "GetBucketAnalyticsConfiguration": ("GET", f"{B}?analytics&id=x"),
    "PutBucketAnalyticsConfiguration": ("PUT", f"{B}?analytics&id=x"),
    "DeleteBucketAnalyticsConfiguration": ("DELETE", f"{B}?analytics&id=x"),
    "ListBucketAnalyticsConfigurations": ("GET", f"{B}?analytics"),
    "GetBucketInventoryConfiguration": ("GET", f"{B}?inventory&id=x"),
    "PutBucketInventoryConfiguration": ("PUT", f"{B}?inventory&id=x"),
    "DeleteBucketInventoryConfiguration": ("DELETE", f"{B}?inventory&id=x"),
    "ListBucketInventoryConfigurations": ("GET", f"{B}?inventory"),
    "GetBucketMetricsConfiguration": ("GET", f"{B}?metrics&id=x"),
    "PutBucketMetricsConfiguration": ("PUT", f"{B}?metrics&id=x"),
    "DeleteBucketMetricsConfiguration": ("DELETE", f"{B}?metrics&id=x"),
    "ListBucketMetricsConfigurations": ("GET", f"{B}?metrics"),
    "GetBucketIntelligentTieringConfiguration": (
        "GET", f"{B}?intelligent-tiering&id=x"),
    "PutBucketIntelligentTieringConfiguration": (
        "PUT", f"{B}?intelligent-tiering&id=x"),
    "DeleteBucketIntelligentTieringConfiguration": (
        "DELETE", f"{B}?intelligent-tiering&id=x"),
    "ListBucketIntelligentTieringConfigurations": (
        "GET", f"{B}?intelligent-tiering"),
    # -- metadata configuration / annotations / abac -------------------------
    "CreateBucketMetadataConfiguration": ("POST", f"{B}?metadataConfiguration"),
    "CreateBucketMetadataTableConfiguration": ("POST", f"{B}?metadataTable"),
    "GetBucketMetadataConfiguration": ("GET", f"{B}?metadataConfiguration"),
    "GetBucketMetadataTableConfiguration": ("GET", f"{B}?metadataTable"),
    "DeleteBucketMetadataConfiguration": ("DELETE", f"{B}?metadataConfiguration"),
    "DeleteBucketMetadataTableConfiguration": ("DELETE", f"{B}?metadataTable"),
    "UpdateBucketMetadataAnnotationTableConfiguration": (
        "PUT", f"{B}?metadataAnnotationTable"),
    "UpdateBucketMetadataInventoryTableConfiguration": (
        "PUT", f"{B}?metadataInventoryTable"),
    "UpdateBucketMetadataJournalTableConfiguration": (
        "PUT", f"{B}?metadataJournalTable"),
    "GetObjectAnnotation": ("GET", f"{K}?annotation&annotationName=a"),
    "PutObjectAnnotation": ("PUT", f"{K}?annotation&annotationName=a"),
    "DeleteObjectAnnotation": ("DELETE", f"{K}?annotation&annotationName=a"),
    "ListObjectAnnotations": ("GET", f"{K}?annotation"),
    "GetBucketAbac": ("GET", f"{B}?abac"),
    "PutBucketAbac": ("PUT", f"{B}?abac"),
    # -- request payment / accelerate / express ------------------------------
    "GetBucketRequestPayment": ("GET", f"{B}?requestPayment"),
    "PutBucketRequestPayment": ("PUT", f"{B}?requestPayment"),
    "GetBucketAccelerateConfiguration": ("GET", f"{B}?accelerate"),
    "PutBucketAccelerateConfiguration": ("PUT", f"{B}?accelerate"),
    "CreateSession": ("GET", "/auth-bucket-new/session"),
}

# Operations that cannot be expressed as a request shape. Empty, and every
# addition needs a reason in the comment beside it -- the meta-test below
# fails if an operation is missing without appearing here.
EXPLICITLY_EXEMPT: dict[str, str] = {}


def _supported_operations() -> list[str]:
    manifest = json.loads(
        (ROOT / "teledrive/s3/operation_manifest.json").read_text())
    return sorted(op["name"] for op in manifest["operations"]
                  if op.get("status") == "supported")


def test_the_table_covers_every_supported_operation():
    """A new supported operation must decide what its unsigned request is."""
    supported = set(_supported_operations())
    mapped = set(REQUESTS) | set(EXPLICITLY_EXEMPT)
    unmapped = sorted(supported - mapped)
    stale = sorted(mapped - supported)
    assert not unmapped, f"supported operations with no unsigned request: {unmapped}"
    assert not stale, f"table names operations that are not supported: {stale}"


@pytest.mark.parametrize("operation", sorted(REQUESTS))
def test_an_unsigned_request_is_rejected_and_changes_nothing(service, operation):
    """No Authorization header at all: 401/403, no mutation, no bytes."""
    method, path = REQUESTS[operation]
    client, _creds, telegram, _conn, _key = service

    # A real bucket and object exist, so a missing auth check has something
    # to corrupt rather than answering 404 by accident.
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", K, b"auth-matrix-bytes").status_code == 200
    uploads_before = telegram.uploads

    reply = client.request(method, path, content=b"" if method != "PUT" else b"")

    assert reply.status_code in (401, 403), (
        f"{operation}: an unsigned {method} {path} answered "
        f"{reply.status_code}: {reply.text[:200]}")

    # The fixture is intact and nothing moved.
    assert signed(service, "HEAD", K).status_code == 200
    head = signed(service, "HEAD", K)
    assert head.headers["content-length"] == str(len(b"auth-matrix-bytes"))
    assert telegram.uploads == uploads_before


def test_batch_version_delete_queues_media_for_gc(service):
    """The batch-delete GC enqueue must actually run.

    `RetainedMediaGC(db)` referenced an unbound name in this function, and a
    bare `except Exception: pass` swallowed the NameError -- so the
    "queue the revoked version's media" step had never executed and media was
    reclaimed only by a later broad sweep. An ImportError-free reference is
    not enough: the queue row is the observable outcome.
    """
    from sqlalchemy import text
    client, _creds, _telegram, connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", K, b"gc-queue-bytes").status_code == 200

    db = connection()
    try:
        oid = db.connection.execute(text(
            "SELECT object_id FROM storage_object_heads WHERE bucket = :b"),
            {"b": "auth-bucket"}).scalar_one()
        # Physical GC must be enabled for the enqueue to happen at all.
        db.connection.execute(text(
            "INSERT INTO storage_gc_state (id, enabled, updated_ns, updated_by) "
            "VALUES (1, :e, :n, 'test') "
            "ON CONFLICT (id) DO UPDATE SET enabled = :e"),
            {"e": True, "n": 1})
        db.connection.commit()
    finally:
        db.close()

    body = (
        "<Delete><Object><Key>asset.bin</Key>"
        f"<VersionId>{oid}</VersionId></Object></Delete>").encode()
    import base64 as _b64
    import hashlib as _hashlib
    reply = signed(service, "POST", f"{B}?delete", body, extra_headers={
        "Content-MD5": _b64.b64encode(
            _hashlib.md5(body, usedforsecurity=False).digest()).decode()})
    assert reply.status_code == 200, reply.text

    db = connection()
    try:
        queued = db.connection.execute(text(
            "SELECT COUNT(*) FROM storage_gc_queue WHERE object_id = :o"),
            {"o": oid}).scalar_one()
    finally:
        db.close()
    assert queued == 1, "the revoked version was never queued for collection"
