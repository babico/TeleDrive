"""P2 adversarial sweep: every manifest-unsupported operation fails closed.

Driven directly by teledrive/s3/operation_manifest.json: for each
operation still marked unsupported, the mapped AWS-shaped request is
sent with a VALID signature against a live gateway listener. The
contract: no accidental 2xx, no mutation of the existing bucket or
object, and zero Telegram traffic. This closes the spec checklist item
"for unsupported operations, add adversarial selector/HTTP method
tests: no accidental HTTP 200 or mutation".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.s3.test_s3_gateway import service, signed

ROOT = Path(__file__).resolve().parents[2]

# Unsupported operation -> the AWS-shaped request that names it.
# Selector ops map to their subresource; endpoint-shaped ops (sessions,
# WriteGetObjectResponse) map to their documented URI shapes.
REQUESTS = {
    # P2-C — access control writes
    "DeletePublicAccessBlock": ("DELETE", "/sweep-bucket?publicAccessBlock"),
    "PutBucketOwnershipControls": ("PUT", "/sweep-bucket?ownershipControls"),
    "DeleteBucketOwnershipControls": ("DELETE", "/sweep-bucket?ownershipControls"),
    "PutBucketPolicy": ("PUT", "/sweep-bucket?policy"),
    "DeleteBucketPolicy": ("DELETE", "/sweep-bucket?policy"),
    # P2-B — retention writes. PutBucketEncryption/DeleteBucketEncryption
    # and UpdateObjectEncryption are REAL SSE-C operations now — covered by
    # tests/s3/test_s3_sse_c.py.
    # P2-D — replication and restore. RestoreObject is now a real operation
    # (honest 403 InvalidObjectState) ahead of the central inventory sync.
    # P2-F — website, notifications, logging writes
    "PutBucketWebsite": ("PUT", "/sweep-bucket?website"),
    "DeleteBucketWebsite": ("DELETE", "/sweep-bucket?website"),
    # P3-G — analytics / inventory / metrics / intelligent-tiering
    "GetBucketAnalyticsConfiguration": ("GET", "/sweep-bucket?analytics&id=x"),
    "PutBucketAnalyticsConfiguration": ("PUT", "/sweep-bucket?analytics&id=x"),
    "DeleteBucketAnalyticsConfiguration": ("DELETE", "/sweep-bucket?analytics&id=x"),
    "ListBucketAnalyticsConfigurations": ("GET", "/sweep-bucket?analytics"),
    "GetBucketInventoryConfiguration": ("GET", "/sweep-bucket?inventory&id=x"),
    "PutBucketInventoryConfiguration": ("PUT", "/sweep-bucket?inventory&id=x"),
    "DeleteBucketInventoryConfiguration": ("DELETE", "/sweep-bucket?inventory&id=x"),
    "ListBucketInventoryConfigurations": ("GET", "/sweep-bucket?inventory"),
    "GetBucketMetricsConfiguration": ("GET", "/sweep-bucket?metrics&id=x"),
    "PutBucketMetricsConfiguration": ("PUT", "/sweep-bucket?metrics&id=x"),
    "DeleteBucketMetricsConfiguration": ("DELETE", "/sweep-bucket?metrics&id=x"),
    "ListBucketMetricsConfigurations": ("GET", "/sweep-bucket?metrics"),
    "GetBucketIntelligentTieringConfiguration": ("GET", "/sweep-bucket?intelligent-tiering&id=x"),
    "PutBucketIntelligentTieringConfiguration": ("PUT", "/sweep-bucket?intelligent-tiering&id=x"),
    "DeleteBucketIntelligentTieringConfiguration": ("DELETE", "/sweep-bucket?intelligent-tiering&id=x"),
    "ListBucketIntelligentTieringConfigurations": ("GET", "/sweep-bucket?intelligent-tiering"),
    # P3-H — AWS-specific and directory-bucket services
    "CreateBucketMetadataConfiguration": ("POST", "/sweep-bucket?metadataConfiguration"),
    "CreateBucketMetadataTableConfiguration": ("POST", "/sweep-bucket?metadataTable"),
    "GetBucketMetadataConfiguration": ("GET", "/sweep-bucket?metadataConfiguration"),
    "GetBucketMetadataTableConfiguration": ("GET", "/sweep-bucket?metadataTable"),
    "DeleteBucketMetadataConfiguration": ("DELETE", "/sweep-bucket?metadataConfiguration"),
    "DeleteBucketMetadataTableConfiguration": ("DELETE", "/sweep-bucket?metadataTable"),
    "UpdateBucketMetadataAnnotationTableConfiguration": ("PUT", "/sweep-bucket?metadataAnnotationTable"),
    "UpdateBucketMetadataInventoryTableConfiguration": ("PUT", "/sweep-bucket?metadataInventoryTable"),
    "UpdateBucketMetadataJournalTableConfiguration": ("PUT", "/sweep-bucket?metadataJournalTable"),
    "GetObjectAnnotation": ("GET", "/sweep-bucket/asset.bin?annotation"),
    "PutObjectAnnotation": ("PUT", "/sweep-bucket/asset.bin?annotation"),
    "DeleteObjectAnnotation": ("DELETE", "/sweep-bucket/asset.bin?annotation"),
    "ListObjectAnnotations": ("GET", "/sweep-bucket/asset.bin?annotations"),
    "GetBucketAbac": ("GET", "/sweep-bucket?abac"),
    "PutBucketAbac": ("PUT", "/sweep-bucket?abac"),
    "PutBucketRequestPayment": ("PUT", "/sweep-bucket?requestPayment"),
    "PutBucketAccelerateConfiguration": ("PUT", "/sweep-bucket?accelerate"),
    "GetObjectTorrent": ("GET", "/sweep-bucket/asset.bin?torrent"),
    "CreateSession": ("POST", "/sweep-bucket/asset.bin?session"),
    "ListDirectoryBuckets": ("GET", "/?list-type=directory"),
    "RenameObject": ("PUT", "/sweep-bucket/asset.bin?rename"),
    "SelectObjectContent": ("POST", "/sweep-bucket/asset.bin?select&select-type=2"),
    "WriteGetObjectResponse": ("POST", "/WriteGetObjectResponse"),
}


# Operations implemented ahead of the centrally-synced inventory. They are
# still listed in the manifest as unsupported until the owner promotes them,
# so keep the manifest-driven mapping intact and skip only their runtime
# assertion (their real behavior is covered by tests/s3/test_s3_website.py).
PROMOTED_AHEAD_OF_MANIFEST = frozenset({
    "PutBucketWebsite", "DeleteBucketWebsite",
    # Phase O is implemented ahead of the centrally-synced inventory.
    "RenameObject", "SelectObjectContent", "RestoreObject",
    "GetObjectAnnotation", "PutObjectAnnotation",
    "DeleteObjectAnnotation", "ListObjectAnnotations",
    "PutBucketRequestPayment", "PutBucketAccelerateConfiguration",
    # Phase N: analytics/inventory/metrics configuration CRUD.
    "GetBucketAnalyticsConfiguration", "PutBucketAnalyticsConfiguration",
    "DeleteBucketAnalyticsConfiguration", "ListBucketAnalyticsConfigurations",
    "GetBucketInventoryConfiguration", "PutBucketInventoryConfiguration",
    "DeleteBucketInventoryConfiguration", "ListBucketInventoryConfigurations",
    "GetBucketMetricsConfiguration", "PutBucketMetricsConfiguration",
    "DeleteBucketMetricsConfiguration", "ListBucketMetricsConfigurations",
    # Phase N5: Intelligent-Tiering configuration CRUD.
    "GetBucketIntelligentTieringConfiguration",
    "PutBucketIntelligentTieringConfiguration",
    "DeleteBucketIntelligentTieringConfiguration",
    "ListBucketIntelligentTieringConfigurations",
    # Phase O3: S3 Metadata configuration is now promoted to "supported" in
    # the manifest; the sweep entries above are retained (and skipped) so
    # the mapping stays complete and the AWS method/selector shapes remain
    # documented in one place.
    "CreateBucketMetadataConfiguration",
    "CreateBucketMetadataTableConfiguration",
    "GetBucketMetadataConfiguration",
    "GetBucketMetadataTableConfiguration",
    "DeleteBucketMetadataConfiguration",
    "DeleteBucketMetadataTableConfiguration",
    "UpdateBucketMetadataAnnotationTableConfiguration",
    "UpdateBucketMetadataInventoryTableConfiguration",
    "UpdateBucketMetadataJournalTableConfiguration",
    # Phase L: policy engine, ownership controls, ABAC and PAB deletion.
    "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketOwnershipControls", "DeleteBucketOwnershipControls",
    "GetBucketAbac", "PutBucketAbac",
    "DeletePublicAccessBlock",
})


def _unsupported_operations() -> list[str]:
    manifest = json.loads(
        (ROOT / "teledrive/s3/operation_manifest.json").read_text())
    return [op["name"] for op in manifest["operations"]
            if op.get("status") == "unsupported"
            and op["name"] not in PROMOTED_AHEAD_OF_MANIFEST]


def test_every_unsupported_operation_is_mapped_by_the_sweep():
    """The sweep cannot silently skip a newly unsupported operation."""
    unmapped = [name for name in _unsupported_operations()
                if name not in REQUESTS]
    extra = [name for name in REQUESTS
             if name not in set(_unsupported_operations())
             and name not in PROMOTED_AHEAD_OF_MANIFEST]
    assert not unmapped, f"Unmapped unsupported operations: {unmapped}"
    assert not extra, f"Sweep maps supported/renamed operations: {extra}"


@pytest.mark.parametrize("operation", sorted(REQUESTS))
def test_unsupported_operation_never_succeeds_or_mutates(service, operation):
    if operation in PROMOTED_AHEAD_OF_MANIFEST:
        pytest.skip("Implemented ahead of the inventory sync")
    method, path = REQUESTS[operation]
    assert signed(service, "PUT", "/sweep-bucket").status_code == 200
    assert signed(service, "PUT", "/sweep-bucket/asset.bin",
                  b"sweep-protected-bytes").status_code == 200
    telegram = service[2]
    uploads_before = telegram.uploads

    reply = signed(service, method, path, b"<configuration/>"
                   if method in ("PUT", "POST") else b"")

    # Fail closed: never a success status, never a redirect-to-2xx.
    assert reply.status_code not in (200, 201, 204, 206, 301, 302), (
        operation, reply.status_code, reply.text[:200])

    # The existing bucket and object are untouched, and not one byte
    # moved to Telegram for an unsupported control operation.
    assert signed(service, "HEAD", "/sweep-bucket").status_code == 200
    head = signed(service, "HEAD", "/sweep-bucket/asset.bin")
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"sweep-protected-bytes"))
    assert telegram.uploads == uploads_before
