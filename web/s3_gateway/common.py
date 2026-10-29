"""Shared S3 gateway helpers.

Move-only extraction from ``web/s3.py`` (handoff 01, steps 4-5).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import parse_qsl

from fastapi.responses import Response

from teledrive.s3.aws_chunked import streaming_mode
from teledrive.s3.checksums import crc64nvme
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.object_metadata import signed_header_names
from teledrive.s3.sigv4 import SigV4Error
from teledrive.s3.tagging import TaggingError, validate_tags

from web.app import _enforce_bucket_quota
from web.s3_gateway.checksums import (
    _verify_bucket_control_payload, _verify_upload_sha256,
)
from web.s3_gateway.xml import _error, _parse_tag_xml


def storage_transport(db):
    """Resolve the transport through ``web.s3``.

    ``tests/s3`` monkeypatches ``gateway.storage_transport`` (the attribute on
    the ``web.s3`` module).  Extracted handlers must keep resolving that name
    at call time, exactly like the original free-global lookup did.
    """
    from web import s3

    return s3.storage_transport(db)


def _chunk_size():
    """Resolve the chunk size through ``web.s3`` for the same reason."""
    from web import s3

    return s3.RECOMMENDED_CHUNK_SIZE


def _notification_allowlist():
    """Resolve the allowlist through ``web.s3`` for the same reason."""
    from web import s3

    return s3._notification_allowlist()


def _quota_guard(db, bucket: str, key: str, size: int) -> Response | None:
    """Enforce TeleDrive per-bucket quotas on S3-path uploads.

    Returns an S3-style 413 error response when the upload would exceed the
    configured quota, or None when the upload may proceed. The REST upload
    path enforces the same policy inside web.app.
    """
    from fastapi import HTTPException as _HTTPException
    try:
        _enforce_bucket_quota(db, bucket, key, size)
    except _HTTPException as exc:
        return _error("EntityTooLarge", str(exc.detail), 413)
    return None


def _reject_unimplemented_write_options(request: Request) -> None:
    """Fail closed for dangerous S3 semantics we cannot yet guarantee.

    In particular, acknowledging encryption, retention, ACL or a storage
    class without implementing its semantics would mislead backup clients.
    Do not stage bytes or contact Telegram when any option is present.
    """
    rejected = {
        "x-amz-grant-read", "x-amz-grant-write",
        "x-amz-grant-full-control", "x-amz-grant-read-acp",
        "x-amz-grant-write-acp",
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-server-side-encryption-context",
        # SSE-C customer-key headers are handled by dedicated routes below;
        # every operation that cannot honour them rejects them explicitly.
        "x-amz-bucket-key-enabled",
        "x-amz-website-redirect-location", "x-amz-object-lock-mode",
        "x-amz-object-lock-retain-until-date", "x-amz-object-lock-legal-hold",
        "x-amz-request-payer", "x-amz-trailer",
        "x-amz-bypass-governance-retention", "x-amz-mfa",
        "x-amz-expected-bucket-owner",
        "x-amz-decoded-content-length",
    }
    if streaming_mode(request) is not None:
        # aws-chunked streaming uploads legitimately carry the trailer
        # declaration and the decoded length; the decoder enforces both
        # (and sigv4 requires a signed x-amz-trailer).
        rejected -= {"x-amz-trailer", "x-amz-decoded-content-length"}
    # The S3 gateway is permanently private and has exactly one storage
    # tier, so these explicit default values do not change actual behavior.
    # ``bucket-owner-full-control`` is accepted because Phase L5 gives it
    # real meaning under BucketOwnerPreferred. Reject every other canned
    # ACL / storage-class rather than pretending to provide public-read,
    # Glacier, Standard-IA or replicated durability.
    defaults = {
        "x-amz-storage-class": "STANDARD",
    }
    signed = signed_header_names(request)
    for name, expected in defaults.items():
        actual = request.headers.get(name)
        if actual is None:
            continue
        if name not in signed:
            raise SigV4Error("AccessDenied", "S3 access mode must be signed")
        if actual != expected:
            raise SigV4Error("NotImplemented", "Unsupported S3 ACL or storage tier")
    canned_acl = request.headers.get("x-amz-acl")
    if canned_acl is not None:
        if "x-amz-acl" not in signed:
            raise SigV4Error("AccessDenied", "S3 access mode must be signed")
        if canned_acl not in {"private", "bucket-owner-full-control"}:
            raise SigV4Error("NotImplemented", "Unsupported S3 ACL or storage tier")
    if (any(name in request.headers for name in rejected)
            or (request.headers.get("content-encoding", "").lower() == "aws-chunked"
                and streaming_mode(request) is None)):
        raise SigV4Error(
            "NotImplemented",
            "S3 encryption, retention, ACL, storage class or aws-chunked semantics unsupported",
        )


def _initial_tags(request: Request, owner: str, credentials: S3CredentialStore):
    """Parse only SigV4-bound x-amz-tagging; never let an unsigned header mutate metadata."""
    raw = request.headers.get("x-amz-tagging")
    if raw is None:
        return None
    if len(raw.encode("utf-8")) > 8192:
        raise TaggingError("InvalidTag", "Tag header is too large")
    if "X-Amz-Algorithm" in request.query_params:
        signed = request.query_params.get("X-Amz-SignedHeaders", "").split(";")
    else:
        auth = request.headers.get("authorization", "")
        signed = auth.partition("SignedHeaders=")[2].split(",", 1)[0].split(";")
    if "x-amz-tagging" not in signed:
        raise SigV4Error("AccessDenied", "x-amz-tagging must be signed")
    if credentials.resolve(owner, "s3:PutObjectTagging") is None:
        raise SigV4Error("AccessDenied", "PutObjectTagging permission required")
    return _parse_initial_tags(raw)


def _parse_initial_tags(raw: str) -> list[tuple[str, str]]:
    """Strictly decode and validate either signed header or POST form tags."""
    import re
    if len(raw.encode("utf-8")) > 8192:
        raise TaggingError("InvalidTag", "Tag payload is too large")
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
        raise TaggingError("InvalidTag", "Malformed tag URL encoding")
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=10)
    except (UnicodeError, ValueError) as exc:
        raise TaggingError("InvalidTag", "Malformed tagging header") from exc
    return validate_tags(pairs)


async def _tag_request_tags(request: Request, *, bucket: bool = False) -> list[tuple[str, str]]:
    body = bytearray()
    async for block in request.stream():
        body.extend(block)
        if len(body) > (256 * 1024 if bucket else 16 * 1024):
            raise TaggingError("MalformedXML", "Tagging XML exceeds maximum size")
    if bucket:
        _verify_bucket_control_payload(request, bytes(body))
    else:
        _verify_upload_sha256(
            request, hashlib.sha256(body).digest(), crc64nvme_value=crc64nvme(body),
        )
        md5_header = request.headers.get("content-md5")
        if md5_header and not hmac.compare_digest(
            md5_header,
            base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii")
        ):
            raise TaggingError("BadDigest", "Content-MD5 checksum mismatch")
    return _parse_tag_xml(bytes(body), bucket=bucket)


# --- AWS read-compatibility for optional, unconfigured features -----------
#
# Real-world clients (s3fs, Cyberduck, Terraform, MinIO tools) probe these
# optional AWS features at startup. TeleDrive answers with valid AWS-shaped
# READ responses for the enforced private-only model; every configuration
# attempt fails closed with 501 before any SQL or Telegram side effect.

_COMPAT_BUCKET_READS: dict[str, str] = {
    "acl": "s3:GetBucketAcl",
    "ownershipControls": "s3:GetOwnershipControls",
    "policy": "s3:GetBucketPolicy",
    "website": "s3:GetBucketWebsite",
    "logging": "s3:GetBucketLogging",
    "notification": "s3:GetBucketNotification",
    "notificationConfiguration": "s3:GetBucketNotification",
    "requestPayment": "s3:GetBucketRequestPayment",
    "accelerate": "s3:GetAccelerateConfiguration",
    "object-lock": "s3:GetBucketObjectLockConfiguration",
}

_COMPAT_OBJECT_READS: dict[str, str] = {
    "acl": "s3:GetObjectAcl",
    "retention": "s3:GetObjectRetention",
    "legal-hold": "s3:GetObjectLegalHold",
}
