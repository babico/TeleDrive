"""Upload checksum verification and effective ETag helpers.

Move-only extraction from ``web/s3.py`` (handoff 01, step 3).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import zlib

from fastapi import Request

from teledrive.s3.checksums import crc32c, crc64nvme
from teledrive.s3.multipart import MultipartStore
from teledrive.s3.object_metadata import signed_header_names
from teledrive.s3.sigv4 import STREAMING_MODES, SigV4Error
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.sse import CUSTOMER_ALGORITHM, CUSTOMER_KEY_MD5


def _verify_upload_sha256(
    request: Request, digest: bytes, *, md5_digest: bytes | None = None,
    sha1_digest: bytes | None = None,
    crc64nvme_value: int | None = None,
    trailer: dict[str, str] | None = None,
) -> None:
    """Verify *every* supplied checksum, not only the first matching digest.

    Signature verification and upload checksum validation are independent.
    A valid SHA-256 content digest must never permit a contradictory
    Content-MD5, SHA-1 or x-amz-checksum-sha256 to go unreported.
    aws-chunked requests carry checksums in the TRAILER instead of
    headers; the trailer dict is consulted as a header extension.
    """

    def checksum_header(name: str) -> str | None:
        value = request.headers.get(name)
        if value is None and trailer is not None:
            value = trailer.get(name)
        return value

    actual = base64.b64encode(digest).decode("ascii")
    sha256_header = checksum_header("x-amz-checksum-sha256")
    if sha256_header is not None and not hmac.compare_digest(sha256_header, actual):
        raise SigV4Error("BadDigest", "SHA-256 checksum mismatch")
    md5_header = checksum_header("content-md5")
    if md5_header is not None:
        if md5_digest is None or not hmac.compare_digest(
            md5_header, base64.b64encode(md5_digest).decode("ascii")
        ):
            raise SigV4Error("BadDigest", "Content-MD5 checksum mismatch")
    crc64_header = checksum_header("x-amz-checksum-crc64nvme")
    if crc64_header is not None:
        if crc64nvme_value is None:
            # Never acknowledge an unverified CRC64NVME declaration.
            raise SigV4Error("NotImplemented", "CRC64NVME not verified on this operation")
        actual_crc64 = base64.b64encode(
            crc64nvme_value.to_bytes(8, "big")
        ).decode("ascii")
        if not hmac.compare_digest(crc64_header, actual_crc64):
            raise SigV4Error("BadDigest", "CRC64NVME checksum mismatch")
    sha1_header = checksum_header("x-amz-checksum-sha1")
    if sha1_header is not None:
        if sha1_digest is None or not hmac.compare_digest(
            sha1_header, base64.b64encode(sha1_digest).decode("ascii")
        ):
            raise SigV4Error("BadDigest", "SHA-1 checksum mismatch")
    declared = checksum_header("x-amz-sdk-checksum-algorithm")
    if declared is not None:
        allowed = {"SHA1": "x-amz-checksum-sha1", "SHA256": "x-amz-checksum-sha256",
                   "CRC32": "x-amz-checksum-crc32",
                   "CRC32C": "x-amz-checksum-crc32c",
                   "CRC64NVME": "x-amz-checksum-crc64nvme"}
        if declared not in allowed:
            raise SigV4Error("NotImplemented", "Unsupported SDK checksum algorithm")
        if checksum_header(allowed[declared]) is None:
            raise SigV4Error("BadDigest", "Declared SDK checksum is missing")

    hexdigest = digest.hex()
    signed_content = request.headers.get("x-amz-content-sha256", "")
    presigned = "X-Amz-Algorithm" in request.query_params
    if signed_content == hexdigest:
        return
    if signed_content in STREAMING_MODES:
        # aws-chunked: every chunk signature was verified during decoding
        # (signed modes) and every supplied header/trailer checksum was
        # checked above — that IS the payload integrity proof.
        return
    if sha256_header is not None and hmac.compare_digest(sha256_header, actual):
        return
    if (not presigned and signed_content == "UNSIGNED-PAYLOAD"
            and md5_header is not None and md5_digest is not None):
        # Header-mode SigV4 has already authenticated the signed MD5 header.
        if "content-md5" in signed_header_names(request):
            return
    raise SigV4Error("XAmzContentSHA256Mismatch", "Signed upload checksum mismatch")


def _verify_bucket_control_payload(request: Request, body: bytes) -> None:
    """Exact signed checksum policy for small S3 bucket-control XML payloads."""
    import zlib
    for header, actual in (
        ("x-amz-checksum-crc32", zlib.crc32(body) & 0xffffffff),
        ("x-amz-checksum-crc32c", crc32c(body)),
    ):
        declared = request.headers.get(header)
        if declared is not None and not hmac.compare_digest(
            declared, base64.b64encode(actual.to_bytes(4, "big")).decode(),
        ):
            raise SigV4Error("BadDigest", "Bucket XML checksum mismatch")
    _verify_upload_sha256(
        request, hashlib.sha256(body).digest(),
        md5_digest=hashlib.md5(body, usedforsecurity=False).digest(),
        sha1_digest=hashlib.sha1(body, usedforsecurity=False).digest(),
        crc64nvme_value=crc64nvme(body),
    )


def _effective_object_etag(catalog: BucketCatalog, item) -> str:
    """S3 ETag: the ciphertext digest for SSE-C, else the layout/plaintext one.

    SSE-C objects must not advertise a plaintext MD5/ETag (AWS never does).
    """
    info = catalog.manifests.encryption_info(item.id)
    if info is not None and info.get("etag"):
        return str(info["etag"])
    return MultipartStore(catalog).object_etag(item.id, item.sha256)


def _ssec_response_headers(key) -> dict[str, str]:
    """AWS SSE-C response headers.  Never include the key itself."""
    return {
        CUSTOMER_ALGORITHM: "AES256",
        CUSTOMER_KEY_MD5: key.key_md5_b64,
    }
