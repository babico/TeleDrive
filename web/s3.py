"""Telegram-backed path-style S3 gateway (initial core subset).

Run as a separate ASGI process at port 9000. Shares SQL metadata and Telegram
Bot API credentials with REST; never stores object bodies in another S3 service.
Unimplemented S3 operations explicitly return NotImplemented (501).

Phase O wire shapes implemented here:

* RenameObject: ``PUT /{bucket}/{destination}?renameObject`` with the source in
  signed ``x-amz-rename-source: bucket/source`` header (the AWS directory-bucket
  shape). TeleDrive also accepts standard buckets — a documented SUPERSET of
  AWS, which limits RenameObject to directory buckets — because the rename is a
  single SQL head move with no Telegram byte copy. Overwrite is rejected.
* SelectObjectContent: ``POST /{bucket}/{key}?select&select-type=2`` with the
  AWS XML request and a real AWS event-stream response (see teledrive/s3/select.py).
* RestoreObject: ``POST /{bucket}/{key}?restore`` with strict AWS XML; without
  an archive tier every object is immediately readable, so the truthful answer
  is ``403 InvalidObjectState`` (see teledrive/s3/restore.py).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import tempfile
import time
import zlib
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import unquote, parse_qsl, quote, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree as ET
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import insert, select, text, update

from teledrive.db import Database
from teledrive.s3.credentials import S3CredentialStore, load_master_key
from teledrive.s3.route_guard import (
    validate_s3_query, is_directory_bucket_listing, S3QueryError)
from teledrive.s3.bucket_listing import list_buckets_xml, BucketListingError
from teledrive.s3.directory_buckets import (
    create_session_error, list_directory_buckets_xml)
from teledrive.s3.checksums import crc32c, crc64nvme
from teledrive.s3.aws_chunked import AwsChunkedDecoder, streaming_mode
from teledrive.s3.sigv4 import (STREAMING_MODES, SigV4Error,
                                signing_service_hint, verify_header_signature)
from teledrive.s3.post_policy import parse_form, verify_post_policy, FORM_LIMIT
from teledrive.s3.multipart import MultipartStore, MultipartError, MAX_PARTS
from teledrive.s3.batch_delete import BatchDeleteError, MAX_XML_BYTES, parse_batch, verify_body
from teledrive.s3.conditions import http_last_modified, read_precondition
from teledrive.s3.write_conditions import (check_write_precondition,
    WritePreconditionError, ExpectedHead)
from teledrive.s3.tagging import (ObjectTagStore, BucketTagStore, TaggingError,
                                  validate_tags, object_tags)
from teledrive.s3.acl import (AclError, parse_acl_xml, render_acl_xml,
                              is_public_grant_set,
                              permits as acl_permits)
from teledrive.s3.cors import (BucketCORSStore, CORSError, MAX_CORS_XML_BYTES,
    parse_cors_xml, cors_xml, matching_rule, response_cors_headers)
from teledrive.s3.versioning import (VersioningError, MAX_VERSIONING_XML_BYTES,
    parse_versioning_xml, versioning_xml)
from teledrive.s3.public_access import (PublicAccessError, MAX_PUBLIC_ACCESS_XML_BYTES,
    parse_public_access_xml, public_access_xml)
from teledrive.s3.policy import (
    BucketAbacStore, BucketPolicyStore, PolicyError, MAX_POLICY_BYTES,
    evaluate as evaluate_policy, evaluate_abac,
    parse_abac_document, parse_policy,
)
from teledrive.s3.ownership import (
    OwnershipError, MAX_OWNERSHIP_XML_BYTES, parse_ownership_xml,
    ownership_xml,
)
from teledrive.s3.lifecycle import (LifecycleError, MAX_XML as MAX_LIFECYCLE_XML,
    BucketLifecycleStore, parse_lifecycle_xml, lifecycle_xml)
from teledrive.s3.replication import (ReplicationError,
    MAX_REPLICATION_XML_BYTES, BucketReplicationStore,
    parse_replication_xml, replication_xml)
from teledrive.s3.notifications import (
    NotificationError, NotificationStore, MAX_NOTIFICATION_XML_BYTES,
    MAX_LOGGING_XML_BYTES, approved_destinations, destination_is_approved,
    logging_xml, notification_xml, parse_logging_xml, parse_notification_xml,
)
from teledrive.s3.website import (
    MAX_WEBSITE_XML_BYTES, WebsiteConfigStore, WebsiteError,
    parse_website_xml, website_xml,
)
from teledrive.s3.annotations import (
    AnnotationError, AnnotationStore, MAX_ANNOTATION_RESULTS,
    MAX_ANNOTATION_VALUE_BYTES, annotation_etag, annotation_http_date,
    annotations_xml, continuation_token,
    parse_continuation_token, put_annotation_xml, validate_annotation_name,
    validate_annotation_prefix, validate_annotation_value,
)
from teledrive.s3.bucket_flags import (
    BucketFlagError, MAX_BUCKET_FLAG_XML_BYTES as MAX_BUCKET_FLAG_XML,
    accelerate_xml, parse_accelerate_xml, parse_request_payment_xml,
    request_payment_xml,
)
from teledrive.s3.report_configs import (
    MAX_REPORT_XML_BYTES, KINDS as REPORT_KINDS, NO_SUCH_CONFIGURATION,
    ReportConfigError, ReportConfigStore, config_xml as report_config_xml,
    list_xml as report_list_xml, parse_document as parse_report_document,
)
from teledrive.s3.metadata_journal import (
    MAX_METADATA_XML_BYTES, MetadataConfigurationError,
    MetadataConfigurationStore, configuration_xml as metadata_configuration_xml,
    parse_annotation_update as parse_metadata_annotation_update,
    parse_create_configuration as parse_metadata_create_configuration,
    parse_create_table_configuration as parse_metadata_create_table_configuration,
    parse_inventory_update as parse_metadata_inventory_update,
    parse_journal_update as parse_metadata_journal_update,
    table_configuration_xml as metadata_table_configuration_xml,
)
from teledrive.s3.object_metadata import (
    ObjectMetadataStore, ObjectMetadataError, parse_object_metadata, signed_header_names,
    STANDARD_HEADERS,
)
from teledrive.s3.select import (
    SelectError, MAX_REQUEST_XML_BYTES as MAX_SELECT_XML_BYTES,
    MAX_SCAN_BYTES as MAX_SELECT_SCAN_BYTES,
    build_event_stream, parse_select_request, run_select,
)
from teledrive.s3.restore import (
    RestoreError, MAX_RESTORE_XML_BYTES, is_applicable as _restore_is_applicable,
    is_restored as _restore_is_restored, parse_restore_request,
    restore_header as _restore_header,
)
from teledrive.s3.tiering import (
    MAX_TIERING_XML_BYTES, NO_SUCH_CONFIGURATION as NO_SUCH_TIERING_CONFIGURATION,
    TieringError, TieringStore, config_xml as tiering_config_xml,
    list_xml as tiering_list_xml, parse_document as parse_tiering_document,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.copy import copy_object, CopyConflict
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.manifest import ManifestStore, objects
from teledrive.storage.sse import (
    CUSTOMER_ALGORITHM, CUSTOMER_KEY_MD5, CUSTOMER_HEADERS, SOURCE_PREFIX,
    SSECError, parse_ssec_headers, verify_chunk_layout, verify_key_md5,
)
from teledrive.s3.bucket_encryption import (
    MAX_ENCRYPTION_XML_BYTES, BucketEncryptionError, BucketEncryptionStore,
    encryption_xml, parse_encryption_xml,
)
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
import web.app as _webapp
from web.app import (db_connect, storage_transport, _secure_mkdir,
                     _enforce_bucket_quota, _log)

from web.s3_gateway.context import _S3RequestContext
from web.s3_gateway.xml import (
    _canned_private_acl_xml, _compat_bucket_read_response,
    _compat_object_read_response, _error, _list_xml, _parse_tag_xml,
    _tag_xml, _xml, _xml_ok,
)

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
app = FastAPI(title="TeleDrive S3 (initial compatibility subset)", docs_url=None,
              redoc_url=None, openapi_url=None)


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


def _headers(item, etag: str | None = None,
             metadata: dict[str, str] | None = None,
             *, checksum_mode: bool = False) -> dict[str, str]:
    headers = {
        "ETag": '"' + (etag or item.sha256) + '"',
        "Content-Length": str(item.size),
        "Accept-Ranges": "bytes",
        "Content-Type": "application/octet-stream",
        "Last-Modified": http_last_modified(item.created_at),
        "x-amz-version-id": item.id,
    }
    if checksum_mode:
        # The immutable manifest stores the digest of the FULL plaintext
        # object, independently of ETag/part layout. This is a real SHA-256,
        # not an invented checksum or AWS multipart checksum composition.
        headers["x-amz-checksum-sha256"] = base64.b64encode(
            bytes.fromhex(item.sha256)
        ).decode("ascii")
        headers["x-amz-checksum-type"] = "FULL_OBJECT"
    for name, value in (metadata or {}).items():
        # HTTP header names are case-insensitive. Do not emit both
        # Content-Type (the default) and content-type (persisted metadata):
        # SDK clients otherwise interpret them as a comma-joined MIME type.
        if name.lower() == "content-type":
            headers["Content-Type"] = value
        else:
            headers[name] = value
    return headers


def _ssec_response_headers(key) -> dict[str, str]:
    """AWS SSE-C response headers.  Never include the key itself."""
    return {
        CUSTOMER_ALGORITHM: "AES256",
        CUSTOMER_KEY_MD5: key.key_md5_b64,
    }


def _effective_object_etag(catalog: BucketCatalog, item) -> str:
    """S3 ETag: the ciphertext digest for SSE-C, else the layout/plaintext one.

    SSE-C objects must not advertise a plaintext MD5/ETag (AWS never does).
    """
    info = catalog.manifests.encryption_info(item.id)
    if info is not None and info.get("etag"):
        return str(info["etag"])
    return MultipartStore(catalog).object_etag(item.id, item.sha256)


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


def _range(value: str | None, size: int) -> tuple[int, int, bool]:
    if value is None:
        return 0, size, False
    import re
    # Same digit bound as the REST path: an over-long integer raises before
    # any comparison and would escape as a 500 instead of InvalidRange.
    match = re.fullmatch(r"bytes=(\d{0,20})-(\d{0,20})", value.strip())
    if not match or not (match.group(1) or match.group(2)) or size <= 0:
        raise SigV4Error("InvalidRange", "Unsupported byte range")
    first, last = match.groups()
    if first:
        start = int(first)
        end = min(int(last) + 1, size) if last else size
    else:
        amount = int(last)
        start, end = max(size - amount, 0), size
    if start >= size or start >= end or (not first and int(last) <= 0):
        raise SigV4Error("InvalidRange", "Unsatisfiable byte range")
    return start, end, True


def _cursor_encode(master: bytes, bucket: str, prefix: str, delimiter: str,
                   after: str, skip_prefix: str) -> str:
    payload = json.dumps(
        {"bucket": bucket, "prefix": prefix, "delimiter": delimiter,
         "after": after, "skip_prefix": skip_prefix},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = hmac.new(master, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _cursor_decode(token: str, master: bytes, bucket: str,
                   prefix: str, delimiter: str) -> tuple[str, str]:
    try:
        encoded, signature = token.split(".", 1)
        if len(token) > 4096 or not hmac.compare_digest(
            signature, hmac.new(master, encoded.encode(), hashlib.sha256).hexdigest()
        ):
            raise ValueError("Signature mismatch")
        parsed = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (not isinstance(parsed, dict) or parsed.get("bucket") != bucket
                or parsed.get("prefix") != prefix or parsed.get("delimiter") != delimiter
                or not isinstance(parsed.get("after"), str)
                or not isinstance(parsed.get("skip_prefix"), str)):
            raise ValueError("Cursor does not match request")
        return parsed["after"], parsed["skip_prefix"]
    except (ValueError, UnicodeError, TypeError, KeyError, binascii.Error) as exc:
        raise SigV4Error("InvalidArgument", "Invalid continuation token") from exc


def _page(catalog: BucketCatalog, bucket: str, prefix: str,
          delimiter: str, after: str, limit: int,
          skip_prefix: str) -> tuple[list, list[str], str, str, bool]:
    """Page over raw keys without splitting a common-prefix across pages.

    The last emitted prefix is carried in the signed continuation cursor
    so a folder containing >1000 objects is not shown repeatedly.
    """
    keys = []
    common = []
    seen = {skip_prefix} if skip_prefix else set()
    position = after
    last_consumed = after
    while True:
        batch = catalog.list_objects(bucket, prefix=prefix, after=position, limit=1000)
        if not batch:
            return keys, common, last_consumed, skip_prefix, False
        for item in batch:
            key = item.item.key
            tail = key[len(prefix):]
            common_name = ""
            if delimiter and delimiter in tail:
                common_name = prefix + tail.split(delimiter, 1)[0] + delimiter
            if common_name and common_name in seen:
                position = key
                last_consumed = key
                continue
            if len(keys) + len(common) >= limit:
                return keys, common, last_consumed, skip_prefix, True
            if common_name:
                common.append(common_name)
                seen.add(common_name)
                skip_prefix = common_name
            else:
                keys.append(item)
                skip_prefix = ""
            position = key
            last_consumed = key
        if len(batch) < 1000:
            return keys, common, last_consumed, skip_prefix, False


def _virtual_host_bucket(request: Request) -> str | None:
    """Use Host only when a public DNS suffix was explicitly configured.

    SigV4 must authenticate the exact Host afterwards; never trust proxy
    forwarding headers for bucket selection. The default remains path-style.
    """
    suffix = os.environ.get("TELEDRIVE_S3_VHOST_SUFFIX", "").strip().lower().strip(".")
    if not suffix:
        return None
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(suffix) > 253 or re.fullmatch(label + r"(?:\." + label + r")+", suffix) is None:
        raise SigV4Error("InvalidArgument", "Invalid virtual-host DNS suffix")
    authority = request.headers.get("host", "").lower()
    if authority.count(":") == 1 and authority.rsplit(":", 1)[1].isdigit():
        hostname = authority.rsplit(":", 1)[0]
    else:
        hostname = authority
    ending = "." + suffix
    if not hostname.endswith(ending):
        return None
    bucket = hostname[:-len(ending)]
    try:
        BucketCatalog.validate_bucket(bucket)
    except ValueError as exc:
        raise SigV4Error("InvalidArgument", "Invalid virtual-host bucket") from exc
    return bucket


# --- AWS read-compatibility for optional, unconfigured features -----------
#
# Real-world clients (s3fs, Cyberduck, Terraform, MinIO tools) probe these
# optional AWS features at startup. TeleDrive answers with valid AWS-shaped
# READ responses for the enforced private-only model; every configuration
# attempt fails closed with 501 before any SQL or Telegram side effect.

def _replication_destinations(db) -> set[str]:
    """Configured TeleDrive credential labels that can receive a replica.

    The live MTProto runtime is authoritative when it is loaded; the
    persisted ``telegram_sessions`` accounts keep the API usable before a
    runtime start (and match what the admin replication endpoint accepts).
    """
    labels: set[str] = set()
    runtime = getattr(_webapp, "mtproto_storage_runtime", None)
    transports = getattr(runtime, "transports", None)
    if callable(transports):
        try:
            labels.update(str(label) for label in transports())
        except Exception:
            pass
    try:
        rows = db.connection.execute(text(
            "SELECT account FROM telegram_sessions "
            "WHERE account IS NOT NULL AND account != ''")).all()
        labels.update(str(row[0]) for row in rows)
    except Exception:
        pass
    return labels


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


async def _handle_form_upload(ctx: _S3RequestContext) -> Response:
    """Browser POST policy upload (form-encoded payload, no SigV4 header)."""
    request, bucket, db, store = ctx.request, ctx.bucket, ctx.db, ctx.store
    if request.headers.get("authorization"):
        raise SigV4Error("AccessDenied", "Ambiguous form and header authentication")
    _reject_unimplemented_write_options(request)
    if any(name in request.headers for name in CUSTOMER_HEADERS):
        # Browser POST policies have no SSE-C contract; accepting the headers
        # would silently store plaintext the client believes is encrypted.
        return _error(
            "NotImplemented",
            "SSE-C customer keys are not accepted on form uploads", 501)
    max_upload = _webapp.REST_MAX_UPLOAD_BYTES
    form_limit = min(FORM_LIMIT, max_upload)
    if form_limit < 1:
        return _error("EntityTooLarge", "Form upload size is disabled", 413)
    form_bytes = bytearray()
    async for block in request.stream():
        form_bytes.extend(block)
        if len(form_bytes) > form_limit:
            return _error("EntityTooLarge", "Browser upload form too large", 413)
    post_fields, payload = parse_form(
        request.headers.get("content-type", ""), bytes(form_bytes),
    )
    post_key = verify_post_policy(
        post_fields, payload, bucket, store.resolve, max_bytes=form_limit,
    )
    # Signed form fields are validated using the same bounded
    # metadata contract as ordinary S3 PUT. Browser-controlled MIME,
    # cache rules and x-amz-meta-* values must not be silently
    # accepted without durable storage.
    post_headers = {
        name.lower(): value for name, value in post_fields.items()
        if name.lower() in STANDARD_HEADERS
        or name.startswith("x-amz-meta-")
    }
    post_metadata = parse_object_metadata(
        post_headers, set(post_headers),
    )
    # Tagging is a separate S3 capability, not included in generic
    # PutObject credentials. Enforce BOTH privileges before sending
    # even a single byte, then publish tags in the HEAD transaction.
    form_tags = None
    if "x-amz-tagging" in post_fields:
        credential_access = post_fields["x-amz-credential"].split("/", 1)[0]
        if store.resolve(credential_access, "s3:PutObjectTagging") is None:
            raise SigV4Error("AccessDenied", "PutObjectTagging permission required")
        form_tags = _parse_initial_tags(post_fields["x-amz-tagging"])
    post_catalog = BucketCatalog(ManifestStore(db))
    # Phase D ACL intersection gate for form uploads: the POST policy
    # already proved the credential's own PutObject scope; the bucket
    # ACL may still narrow access to this exact key.
    form_credential = post_fields["x-amz-credential"].split("/", 1)[0]
    allowed, reason = _authorize_resource(
        post_catalog, store, form_credential, "s3:PutObject",
        bucket, post_key, request)
    if not allowed:
        raise SigV4Error("AccessDenied", reason)
    if bucket not in post_catalog.list_buckets():
        return _error("NoSuchBucket", "Upload bucket does not exist", 404)
    directory = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(directory)
    fd, temp_name = tempfile.mkstemp(prefix="s3-form-", dir=directory)
    staged = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as dest:
            dest.write(payload)
            dest.flush()
            os.fsync(dest.fileno())
        transport = storage_transport(db)
        await transport.verify_target()
        quota_error = _quota_guard(db, bucket, post_key, len(payload))
        if quota_error is not None:
            return quota_error
        obj = await TelegramObjectStorage(
            post_catalog.manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE,
            scratch_directory=directory,
        ).put_file(bucket, post_key, staged)
        ObjectMetadataStore(post_catalog).attach_uncommitted(
            obj.id, post_metadata,
        )
        if form_tags is not None:
            ObjectTagStore(post_catalog).attach_uncommitted(
                obj.id, form_tags,
            )
        post_catalog.publish(obj.id, now=int(time.time()))
        _apply_bucket_owner_preferred(
            post_catalog, bucket, post_key, form_credential, request)
        etag = '"' + obj.sha256 + '"'
        response_headers = {"ETag": etag, "x-amz-version-id": obj.id}
        # A redirect is an explicit signed browser instruction. The
        # gateway never contacts the target and does not disclose
        # credentials or original payload in the callback parameters.
        redirect = post_fields.get("success_action_redirect")
        if redirect is not None:
            parsed_redirect = urlsplit(redirect)  # verified HTTPS URL
            parameters = urlencode({
                "bucket": bucket, "key": post_key, "etag": etag,
            })
            redirect_query = (parsed_redirect.query + "&" + parameters
                              if parsed_redirect.query else parameters)
            location = urlunsplit((
                parsed_redirect.scheme, parsed_redirect.netloc,
                parsed_redirect.path, redirect_query, "",
            ))
            return Response(status_code=303, headers={
                **response_headers, "Location": location,
            })
        # The requested response status is itself an exact signed
        # policy condition; no unsigned status override is accepted.
        status = int(post_fields.get("success_action_status", "204"))
        if status == 201:
            # Quote untrusted key text before placing it in Location.
            # The XML serializer escapes the same key in the body.
            location = (str(request.base_url).rstrip("/")
                        + "/" + quote(bucket, safe="")
                        + "/" + quote(post_key, safe="/"))
            response_headers["Location"] = location
            return Response(_xml("PostResponse", [
                ("Location", location), ("Bucket", bucket),
                ("Key", post_key), ("ETag", etag),
            ]), media_type="application/xml", status_code=201,
                headers=response_headers)
        return Response(status_code=status, headers=response_headers)
    finally:
        staged.unlink(missing_ok=True)


async def _handle_batch_delete(ctx: _S3RequestContext) -> Response:
    """POST ?delete: multi-object delete with a DeleteObjects XML body."""
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "The specified bucket does not exist", 404)
    if request.headers.get("x-amz-mfa") or request.headers.get(
        "x-amz-bypass-governance-retention"
    ):
        return _error("NotImplemented", "Retention/MFA Delete unsupported", 501)
    body = bytearray()
    async for block in request.stream():
        body.extend(block)
        if len(body) > MAX_XML_BYTES:
            raise BatchDeleteError("MalformedXML", "DeleteObjects XML exceeds 1 MiB")
    payload = bytes(body)
    verify_body(payload, request.headers)
    batch = parse_batch(payload)
    result = ET.Element("DeleteResult", xmlns=NAMESPACE)
    for key_to_delete, version_id in batch.entries:
        # Phase L: the request-level gate only sees the BUCKET path
        # (POST /bucket?delete has no object key), so a per-object
        # policy or ACL would never be consulted. Check every entry
        # against its own key, exactly like a single-object DELETE.
        allowed, reason = _authorize_resource(
            catalog, ctx.store, ctx.owner, "s3:DeleteObject", bucket,
            key_to_delete, request)
        if not allowed:
            problem = ET.SubElement(result, "Error")
            ET.SubElement(problem, "Key").text = key_to_delete
            if version_id is not None:
                ET.SubElement(problem, "VersionId").text = version_id
            ET.SubElement(problem, "Code").text = "AccessDenied"
            ET.SubElement(problem, "Message").text = reason
            continue
        if version_id is not None:
            # Explicit per-entry version deletion, the same semantics as
            # DELETE ?versionId on a single object.
            try:
                if not catalog.delete_version(bucket, key_to_delete,
                                              version_id):
                    problem = ET.SubElement(result, "Error")
                    ET.SubElement(problem, "Key").text = key_to_delete
                    ET.SubElement(problem, "VersionId").text = version_id
                    ET.SubElement(problem, "Code").text = "NoSuchVersion"
                    ET.SubElement(problem, "Message").text = (
                        "The specified version does not exist")
                    continue
                # GC-integrated delete: queue the revoked version's
                # media for physical collection (grace-fenced).
                try:
                    gcx = RetainedMediaGC(db)
                    if gcx.state()["enabled"]:
                        gcx.enqueue([version_id], "batch-version-delete")
                except Exception:
                    pass
            except ValueError:
                problem = ET.SubElement(result, "Error")
                ET.SubElement(problem, "Key").text = key_to_delete
                ET.SubElement(problem, "VersionId").text = version_id
                ET.SubElement(problem, "Code").text = "InvalidArgument"
                ET.SubElement(problem, "Message").text = "Invalid version ID"
                continue
            except PermissionError as exc:
                # Object-lock fence (retention/legal hold): per-entry
                # AccessDenied inside the 200 DeleteResult, like AWS.
                problem = ET.SubElement(result, "Error")
                ET.SubElement(problem, "Key").text = key_to_delete
                ET.SubElement(problem, "VersionId").text = version_id
                ET.SubElement(problem, "Code").text = "AccessDenied"
                ET.SubElement(problem, "Message").text = str(exc)
                continue
            if not batch.quiet:
                deleted = ET.SubElement(result, "Deleted")
                ET.SubElement(deleted, "Key").text = key_to_delete
                ET.SubElement(deleted, "VersionId").text = version_id
            continue
        try:
            marker = catalog.delete_marker(bucket, key_to_delete)
        except ValueError:
            problem = ET.SubElement(result, "Error")
            ET.SubElement(problem, "Key").text = key_to_delete
            ET.SubElement(problem, "Code").text = "InvalidObjectName"
            ET.SubElement(problem, "Message").text = "Invalid object name"
            continue
        if not batch.quiet:
            deleted = ET.SubElement(result, "Deleted")
            ET.SubElement(deleted, "Key").text = key_to_delete
            ET.SubElement(deleted, "VersionId").text = marker
            ET.SubElement(deleted, "DeleteMarker").text = "true"
            ET.SubElement(deleted, "DeleteMarkerVersionId").text = marker
    return Response(ET.tostring(result, encoding="utf-8", xml_declaration=True),
                    media_type="application/xml", status_code=200)


def _notification_allowlist() -> tuple[str, ...]:
    """Owner-approved webhook destinations (storage.notification_destinations)."""
    raw = os.environ.get("TELEDRIVE_NOTIFICATION_DESTINATIONS", "")
    try:
        storage = getattr(_webapp.effective_config(), "storage", None)
        if isinstance(storage, dict) and storage.get("notification_destinations"):
            raw = str(storage["notification_destinations"])
    except Exception:
        pass
    return approved_destinations(raw)


async def _handle_bucket_metadata_configuration(
        ctx: _S3RequestContext) -> Response:
    """Phase O3: S3 Metadata configuration and real journal-backed GET.

    Real AWS selectors (verified against the API reference):
      * ``?metadataConfiguration``        POST/GET/DELETE (V2)
      * ``?metadataTable``                POST/GET/DELETE (V1)
      * ``?metadataJournalTable``         PUT
      * ``?metadataInventoryTable``       PUT
      * ``?metadataAnnotationTable``      PUT

    GET renders the stored configuration plus statistics from the real
    ``storage_metadata_journal`` table. The table identifiers are documented
    TeleDrive strings, never fabricated AWS S3 Tables ARNs.
    """
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "Bucket does not exist", 404)
    store = MetadataConfigurationStore(catalog)
    selector = ctx.metadata_selector

    async def read_body() -> bytes:
        payload = bytearray()
        async for block in request.stream():
            payload.extend(block)
            if len(payload) > MAX_METADATA_XML_BYTES:
                raise MetadataConfigurationError(
                    "MalformedXML",
                    "Metadata configuration XML exceeds 16 KiB")
        body = bytes(payload)
        if body:
            _verify_bucket_control_payload(request, body)
        return body

    if selector == "metadataConfiguration":
        if request.method == "POST":
            parsed = parse_metadata_create_configuration(await read_body())
            store.create(bucket, parsed)
            return Response(status_code=200)
        if request.method == "GET":
            config = store.get_with_stats(bucket)
            if config is None:
                return _error(
                    NO_SUCH_CONFIGURATION,
                    "The specified metadata configuration does not exist", 404)
            return Response(
                metadata_configuration_xml(
                    bucket, config, config["journal_stats"]),
                media_type="application/xml")
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise MetadataConfigurationError(
                        "InvalidRequest",
                        "DeleteBucketMetadataConfiguration cannot have a body")
            store.delete(bucket)
            return Response(status_code=204)
        return _error("MethodNotAllowed",
                      "Use POST, GET or DELETE for metadataConfiguration", 405)

    if selector == "metadataTable":
        if request.method == "POST":
            parsed = parse_metadata_create_table_configuration(await read_body())
            store.create(bucket, parsed)
            return Response(status_code=200)
        # AWS documents that the V1 GET/DELETE operations answer 405 for a
        # configuration created through the V2 API.
        config = store.get(bucket)
        if request.method == "GET":
            if config is None:
                return _error(
                    NO_SUCH_CONFIGURATION,
                    "The specified metadata configuration does not exist", 404)
            if config.get("api_version") == 2:
                return _error(
                    "MethodNotAllowed",
                    "This bucket has a V2 metadata configuration; use "
                    "GetBucketMetadataConfiguration", 405)
            with_stats = store.get_with_stats(bucket)
            return Response(
                metadata_table_configuration_xml(
                    bucket, with_stats, with_stats["journal_stats"]),
                media_type="application/xml")
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise MetadataConfigurationError(
                        "InvalidRequest",
                        "DeleteBucketMetadataTableConfiguration cannot have "
                        "a body")
            if config is not None and config.get("api_version") == 2:
                return _error(
                    "MethodNotAllowed",
                    "This bucket has a V2 metadata configuration; use "
                    "DeleteBucketMetadataConfiguration", 405)
            store.delete(bucket)
            return Response(status_code=204)
        return _error("MethodNotAllowed",
                      "Use POST, GET or DELETE for metadataTable", 405)

    if selector == "metadataJournalTable":
        if request.method != "PUT":
            return _error("MethodNotAllowed",
                          "Use PUT for metadataJournalTable", 405)
        retention = parse_metadata_journal_update(await read_body())
        store.update_journal(bucket, retention)
        return Response(status_code=200)

    if selector == "metadataInventoryTable":
        if request.method != "PUT":
            return _error("MethodNotAllowed",
                          "Use PUT for metadataInventoryTable", 405)
        enabled = parse_metadata_inventory_update(await read_body())
        store.update_inventory(bucket, enabled)
        return Response(status_code=200)

    if selector == "metadataAnnotationTable":
        if request.method != "PUT":
            return _error("MethodNotAllowed",
                          "Use PUT for metadataAnnotationTable", 405)
        enabled, role = parse_metadata_annotation_update(await read_body())
        store.update_annotation(bucket, enabled, role)
        return Response(status_code=200)

    return _error("NotImplemented", "Unsupported metadata operation", 501)
async def _handle_bucket_encryption(ctx: _S3RequestContext) -> Response:
    """Bucket encryption configuration (SSE-C only).

    There is no bucket-level default key: SSE-C keys are supplied per
    request and never retained.  GET returns the honest stored (empty) rule
    set or a 404; PUT accepts only an empty ServerSideEncryptionConfiguration;
    any AES256 (SSE-S3) or aws:kms default is rejected 501 because no
    server-side key exists for data the client did not encrypt.
    """
    request, bucket, catalog = ctx.request, ctx.bucket, ctx.catalog
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "Bucket does not exist", 404)
    store = BucketEncryptionStore(ctx.db)
    if request.method == "GET":
        rules = store.get(bucket)
        if rules is None:
            return _error(
                "ServerSideEncryptionConfigurationNotFoundError",
                "The server side encryption configuration was not found", 404)
        return Response(encryption_xml(rules), media_type="application/xml")
    if request.method == "PUT":
        payload = bytearray()
        async for block in request.stream():
            payload.extend(block)
            if len(payload) > MAX_ENCRYPTION_XML_BYTES:
                raise BucketEncryptionError(
                    "MalformedXML", "Encryption XML exceeds 16 KiB")
        _verify_bucket_control_payload(request, bytes(payload))
        store.replace(bucket, parse_encryption_xml(bytes(payload)), ctx.owner)
        return Response(status_code=200)
    if request.method == "DELETE":
        async for block in request.stream():
            if block:
                raise BucketEncryptionError(
                    "InvalidRequest",
                    "DeleteBucketEncryption cannot have a body")
        store.delete(bucket)
        return Response(status_code=204)
    return _error("NotImplemented", "Unsupported bucket encryption method", 501)


async def _handle_bucket_controls(ctx: _S3RequestContext) -> Response | None:
    """Bucket control subresources: policy status, lifecycle, public access
    block, versioning, CORS and tagging. Returns None when the request does
    not select any control subresource."""
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    if ctx.metadata_selector is not None:
        return await _handle_bucket_metadata_configuration(ctx)
    if ctx.is_bucket_encryption:
        return await _handle_bucket_encryption(ctx)
    if ctx.is_bucket_policy:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = BucketPolicyStore(catalog)
        if request.method == "GET":
            document = store.get(bucket)
            if document is None:
                return _error("NoSuchBucketPolicy",
                              "The bucket policy does not exist", 404)
            return Response(document, media_type="application/json")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_POLICY_BYTES:
                    raise PolicyError("MalformedPolicy",
                                      "Bucket policy exceeds 20 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            compiled = parse_policy(bytes(payload), bucket=bucket,
                                    credential_store=ctx.store)
            store.replace(bucket, compiled, ctx.owner)
            return Response(status_code=204)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise PolicyError(
                        "InvalidRequest",
                        "DeleteBucketPolicy cannot have a body")
            store.delete(bucket)
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported bucket policy method", 501)
    if ctx.is_bucket_ownership:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        if request.method == "GET":
            return Response(
                ownership_xml(catalog.object_ownership(bucket)),
                media_type="application/xml")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_OWNERSHIP_XML_BYTES:
                    raise OwnershipError("MalformedXML",
                                         "Ownership controls XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            catalog.set_object_ownership(
                bucket, parse_ownership_xml(bytes(payload)))
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise OwnershipError(
                        "InvalidRequest",
                        "DeleteBucketOwnershipControls cannot have a body")
            catalog.clear_object_ownership(bucket)
            return Response(status_code=204)
        return _error("NotImplemented",
                      "Unsupported ownership controls method", 501)
    if ctx.is_bucket_abac:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = BucketAbacStore(catalog)
        if request.method == "GET":
            state = store.get(bucket)
            document = (state or {}).get("document") or {"Status": "Disabled"}
            return Response(
                json.dumps(document, sort_keys=True, separators=(",", ":")),
                media_type="application/json")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_POLICY_BYTES:
                    raise PolicyError("MalformedPolicy",
                                      "ABAC document exceeds 20 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            store.replace(bucket, parse_abac_document(bytes(payload)),
                          ctx.owner)
            return Response(status_code=200)
        return _error("NotImplemented", "Unsupported ABAC method", 501)
    if ctx.is_bucket_policy_status:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        # IsPublic is computed from the actual stored grants and the
        # bucket's PAB flags. Grantee principals are validated access
        # keys, so public grantees are unwritable and the honest scan
        # can only ever answer false — but the computation runs the
        # real data, and IgnorePublicAcls implements the AWS semantics
        # of ignoring public grants when set.
        flags = catalog.public_access_block(bucket)
        _, grants = catalog.bucket_acl(bucket)
        is_public = (is_public_grant_set(grants)
                     and not flags.get("IgnorePublicAcls", True))
        return Response(
            _xml("PolicyStatus", [("IsPublic", "true" if is_public else "false")]),
            media_type="application/xml")
    if ctx.report_kind is not None:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        kind = ctx.report_kind
        store = ReportConfigStore(catalog)
        config_id = request.query_params.get("id")
        if request.method == "GET":
            if config_id is not None:
                if not config_id:
                    return _error("InvalidArgument",
                                  "Report configuration id is empty", 400)
                value = store.get(bucket, kind, config_id)
                if value is None:
                    # AWS uses NoSuchConfiguration for analytics, inventory
                    # AND metrics GETs (not NoSuchInventoryConfiguration).
                    return _error(
                        NO_SUCH_CONFIGURATION,
                        "The specified configuration does not exist", 404)
                return Response(report_config_xml(kind, value),
                                media_type="application/xml")
            return Response(report_list_xml(kind, store.list(bucket, kind)),
                            media_type="application/xml")
        if request.method == "PUT":
            body = bytearray()
            async for block in request.stream():
                body.extend(block)
                if len(body) > MAX_REPORT_XML_BYTES:
                    raise ReportConfigError(
                        "MalformedXML",
                        "Report configuration XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(body))
            config = parse_report_document(
                kind, bytes(body), expected_id=config_id)
            store.put(bucket, kind, config_id, config)
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise ReportConfigError(
                        "InvalidRequest",
                        "Delete report configuration cannot have a body")
            store.delete(bucket, kind, config_id)
            return Response(status_code=204)
        return _error("NotImplemented",
                      "Unsupported report configuration method", 501)
    if ctx.is_bucket_tiering:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = TieringStore(catalog)
        config_id = request.query_params.get("id")
        if request.method == "GET":
            if config_id is not None:
                if not config_id:
                    return _error("InvalidArgument",
                                  "Tiering configuration id is empty", 400)
                value = store.get(bucket, config_id)
                if value is None:
                    return _error(
                        NO_SUCH_TIERING_CONFIGURATION,
                        "The specified configuration does not exist", 404)
                return Response(tiering_config_xml(value),
                                media_type="application/xml")
            return Response(tiering_list_xml(store.list(bucket)),
                            media_type="application/xml")
        if request.method == "PUT":
            body = bytearray()
            async for block in request.stream():
                body.extend(block)
                if len(body) > MAX_TIERING_XML_BYTES:
                    raise TieringError(
                        "MalformedXML",
                        "Tiering configuration XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(body))
            config = parse_tiering_document(bytes(body), expected_id=config_id)
            store.put(bucket, config_id, config)
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise TieringError(
                        "InvalidRequest",
                        "Delete tiering configuration cannot have a body")
            store.delete(bucket, config_id)
            return Response(status_code=204)
        return _error("NotImplemented",
                      "Unsupported tiering configuration method", 501)
    if ctx.is_bucket_website:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = WebsiteConfigStore(catalog)
        if request.method == "GET":
            config = store.get(bucket)
            if config is None or not config.get("enabled", True):
                return _error(
                    "NoSuchWebsiteConfiguration",
                    "The specified bucket does not have a website "
                    "configuration", 404)
            return Response(website_xml(config), media_type="application/xml")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_WEBSITE_XML_BYTES:
                    raise WebsiteError("MalformedXML",
                                       "Website XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            store.replace(bucket, parse_website_xml(bytes(payload)))
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise WebsiteError(
                        "InvalidRequest",
                        "DeleteBucketWebsite cannot have a body")
            # Atomic: removes the configuration and revokes public_read,
            # so a deleted site never leaves a publicly readable bucket.
            store.delete(bucket)
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported website method", 501)
    if ctx.is_bucket_notification:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = NotificationStore(catalog, master_key=ctx.master)
        if request.method == "GET":
            return Response(notification_xml(store.get_config(bucket)),
                            media_type="application/xml")
        if request.method == "PUT":
            body = bytearray()
            async for block in request.stream():
                body.extend(block)
                if len(body) > MAX_NOTIFICATION_XML_BYTES:
                    raise NotificationError(
                        "MalformedXML", "Notification XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(body))
            config = parse_notification_xml(bytes(body))
            if config is not None and not destination_is_approved(
                    config["destination"], _notification_allowlist()):
                raise NotificationError(
                    "AccessDenied",
                    "Webhook destination is not in the owner-approved "
                    "notification allowlist (storage.notification_destinations)",
                    403,
                )
            store.replace_config(bucket, config)
            return Response(status_code=200)
        return _error(
            "NotImplemented",
            "DeleteBucketNotificationConfiguration is not an S3 operation; "
            "PUT an empty NotificationConfiguration to disable events", 501)
    if ctx.is_bucket_logging:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = NotificationStore(catalog, master_key=ctx.master)
        if request.method == "GET":
            return Response(logging_xml(store.get_logging(bucket)),
                            media_type="application/xml")
        if request.method == "PUT":
            body = bytearray()
            async for block in request.stream():
                body.extend(block)
                if len(body) > MAX_LOGGING_XML_BYTES:
                    raise NotificationError(
                        "MalformedXML", "Logging XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(body))
            config = parse_logging_xml(bytes(body))
            if (config is not None
                    and config["target_bucket"] not in catalog.list_buckets()):
                raise NotificationError(
                    "InvalidTargetBucketForLogging",
                    "The logging target bucket does not exist", 400)
            store.replace_logging(bucket, config)
            return Response(status_code=200)
        return _error(
            "NotImplemented",
            "Put an empty BucketLoggingStatus to disable access logging", 501)
    if ctx.is_bucket_lifecycle:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket not found", 404)
        rules = BucketLifecycleStore(catalog)
        if request.method == "GET":
            value = rules.get(bucket)
            if value is None:
                return _error("NoSuchLifecycleConfiguration", "No lifecycle configuration", 404)
            return Response(lifecycle_xml(value), media_type="application/xml")
        if request.method == "PUT":
            data = bytearray()
            async for block in request.stream():
                data.extend(block)
                if len(data) > MAX_LIFECYCLE_XML:
                    raise LifecycleError("MalformedXML", "Lifecycle XML exceeds 32 KiB")
            _verify_bucket_control_payload(request, bytes(data))
            rules.replace(bucket, parse_lifecycle_xml(bytes(data)))
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise LifecycleError("InvalidRequest", "DeleteBucketLifecycle cannot have body")
            rules.replace(bucket, None)
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported lifecycle method", 501)
    if ctx.is_bucket_replication:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        store = BucketReplicationStore(
            catalog, destinations=lambda: _replication_destinations(ctx.db))
        if request.method == "GET":
            config = store.get(bucket)
            if config is None:
                return _error(
                    "ReplicationConfigurationNotFoundError",
                    "The specified bucket does not have a replication "
                    "configuration", 404)
            return Response(replication_xml(config), media_type="application/xml")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_REPLICATION_XML_BYTES:
                    raise ReplicationError(
                        "MalformedXML", "Replication XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            store.replace(bucket, parse_replication_xml(
                bytes(payload), store.destination_labels()))
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise ReplicationError(
                        "InvalidRequest",
                        "DeleteBucketReplication cannot have a body")
            store.delete(bucket)
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported replication method", 501)
    if ctx.is_public_access_block:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        if request.method == "GET":
            return Response(
                public_access_xml(catalog.public_access_block(bucket)),
                media_type="application/xml")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_PUBLIC_ACCESS_XML_BYTES:
                    raise PublicAccessError("MalformedXML",
                                            "Public access XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            flags = parse_public_access_xml(bytes(payload))
            catalog.set_public_access_block(bucket, flags)
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise PublicAccessError(
                        "InvalidRequest",
                        "DeletePublicAccessBlock cannot have a body")
            catalog.clear_public_access_block(bucket)
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported public access method", 501)
    if ctx.is_bucket_versioning:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        if request.method == "GET":
            return Response(
                versioning_xml(catalog.versioning_state(bucket)),
                media_type="application/xml")
        if request.method == "PUT":
            payload = bytearray()
            async for block in request.stream():
                payload.extend(block)
                if len(payload) > MAX_VERSIONING_XML_BYTES:
                    raise VersioningError("MalformedXML",
                                          "Versioning XML exceeds 16 KiB")
            _verify_bucket_control_payload(request, bytes(payload))
            state = parse_versioning_xml(bytes(payload))
            catalog.set_versioning(bucket, state)
            return Response(status_code=200)
        return _error("NotImplemented", "Unsupported bucket versioning method", 501)
    if ctx.is_bucket_cors:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        cors_store = BucketCORSStore(catalog)
        if request.method == "GET":
            rules = cors_store.get(bucket)
            if rules is None:
                return _error("NoSuchCORSConfiguration", "No CORS configuration", 404)
            return Response(cors_xml(rules), media_type="application/xml")
        if request.method == "PUT":
            body = bytearray()
            async for block in request.stream():
                body.extend(block)
                if len(body) > MAX_CORS_XML_BYTES:
                    raise CORSError("MalformedXML", "CORS XML exceeds 64 KiB")
            _verify_upload_sha256(
                request, hashlib.sha256(body).digest(),
                crc64nvme_value=crc64nvme(body),
            )
            md5_header = request.headers.get("content-md5")
            if md5_header and not hmac.compare_digest(
                md5_header,
                base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()
            ):
                raise CORSError("BadDigest", "Content-MD5 mismatch")
            cors_store.replace(bucket, parse_cors_xml(bytes(body)))
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise CORSError("InvalidRequest", "DeleteBucketCors must not have a body")
            cors_store.replace(bucket, [])
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported bucket CORS operation", 501)
    if ctx.is_bucket_tagging:
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        tagstore = BucketTagStore(catalog)
        if request.method == "GET":
            values = tagstore.get(bucket)
            if not values:
                return _error("NoSuchTagSet", "No bucket tag set exists", 404)
            return Response(_tag_xml(values), media_type="application/xml")
        if request.method == "PUT":
            tagstore.replace(bucket, await _tag_request_tags(request, bucket=True))
            return Response(status_code=200)
        if request.method == "DELETE":
            async for block in request.stream():
                if block:
                    raise TaggingError("InvalidRequest", "DeleteBucketTagging must have no body")
            tagstore.replace(bucket, [])
            return Response(status_code=204)
        return _error("NotImplemented", "Unsupported bucket tagging method", 501)
    return None


def _list_bucket_versions(ctx: _S3RequestContext) -> Response:
    """GET ?versions: ListObjectVersions response XML."""
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    if len(request.query_params.getlist("versions")) != 1 or (
        request.query_params.get("versions") not in ("",)
    ):
        return _error("InvalidArgument", "Invalid versions selector", 400)
    for marker in ("prefix", "max-keys", "key-marker", "version-id-marker",
                   "delimiter", "encoding-type"):
        if len(request.query_params.getlist(marker)) > 1:
            return _error("InvalidArgument", "Ambiguous version listing parameter", 400)
    delimiter = request.query_params.get("delimiter", "")
    encoding = request.query_params.get("encoding-type")
    if encoding not in (None, "url"):
        return _error("InvalidArgument", "Only encoding-type=url is supported", 400)
    if len(delimiter.encode("utf-8")) > 16:
        return _error("InvalidArgument", "Version delimiter is too long", 400)
    try:
        maximum = int(request.query_params.get("max-keys", "1000"))
        key_marker = request.query_params.get("key-marker", "")
        version_marker = request.query_params.get("version-id-marker", "")
        prefix = request.query_params.get("prefix", "")
        entries, has_more = catalog.list_bucket_versions(
            bucket, prefix=prefix, key_marker=key_marker,
            version_marker=version_marker, limit=maximum,
        )
    except ValueError:
        return _error("InvalidArgument", "Invalid version list cursor or limit", 400)
    # Delimiter grouping: keys sharing the prefix up to the first
    # delimiter collapse into one CommonPrefixes entry, counted against
    # max-keys exactly like AWS (versions + prefixes share the budget).
    common: list[str] = []
    grouped: list[dict] = []
    seen_prefixes: set[str] = set()
    grouped_more = has_more
    if delimiter:
        for index, entry in enumerate(entries):
            remainder = entry["key"][len(prefix):]
            cut = remainder.find(delimiter)
            if cut >= 0:
                common_prefix = prefix + remainder[:cut + len(delimiter)]
                if common_prefix in seen_prefixes:
                    continue
                if len(grouped) + len(common) >= maximum:
                    grouped_more = True
                    break
                seen_prefixes.add(common_prefix)
                common.append(common_prefix)
            else:
                if len(grouped) + len(common) >= maximum:
                    grouped_more = True
                    break
                grouped.append(entry)
        entries = grouped
        has_more = grouped_more
    encoded = (lambda value: quote(value, safe="")
               if encoding == "url" else value)
    root = ET.Element("ListVersionsResult", xmlns=NAMESPACE)
    for label, value in (
        ("Name", bucket), ("Prefix", encoded(prefix)),
        ("KeyMarker", encoded(key_marker)), ("VersionIdMarker", version_marker),
        ("MaxKeys", maximum), ("IsTruncated", str(has_more).lower()),
    ):
        ET.SubElement(root, label).text = str(value)
    if delimiter:
        ET.SubElement(root, "Delimiter").text = encoded(delimiter)
    if encoding:
        ET.SubElement(root, "EncodingType").text = encoding
    next_key_marker = None
    if has_more and (entries or common):
        next_key_marker = (common[-1] if not entries and common
                           else entries[-1]["key"])
    if next_key_marker is not None:
        ET.SubElement(root, "NextKeyMarker").text = encoded(next_key_marker)
        if entries and not common:
            ET.SubElement(root, "NextVersionIdMarker").text = \
                entries[-1]["version_id"]
    mpu = MultipartStore(catalog)
    for entry in entries:
        element = ET.SubElement(
            root, "DeleteMarker" if entry["is_delete_marker"] else "Version"
        )
        fields = [
            ("Key", encoded(entry["key"])), ("VersionId", entry["version_id"]),
            ("IsLatest", str(entry["is_current"]).lower()),
            ("LastModified", time.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z",
                time.gmtime(entry["committed_ns"] // 1_000_000_000),
            )),
        ]
        if not entry["is_delete_marker"]:
            fields += [
                ("ETag", '"' + mpu.object_etag(
                    entry["version_id"], entry["sha256"]
                ) + '"'),
                ("Size", entry["size"]), ("StorageClass", "STANDARD"),
            ]
        for label, value in fields:
            ET.SubElement(element, label).text = str(value)
    for name in common:
        ET.SubElement(ET.SubElement(root, "CommonPrefixes"),
                      "Prefix").text = encoded(name)
    return Response(
        ET.tostring(root, encoding="utf-8", xml_declaration=True),
        media_type="application/xml",
    )


def _list_multipart_uploads(ctx: _S3RequestContext) -> Response:
    """GET ?uploads: ListMultipartUploads response XML."""
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    owner = ctx.owner
    query = request.query_params
    prefix = query.get("prefix", "")
    delimiter = query.get("delimiter", "")
    encoding = query.get("encoding-type")
    if encoding not in (None, "url"):
        return _error("InvalidArgument", "Only encoding-type=url is supported", 400)
    if len(prefix.encode("utf-8")) > 1024 or len(delimiter.encode("utf-8")) > 16:
        return _error("InvalidArgument", "Multipart prefix/delimiter too long", 400)
    try:
        limit = int(query.get("max-uploads", "1000"))
    except ValueError:
        return _error("InvalidArgument", "Invalid max-uploads", 400)
    if not 1 <= limit <= 1000:
        return _error("InvalidArgument", "max-uploads must be 1..1000", 400)
    marker_key = query.get("key-marker", "")
    marker_id = query.get("upload-id-marker", "")
    if marker_id and not marker_key:
        return _error("InvalidArgument", "Upload-id marker requires key marker", 400)
    multipart = MultipartStore(catalog)
    if delimiter:
        entries, more, next_marker = multipart.list_uploads_grouped(
            bucket, owner, prefix=prefix, delimiter=delimiter,
            after_key=marker_key, after_id=marker_id, limit=limit,
        )
    else:
        records, more = multipart.list_uploads(
            bucket, owner, prefix=prefix, after_key=marker_key,
            after_id=marker_id, limit=limit,
        )
        entries = [("upload", record) for record in records]
        next_marker = ((records[-1].object_key, records[-1].id)
                       if records else ("", ""))

    encode = (lambda value: quote(value, safe="/") if encoding == "url" else value)
    root = ET.Element("ListMultipartUploadsResult", xmlns=NAMESPACE)
    for label, val in (
        ("Bucket", bucket), ("KeyMarker", encode(marker_key)),
        ("UploadIdMarker", marker_id), ("Prefix", encode(prefix)),
        ("MaxUploads", limit), ("IsTruncated", str(more).lower()),
    ):
        ET.SubElement(root, label).text = str(val)
    if delimiter:
        ET.SubElement(root, "Delimiter").text = encode(delimiter)
    if encoding:
        ET.SubElement(root, "EncodingType").text = encoding
    if more:
        ET.SubElement(root, "NextKeyMarker").text = encode(next_marker[0])
        ET.SubElement(root, "NextUploadIdMarker").text = next_marker[1]
    for kind, value in entries:
        if kind == "prefix":
            ET.SubElement(
                ET.SubElement(root, "CommonPrefixes"), "Prefix"
            ).text = encode(value)
            continue
        item = ET.SubElement(root, "Upload")
        for label, contents in (
            ("Key", encode(value.object_key)), ("UploadId", value.id),
            ("StorageClass", "STANDARD"),
            ("Initiated", time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                                        time.gmtime(value.created_at))),
        ):
            ET.SubElement(item, label).text = str(contents)
    return Response(ET.tostring(root, encoding="utf-8", xml_declaration=True),
                    media_type="application/xml")


def _list_objects(ctx: _S3RequestContext) -> Response:
    """GET bucket: ListObjects V1/V2 response XML."""
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    master = ctx.master
    list_type = request.query_params.get("list-type")
    if list_type not in (None, "2"):
        return _error("NotImplemented", "Only ListObjectsV1/V2 are supported", 501)
    version_one = list_type is None
    prefix = request.query_params.get("prefix", "")
    delimiter = request.query_params.get("delimiter", "")
    encoding_type = request.query_params.get("encoding-type")
    if encoding_type not in (None, "url"):
        return _error("InvalidArgument", "Unsupported list encoding-type", 400)
    fetch_owner = request.query_params.get("fetch-owner")
    if fetch_owner not in (None, "true", "false"):
        return _error("InvalidArgument", "fetch-owner must be true or false", 400)
    if len(prefix.encode("utf-8")) > 1024 or len(delimiter.encode("utf-8")) > 16:
        return _error("InvalidArgument", "Prefix or delimiter is too large", 400)
    if version_one:
        if any(p in request.query_params for p in ("continuation-token", "start-after")):
            return _error("InvalidArgument", "V2 cursor is not a V1 marker", 400)
        after = request.query_params.get("marker", "")
        # V1 NextMarker may denote a CommonPrefix. Skip every
        # descendant of that prefix instead of returning it again.
        skip_prefix = after if delimiter and after.endswith(delimiter) else ""
        token = None
    else:
        if "marker" in request.query_params:
            return _error("InvalidArgument", "V1 marker cannot be used with V2", 400)
        token = request.query_params.get("continuation-token")
        if token:
            after, skip_prefix = _cursor_decode(token, master, bucket, prefix, delimiter)
        else:
            after = request.query_params.get("start-after", "")
            skip_prefix = ""
    try:
        limit = int(request.query_params.get("max-keys", "1000"))
    except ValueError:
        return _error("InvalidArgument", "Invalid max-keys", 400)
    if limit < 1 or limit > 1000:
        return _error("InvalidArgument", "max-keys must be between 1 and 1000", 400)
    keys, common, last, skipped, more = _page(
        catalog, bucket, prefix, delimiter, after, limit, skip_prefix
    )
    next_token = (_cursor_encode(master, bucket, prefix, delimiter, last, skipped)
                  if more and not version_one else None)
    next_marker = (max([item.item.key for item in keys] + common)
                   if more and version_one and (keys or common) else None)
    tags = MultipartStore(catalog)
    return Response(_list_xml(bucket, keys, common, prefix, limit,
                              after if version_one or not token else "",
                              delimiter, more, next_token,
                              lambda obj: tags.object_etag(obj.id, obj.sha256),
                              version_one=version_one, next_marker=next_marker,
                              encoding_type=encoding_type,
                              include_owner=(version_one
                                             or fetch_owner == "true"),
                              owner=ctx.owner),
                    media_type="application/xml")


async def _handle_bucket_route(ctx: _S3RequestContext) -> Response:
    """Bucket-level requests: batch delete, control subresources, listings."""
    request = ctx.request
    bucket = ctx.bucket
    catalog = ctx.catalog
    if request.method == "GET" and "session" in request.query_params:
        # CreateSession issues S3 Express One Zone credentials for a
        # DIRECTORY bucket. TeleDrive implements no directory buckets, so no
        # session can ever be issued. The error distinguishes a malformed
        # name, an existing general-purpose bucket (InvalidRequest) and a
        # name that simply does not exist here (NoSuchBucket) — see
        # teledrive/s3/directory_buckets.py for the full justification.
        error = create_session_error(
            bucket,
            bucket_exists=bucket in catalog.list_buckets(),
            session_mode=request.headers.get("x-amz-create-session-mode"),
        )
        return _error(error.code, str(error), error.status)
    if ctx.multi_delete:
        return await _handle_batch_delete(ctx)
    controls = await _handle_bucket_controls(ctx)
    if controls is not None:
        return controls
    if request.method == "PUT" and "requestPayment" in request.query_params:
        # Phase O6: only Payer=BucketOwner is accepted; Requester -> 501.
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        payload = bytearray()
        async for block in request.stream():
            payload.extend(block)
            if len(payload) > MAX_BUCKET_FLAG_XML:
                raise BucketFlagError("MalformedXML",
                                      "Request payment XML exceeds 16 KiB")
        _verify_bucket_control_payload(request, bytes(payload))
        parse_request_payment_xml(bytes(payload))
        return Response(status_code=200)
    if request.method == "PUT" and "accelerate" in request.query_params:
        # Phase O6: only Suspended is accepted; Enabled -> 501.
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "Bucket does not exist", 404)
        payload = bytearray()
        async for block in request.stream():
            payload.extend(block)
            if len(payload) > MAX_BUCKET_FLAG_XML:
                raise BucketFlagError("MalformedXML",
                                      "Accelerate XML exceeds 16 KiB")
        _verify_bucket_control_payload(request, bytes(payload))
        parse_accelerate_xml(bytes(payload))
        return Response(status_code=200)
    if request.method == "PUT":
        try:
            catalog.create_bucket(bucket, int(time.time()))
        except ValueError:
            # AWS us-east-1 semantics: re-creating an owned bucket is
            # idempotent and answers 200. TeleDrive is single-owner
            # private, so an existing bucket is by definition owned by
            # the caller — clients like rclone rely on this during
            # their pre-upload bucket preparation.
            pass
        return Response(status_code=200)
    if request.method == "DELETE":
        try:
            catalog.delete_bucket(bucket)
        except ValueError as exc:
            raise MultipartError("BucketNotEmpty", str(exc), 409) from exc
        return Response(status_code=204)
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "The specified bucket does not exist", 404)
    if request.method == "HEAD":
        return Response(status_code=200)
    compat_selector = next(
        (name for name in _COMPAT_BUCKET_READS
         if name in request.query_params), None) if request.method == "GET" else None
    if compat_selector is not None:
        return _compat_bucket_read_response(compat_selector, ctx.owner)
    if "location" in request.query_params:
        if request.method != "GET":
            return _error("MethodNotAllowed", "GetBucketLocation requires GET", 405)
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "The specified bucket does not exist", 404)
        # AWS represents us-east-1 as an empty LocationConstraint.
        root = ET.Element("LocationConstraint", xmlns=NAMESPACE)
        return Response(
            ET.tostring(root, encoding="utf-8", xml_declaration=True),
            media_type="application/xml",
        )
    if ctx.is_version_listing:
        return _list_bucket_versions(ctx)
    if ctx.mpu_bucket_list:
        return _list_multipart_uploads(ctx)
    return _list_objects(ctx)


async def _handle_multipart(ctx: _S3RequestContext) -> Response:
    """Multipart upload operations on an object path (initiate, part,
    complete, abort, list parts)."""
    mpu = MultipartStore(ctx.catalog)
    if ctx.mpu_start:
        return await _mpu_initiate(ctx, mpu)
    upload_id = ctx.mpu_id
    if not upload_id:
        raise MultipartError("NoSuchUpload", "Missing UploadId", 404)
    if ctx.mpu_abort:
        # AWS requires the SSE-C key on AbortMultipartUpload too; verifying it
        # here keeps the upload's key binding meaningful on every verb.
        marker = mpu.encryption_marker(upload_id, ctx.bucket, ctx.key,
                                       ctx.owner)
        sse_key = parse_ssec_headers(ctx.request.headers,
                                     signed_header_names(ctx.request))
        if marker is not None:
            if sse_key is None or not hmac.compare_digest(
                    str(marker.get("key_md5", "")), sse_key.key_md5_b64):
                raise SSECError(
                    "InvalidRequest",
                    "AbortMultipartUpload requires the SSE-C key used to "
                    "create the upload")
        elif sse_key is not None:
            raise SSECError(
                "InvalidRequest",
                "The upload was not created with SSE-C; remove the customer "
                "key headers")
        # GC-integrated abort: with GC enabled, the staged part media is
        # queued for physical collection; disabled GC keeps the
        # journal-retention behavior (orphan protection pending GC).
        try:
            from teledrive.s3.multipart import parts as _part_rows
            part_ids = [row for row in ctx.db.connection.execute(
                select(_part_rows.c.object_id).where(
                    _part_rows.c.upload_id == upload_id)).scalars()]
        except Exception:
            part_ids = []
        mpu.abort(upload_id, ctx.bucket, ctx.key, ctx.owner)
        if part_ids:
            try:
                gcx = RetainedMediaGC(ctx.db)
                if gcx.state()["enabled"]:
                    gcx.enqueue(part_ids, "mpu-abort")
            except Exception:
                pass
        return Response(status_code=204)
    if ctx.mpu_list:
        return await _mpu_list_parts(ctx, mpu, upload_id)
    if ctx.mpu_complete:
        return await _mpu_complete(ctx, mpu, upload_id)
    return await _mpu_upload_part(ctx, mpu, upload_id)


async def _mpu_initiate(ctx: _S3RequestContext, mpu: MultipartStore) -> Response:
    """POST ?uploads: CreateMultipartUpload (metadata-only initiate)."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    owner = ctx.owner
    # Initiate is metadata-only. Reject any supplied body before
    # allocating a durable multipart session, including if a
    # leaked presigned URL is replayed with altered content.
    async for block in request.stream():
        if block:
            raise MultipartError(
                "InvalidRequest", "CreateMultipartUpload requires an empty body"
            )
    http_properties = parse_object_metadata(
        request.headers, signed_header_names(request),
    )
    sse_key = parse_ssec_headers(request.headers, signed_header_names(request))
    upload_id = mpu.initiate(
        bucket, key, owner, http_metadata=http_properties,
        sse_key_md5=(sse_key.key_md5_b64 if sse_key is not None else None),
    )
    headers = _ssec_response_headers(sse_key) if sse_key is not None else {}
    return Response(_xml("InitiateMultipartUploadResult", [
        ("Bucket", bucket), ("Key", key), ("UploadId", upload_id),
    ]), media_type="application/xml", status_code=200, headers=headers)


async def _mpu_list_parts(ctx: _S3RequestContext, mpu: MultipartStore,
                          upload_id: str) -> Response:
    """GET ?uploadId: ListParts response XML."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    owner = ctx.owner
    upload_encryption = mpu.encryption_marker(upload_id, bucket, key, owner)
    sse_key = parse_ssec_headers(request.headers, signed_header_names(request))
    if upload_encryption is not None:
        if sse_key is None or not hmac.compare_digest(
                str(upload_encryption.get("key_md5", "")), sse_key.key_md5_b64):
            raise SSECError(
                "InvalidRequest",
                "ListParts requires the SSE-C key used to create the upload")
    elif sse_key is not None:
        raise SSECError(
            "InvalidRequest",
            "The upload was not created with SSE-C; remove the customer key "
            "headers")
    try:
        raw_marker = request.query_params.get("part-number-marker", "0")
        raw_limit = request.query_params.get("max-parts", "1000")
        if (re.fullmatch(r"[0-9]{1,5}", raw_marker) is None
                or re.fullmatch(r"[0-9]{1,4}", raw_limit) is None):
            raise ValueError("Invalid decimal")
        marker = int(raw_marker)
        limit = int(raw_limit)
    except ValueError:
        raise MultipartError("InvalidArgument", "Invalid ListParts pagination")
    selected_parts, more = mpu.list_parts_page(
        upload_id, bucket, key, owner, marker=marker, limit=limit,
    )
    result = ET.Element("ListPartsResult", xmlns=NAMESPACE)
    for title, val in (
        ("Bucket", bucket), ("Key", key), ("UploadId", upload_id),
        ("PartNumberMarker", marker), ("MaxParts", limit),
        ("StorageClass", "STANDARD"),
        ("IsTruncated", str(more).lower()),
    ):
        ET.SubElement(result, title).text = str(val)
    if more:
        ET.SubElement(result, "NextPartNumberMarker").text = str(
            selected_parts[-1].number
        )
    for part in selected_parts:
        row = ET.SubElement(result, "Part")
        ET.SubElement(row, "PartNumber").text = str(part.number)
        ET.SubElement(row, "ETag").text = '"' + part.etag + '"'
        ET.SubElement(row, "LastModified").text = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(part.updated_at),
        )
        ET.SubElement(row, "Size").text = str(part.size)
    return Response(ET.tostring(result, encoding="utf-8", xml_declaration=True),
                    media_type="application/xml",
                    headers=(_ssec_response_headers(sse_key)
                             if sse_key is not None else None))


async def _mpu_complete(ctx: _S3RequestContext, mpu: MultipartStore,
                        upload_id: str) -> Response:
    """POST ?uploadId: CompleteMultipartUpload assembly and publish."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    owner = ctx.owner
    catalog = ctx.catalog
    db = ctx.db
    mpu.require(upload_id, bucket, key, owner, allow_completed=True)
    upload_encryption = mpu.encryption_marker(
        upload_id, bucket, key, owner, allow_completed=True)
    sse_key = parse_ssec_headers(request.headers, signed_header_names(request))
    if upload_encryption is not None:
        if sse_key is None or not hmac.compare_digest(
                str(upload_encryption.get("key_md5", "")), sse_key.key_md5_b64):
            raise SSECError(
                "InvalidRequest",
                "CompleteMultipartUpload requires the SSE-C key used to "
                "create the upload")
    elif sse_key is not None:
        raise SSECError(
            "InvalidRequest",
            "The upload was not created with SSE-C; remove the customer key "
            "headers")
    expected_completion_head = check_write_precondition(
        request, catalog, bucket, key,
    )
    content = bytearray()
    async for block in request.stream():
        content.extend(block)
        if len(content) > 1024 * 1024:
            raise MultipartError("MalformedXML", "Complete XML exceeds 1 MiB")
    if hashlib.sha256(content).hexdigest() != request.headers.get("x-amz-content-sha256"):
        raise MultipartError("XAmzContentSHA256Mismatch", "Completion XML checksum mismatch")
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise MultipartError("MalformedXML", "XML entities are not accepted")
    try:
        document = SafeET.fromstring(content)
        if document.tag.rsplit("}", 1)[-1] != "CompleteMultipartUpload":
            raise ValueError("Wrong XML root")
        selected = []
        part_checksums: dict[int, str] = {}
        for element in document:
            if element.tag.rsplit("}", 1)[-1] != "Part":
                raise ValueError("Unexpected XML element")
            number = element.findtext("{*}PartNumber")
            etag = element.findtext("{*}ETag")
            if not number or not number.isdigit() or not etag:
                raise ValueError("Missing part number or ETag")
            declared_sha = element.findtext("{*}ChecksumSHA256")
            if declared_sha is not None:
                part_checksums[int(number)] = declared_sha
            selected.append((int(number), etag.strip('"').lower()))
    except (ValueError, ET.ParseError) as exc:
        raise MultipartError("MalformedXML", "Invalid CompleteMultipartUpload XML") from exc
    # Request-level checksum mode. Only COMPOSITE is verifiable without
    # re-streaming assembled bytes: it hashes the concatenated per-part
    # SHA-256 digests, which the staged parts already carry.
    checksum_type = request.headers.get("x-amz-checksum-type")
    if checksum_type not in (None, "COMPOSITE", "FULL_OBJECT"):
        raise MultipartError(
            "InvalidArgument", "Unsupported x-amz-checksum-type")
    checksum_headers = ("x-amz-checksum-sha256", "x-amz-checksum-sha1",
                        "x-amz-checksum-crc32", "x-amz-checksum-crc32c",
                        "x-amz-checksum-crc64nvme")
    declared_checksums = {
        name: request.headers.get(name) for name in checksum_headers
        if request.headers.get(name) is not None}
    non_sha_declared = [name for name in declared_checksums
                        if name != "x-amz-checksum-sha256"]
    if non_sha_declared and checksum_type is None:
        raise MultipartError(
            "InvalidArgument",
            "x-amz-checksum-type is required for completion checksums")
    # FULL_OBJECT checksums and non-SHA composites are verified in one
    # streaming pass over the assembled bytes (below, once the engine
    # exists); SHA-256 composites verify from the staged part digests.
    streaming_verification = bool(
        declared_checksums and (
            checksum_type == "FULL_OBJECT"
            or (checksum_type == "COMPOSITE" and non_sha_declared)))
    from teledrive.s3.multipart import parts as _parts_table
    from teledrive.storage.manifest import objects as _objects_table
    part_digests: dict[int, str] = {
        number: sha for number, sha in db.connection.execute(
            select(_parts_table.c.number, _objects_table.c.sha256)
            .select_from(_parts_table.join(
                _objects_table,
                _objects_table.c.id == _parts_table.c.object_id))
            .where(_parts_table.c.upload_id == upload_id))
    }
    for number, declared in part_checksums.items():
        stored = part_digests.get(number)
        if stored is None:
            raise MultipartError(
                "InvalidPart", "Checksum declared for an unknown part")
        actual = base64.b64encode(bytes.fromhex(stored)).decode("ascii")
        if not hmac.compare_digest(declared, actual):
            raise MultipartError(
                "BadDigest", f"Part {number} SHA-256 checksum mismatch")
    composite_checksum = None
    sha256_declaration = declared_checksums.get("x-amz-checksum-sha256")
    if (sha256_declaration is not None
            and checksum_type in (None, "COMPOSITE")):
        try:
            composite = hashlib.sha256(b"".join(
                bytes.fromhex(part_digests[number])
                for number, _ in sorted(selected)
                if (part_digests.get(number) is not None)
            )).digest()
        except KeyError as exc:
            raise MultipartError(
                "InvalidPart", "Completion references an unstaged part"
            ) from exc
        composite_checksum = base64.b64encode(composite).decode("ascii")
        if not hmac.compare_digest(sha256_declaration, composite_checksum):
            raise MultipartError(
                "BadDigest", "Composite SHA-256 checksum mismatch")
    transport = storage_transport(db)
    scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(scratch)
    # Enforce bucket quota using the total selected part size
    # before any assembly/publish work begins. Query the parts
    # table directly: list_parts() enforces upload ownership and
    # would reject the idempotent repeat of an already-completed
    # upload.
    selected_numbers = {number for number, _ in selected}
    part_rows = db.connection.execute(
        select(_parts_table.c.number, _parts_table.c.size).where(
            _parts_table.c.upload_id == upload_id
        )
    ).all()
    selected_size = sum(
        size for number, size in part_rows
        if number in selected_numbers
    )
    quota_error = _quota_guard(db, bucket, key, selected_size)
    if quota_error is not None:
        return quota_error
    engine = TelegramObjectStorage(
        catalog.manifests, transport,
        chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
    )
    if streaming_verification:
        # One streaming pass over the assembled part bytes computes
        # every algorithm: FULL_OBJECT digests directly, and non-SHA
        # COMPOSITE values from the concatenated binary part checksums
        # (little-endian for CRCs, natural digests for SHA).
        full = {"sha256": hashlib.sha256(),
                "sha1": hashlib.sha1(usedforsecurity=False)}
        part_crc32: list[bytes] = []
        part_crc32c: list[bytes] = []
        part_crc64: list[bytes] = []
        crc32_state = crc32c_state = crc64_state = 0
        try:
            for number, _etag in sorted(selected):
                part_object = db.connection.execute(
                    select(_parts_table.c.object_id).where(
                        _parts_table.c.upload_id == upload_id,
                        _parts_table.c.number == number)
                ).scalar_one()
                part_crc32_state = part_crc32c_state = part_crc64_state = 0
                async for piece in engine.iter_bytes(
                        part_object, sse_key=sse_key):
                    full["sha256"].update(piece)
                    full["sha1"].update(piece)
                    crc32_state = zlib.crc32(piece, crc32_state)
                    crc32c_state = crc32c(piece, crc32c_state)
                    crc64_state = crc64nvme(piece, crc64_state)
                    part_crc32_state = zlib.crc32(piece, part_crc32_state)
                    part_crc32c_state = crc32c(piece, part_crc32c_state)
                    part_crc64_state = crc64nvme(piece, part_crc64_state)
                part_crc32.append(
                    (part_crc32_state & 0xffffffff).to_bytes(4, "little"))
                part_crc32c.append(
                    (part_crc32c_state & 0xffffffff).to_bytes(4, "little"))
                part_crc64.append(
                    part_crc64_state.to_bytes(8, "little"))
        except FileNotFoundError as exc:
            raise MultipartError(
                "InvalidPart", "Completion references an unstaged part"
            ) from exc
        # CRC full-object values are finalized big-endian; composite
        # CRCs checksum the little-endian part concatenation.
        def _crc_value(state, parts, width, algo):
            if checksum_type == "COMPOSITE":
                if algo == "crc32":
                    value = zlib.crc32(b"".join(parts)) & 0xffffffff
                elif algo == "crc32c":
                    value = crc32c(b"".join(parts))
                else:
                    value = crc64nvme(b"".join(parts))
            else:
                value = state
            return base64.b64encode(
                value.to_bytes(width, "big")).decode("ascii")
        computed = {
            "x-amz-checksum-sha256":
                base64.b64encode(full["sha256"].digest()).decode("ascii"),
            "x-amz-checksum-sha1":
                base64.b64encode(full["sha1"].digest()).decode("ascii"),
            "x-amz-checksum-crc32": _crc_value(
                crc32_state & 0xffffffff, part_crc32, 4, "crc32"),
            "x-amz-checksum-crc32c": _crc_value(
                crc32c_state & 0xffffffff, part_crc32c, 4, "crc32c"),
            "x-amz-checksum-crc64nvme": _crc_value(
                crc64_state, part_crc64, 8, "crc64nvme"),
        }
        for name, declared in declared_checksums.items():
            actual = computed.get(name)
            if actual is None or not hmac.compare_digest(declared, actual):
                raise MultipartError(
                    "BadDigest", f"Completion {name} checksum mismatch")
        composite_checksum = computed.get("x-amz-checksum-sha256")
    finished = await mpu.complete(
        upload_id, bucket, key, owner, selected, engine,
        expected_generation=(
            expected_completion_head.generation
            if expected_completion_head else None
        ),
        expected_object_id=(
            expected_completion_head.object_id
            if expected_completion_head else None
        ),
    )
    result_fields = [("Bucket", bucket), ("Key", key),
                     ("ETag", '"' + finished.etag + '"')]
    if composite_checksum is not None:
        result_fields.append(("ChecksumSHA256", composite_checksum))
    return Response(_xml("CompleteMultipartUploadResult", result_fields),
                    status_code=200, media_type="application/xml",
                    headers=(_ssec_response_headers(sse_key)
                             if sse_key is not None else None))


async def _mpu_upload_part(ctx: _S3RequestContext, mpu: MultipartStore,
                           upload_id: str) -> Response:
    """PUT ?uploadId&partNumber: UploadPart staging and checksum verify."""
    if ctx.request.headers.get("x-amz-copy-source") is not None:
        return await _mpu_upload_part_copy(ctx, mpu, upload_id)
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    owner = ctx.owner
    catalog = ctx.catalog
    db = ctx.db
    # UploadPart: checksum is verified before any Telegram send.
    upload_encryption = mpu.encryption_marker(upload_id, bucket, key, owner)
    sse_key = parse_ssec_headers(request.headers, signed_header_names(request))
    if upload_encryption is not None:
        if sse_key is None or not hmac.compare_digest(
                str(upload_encryption.get("key_md5", "")), sse_key.key_md5_b64):
            raise SSECError(
                "InvalidRequest",
                "UploadPart requires the SSE-C key used to create the upload")
    elif sse_key is not None:
        raise SSECError(
            "InvalidRequest",
            "The upload was not created with SSE-C; remove the customer key "
            "headers")
    try:
        number = int(request.query_params.get("partNumber", ""))
    except ValueError:
        raise MultipartError("InvalidArgument", "Invalid part number")
    if not 1 <= number <= MAX_PARTS:
        raise MultipartError("InvalidArgument", "Invalid part number")
    scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(scratch)
    max_bytes = _webapp.REST_MAX_UPLOAD_BYTES
    fd, name = tempfile.mkstemp(prefix="s3-part-", dir=scratch)
    stage = Path(name)
    try:
        sha = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False)
        sha1 = hashlib.sha1(usedforsecurity=False)
        crc = 0
        crc32c_value = 0
        crc64_value = 0
        size = 0
        decoder = None
        if streaming_mode(request) is not None:
            decoder = AwsChunkedDecoder(request, ctx.store.resolve,
                                        "s3:PutObject")
            part_stream = decoder.blocks()
        else:
            part_stream = request.stream()
        with os.fdopen(fd, "wb") as output:
            async for block in part_stream:
                size += len(block)
                if max_bytes < 1 or size > max_bytes:
                    raise MultipartError("EntityTooLarge", "Part exceeds configured upload maximum", 413)
                sha.update(block)
                md5.update(block)
                sha1.update(block)
                crc = zlib.crc32(block, crc)
                crc32c_value = crc32c(block, crc32c_value)
                crc64_value = crc64nvme(block, crc64_value)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        _verify_upload_sha256(
            request, sha.digest(), md5_digest=md5.digest(),
            sha1_digest=sha1.digest(), crc64nvme_value=crc64_value,
            trailer=decoder.trailer if decoder is not None else None,
        )
        checksum_crc = (request.headers.get("x-amz-checksum-crc32")
                        or (decoder.trailer if decoder else {}).get(
                            "x-amz-checksum-crc32"))
        if checksum_crc and checksum_crc != base64.b64encode(
            (crc & 0xffffffff).to_bytes(4, "big")
        ).decode():
            raise MultipartError("BadDigest", "CRC32 checksum mismatch")
        declared_crc32c = request.headers.get("x-amz-checksum-crc32c")
        if declared_crc32c is not None and not hmac.compare_digest(
            declared_crc32c,
            base64.b64encode(crc32c_value.to_bytes(4, "big")).decode("ascii"),
        ):
            raise MultipartError("BadDigest", "CRC32C checksum mismatch")
        transport = storage_transport(db)
        await transport.verify_target()
        engine = TelegramObjectStorage(
            catalog.manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
        )
        staged = await engine.put_file(bucket, key, stage, dedup=False,
                                       sse_key=sse_key)
        if sse_key is not None:
            # Never return a plaintext MD5 for an SSE-C part: the part ETag
            # is the ciphertext digest the completion path verifies.
            part_info = catalog.manifests.encryption_info(staged.id) or {}
            tag = str(part_info.get("etag") or "")
            if len(tag) != 64:
                raise MultipartError(
                    "InternalError", "Staged SSE-C part has no digest")
        else:
            tag = md5.hexdigest()
        mpu.record_part(upload_id, bucket, key, owner,
                        number=number, object_id=staged.id, etag=tag)
        headers = {"ETag": '"' + tag + '"'}
        if sse_key is not None:
            headers.update(_ssec_response_headers(sse_key))
        return Response(status_code=200, headers=headers)
    finally:
        stage.unlink(missing_ok=True)


async def _mpu_upload_part_copy(ctx: _S3RequestContext, mpu: MultipartStore,
                               upload_id: str) -> Response:
    """PUT ?uploadId&partNumber with x-amz-copy-source: UploadPartCopy.

    The part aliases the SOURCE's Telegram chunks through a fresh staged
    manifest for the destination bucket/key — no bytes move, and the
    source is never at risk: multipart completion only READS part
    manifests. Copy-source byte RANGES are deliberately unsupported
    (consistent with CopyObject).
    """
    request = ctx.request
    bucket, key, owner = ctx.bucket, ctx.key, ctx.owner
    if "X-Amz-Algorithm" in request.query_params:
        raise SigV4Error("NotImplemented", "Presigned UploadPartCopy unsupported")
    authorization = request.headers.get("authorization", "")
    signed = authorization.partition("SignedHeaders=")[2].split(",", 1)[0].split(";")
    if ("x-amz-copy-source" not in signed
            or ctx.store.resolve(owner, "s3:GetObject") is None):
        raise SigV4Error("AccessDenied", "Signed source and GetObject scope required")
    # P8: honour the SOURCE object's ACL for multipart part copies too.
    _require_source_acl(ctx.catalog, ctx.store, owner,
                        request.headers["x-amz-copy-source"], request)
    if (request.headers.get("x-amz-copy-source-if-match") is not None
            and "x-amz-copy-source-if-match" not in signed):
        raise SigV4Error("AccessDenied", "Copy precondition must be signed")
    copy_range = request.headers.get("x-amz-copy-source-range")
    if copy_range is not None and "x-amz-copy-source-range" not in signed:
        raise SigV4Error("AccessDenied", "Copy-source range must be signed")
    async for block in request.stream():
        if block:
            raise MultipartError("InvalidRequest",
                                 "UploadPartCopy requires an empty body")
    source_header = request.headers["x-amz-copy-source"]
    if (source_header.startswith("//") or "://" in source_header
            or "?" in source_header):
        raise MultipartError("InvalidArgument",
                             "CopySource must be a plain local bucket/object path")
    path = unquote(source_header[1:] if source_header.startswith("/")
                   else source_header)
    src_bucket, slash, src_key = path.partition("/")
    if not slash or not src_bucket or not src_key:
        raise MultipartError("InvalidArgument", "Invalid CopySource bucket/object key")
    if src_bucket not in ctx.catalog.list_buckets():
        return _error("NoSuchBucket", "CopySource bucket does not exist", 404)
    try:
        source = ctx.catalog.get(src_bucket, src_key).item
    except FileNotFoundError:
        return _error("NoSuchKey", "CopySource object does not exist", 404)
    # AWS copy-source ranges are INCLUSIVE byte positions.
    range_start, range_end = 0, source.size - 1
    if copy_range is not None:
        match = re.fullmatch(r"bytes=(\d+)-(\d+)", copy_range.strip())
        if match is None:
            raise MultipartError("InvalidArgument",
                                 "CopySourceRange must be bytes=first-last")
        range_start, range_end = int(match.group(1)), int(match.group(2))
        if (range_start > range_end or range_start < 0
                or range_end >= max(source.size, 1)):
            raise MultipartError("InvalidRange",
                                 "Copy-source range is outside the object",
                                 416)
    try:
        number = int(request.query_params.get("partNumber", ""))
    except ValueError:
        raise MultipartError("InvalidArgument", "Invalid part number")
    if not 1 <= number <= MAX_PARTS:
        raise MultipartError("InvalidArgument", "Invalid part number")
    mpu.require(upload_id, bucket, key, owner)
    db = ctx.db
    # Part bytes are COPIED through Telegram (our storage backend): the
    # source is downloaded to scratch and staged exactly like a regular
    # UploadPart. Completion physically re-owns chunk rows per part, so
    # an object-level alias part cannot work — and must never move the
    # source's chunks.
    scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(scratch)
    fd, name = tempfile.mkstemp(prefix="s3-partcopy-", dir=scratch)
    stage = Path(name)
    try:
        os.close(fd)
        transport = storage_transport(db)
        await transport.verify_target()
        engine = TelegramObjectStorage(
            ctx.catalog.manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
        )
        with open(stage, "wb") as out:
            async for piece in engine.iter_bytes(
                    source.id, start=range_start, end=range_end + 1):
                out.write(piece)
        md5 = hashlib.md5(usedforsecurity=False)
        with open(stage, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                md5.update(block)
        staged = await engine.put_file(bucket, key, stage, dedup=False)
        etag = md5.hexdigest()
        mpu.record_part(upload_id, bucket, key, owner, number=number,
                        object_id=staged.id, etag=etag)
        now = int(time.time())
        return Response(_xml("CopyPartResult", [
            ("ETag", '"' + etag + '"'),
            ("LastModified", time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))),
        ]), media_type="application/xml", status_code=200)
    finally:
        stage.unlink(missing_ok=True)


class ObjectLockError(ValueError):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status


def _iso8601_ns(ns: int) -> str:
    import datetime
    moment = datetime.datetime.fromtimestamp(
        ns / 1_000_000_000, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ns % 1_000_000_000:09d}"[:3] + "Z"


def _parse_iso8601_ns(raw: str) -> int:
    import datetime
    moment = datetime.datetime.fromisoformat(
        raw.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("Retention date requires a timezone")
    return int(moment.timestamp() * 1_000_000_000)


async def _read_verified_body(request: Request, store, permission: str, *,
                               max_bytes: int) -> tuple[bytes, dict[str, str]]:
    """Read a bounded request body, decoding aws-chunked if present.

    boto3 attaches SDK checksums to blob payloads as aws-chunked trailers
    (x-amz-sdk-checksum-algorithm plus x-amz-checksum-crc32 in the
    trailer), so a handler that reads request.stream() directly sees chunk
    framing instead of the payload and then reports the declared checksum
    as missing. Returns (payload, trailer_headers).
    """
    decoder = None
    if streaming_mode(request) is not None:
        decoder = AwsChunkedDecoder(request, store.resolve, permission)
        blocks = decoder.blocks()
    else:
        blocks = request.stream()
    body = bytearray()
    async for block in blocks:
        body.extend(block)
        if len(body) > max_bytes:
            raise AnnotationError(
                "InvalidRequest",
                f"Request payload exceeds {max_bytes} bytes")
    return bytes(body), (decoder.trailer if decoder is not None else {})


def _require_source_acl(catalog, store, access_key: str, source_header: str,
                        request) -> None:
    """Fail closed when a copy source is narrowed by policy or its ACL."""
    path = unquote(source_header[1:] if source_header.startswith("/")
                   else source_header)
    src_bucket, slash, src_key = path.partition("/")
    if not slash or not src_bucket or not src_key:
        return
    allowed, _reason = _authorize_resource(
        catalog, store, access_key, "s3:GetObject", src_bucket, src_key,
        request)
    if not allowed:
        raise SigV4Error("AccessDenied",
                         "Access denied by source object ACL or policy")


def _ownership_model(catalog, bucket: str) -> str:
    try:
        return catalog.object_ownership(bucket)
    except FileNotFoundError:
        return "BucketOwnerEnforced"


# ListBucket parameters have well-defined DEFAULTS, and omitting them from
# the policy context made a Deny silently miss the request it was written to
# block: "Deny s3:ListBucket with StringLike {s3:prefix: *}" answered 403 for
# ?prefix=a but 200 for a bare GET, which enumerated the entire bucket. A
# missing context key fails a positive condition, so the defaults MUST be
# present for the request to be evaluated as AWS would evaluate it.
_LIST_DEFAULTS = {"prefix": "", "delimiter": "", "max-keys": "1000"}


def _policy_context(catalog, store, access_key: str, bucket: str,
                    key: str | None, request, action: str | None = None) -> dict:
    """Context keys the condition engine can honestly evaluate."""
    context: dict = {}
    for name, default in _LIST_DEFAULTS.items():
        value = request.query_params.get(name)
        if value is None and action != "s3:ListBucket":
            continue
        context["s3:" + name] = default if value is None else value
    client = getattr(request, "client", None)
    if client is not None and client.host:
        context["aws:SourceIp"] = client.host
    canned_acl = request.headers.get("x-amz-acl")
    if canned_acl:
        context["s3:x-amz-acl"] = canned_acl
    try:
        for tag_key, tag_value in store.principal_tags(access_key).items():
            context["aws:PrincipalTag/" + tag_key] = tag_value
    except Exception:
        pass
    if key is not None:
        try:
            item = catalog.get(bucket, key).item
            # Direct read: constructing ObjectTagStore would run DDL in
            # the authorization path. object_tags already exists via the
            # catalog's metadata bootstrap.
            rows = catalog.db.connection.execute(select(
                object_tags.c.tag_key, object_tags.c.tag_value).where(
                object_tags.c.object_id == item.id)).all()
            for tag_key, tag_value in rows:
                context["s3:ExistingObjectTag/" + tag_key] = tag_value
        except Exception:
            # No current object (or no tag table yet): tag conditions
            # simply have no value, which fails positive conditions.
            pass
    return context


def _acl_allows(catalog, access_key: str, action: str, bucket: str,
                key: str | None, *, ownership: str | None = None) -> bool:
    """Fetch the resource's grant rows and apply the intersection.

    BucketOwnerEnforced ignores OBJECT ACL grants (the default); the
    bucket ACL still constrains bucket-level access.  ObjectWriter and
    BucketOwnerPreferred apply both levels (Phase D behaviour).
    """
    if ownership is None:
        ownership = _ownership_model(catalog, bucket)
    bucket_rows, object_rows = catalog.acl_grants_for(bucket, key)
    if ownership == "BucketOwnerEnforced":
        object_rows = []
    return acl_permits(action=action, access_key=access_key,
                       bucket_rows=bucket_rows, object_rows=object_rows,
                       key=key)


_ABAC_CONTROL_EXEMPT = frozenset({
    # ABAC is a data-access gate; the owner must remain able to manage
    # the ABAC/policy controls that could otherwise lock the bucket.
    "s3:PutBucketAbac", "s3:GetBucketAbac",
    "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:GetBucketPolicy",
    "s3:PutBucketOwnershipControls", "s3:DeleteBucketOwnershipControls",
    "s3:GetOwnershipControls",
})


def _apply_bucket_owner_preferred(catalog, bucket: str, key: str,
                                  owner: str, request) -> None:
    """BucketOwnerPreferred: a ``bucket-owner-full-control`` upload adds
    an owner FULL_CONTROL object grant.  Other models ignore it."""
    if request.headers.get("x-amz-acl") != "bucket-owner-full-control":
        return
    if _ownership_model(catalog, bucket) != "BucketOwnerPreferred":
        return
    bucket_owner, _bucket_grants = catalog.bucket_acl(bucket)
    target_owner = bucket_owner or owner
    stored_owner, grants = catalog.object_acl(bucket, key)
    catalog.set_object_acl(
        bucket, key, stored_owner or target_owner,
        list(grants) + [(target_owner, "FULL_CONTROL")])


def _authorize_resource(catalog, store, access_key: str, action: str,
                        bucket: str, key: str | None, request):
    """The single resource-authorization decision point.

    Returns ``(allowed, reason)``.  SigV4 scope checks stay outside this
    function (they authenticate the credential's own permission set).
    Precedence:

    1. bucket policy explicit Deny  → deny
    2. bucket policy explicit Allow → allow (ACL layer skipped)
    3. otherwise → the ACL intersection gate (ownership-aware)
    """
    resource_key = bucket if key is None else f"{bucket}/{key}"
    context = _policy_context(catalog, store, access_key, bucket, key,
                              request, action)
    decision = None
    try:
        compiled = BucketPolicyStore(catalog).get_compiled(bucket)
    except FileNotFoundError:
        compiled = None
    if compiled is not None:
        decision = evaluate_policy(
            compiled.statements, action, resource_key, access_key, context)
        if decision == "deny":
            return False, "Access denied by bucket policy"
    try:
        abac = BucketAbacStore(catalog).get(bucket)
    except FileNotFoundError:
        abac = None
    if (action not in _ABAC_CONTROL_EXEMPT
            and not evaluate_abac(abac, context)):
        return False, "Access denied by bucket ABAC condition"
    if decision == "allow":
        return True, ""
    if _acl_allows(catalog, access_key, action, bucket, key):
        return True, ""
    return False, "Access denied by resource ACL"


async def _read_acl_body(request: Request, *, bucket_level: bool) -> bytes:
    """Bounded ACL XML body with the signed checksum policy applied."""
    body = bytearray()
    async for block in request.stream():
        body.extend(block)
        if len(body) > 16384:
            raise AclError("MalformedXML", "ACL XML exceeds 16 KiB")
    if bucket_level:
        _verify_bucket_control_payload(request, bytes(body))
    else:
        _verify_upload_sha256(
            request, hashlib.sha256(body).digest(),
            crc64nvme_value=crc64nvme(body),
        )
    return bytes(body)


def _validated_acl(payload: bytes, *, object_level: bool, caller: str,
                   store: S3CredentialStore,
                   stored_owner: str | None = None
                   ) -> tuple[str, list[tuple[str, str]]]:
    """Parse an AccessControlPolicy and validate its principals.

    Every CanonicalUser ID (owner and grantees) must be an active
    TeleDrive credential — an unknown ID is rejected at write time
    instead of silently never matching. The owner defaults to the
    caller when the document omits the Owner block.
    """
    doc_owner, grants = parse_acl_xml(payload, object_level=object_level)
    # Ownership is IMMUTABLE. The first successful write establishes the
    # caller as owner; every later write keeps that owner. Without this,
    # any credential allowed to write the ACL could declare itself the
    # owner and lock the real owner out (a full takeover).
    acl_owner = stored_owner or caller
    if doc_owner is not None and doc_owner != acl_owner:
        raise AclError("InvalidArgument",
                       "ACL owner cannot be changed")
    if not store.is_active(acl_owner):
        raise AclError("InvalidArgument",
                       "ACL owner is not an active credential")
    for grantee, _permission in grants:
        if not store.is_active(grantee):
            raise AclError("InvalidArgument",
                           f"Unknown ACL grantee {grantee[:8]}…")
    return acl_owner, grants


async def _read_verified_xml_body(request: Request, limit: int, error_cls):
    """Bounded XML body with the signed payload/checksum policy applied."""
    body = bytearray()
    async for block in request.stream():
        body.extend(block)
        if len(body) > limit:
            raise error_cls("MalformedXML", "XML request body exceeds its limit")
    payload = bytes(body)
    _verify_upload_sha256(
        request, hashlib.sha256(payload).digest(),
        md5_digest=hashlib.md5(payload, usedforsecurity=False).digest(),
        sha1_digest=hashlib.sha1(payload, usedforsecurity=False).digest(),
        crc64nvme_value=crc64nvme(payload),
    )
    return payload


async def _handle_bucket_acl(ctx: _S3RequestContext) -> Response:
    """GET/PUT ?acl on a bucket: the Phase D grant store."""
    request, bucket, catalog = ctx.request, ctx.bucket, ctx.catalog
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "The specified bucket does not exist", 404)
    if request.method == "GET":
        stored_owner, grants = catalog.bucket_acl(bucket)
        if stored_owner is None:
            # No ACL has ever been written: the unrestricted baseline
            # answers with the caller's private canned ACL.
            return Response(_canned_private_acl_xml(ctx.owner),
                            media_type="application/xml")
        return Response(render_acl_xml(stored_owner, grants),
                        media_type="application/xml")
    if request.method != "PUT":
        return _error("NotImplemented", "Unsupported ACL method", 501)
    payload = await _read_acl_body(request, bucket_level=True)
    try:
        stored_owner, _rows = catalog.bucket_acl(bucket)
        # Phase E: with BlockPublicAcls on, only the bucket ACL's
        # owner may author grants — the PAB flag guards the grant
        # store instead of (nonexistent) public ACLs. The first write
        # (no stored ACL) still establishes the owner. Checked before
        # the document is even parsed, so a grantee learns nothing.
        if (catalog.public_access_block(bucket).get("BlockPublicAcls")
                and stored_owner is not None
                and stored_owner != ctx.owner):
            raise AclError("AccessDenied",
                           "BlockPublicAcls restricts ACL writes to "
                           "the ACL owner", 403)
        acl_owner, grants = _validated_acl(
            payload, object_level=False, caller=ctx.owner, store=ctx.store,
            stored_owner=stored_owner)
        catalog.set_bucket_acl(bucket, acl_owner, grants)
    except AclError as exc:
        return _error(exc.code, str(exc), exc.status)
    except FileNotFoundError:
        return _error("NoSuchBucket", "The specified bucket does not exist", 404)
    return Response(status_code=200)


async def _handle_object_acl(ctx: _S3RequestContext) -> Response:
    """GET/PUT ?acl on the current object (exact key, never siblings)."""
    request, bucket, key, catalog = (
        ctx.request, ctx.bucket, ctx.key, ctx.catalog)
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "The specified bucket does not exist", 404)
    try:
        catalog.get(bucket, key)
    except FileNotFoundError:
        return _error("NoSuchKey", "The requested resource does not exist", 404)
    if request.method == "GET":
        stored_owner, grants = catalog.object_acl(bucket, key)
        if stored_owner is None:
            return Response(_canned_private_acl_xml(ctx.owner),
                            media_type="application/xml")
        return Response(render_acl_xml(stored_owner, grants),
                        media_type="application/xml")
    if request.method != "PUT":
        return _error("NotImplemented", "Unsupported ACL method", 501)
    payload = await _read_acl_body(request, bucket_level=False)
    try:
        stored_owner, _rows = catalog.object_acl(bucket, key)
        # Phase E: BlockPublicAcls guards object ACL writes the same
        # way — only the stored ACL's owner may replace them.
        if (catalog.public_access_block(bucket).get("BlockPublicAcls")
                and stored_owner is not None
                and stored_owner != ctx.owner):
            raise AclError("AccessDenied",
                           "BlockPublicAcls restricts ACL writes to "
                           "the ACL owner", 403)
        acl_owner, grants = _validated_acl(
            payload, object_level=True, caller=ctx.owner, store=ctx.store,
            stored_owner=stored_owner)
        catalog.set_object_acl(bucket, key, acl_owner, grants)
    except AclError as exc:
        return _error(exc.code, str(exc), exc.status)
    except FileNotFoundError:
        return _error("NoSuchBucket", "The specified bucket does not exist", 404)
    return Response(status_code=200)


async def _handle_bucket_object_lock(ctx: _S3RequestContext) -> Response:
    """GET/PUT ?object-lock: bucket-level Object Lock configuration."""
    request, bucket, catalog = ctx.request, ctx.bucket, ctx.catalog
    if bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "Bucket does not exist", 404)
    if request.method == "GET":
        config = catalog.object_lock_config(bucket)
        if config is None:
            return _error("ObjectLockConfigurationNotFoundError",
                          "Object Lock configuration does not exist for "
                          "this bucket", 404)
        root = ET.Element("ObjectLockConfiguration", xmlns=NAMESPACE)
        ET.SubElement(root, "ObjectLockEnabled").text = "Enabled"
        if config.get("default_mode"):
            rule = ET.SubElement(root, "Rule")
            default = ET.SubElement(rule, "DefaultRetention")
            ET.SubElement(default, "Mode").text = config["default_mode"]
            if config.get("default_days"):
                ET.SubElement(default, "Days").text = str(
                    config["default_days"])
        return _xml_ok(root)
    if request.method != "PUT":
        return _error("NotImplemented", "Unsupported object-lock method", 501)
    request, bucket, catalog = ctx.request, ctx.bucket, ctx.catalog
    payload = bytearray()
    async for block in request.stream():
        payload.extend(block)
        if len(payload) > 16384:
            raise ObjectLockError("MalformedXML", "Object lock XML exceeds 16 KiB")
    _verify_bucket_control_payload(request, bytes(payload))
    try:
        root = SafeET.fromstring(bytes(payload))
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ObjectLockError("MalformedXML", "Invalid object lock XML") from exc
    if root.tag not in {"ObjectLockConfiguration",
                        f"{{{NAMESPACE}}}ObjectLockConfiguration"} or root.attrib:
        raise ObjectLockError("MalformedXML", "Unexpected object lock document")
    enabled = None
    mode, days = None, None
    for element in root:
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "ObjectLockEnabled" and enabled is None:
            enabled = (element.text or "").strip()
        elif tag == "Rule" and mode is None and not element.attrib:
            for sub in element:
                subtag = sub.tag.rsplit("}", 1)[-1]
                if subtag != "DefaultRetention":
                    raise ObjectLockError("MalformedXML",
                                          "Unexpected lock rule element")
                for leaf in sub:
                    leaf_tag = leaf.tag.rsplit("}", 1)[-1]
                    if leaf_tag == "Mode" and mode is None:
                        mode = (leaf.text or "").strip()
                    elif leaf_tag == "Days" and days is None:
                        raw = (leaf.text or "").strip()
                        if not raw.isdigit() or not 1 <= int(raw) <= 3650:
                            raise ObjectLockError("InvalidArgument",
                                                  "Default retention days "
                                                  "outside 1..3650")
                        days = int(raw)
                    else:
                        raise ObjectLockError("MalformedXML",
                                              "Unexpected default retention")
        else:
            raise ObjectLockError("MalformedXML", "Unexpected object lock field")
    if enabled != "Enabled":
        raise ObjectLockError("InvalidArgument",
                              "ObjectLockEnabled must be Enabled")
    if mode is not None and mode not in ("COMPLIANCE", "GOVERNANCE"):
        raise ObjectLockError("InvalidArgument", "Invalid lock mode")
    try:
        catalog.set_object_lock_config(bucket, mode=mode or "COMPLIANCE",
                                       days=days)
    except FileNotFoundError:
        return _error("NoSuchBucket", "Bucket does not exist", 404)
    except ValueError as exc:
        return _error("InvalidArgument", str(exc), 400)
    return Response(status_code=200)


async def _handle_object_lock_controls(ctx: _S3RequestContext) -> Response:
    """GET/PUT ?retention and ?legal-hold on an object (optionally a
    selected published VersionId)."""
    request, bucket, key, catalog = (
        ctx.request, ctx.bucket, ctx.key, ctx.catalog)
    selector = ("retention" if "retention" in request.query_params
                else "legal-hold")
    version_id = request.query_params.get("versionId", "")
    if version_id and len(version_id) > 80:
        return _error("InvalidArgument", "Invalid version ID", 400)
    try:
        if version_id:
            if not catalog.is_visible_version(bucket, key, version_id):
                return _error("NoSuchVersion",
                              "Object version is not published", 404)
            item = catalog.manifests.get(version_id)
        else:
            item = catalog.get(bucket, key).item
    except FileNotFoundError:
        return _error("NoSuchKey", "The requested resource does not exist",
                      404)

    if request.method == "GET":
        state = catalog.object_lock_state(item.id)
        if selector == "retention":
            if state["mode"] is None:
                return _error("NoSuchObjectLockConfiguration",
                              "The specified object does not have a "
                              "ObjectLock configuration", 404)
            root = ET.Element("Retention", xmlns=NAMESPACE)
            ET.SubElement(root, "Mode").text = state["mode"]
            ET.SubElement(root, "RetainUntilDate").text = _iso8601_ns(
                int(state["retain_until_ns"]))
            return _xml_ok(root)
        root = ET.Element("LegalHold", xmlns=NAMESPACE)
        ET.SubElement(root, "Status").text = (
            "ON" if state["legal_hold"] else "OFF")
        return _xml_ok(root)

    if request.method == "PUT":
        payload = bytearray()
        async for block in request.stream():
            payload.extend(block)
            if len(payload) > 16384:
                raise ObjectLockError("MalformedXML",
                                      "Lock control XML exceeds 16 KiB")
        body = bytes(payload)
        # The body MUST be bound to what the signature covered. A presigned
        # PUT signs UNSIGNED-PAYLOAD and can carry a signed
        # x-amz-checksum-sha256 instead, so checking only
        # x-amz-content-sha256 let such a URL be replayed with a DIFFERENT
        # Retention document -- the signature proved the URL, not the body.
        import hashlib as _hashlib
        body_digest = _hashlib.sha256(body).hexdigest()
        signed_digest = request.headers.get("x-amz-content-sha256", "")
        bound = False
        if signed_digest and signed_digest not in STREAMING_MODES:
            if not hmac.compare_digest(signed_digest, body_digest):
                raise ObjectLockError("XAmzContentSHA256Mismatch",
                                      "Lock control body checksum mismatch")
            bound = True
        checksum = request.headers.get("x-amz-checksum-sha256", "")
        if checksum:
            import base64 as _base64
            try:
                expected = _base64.b64decode(checksum, validate=True)
            except Exception:
                raise ObjectLockError(
                    "InvalidRequest", "Malformed x-amz-checksum-sha256") from None
            if not hmac.compare_digest(expected, bytes.fromhex(body_digest)):
                raise ObjectLockError("BadDigest",
                                      "Lock control body checksum mismatch")
            bound = True
        elif signed_digest in STREAMING_MODES and not bound:
            # A streaming-payload PUT without a verifiable checksum cannot be
            # bound to the signed request at all, so it is refused rather
            # than accepting an unverifiable retention change.
            raise ObjectLockError(
                "InvalidRequest",
                "A streaming-payload lock control requires "
                "x-amz-checksum-sha256")
        try:
            root = SafeET.fromstring(body)
        except (ET.ParseError, DefusedXmlException) as exc:
            raise ObjectLockError("MalformedXML",
                                  "Invalid lock control XML") from exc
        try:
            if selector == "retention":
                if root.tag not in {"Retention", f"{{{NAMESPACE}}}Retention"}:
                    raise ObjectLockError("MalformedXML",
                                          "Expected a Retention document")
                mode = until = None
                for element in root:
                    tag = element.tag.rsplit("}", 1)[-1]
                    if tag == "Mode" and mode is None:
                        mode = (element.text or "").strip()
                    elif tag == "RetainUntilDate" and until is None:
                        until = _parse_iso8601_ns((element.text or "").strip())
                    else:
                        raise ObjectLockError("MalformedXML",
                                              "Unexpected retention field")
                if mode is None:
                    catalog.clear_retention(item.id)
                else:
                    if until is None or until <= time.time_ns():
                        raise ObjectLockError("InvalidArgument",
                                              "Retention must end in the future")
                    catalog.set_retention(item.id, mode=mode, until_ns=until)
            else:
                if root.tag not in {"LegalHold", f"{{{NAMESPACE}}}LegalHold"}:
                    raise ObjectLockError("MalformedXML",
                                          "Expected a LegalHold document")
                status = None
                for element in root:
                    if element.tag.rsplit("}", 1)[-1] == "Status" \
                            and status is None:
                        status = (element.text or "").strip()
                    else:
                        raise ObjectLockError("MalformedXML",
                                              "Unexpected legal-hold field")
                if status not in ("ON", "OFF"):
                    raise ObjectLockError("InvalidArgument",
                                          "LegalHold status must be ON or OFF")
                catalog.set_legal_hold(item.id, status == "ON")
        except PermissionError as exc:
            return _error("AccessDenied", str(exc), 403)
        except ValueError as exc:
            return _error("InvalidArgument", str(exc), 400)
        return Response(status_code=200)
    return _error("NotImplemented", "Unsupported lock control method", 501)


async def _handle_object_annotations(ctx: _S3RequestContext) -> Response:
    """Object ?annotation: singular CRUD and the list form.

    Wire shape (real AWS, confirmed against the API reference):
      * ``?annotation&annotationName=<name>`` — GET/PUT/DELETE one annotation
      * ``?annotation[&annotation-prefix=..][&max-annotation-results=..]
        [&continuation-token=..]`` — GET a page of annotation entries

    Annotations are separate from tags and object metadata: this handler
    never calls the tag store or metadata store. A versionId selector is
    refused by the route guard, because annotations are attached to the
    current object and are removed when that version is revoked.
    """
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    catalog = ctx.catalog
    try:
        object_id = catalog.get(bucket, key).item.id
    except FileNotFoundError:
        return _error("NoSuchKey", "Object does not exist", 404)
    store = AnnotationStore(catalog)
    name = request.query_params.get("annotationName")
    if name is None:
        if request.method != "GET":
            return _error("NotImplemented",
                          "Listing annotations requires GET", 501)
        prefix = validate_annotation_prefix(
            request.query_params.get("annotation-prefix", ""))
        try:
            max_results = int(request.query_params.get(
                "max-annotation-results", "1000"))
        except ValueError:
            return _error("InvalidArgument",
                          "Invalid max-annotation-results", 400)
        if not 1 <= max_results <= MAX_ANNOTATION_RESULTS:
            return _error(
                "InvalidArgument",
                f"max-annotation-results must be between 1 and "
                f"{MAX_ANNOTATION_RESULTS}", 400)
        token = request.query_params.get("continuation-token")
        after = (parse_continuation_token(ctx.master, bucket, key, token)
                 if token is not None else None)
        entries, next_after = store.list(
            object_id, prefix=prefix, after=after, limit=max_results)
        next_token = (continuation_token(ctx.master, bucket, key, next_after)
                      if next_after is not None else None)
        return Response(
            annotations_xml(bucket, key, prefix, max_results, entries,
                            next_token=next_token),
            media_type="application/xml", status_code=200,
            headers={"x-amz-object-version-id": object_id})
    name = validate_annotation_name(name)
    if request.method == "GET":
        entry = store.get(object_id, name)
        if entry is None:
            return _error("NoSuchAnnotation",
                          "The specified annotation does not exist", 404)
        headers = {
            "Content-Length": str(len(entry["value"].encode("utf-8"))),
            "ETag": annotation_etag(entry["value"]),
            "Last-Modified": annotation_http_date(entry["updated_ns"]),
            "x-amz-object-version-id": object_id,
        }
        if ctx.checksum_mode == "ENABLED":
            digest = hashlib.sha256(entry["value"].encode("utf-8")).digest()
            headers["x-amz-checksum-sha256"] = base64.b64encode(digest).decode("ascii")
            headers["x-amz-checksum-type"] = "FULL_OBJECT"
        return Response(entry["value"].encode("utf-8"),
                        media_type="text/plain", status_code=200,
                        headers=headers)
    if request.method == "PUT":
        body, trailer = await _read_verified_body(
            request, ctx.store, "s3:PutObjectAnnotation",
            max_bytes=MAX_ANNOTATION_VALUE_BYTES)
        _verify_upload_sha256(
            request, hashlib.sha256(body).digest(),
            md5_digest=hashlib.md5(body, usedforsecurity=False).digest(),
            sha1_digest=hashlib.sha1(body, usedforsecurity=False).digest(),
            crc64nvme_value=crc64nvme(body),
            trailer=trailer,
        )
        value = validate_annotation_value(body)
        store.put(object_id, name, value, actor=ctx.owner, bucket=bucket,
                  object_key=key)
        return Response(
            put_annotation_xml(key, name), media_type="application/xml",
            status_code=200,
            headers={
                "ETag": annotation_etag(value),
                "x-amz-object-version-id": object_id,
            })
    if request.method == "DELETE":
        async for block in request.stream():
            if block:
                raise AnnotationError(
                    "InvalidRequest",
                    "DeleteObjectAnnotation must have no body")
        # Idempotent by contract: absent annotation still answers 204.
        store.delete(object_id, name, actor=ctx.owner, bucket=bucket,
                     object_key=key)
        return Response(status_code=204,
                        headers={"x-amz-object-version-id": object_id})
    return _error("NotImplemented",
                  "Unsupported object annotation method", 501)


async def _handle_object_tagging(ctx: _S3RequestContext) -> Response:
    """Object ?tagging: GET/PUT/DELETE object tags, optionally versioned."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    catalog = ctx.catalog
    is_version_tagging = ctx.is_version_tagging
    if is_version_tagging:
        selected_id = request.query_params.get("versionId", "")
        if not selected_id or len(selected_id) > 80:
            return _error("InvalidArgument", "Invalid object VersionId", 400)
        target_id = selected_id
    else:
        try:
            target_id = catalog.get(bucket, key).item.id
        except FileNotFoundError:
            return _error("NoSuchKey", "Object does not exist", 404)
    tags = ObjectTagStore(catalog)
    if request.method == "GET":
        if is_version_tagging:
            # Phase J: never expose a deferred (unpublished) journal through
            # GET. Only a proven published version is readable.
            if not catalog.is_visible_version(bucket, key, target_id):
                return _error("NoSuchVersion", "Object version is not published", 404)
        return Response(_tag_xml(tags.get(target_id)),
                        media_type="application/xml", status_code=200,
                        headers={"x-amz-version-id": target_id})
    if request.method == "PUT":
        parsed = await _tag_request_tags(request)
        if is_version_tagging:
            # Published -> real tags; READY-but-unpublished -> journal that
            # publish applies atomically in the head-move transaction.
            tags.replace_version(bucket, key, target_id, parsed,
                                 actor=ctx.owner)
        else:
            tags.replace_current(bucket, key, parsed, actor=ctx.owner)
        return Response(status_code=200, headers={"x-amz-version-id": target_id})
    if request.method == "DELETE":
        async for block in request.stream():
            if block:
                raise TaggingError("InvalidRequest", "DeleteObjectTagging must have no body")
        if is_version_tagging:
            tags.replace_version(bucket, key, target_id, [], actor=ctx.owner)
        else:
            tags.replace_current(bucket, key, [], actor=ctx.owner)
        return Response(status_code=204, headers={"x-amz-version-id": target_id})
    return _error("NotImplemented", "Unsupported object tagging method", 501)


async def _handle_version_delete(ctx: _S3RequestContext) -> Response:
    """DELETE ?versionId: remove one specific object version."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    db = ctx.db
    catalog = ctx.catalog
    if any(h in request.headers for h in ("if-match", "if-none-match")):
        return _error("NotImplemented", "Conditional VersionId delete unsupported", 501)
    version_id = request.query_params["versionId"]
    if not version_id or len(version_id) > 80:
        return _error("InvalidArgument", "Invalid version ID", 400)
    is_marker = db.connection.execute(select(objects.c.status).where(
        objects.c.id == version_id,
        objects.c.bucket == bucket,
        objects.c.object_key == key,
    )).scalar_one_or_none() == "delete-marker"
    if not catalog.delete_version(bucket, key, version_id):
        return _error("NoSuchVersion", "Version does not exist", 404)
    # GC-integrated delete: with physical GC enabled, the revoked
    # version's media is queued for collection once the grace period
    # passes. Disabled GC keeps today's journal-retention behavior.
    try:
        gcx = RetainedMediaGC(db)
        if gcx.state()["enabled"]:
            gcx.enqueue([version_id], "version-delete")
    except Exception:
        pass  # queueing must never break the logical delete
    headers = {"x-amz-version-id": version_id}
    if is_marker:
        headers["x-amz-delete-marker"] = "true"
    return Response(status_code=204, headers=headers)


async def _handle_copy_object(ctx: _S3RequestContext) -> Response:
    """PUT with x-amz-copy-source: server-side CopyObject."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    catalog = ctx.catalog
    store = ctx.store
    owner = ctx.owner
    inline_tags = ctx.inline_tags
    # The source path must be signed. Otherwise a valid PUT signature
    # could be replayed to copy a different private source object.
    # Presigned URLs carry their signed-header list in the query.
    presigned = "X-Amz-Algorithm" in request.query_params
    if presigned:
        signed_headers = request.query_params.get(
            "X-Amz-SignedHeaders", "").split(";")
    else:
        authorization = request.headers.get("authorization", "")
        signed_headers = authorization.partition("SignedHeaders=")[2].split(",", 1)[0].split(";")
    source_header = request.headers["x-amz-copy-source"]
    if ("x-amz-copy-source" not in signed_headers
            or store.resolve(owner, "s3:GetObject") is None):
        raise SigV4Error("AccessDenied", "Signed source and GetObject scope required")
    # P8: the request-level ACL gate only sees the DESTINATION key. The
    # source object's own ACL must be honoured too, or a credential whose
    # access to that exact key was narrowed could still copy it out.
    _require_source_acl(catalog, store, owner, source_header, request)
    qualifiers = (
        "x-amz-copy-source-if-match", "x-amz-copy-source-if-none-match",
        "x-amz-copy-source-if-modified-since",
        "x-amz-copy-source-if-unmodified-since",
    )
    for condition in qualifiers:
        if request.headers.get(condition) is not None and condition not in signed_headers:
            raise SigV4Error("AccessDenied", "Copy precondition must be signed")
    unsupported_headers = (
        "x-amz-server-side-encryption", "x-amz-storage-class",
    )
    if any(request.headers.get(name) is not None for name in unsupported_headers):
        return _error("NotImplemented", "CopyObject option is unsupported", 501)
    if (request.headers.get("x-amz-metadata-directive") is not None
            and "x-amz-metadata-directive" not in signed_headers):
        raise SigV4Error(
            "AccessDenied", "Copy metadata directive must be signed"
        )
    metadata_directive = request.headers.get(
        "x-amz-metadata-directive", "COPY"
    )
    if metadata_directive not in {"COPY", "REPLACE"}:
        raise ObjectMetadataError("InvalidArgument", "Invalid metadata directive")
    copy_properties = parse_object_metadata(
        request.headers, signed_header_names(request),
    )
    if metadata_directive == "COPY" and copy_properties:
        raise ObjectMetadataError(
            "InvalidRequest", "Object metadata requires MetadataDirective=REPLACE"
        )
    tag_directive = request.headers.get("x-amz-tagging-directive", "COPY")
    if tag_directive not in {"COPY", "REPLACE"}:
        raise TaggingError("InvalidArgument", "Invalid CopyObject tagging directive")
    if tag_directive == "COPY" and inline_tags is not None:
        raise TaggingError("InvalidRequest", "x-amz-tagging requires TaggingDirective=REPLACE")
    if (request.headers.get("x-amz-tagging-directive") is not None
            and "x-amz-tagging-directive" not in signed_headers):
        raise SigV4Error("AccessDenied", "Copy tagging directive must be signed")
    # Copying nonempty source tags is a separate protected read/write
    # operation; GetObject/PutObject alone must not bypass tag scopes.
    if tag_directive == "REPLACE":
        if store.resolve(owner, "s3:PutObjectTagging") is None:
            raise SigV4Error("AccessDenied", "Copy tag replacement needs PutObjectTagging")

    if (request.headers.get("x-amz-metadata-directive") is not None
            and "x-amz-metadata-directive" not in signed_headers):
        raise SigV4Error("AccessDenied", "Metadata directive must be signed")
    # A signed CopySource may name a specific historical version.
    # Never treat arbitrary query selectors or duplicate VersionIds as
    # part of the object key; URI escapes are decoded only afterwards.
    if source_header.startswith("//") or "://" in source_header:
        return _error("InvalidArgument", "Copy source must be a local bucket/object path", 400)
    original_header, divider, source_query = source_header.partition("?")
    source_version_id = None
    if divider:
        try:
            qualifiers = parse_qsl(
                source_query, keep_blank_values=True, strict_parsing=True,
                encoding="utf-8", errors="strict", max_num_fields=2,
            )
        except (UnicodeError, ValueError):
            return _error("InvalidArgument", "Malformed CopySource version selector", 400)
        if len(qualifiers) != 1 or qualifiers[0][0] != "versionId":
            return _error("InvalidArgument", "Only a single source VersionId is supported", 400)
        source_version_id = qualifiers[0][1]
        if not source_version_id or len(source_version_id) > 80:
            return _error("InvalidArgument", "Invalid CopySource version ID", 400)
    original_path = unquote(
        original_header[1:] if original_header.startswith("/") else original_header
    )
    src_bucket, slash, src_key = original_path.partition("/")
    if not slash or not src_bucket or not src_key:
        return _error("InvalidArgument", "Invalid CopySource bucket/object key", 400)
    if src_bucket not in catalog.list_buckets():
        return _error("NoSuchBucket", "CopySource bucket does not exist", 404)
    if source_version_id is not None:
        if not catalog.is_visible_version(src_bucket, src_key, source_version_id):
            return _error("NoSuchVersion", "CopySource version is not published", 404)
        try:
            source_item = catalog.manifests.get(source_version_id)
        except FileNotFoundError:
            return _error("NoSuchVersion", "CopySource version not readable", 404)
        if source_item.bucket != src_bucket or source_item.key != src_key:
            return _error("NoSuchVersion", "CopySource key mismatch", 404)
    else:
        try:
            source_item = catalog.get(src_bucket, src_key).item
        except FileNotFoundError:
            return _error("NoSuchKey", "CopySource object does not exist", 404)
    if tag_directive == "COPY" and ObjectTagStore(catalog).get(source_item.id):
        if (store.resolve(owner, "s3:GetObjectTagging") is None
                or store.resolve(owner, "s3:PutObjectTagging") is None):
            raise SigV4Error("AccessDenied", "Copying source tags needs tag read/write scopes")
    existing_tag = MultipartStore(catalog).object_etag(source_item.id, source_item.sha256)
    if_match = request.headers.get("x-amz-copy-source-if-match")
    if_none_match = request.headers.get("x-amz-copy-source-if-none-match")
    quoted_tag = '"' + existing_tag + '"'
    if (if_match is not None and if_match not in (quoted_tag, "*")
            or if_none_match is not None and if_none_match in (quoted_tag, "*")):
        return _error("PreconditionFailed", "CopySource ETag precondition failed", 412)
    # Date-based copy-source conditions with AWS precedence: a passing
    # ETag condition overrides the contradicting date condition.
    def _http_date(name):
        raw = request.headers.get(name)
        if raw is None:
            return None
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if parsed is None or parsed.tzinfo is None:
            return _error("InvalidArgument", "Malformed CopySource date condition", 400)
        return parsed.timestamp()
    if_modified_since = _http_date("x-amz-copy-source-if-modified-since")
    if_unmodified_since = _http_date("x-amz-copy-source-if-unmodified-since")
    if if_modified_since is None and request.headers.get(
            "x-amz-copy-source-if-modified-since") is not None:
        return _error("InvalidArgument", "Malformed CopySource date condition", 400)
    if if_unmodified_since is None and request.headers.get(
            "x-amz-copy-source-if-unmodified-since") is not None:
        return _error("InvalidArgument", "Malformed CopySource date condition", 400)
    source_mtime = float(source_item.created_at)
    if (if_unmodified_since is not None and if_match is None
            and source_mtime > if_unmodified_since):
        return _error("PreconditionFailed",
                      "CopySource modified since the requested date", 412)
    if (if_modified_since is not None and if_none_match is None
            and source_mtime <= if_modified_since):
        return _error("PreconditionFailed",
                      "CopySource not modified since the requested date", 412)
    # CopyObject is a metadata-only operation and has no upload body.
    # Consume streaming requests safely rather than trusting Content-Length.
    async for block in request.stream():
        if block:
            return _error("InvalidRequest", "CopyObject request must have no body", 400)
    # A ranged copy-source stages REAL bytes: the destination is a new
    # payload sliced out of the source (exactly like UploadPartCopy),
    # never a metadata alias. AWS ranges are inclusive.
    copy_range = request.headers.get("x-amz-copy-source-range")
    if copy_range is not None:
        if "x-amz-copy-source-range" not in signed_headers:
            raise SigV4Error("AccessDenied", "Copy-source range must be signed")
        match = re.fullmatch(r"bytes=(\d+)-(\d+)", copy_range.strip())
        if match is None:
            return _error("InvalidArgument",
                          "CopySourceRange must be bytes=first-last", 400)
        range_start, range_end = int(match.group(1)), int(match.group(2))
        if (range_start > range_end or range_start < 0
                or range_end >= max(source_item.size, 1)):
            return _error("InvalidRange",
                          "Copy-source range is outside the object", 416)
        scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
        _secure_mkdir(scratch)
        fd, name = tempfile.mkstemp(prefix="s3-copyrange-", dir=scratch)
        stage = Path(name)
        try:
            os.close(fd)
            transport = storage_transport(ctx.db)
            await transport.verify_target()
            engine = TelegramObjectStorage(
                catalog.manifests, transport,
                chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
            )
            with open(stage, "wb") as out:
                async for piece in engine.iter_bytes(
                        source_item.id, start=range_start,
                        end=range_end + 1):
                    out.write(piece)
            item = await engine.put_file(bucket, key, stage, dedup=False)
            if metadata_directive == "REPLACE" and copy_properties:
                ObjectMetadataStore(catalog).attach_uncommitted(
                    item.id, copy_properties)
            if tag_directive == "REPLACE" and inline_tags:
                ObjectTagStore(catalog).attach_uncommitted(item.id, inline_tags)
            try:
                catalog.publish(item.id, now=int(time.time()))
            except ValueError as exc:
                return _error("OperationAborted",
                              "Concurrent destination mutation", 409)
            copied = ET.Element("CopyObjectResult", xmlns=NAMESPACE)
            ET.SubElement(copied, "LastModified").text = time.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()
            )
            ET.SubElement(copied, "ETag").text = '"' + MultipartStore(
                catalog).object_etag(item.id, item.sha256) + '"'
            return Response(
                ET.tostring(copied, encoding="utf-8", xml_declaration=True),
                media_type="application/xml", status_code=200)
        finally:
            stage.unlink(missing_ok=True)
    try:
        result = copy_object(
            catalog, src_bucket, src_key, bucket, key,
            expected_source_id=source_item.id,
            source_version_id=source_version_id,
            replacement_tags=(inline_tags or []) if tag_directive == "REPLACE" else None,
            replacement_metadata=copy_properties if metadata_directive == "REPLACE" else None,
        )
    except CopyConflict:
        return _error("OperationAborted", "Concurrent source/destination mutation", 409)
    copied = ET.Element("CopyObjectResult", xmlns=NAMESPACE)
    ET.SubElement(copied, "LastModified").text = time.strftime(
        "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()
    )
    ET.SubElement(copied, "ETag").text = '"' + result.etag + '"'
    return Response(ET.tostring(copied, encoding="utf-8", xml_declaration=True),
                    media_type="application/xml", status_code=200)


async def _handle_object_delete(ctx: _S3RequestContext,
                                expected_head: ExpectedHead | None) -> Response:
    """DELETE object key (with optional conditional write preconditions)."""
    bucket = ctx.bucket
    key = ctx.key
    catalog = ctx.catalog
    try:
        marker = catalog.delete_marker(
            bucket, key,
            expected_generation=expected_head.generation if expected_head else None,
            expected_object_id=expected_head.object_id if expected_head else None,
        )
    except ValueError as exc:
        if expected_head is not None:
            raise WritePreconditionError(
                "PreconditionFailed", "Object changed during conditional DELETE", 412
            ) from exc
        raise
    if marker is None:
        # Suspended bucket: unversioned-style delete, no marker headers.
        return Response(status_code=204)
    return Response(status_code=204, headers={
        "x-amz-delete-marker": "true", "x-amz-version-id": marker,
    })


async def _handle_object_encryption(ctx: _S3RequestContext) -> Response:
    """PUT ?encryption: UpdateObjectEncryption (SSE-C key rotation).

    The new key arrives in ``x-amz-server-side-encryption-customer-*`` and the
    current key (required only when the object is already SSE-C) in the
    ``x-amz-copy-source-`` prefixed family.  The object is re-encrypted chunk
    by chunk; the key is never stored.
    """
    request, bucket, key, catalog = ctx.request, ctx.bucket, ctx.key, ctx.catalog
    if request.method != "PUT":
        return _error("NotImplemented",
                      "UpdateObjectEncryption requires PUT", 501)
    try:
        item = catalog.get(bucket, key).item
    except FileNotFoundError:
        return _error("NoSuchKey", "The specified key does not exist", 404)
    async for block in request.stream():
        if block:
            raise SSECError("InvalidRequest",
                            "UpdateObjectEncryption requires an empty body")
    signed = signed_header_names(request)
    new_key = parse_ssec_headers(request.headers, signed)
    if new_key is None:
        raise SSECError(
            "InvalidArgument",
            "UpdateObjectEncryption requires the new SSE-C key headers")
    old_key = parse_ssec_headers(request.headers, signed, prefix=SOURCE_PREFIX)
    scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(scratch)
    transport = storage_transport(ctx.db)
    await transport.verify_target()
    engine = TelegramObjectStorage(
        catalog.manifests, transport,
        chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
    )
    digest = await engine.reencrypt(item.id, old_key, new_key)
    headers = _ssec_response_headers(new_key)
    headers["x-amz-version-id"] = item.id
    headers["ETag"] = '"' + digest + '"'
    return Response(status_code=200, headers=headers)


async def _handle_object_put(ctx: _S3RequestContext,
                             expected_head: ExpectedHead | None) -> Response:
    """PUT object key: staged upload with checksums, metadata and tags."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    db = ctx.db
    catalog = ctx.catalog
    inline_tags = ctx.inline_tags
    # Parse SSE-C before staging any byte: a malformed or unsigned family
    # must fail closed without touching scratch space or Telegram.
    sse_key = parse_ssec_headers(request.headers, signed_header_names(request))
    root = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(root)
    max_bytes = _webapp.REST_MAX_UPLOAD_BYTES
    transport = storage_transport(db)
    await transport.verify_target()
    fd, name = tempfile.mkstemp(prefix="s3-upload-", dir=root)
    stage = Path(name)
    digest = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    crc = 0
    crc32c_value = 0
    crc64_value = 0
    length = 0
    try:
        # aws-chunked streaming uploads (signed chunks / trailer
        # checksums) are decoded and verified transparently.
        decoder = None
        if streaming_mode(request) is not None:
            decoder = AwsChunkedDecoder(request, ctx.store.resolve,
                                        "s3:PutObject")
            body = decoder.blocks()
        else:
            body = request.stream()
        with os.fdopen(fd, "wb") as dest:
            async for block in body:
                length += len(block)
                if max_bytes < 1 or length > max_bytes:
                    return _error("EntityTooLarge", "Upload exceeds configured maximum", 413)
                digest.update(block)
                md5.update(block)
                sha1.update(block)
                crc = zlib.crc32(block, crc)
                crc32c_value = crc32c(block, crc32c_value)
                crc64_value = crc64nvme(block, crc64_value)
                dest.write(block)
            dest.flush()
            os.fsync(dest.fileno())
        _verify_upload_sha256(
            request, digest.digest(), md5_digest=md5.digest(),
            sha1_digest=sha1.digest(), crc64nvme_value=crc64_value,
            trailer=decoder.trailer if decoder is not None else None,
        )
        # Enforce bucket quota (same TeleDrive-level policy as the
        # REST upload path) before any Telegram upload work starts.
        quota_error = _quota_guard(db, bucket, key, length)
        if quota_error is not None:
            return quota_error
        trailer_headers = decoder.trailer if decoder is not None else {}
        checksum_crc = (request.headers.get("x-amz-checksum-crc32")
                        or trailer_headers.get("x-amz-checksum-crc32"))
        if checksum_crc and checksum_crc != base64.b64encode((crc & 0xffffffff).to_bytes(4, "big")).decode():
            return _error("BadDigest", "CRC32 checksum mismatch", 400)
        declared_crc32c = (request.headers.get("x-amz-checksum-crc32c")
                           or trailer_headers.get("x-amz-checksum-crc32c"))
        if declared_crc32c is not None and not hmac.compare_digest(
            declared_crc32c,
            base64.b64encode(crc32c_value.to_bytes(4, "big")).decode("ascii"),
        ):
            return _error("BadDigest", "CRC32C checksum mismatch", 400)
        engine = TelegramObjectStorage(
            catalog.manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=root,
        )
        # Metadata, tags and the head pointer share one SQL
        # transaction. A failed metadata write cannot publish a
        # partially described object.
        http_properties = parse_object_metadata(
            request.headers, signed_header_names(request),
        )
        http_store = ObjectMetadataStore(catalog)
        tag_store = ObjectTagStore(catalog) if inline_tags is not None else None
        item = await engine.put_file(bucket, key, stage, sse_key=sse_key)
        http_store.attach_uncommitted(item.id, http_properties)
        if tag_store is not None:
            tag_store.attach_uncommitted(item.id, inline_tags)
        try:
            catalog.publish(
                item.id, now=int(time.time()),
                expected_generation=expected_head.generation if expected_head else None,
                expected_object_id=expected_head.object_id if expected_head else None,
            )
        except ValueError as exc:
            if expected_head is not None:
                raise WritePreconditionError(
                    "PreconditionFailed", "Object changed during conditional PUT", 412
                ) from exc
            raise
        _apply_bucket_owner_preferred(catalog, bucket, key, ctx.owner, request)
        response_headers = {
            "ETag": '"' + _effective_object_etag(catalog, item) + '"',
            "x-amz-version-id": item.id,
        }
        if sse_key is not None:
            response_headers.update(_ssec_response_headers(sse_key))
        return Response(status_code=200, headers=response_headers)
    finally:
        stage.unlink(missing_ok=True)


def _object_attributes(ctx: _S3RequestContext, item,
                       item_etag: str) -> Response:
    """GET ?attributes: GetObjectAttributes response XML."""
    request = ctx.request
    catalog = ctx.catalog
    raw = request.headers.get("x-amz-object-attributes", "")
    signed = signed_header_names(request)
    if "x-amz-object-attributes" not in signed:
        raise SigV4Error("AccessDenied", "Object attributes header must be signed")
    if len(request.headers.getlist("x-amz-object-attributes")) != 1:
        return _error("InvalidArgument", "Duplicate object attributes header", 400)
    requested = raw.split(",")
    if (not requested or any(not name for name in requested)
            or len(set(requested)) != len(requested)):
        return _error("InvalidArgument", "Invalid object attributes list", 400)
    permitted = {"ETag", "ObjectSize", "Checksum", "StorageClass", "ObjectParts"}
    if any(name not in permitted for name in requested):
        return _error("NotImplemented", "Requested object attributes are unsupported", 501)

    options = {}
    for name, default, low, high in (
        ("x-amz-max-parts", 1000, 1, 1000),
        ("x-amz-part-number-marker", 0, 0, MAX_PARTS),
    ):
        values = request.headers.getlist(name)
        if values:
            if name not in signed:
                raise SigV4Error("AccessDenied", "Object parts pagination must be signed")
            if (len(values) != 1
                    or re.fullmatch(r"[0-9]{1,5}", values[0]) is None
                    or not low <= int(values[0]) <= high):
                return _error("InvalidArgument", "Invalid object parts pagination", 400)
            if "ObjectParts" not in requested:
                return _error("InvalidArgument", "Part pagination requires ObjectParts", 400)
            options[name] = int(values[0])
        else:
            options[name] = default
    result = ET.Element("GetObjectAttributesOutput", xmlns=NAMESPACE)
    if "ETag" in requested:
        ET.SubElement(result, "ETag").text = '"' + item_etag + '"'
    if "ObjectSize" in requested:
        ET.SubElement(result, "ObjectSize").text = str(item.size)
    if "Checksum" in requested:
        checksum = ET.SubElement(result, "Checksum")
        # Immutable object SHA-256 covers the full plaintext bytes,
        # independent of multipart ETag and physical Telegram chunks.
        ET.SubElement(checksum, "ChecksumSHA256").text = base64.b64encode(
            bytes.fromhex(item.sha256)
        ).decode("ascii")
        ET.SubElement(checksum, "ChecksumType").text = "FULL_OBJECT"
    if "StorageClass" in requested:
        # The catalog's real access-tier label. Archived objects are gated
        # by the read path unless a restore window is open.
        ET.SubElement(result, "StorageClass").text = getattr(
            item, "storage_class", "STANDARD")
    if "ObjectParts" in requested:
        layout = MultipartStore(catalog).object_parts_for_version(item.id, item.size)
        # AWS omits ObjectParts for a plain single PUT. This must not
        # fabricate logical parts out of Telegram's internal chunks.
        if layout is not None:
            marker = options["x-amz-part-number-marker"]
            limit = options["x-amz-max-parts"]
            remaining = [part for part in layout if part[0] > marker]
            page = remaining[:limit]
            listing = ET.SubElement(result, "ObjectParts")
            for name, value in (
                ("PartsCount", len(layout)),
                ("PartNumberMarker", marker),
                ("MaxParts", limit),
                ("IsTruncated", str(len(remaining) > len(page)).lower()),
            ):
                ET.SubElement(listing, name).text = str(value)
            if len(remaining) > len(page):
                ET.SubElement(listing, "NextPartNumberMarker").text = str(page[-1][0])
            for number, size, digest, _etag in page:
                part_node = ET.SubElement(listing, "Part")
                ET.SubElement(part_node, "PartNumber").text = str(number)
                ET.SubElement(part_node, "Size").text = str(size)
                ET.SubElement(part_node, "ChecksumSHA256").text = base64.b64encode(
                    bytes.fromhex(digest)
                ).decode("ascii")
    return Response(
        ET.tostring(result, encoding="utf-8", xml_declaration=True),
        media_type="application/xml", status_code=200,
        headers={
            "x-amz-version-id": item.id,
            "Last-Modified": http_last_modified(item.created_at),
        },
    )


async def _handle_object_read(ctx: _S3RequestContext) -> Response:
    """Object GET/HEAD: versioned reads, preconditions, ranges and
    streaming downloads. Sets ctx.retain for streamed responses."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    db = ctx.db
    catalog = ctx.catalog
    checksum_mode = ctx.checksum_mode
    if ctx.is_version_read:
        version_id = request.query_params["versionId"]
        if not version_id or len(version_id) > 80:
            return _error("InvalidArgument", "Invalid version ID", 400)
        if not catalog.is_visible_version(bucket, key, version_id):
            return _error("NoSuchVersion", "Object version is not published", 404)
        status_row = db.connection.execute(select(
            objects.c.status, objects.c.created_at
        ).where(objects.c.id == version_id)).one_or_none()
        if status_row is not None and status_row[0] == "delete-marker":
            response = _error(
                "MethodNotAllowed", "Requested version is a delete marker", 405,
            )
            response.headers.update({
                "x-amz-delete-marker": "true", "x-amz-version-id": version_id,
                "Last-Modified": http_last_modified(int(status_row[1])),
            })
            return response
        try:
            item = catalog.manifests.get(version_id)
        except FileNotFoundError:
            return _error("NoSuchVersion", "Object version is not readable", 404)
        if item.bucket != bucket or item.key != key:
            return _error("NoSuchVersion", "Version ownership mismatch", 404)
    else:
        try:
            item = catalog.get(bucket, key).item
        except FileNotFoundError:
            marker = catalog.current_marker(bucket, key)
            if marker is not None:
                result = _error("NoSuchKey", "Current version is a delete marker", 404)
                result.headers["x-amz-delete-marker"] = "true"
                result.headers["x-amz-version-id"] = marker
                return result
            return _error("NoSuchKey", "The specified key does not exist", 404)
    item_etag = _effective_object_etag(catalog, item)
    encryption_info = catalog.manifests.encryption_info(item.id)
    sse_key = parse_ssec_headers(request.headers, signed_header_names(request))
    if encryption_info is not None:
        if sse_key is None:
            return _error(
                "InvalidRequest",
                "The object was stored with SSE-C; supply the customer key "
                "headers", 400)
        verify_key_md5(encryption_info, sse_key)
    elif sse_key is not None:
        return _error(
            "InvalidRequest",
            "The object was not stored with SSE-C; remove the customer key "
            "headers", 400)
    if encryption_info is not None:
        # Validate the authenticated chunk layout before any response byte
        # can be sent: a spliced/reordered journal must be a clean 400, not
        # a truncated 200 stream.
        verify_chunk_layout(
            catalog.manifests.parts(item.id),
            catalog.manifests.resolve_content_id(item.id))
    read_now_ns = time.time_ns()
    read_state = catalog.object_read_state(item.id, now_ns=read_now_ns)
    if read_state["archived"]:
        # AWS behaviour: the bytes may exist, but this storage class is not
        # immediately readable. The Telegram chunks are untouched; the gate
        # lives in our catalog and opens only via RestoreObject.
        return _error(
            "InvalidObjectState",
            "The operation is not valid for the object's storage class; "
            "the object is archived and must be restored before reading",
            403,
        )
    if ctx.is_object_attributes:
        return _object_attributes(ctx, item, item_etag)
    http_properties = ObjectMetadataStore(catalog).get(item.id)
    precondition = read_precondition(request, item_etag, item.created_at)
    if precondition == 304:
        return Response(status_code=304, headers={
            "ETag": '"' + item_etag + '"',
            "Last-Modified": http_last_modified(item.created_at),
        })
    if precondition == 412:
        return _error("PreconditionFailed", "Object precondition failed", 412)
    # Every successful GetObject/HeadObject counts, including ranged and
    # versioned reads. Failed/denied/precondition requests never reach here.
    catalog.record_object_access(item.id, now_ns=read_now_ns)
    if request.method == "HEAD":
        headers = _headers(
            item, item_etag, http_properties,
            checksum_mode=(checksum_mode == "ENABLED"
                           and encryption_info is None),
        )
        if sse_key is not None:
            headers.update(_ssec_response_headers(sse_key))
        restore_state = _restore_header(item, now_ns=read_now_ns)
        if restore_state is not None:
            headers["x-amz-restore"] = restore_state
        return Response(status_code=200, headers=headers)
    start, end, partial = _range(request.headers.get("range"), item.size)
    transport = storage_transport(db)
    scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(scratch)
    engine = TelegramObjectStorage(
        catalog.manifests, transport,
        chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
    )

    async def stream():
        try:
            async for piece in engine.iter_bytes(
                    item.id, start=start, end=end, sse_key=sse_key):
                yield piece
        finally:
            db.close()

    ctx.retain = True
    # AWS does NOT return x-amz-checksum-* on a 206: the checksum covers the
    # WHOLE object, so advertising it beside a byte slice makes every strict
    # client (boto3, aws-cli) reject the response as a checksum mismatch.
    # SSE-C objects also never advertise a plaintext checksum: the stored
    # manifest digest can be the ciphertext digest for multipart uploads.
    headers = _headers(item, item_etag, http_properties,
                       checksum_mode=(checksum_mode == "ENABLED"
                                      and not partial
                                      and encryption_info is None))
    if sse_key is not None:
        headers.update(_ssec_response_headers(sse_key))
    restore_state = _restore_header(item, now_ns=read_now_ns)
    if restore_state is not None:
        headers["x-amz-restore"] = restore_state
    headers["Content-Length"] = str(end - start)
    if partial:
        headers["Content-Range"] = f"bytes {start}-{end-1}/{item.size}"
    return StreamingResponse(stream(), status_code=206 if partial else 200, headers=headers)


async def _handle_object_rename(ctx: _S3RequestContext) -> Response:
    """PUT ?renameObject: atomically move the current head to this key.

    Wire shape (the AWS directory-bucket shape): the destination key is the
    request URI key and ``x-amz-rename-source`` carries the source as a local
    ``bucket/key`` path. This implementation supports standard buckets too —
    a documented SUPERSET of AWS, which limits RenameObject to directory
    buckets — because the catalog is metadata-first: no Telegram bytes move.
    Overwrite is rejected (409); conditional rename headers are unsupported.
    """
    request = ctx.request
    bucket = ctx.bucket
    destination_key = ctx.key
    catalog = ctx.catalog
    owner = ctx.owner
    source_header = request.headers.get("x-amz-rename-source")
    if source_header is None:
        return _error("InvalidRequest", "x-amz-rename-source is required", 400)
    if "x-amz-rename-source" not in signed_header_names(request):
        raise SigV4Error("AccessDenied", "x-amz-rename-source must be signed")
    if any(name.startswith("x-amz-rename-source-if-")
           for name in request.headers):
        return _error(
            "NotImplemented",
            "Conditional rename is unsupported; the destination must not exist",
            501,
        )
    if source_header.startswith("//") or "://" in source_header or "?" in source_header:
        return _error("InvalidArgument",
                      "Rename source must be a local bucket/object path", 400)
    path = unquote(source_header[1:] if source_header.startswith("/")
                   else source_header)
    source_bucket, slash, source_key = path.partition("/")
    if not slash or not source_bucket or not source_key:
        return _error("InvalidArgument", "Invalid rename source bucket/object key", 400)
    if source_bucket != bucket:
        return _error("InvalidRequest",
                      "RenameObject source and destination must be in the same bucket",
                      400)
    if source_key == destination_key:
        return _error("InvalidRequest",
                      "Rename source and destination keys are identical", 400)
    try:
        source = catalog.get(bucket, source_key)
    except FileNotFoundError:
        return _error("NoSuchKey", "Rename source object does not exist", 404)
    if catalog.current_marker(bucket, source_key) is not None:
        return _error("NoSuchKey", "Rename source object does not exist", 404)
    # The request-level ACL gate only saw the DESTINATION key. Rename needs
    # READ on the source and WRITE on the destination, both enforced here.
    if not _acl_allows(catalog, owner, "s3:GetObject", bucket, source_key):
        raise SigV4Error("AccessDenied", "Access denied by source object ACL")
    if not _acl_allows(catalog, owner, "s3:PutObject", bucket, destination_key):
        raise SigV4Error("AccessDenied", "Access denied by destination object ACL")
    async for block in request.stream():
        if block:
            return _error("InvalidRequest", "RenameObject request must have no body", 400)
    try:
        catalog.rename_object(
            bucket, source_key, destination_key,
            now=int(time.time()),
            expected_source_id=source.item.id,
            expected_generation=source.generation,
        )
    except FileExistsError:
        return _error("OperationAborted",
                      "Rename destination object already exists", 409)
    except FileNotFoundError:
        return _error("NoSuchKey", "Rename source object does not exist", 404)
    except PermissionError as exc:
        return _error("AccessDenied", str(exc), 403)
    except ValueError:
        return _error("OperationAborted",
                      "Concurrent rename or invalid destination", 409)
    return Response(status_code=200)


async def _handle_select_object_content(ctx: _S3RequestContext) -> Response:
    """POST ?select&select-type=2: run the bounded SQL subset on real bytes."""
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    catalog = ctx.catalog
    owner = ctx.owner
    if request.query_params.get("select-type") != "2":
        return _error("InvalidArgument", "select-type=2 is required", 400)
    if "versionId" in request.query_params:
        return _error("NotImplemented",
                      "Versioned SelectObjectContent is unsupported", 501)
    payload = await _read_verified_xml_body(
        request, MAX_SELECT_XML_BYTES, SelectError)
    select_request = parse_select_request(payload)
    try:
        current = catalog.get(bucket, key)
    except FileNotFoundError:
        return _error("NoSuchKey", "The specified key does not exist", 404)
    if catalog.current_marker(bucket, key) is not None:
        return _error("NoSuchKey", "The specified key does not exist", 404)
    if not _acl_allows(catalog, owner, "s3:GetObject", bucket, key):
        raise SigV4Error("AccessDenied", "Access denied by object ACL")
    scratch = Path(_webapp.STORAGE_SCRATCH_DIR)
    _secure_mkdir(scratch)
    fd, name = tempfile.mkstemp(prefix="s3-select-", dir=scratch)
    stage = Path(name)
    os.close(fd)
    try:
        transport = storage_transport(ctx.db)
        await transport.verify_target()
        engine = TelegramObjectStorage(
            catalog.manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=scratch,
        )
        total = 0
        with open(stage, "wb") as out:
            async for piece in engine.iter_bytes(current.item.id):
                total += len(piece)
                if total > MAX_SELECT_SCAN_BYTES:
                    raise SelectError(
                        "EntityTooLarge",
                        f"Select scan exceeds the {MAX_SELECT_SCAN_BYTES}-byte limit",
                        413,
                    )
                out.write(piece)
        result = run_select(stage, select_request)
        body = build_event_stream(result)
        return Response(body, status_code=200,
                        media_type="application/vnd.amazon.eventstream")
    finally:
        stage.unlink(missing_ok=True)


async def _perform_restore(ctx: _S3RequestContext, item,
                           restore_request) -> Response:
    """Open a bounded restore window on an archived catalog object.

    The Telegram chunks never moved; this only flips the access gate. The
    window is a stored nanosecond deadline, so expiry needs no scheduler.
    """
    now_ns = time.time_ns()
    if _restore_is_restored(item, now_ns=now_ns):
        # AWS RestoreObject answers 409 RestoreAlreadyInProgress while a
        # restore window is still active for the same object.
        return _error(
            "RestoreAlreadyInProgress",
            "The object restore is already in progress",
            409,
        )
    until_ns = now_ns + restore_request.days * 86_400_000_000_000
    try:
        ctx.catalog.db.connection.execute(
            update(objects).where(objects.c.id == item.id)
            .values(restore_until_ns=until_ns))
        ctx.catalog.db.commit()
    except BaseException:
        ctx.catalog.db.connection.rollback()
        raise
    return Response(status_code=202)


async def _handle_restore_object(ctx: _S3RequestContext) -> Response:
    """POST ?restore: strict AWS RestoreRequest, then the real tier state.

    A STANDARD-class object is already immediately readable, so AWS-conformant
    behaviour is ``403 InvalidObjectState``. An ARCHIVE_ACCESS/
    DEEP_ARCHIVE_ACCESS object gets a real restore window (202) and reads work
    again until that window expires.
    """
    request = ctx.request
    bucket = ctx.bucket
    key = ctx.key
    catalog = ctx.catalog
    payload = await _read_verified_xml_body(
        request, MAX_RESTORE_XML_BYTES, RestoreError)
    restore_request = parse_restore_request(payload)
    if "versionId" in request.query_params:
        version_id = request.query_params["versionId"]
        if not version_id or len(version_id) > 80:
            return _error("InvalidArgument", "Invalid object VersionId", 400)
        if not catalog.is_visible_version(bucket, key, version_id):
            return _error("NoSuchVersion", "Object version is not published", 404)
        try:
            item = catalog.manifests.get(version_id)
        except FileNotFoundError:
            return _error("NoSuchVersion", "Object version is not readable", 404)
        status = ctx.db.connection.execute(select(objects.c.status).where(
            objects.c.id == version_id)).scalar_one_or_none()
        if (item.bucket != bucket or item.key != key or status != "ready"):
            return _error("NoSuchVersion", "Object version is not readable", 404)
    else:
        try:
            item = catalog.get(bucket, key).item
        except FileNotFoundError:
            return _error("NoSuchKey", "The specified key does not exist", 404)
        if catalog.current_marker(bucket, key) is not None:
            return _error("NoSuchKey", "The specified key does not exist", 404)
    if not _restore_is_applicable(item):
        return _error(
            "InvalidObjectState",
            "The operation is not valid for the object's storage class; "
            "this object is already in an immediately readable class",
            403,
        )
    return await _perform_restore(ctx, item, restore_request)


async def _handle(request: Request):
    db = None
    retain = False
    try:
        raw_path = request.scope.get("raw_path", b"/").decode("ascii")
        logical = unquote(raw_path.lstrip("/"))
        virtual_bucket = _virtual_host_bucket(request)
        if virtual_bucket is not None:
            bucket, separator, key = virtual_bucket, "/" if logical else "", logical
        else:
            bucket, separator, key = logical.partition("/")
        signing_service = signing_service_hint(request)
        directory_buckets = is_directory_bucket_listing(
            request.method, bucket, bool(separator), request.query_params,
            signing_service)
        validate_s3_query(request.method, bucket, bool(separator),
                          request.query_params, signing_service)
        # S3 Object Lambda's WriteGetObjectResponse is an endpoint-shaped
        # API (POST /WriteGetObjectResponse), not a bucket. Name the missing
        # backing instead of degrading into a generic 501.
        if (request.method == "POST" and not separator
                and bucket == "WriteGetObjectResponse"):
            return _error(
                "NotImplemented",
                "WriteGetObjectResponse is unavailable: S3 Object Lambda has "
                "no backing here because TeleDrive has no Lambda runtime",
                501,
            )
        if not bucket:
            if request.method != "GET":
                return _error("MethodNotAllowed", "Use GET to list buckets", 405)
            # ListDirectoryBuckets (S3 Express One Zone) and ListBuckets
            # share GET /; see route_guard.is_directory_bucket_listing.
            action = ("s3:ListDirectoryBuckets" if directory_buckets
                      else "s3:ListAllMyBuckets")
        elif not separator:
            action = {
                "GET": "s3:ListBucket", "HEAD": "s3:ListBucket",
                "PUT": "s3:CreateBucket", "DELETE": "s3:DeleteBucket",
            }.get(request.method)
        else:
            action = {
                "GET": "s3:GetObject", "HEAD": "s3:GetObject",
                "PUT": "s3:PutObject", "DELETE": "s3:DeleteObject",
            }.get(request.method)
        form_upload = bool(bucket and not separator and request.method == "POST"
                           and not request.query_params)
        multi_delete = bool(bucket and not separator and request.method == "POST"
                            and "delete" in request.query_params)
        if "delete" in request.query_params and not multi_delete:
            return _error("NotImplemented", "Unsupported DeleteObjects route", 501)
        if request.method in ("PUT", "DELETE") or (
            request.method == "POST" and separator and request.query_params.get("uploadId")
        ):
            if any(name in request.headers for name in ("if-modified-since", "if-unmodified-since")):
                return _error("NotImplemented", "Conditional write dates are unsupported", 501)
            has_write_cond = any(name in request.headers for name in ("if-match", "if-none-match"))
            # SigV4 presigned URLs carry authentication query fields, not
            # operation selectors. Permit these to use the same signed CAS.
            auth_only_query = all(name.startswith("X-Amz-")
                                  for name in request.query_params)
            simple_object = bool(request.method in ("PUT", "DELETE")
                                 and separator and auth_only_query
                                 and not request.headers.get("x-amz-copy-source"))
            multipart_completion = bool(
                request.method == "POST" and separator
                and request.query_params.get("uploadId")
                and all(k == "uploadId" or k.startswith("X-Amz-")
                        for k in request.query_params)
            )
            if has_write_cond and not (simple_object or multipart_completion):
                return _error("NotImplemented", "Unsupported conditional S3 operation", 501)
        is_version_read = bool(
            separator and request.method in ("GET", "HEAD")
            and "versionId" in request.query_params
            and all(
                key_name == "versionId"
                or (key_name == "attributes" and "attributes" in request.query_params
                    and request.method == "GET")
                or key_name.startswith("X-Amz-")
                for key_name in request.query_params
            )
        )
        if is_version_read and len(request.query_params.getlist("versionId")) != 1:
            return _error("InvalidArgument", "Ambiguous version ID", 400)
        is_version_delete = bool(
            separator and request.method == "DELETE"
            and "versionId" in request.query_params
            and "tagging" not in request.query_params
        )
        if is_version_delete and (
            len(request.query_params.getlist("versionId")) != 1
            or any(k != "versionId" and not k.startswith("X-Amz-")
                   for k in request.query_params)
        ):
            return _error("InvalidArgument", "Ambiguous VersionId deletion selector", 400)
        is_version_listing = bool(
            bucket and not separator and request.method == "GET"
            and "versions" in request.query_params
        )
        if is_version_listing and any(
            item not in {"versions", "prefix", "max-keys", "key-marker",
                         "version-id-marker", "delimiter", "encoding-type"}
            and not item.startswith("X-Amz-")
            for item in request.query_params
        ):
            return _error("NotImplemented", "Unsupported ListObjectVersions parameter", 501)
        mpu_bucket_list = bool(bucket and not separator and "uploads" in request.query_params
                               and request.method == "GET")
        mpu_start = bool(separator and "uploads" in request.query_params and request.method == "POST")
        mpu_id = request.query_params.get("uploadId") if separator else None
        mpu_part = bool(mpu_id and request.method == "PUT" and "partNumber" in request.query_params)
        mpu_complete = bool(mpu_id and request.method == "POST")
        mpu_abort = bool(mpu_id and request.method == "DELETE")
        mpu_list = bool(mpu_id and request.method == "GET")
        is_object_attributes = bool(separator and "attributes" in request.query_params)
        is_object_rename = bool(
            separator
            and ("renameObject" in request.query_params
                 or "rename" in request.query_params))
        is_object_select = bool(separator and "select" in request.query_params)
        is_object_restore = bool(separator and "restore" in request.query_params)
        is_object_tagging = bool(separator and "tagging" in request.query_params)
        is_version_tagging = bool(is_object_tagging and "versionId" in request.query_params)
        is_object_annotation = bool(
            separator and "annotation" in request.query_params)
        if is_version_tagging and (
            len(request.query_params.getlist("versionId")) != 1
            or any(name not in {"tagging", "versionId"} and not name.startswith("X-Amz-")
                   for name in request.query_params)
        ):
            return _error("InvalidArgument", "Ambiguous versioned tagging selector", 400)
        is_bucket_tagging = bool(bucket and not separator and "tagging" in request.query_params)
        is_bucket_cors = bool(bucket and not separator and "cors" in request.query_params)
        is_bucket_versioning = bool(bucket and not separator and "versioning" in request.query_params)
        is_public_access_block = bool(bucket and not separator and "publicAccessBlock" in request.query_params)
        is_bucket_lifecycle = bool(bucket and not separator and "lifecycle" in request.query_params)
        is_bucket_policy_status = bool(bucket and not separator and "policyStatus" in request.query_params)
        is_bucket_policy = bool(bucket and not separator and "policy" in request.query_params)
        is_bucket_ownership = bool(
            bucket and not separator and "ownershipControls" in request.query_params)
        is_bucket_abac = bool(bucket and not separator and "abac" in request.query_params)
        is_bucket_replication = bool(bucket and not separator and "replication" in request.query_params)
        is_bucket_website = bool(bucket and not separator and "website" in request.query_params)
        is_bucket_notification = bool(
            bucket and not separator
            and ("notification" in request.query_params
                 or "notificationConfiguration" in request.query_params))
        is_bucket_logging = bool(
            bucket and not separator and "logging" in request.query_params)
        is_bucket_encryption = bool(
            bucket and not separator and "encryption" in request.query_params)
        is_object_encryption = bool(
            separator and "encryption" in request.query_params)
        report_kind = next(
            (name for name in REPORT_KINDS
             if bucket and not separator and name in request.query_params),
            None,
        )
        is_bucket_tiering = bool(
            bucket and not separator
            and "intelligent-tiering" in request.query_params)
        metadata_selector = next(
            (name for name in (
                "metadataConfiguration", "metadataTable",
                "metadataJournalTable", "metadataInventoryTable",
                "metadataAnnotationTable",
            ) if bucket and not separator and name in request.query_params),
            None,
        )
        compat_bucket_read = None
        if bucket and not separator and request.method == "GET":
            compat_bucket_read = next(
                (name for name in _COMPAT_BUCKET_READS
                 if name in request.query_params), None)
        compat_object_read = None
        if separator and request.method == "GET":
            compat_object_read = next(
                (name for name in _COMPAT_OBJECT_READS
                 if name in request.query_params), None)
        if is_bucket_lifecycle and (
            len(request.query_params.getlist("lifecycle")) != 1
            or request.query_params.get("lifecycle") != ""
            or any(k != "lifecycle" and not k.startswith("X-Amz-")
                   for k in request.query_params)
        ):
            return _error("InvalidArgument", "Ambiguous lifecycle selector", 400)
        if is_public_access_block and (
            len(request.query_params.getlist("publicAccessBlock")) != 1
            or request.query_params.get("publicAccessBlock") != ""
            or any(name != "publicAccessBlock" and not name.startswith("X-Amz-")
                   for name in request.query_params)
        ):
            return _error("InvalidArgument", "Invalid public access control selector", 400)
        if is_bucket_versioning and (
            len(request.query_params.getlist("versioning")) != 1
            or request.query_params.get("versioning") != ""
            or any(name != "versioning" and not name.startswith("X-Amz-")
                   for name in request.query_params)
        ):
            return _error("InvalidArgument", "Invalid bucket versioning selector", 400)
        if is_bucket_replication and (
            len(request.query_params.getlist("replication")) != 1
            or request.query_params.get("replication") != ""
            or any(name != "replication" and not name.startswith("X-Amz-")
                   for name in request.query_params)
        ):
            return _error("InvalidArgument", "Invalid replication selector", 400)
        if (is_object_tagging or is_bucket_tagging) and any(
            k in request.query_params for k in ("uploads", "uploadId")
        ):
            return _error("NotImplemented", "Tagging with multipart selectors unsupported", 501)
        if is_bucket_tagging and "versionId" in request.query_params:
            return _error("NotImplemented", "Bucket tags cannot select object versions", 501)
        if report_kind is not None:
            if request.method not in {"GET", "PUT", "DELETE"}:
                return _error("MethodNotAllowed",
                              "Report configuration uses GET, PUT or DELETE", 405)
            allowed_params = {report_kind, "id"}
            if any(name not in allowed_params and not name.startswith("X-Amz-")
                   for name in request.query_params):
                return _error("InvalidArgument",
                              "Invalid report configuration selector", 400)
            if len(request.query_params.getlist(report_kind)) != 1 or (
                    request.query_params.get(report_kind) != ""):
                return _error("InvalidArgument",
                              "Invalid report configuration selector", 400)
            id_values = request.query_params.getlist("id")
            if len(id_values) > 1:
                return _error("InvalidArgument",
                              "Ambiguous report configuration id", 400)
            if request.method in {"PUT", "DELETE"} and not id_values:
                return _error("InvalidArgument",
                              "Report configuration id query is required", 400)
        if is_bucket_tiering:
            if request.method not in {"GET", "PUT", "DELETE"}:
                return _error(
                    "MethodNotAllowed",
                    "Intelligent-Tiering configuration uses GET, PUT or DELETE",
                    405)
            if any(name not in {"intelligent-tiering", "id"}
                   and not name.startswith("X-Amz-")
                   for name in request.query_params):
                return _error("InvalidArgument",
                              "Invalid tiering configuration selector", 400)
            if (len(request.query_params.getlist("intelligent-tiering")) != 1
                    or request.query_params.get("intelligent-tiering") != ""):
                return _error("InvalidArgument",
                              "Invalid tiering configuration selector", 400)
            id_values = request.query_params.getlist("id")
            if len(id_values) > 1:
                return _error("InvalidArgument",
                              "Ambiguous tiering configuration id", 400)
            if request.method in {"PUT", "DELETE"} and not id_values:
                return _error("InvalidArgument",
                              "Tiering configuration id query is required", 400)
        if metadata_selector is not None:
            if (request.method not in {
                    "GET", "POST", "PUT", "DELETE"}):
                return _error("MethodNotAllowed",
                              "Unsupported metadata configuration method", 405)
            allowed_params = {metadata_selector}
            if any(name not in allowed_params and not name.startswith("X-Amz-")
                   for name in request.query_params):
                return _error("InvalidArgument",
                              "Invalid metadata configuration selector", 400)
            if (len(request.query_params.getlist(metadata_selector)) != 1
                    or request.query_params.get(metadata_selector) != ""):
                return _error("InvalidArgument",
                              "Invalid metadata configuration selector", 400)
        if is_bucket_encryption:
            action = {
                "GET": "s3:GetBucketEncryption",
                "PUT": "s3:PutBucketEncryption",
                "DELETE": "s3:DeleteBucketEncryption",
            }.get(request.method)
        elif is_object_encryption:
            # UpdateObjectEncryption rotates an existing object to a new
            # customer key (SSE-C only). Reads are not a separate API.
            action = ("s3:PutObjectEncryption"
                      if request.method == "PUT" else None)
        elif is_bucket_notification:
            action = {"GET": "s3:GetBucketNotification",
                      "PUT": "s3:PutBucketNotification"}.get(request.method)
        elif is_bucket_policy:
            action = {
                "GET": "s3:GetBucketPolicy",
                "PUT": "s3:PutBucketPolicy",
                "DELETE": "s3:DeleteBucketPolicy",
            }.get(request.method)
        elif is_bucket_ownership:
            action = {
                "GET": "s3:GetOwnershipControls",
                "PUT": "s3:PutBucketOwnershipControls",
                "DELETE": "s3:DeleteBucketOwnershipControls",
            }.get(request.method)
        elif is_bucket_abac:
            action = {
                "GET": "s3:GetBucketAbac",
                "PUT": "s3:PutBucketAbac",
            }.get(request.method)
        elif is_bucket_logging:
            action = {"GET": "s3:GetBucketLogging",
                      "PUT": "s3:PutBucketLogging"}.get(request.method)
        elif report_kind is not None:
            action = {
                "GET": f"s3:GetBucket{report_kind.capitalize()}Configuration",
                "PUT": f"s3:PutBucket{report_kind.capitalize()}Configuration",
                "DELETE": f"s3:DeleteBucket{report_kind.capitalize()}Configuration",
            }.get(request.method)
        elif is_bucket_tiering:
            if request.method == "GET":
                action = ("s3:ListBucketIntelligentTieringConfigurations"
                          if "id" not in request.query_params
                          else "s3:GetBucketIntelligentTieringConfiguration")
            else:
                action = {
                    "PUT": "s3:PutBucketIntelligentTieringConfiguration",
                    "DELETE": "s3:DeleteBucketIntelligentTieringConfiguration",
                }.get(request.method)
        elif metadata_selector is not None:
            # Phase O3. The V1 and V2 create/get/delete operations share ONE
            # IAM action name in AWS (verified in the API reference).
            if metadata_selector in ("metadataConfiguration", "metadataTable"):
                action = {
                    "POST": "s3:CreateBucketMetadataTableConfiguration",
                    "GET": "s3:GetBucketMetadataTableConfiguration",
                    "DELETE": "s3:DeleteBucketMetadataTableConfiguration",
                }.get(request.method)
            elif metadata_selector == "metadataJournalTable":
                action = ("s3:UpdateBucketMetadataJournalTableConfiguration"
                          if request.method == "PUT" else None)
            elif metadata_selector == "metadataInventoryTable":
                action = ("s3:UpdateBucketMetadataInventoryTableConfiguration"
                          if request.method == "PUT" else None)
            else:
                action = ("s3:UpdateBucketMetadataAnnotationTableConfiguration"
                          if request.method == "PUT" else None)
        elif is_bucket_website:
            action = {
                "GET": "s3:GetBucketWebsite",
                "PUT": "s3:PutBucketWebsite",
                "DELETE": "s3:DeleteBucketWebsite",
            }.get(request.method)
        elif compat_bucket_read is not None:
            action = _COMPAT_BUCKET_READS[compat_bucket_read]
        elif compat_object_read is not None:
            action = _COMPAT_OBJECT_READS[compat_object_read]
        elif not separator and "requestPayment" in request.query_params:
            # Phase O6: writable-but-single-state (BucketOwner only).
            action = {
                "GET": "s3:GetBucketRequestPayment",
                "PUT": "s3:PutBucketRequestPayment",
            }.get(request.method)
        elif not separator and "session" in request.query_params:
            # CreateSession is a GET on the bucket URI (S3 Express). The
            # operation has no writable side, so other methods stay 501.
            action = "s3:CreateSession" if request.method == "GET" else None
        elif not separator and "accelerate" in request.query_params:
            # Phase O6: writable-but-single-state (Suspended only).
            action = {
                "GET": "s3:GetAccelerateConfiguration",
                "PUT": "s3:PutBucketAccelerateConfiguration",
            }.get(request.method)
        elif not separator and "acl" in request.query_params:
            action = {"GET": "s3:GetBucketAcl",
                      "PUT": "s3:PutBucketAcl"}.get(request.method)
        elif separator and "acl" in request.query_params:
            action = {"GET": "s3:GetObjectAcl",
                      "PUT": "s3:PutObjectAcl"}.get(request.method)
        elif separator and "retention" in request.query_params:
            action = {"GET": "s3:GetObjectRetention",
                      "PUT": "s3:PutObjectRetention"}.get(request.method)
        elif separator and "legal-hold" in request.query_params:
            action = {"GET": "s3:GetObjectLegalHold",
                      "PUT": "s3:PutObjectLegalHold"}.get(request.method)
        elif not separator and "object-lock" in request.query_params:
            action = {"GET": "s3:GetBucketObjectLockConfiguration",
                      "PUT": "s3:PutBucketObjectLockConfiguration"
                      }.get(request.method)
        elif is_object_attributes:
            if request.method != "GET" or any(
                p in request.query_params for p in ("uploadId", "uploads", "tagging")
            ):
                return _error("NotImplemented", "Unsupported GetObjectAttributes variant", 501)
            action = "s3:GetObjectAttributes"
        elif is_object_rename:
            action = "s3:RenameObject" if request.method == "PUT" else None
        elif is_object_select:
            action = "s3:SelectObjectContent" if request.method == "POST" else None
        elif is_object_restore:
            action = "s3:RestoreObject" if request.method == "POST" else None
        elif form_upload:
            action = "s3:PutObject"
        elif multi_delete:
            if any(p in request.query_params for p in ("tagging", "uploads", "uploadId", "versionId")):
                return _error("NotImplemented", "Conflicting DeleteObjects controls", 501)
            action = "s3:DeleteObject"
        elif is_object_annotation:
            if request.query_params.get("annotationName") is not None:
                action = {
                    "GET": "s3:GetObjectAnnotation",
                    "PUT": "s3:PutObjectAnnotation",
                    "DELETE": "s3:DeleteObjectAnnotation",
                }.get(request.method)
            else:
                action = ("s3:ListObjectAnnotations"
                          if request.method == "GET" else None)
        elif is_object_tagging:
            action = {
                "GET": "s3:GetObjectTagging",
                "PUT": "s3:PutObjectTagging",
                "DELETE": "s3:DeleteObjectTagging",
            }.get(request.method)
        elif is_bucket_tagging:
            action = {
                "GET": "s3:GetBucketTagging",
                "PUT": "s3:PutBucketTagging",
                "DELETE": "s3:DeleteBucketTagging",
            }.get(request.method)
        elif is_bucket_cors:
            action = {
                "GET": "s3:GetBucketCORS",
                "PUT": "s3:PutBucketCORS",
                "DELETE": "s3:PutBucketCORS",
            }.get(request.method)
        elif is_bucket_versioning:
            action = {
                "GET": "s3:GetBucketVersioning",
                "PUT": "s3:PutBucketVersioning",
            }.get(request.method)
        elif is_public_access_block:
            action = {
                "GET": "s3:GetBucketPublicAccessBlock",
                "PUT": "s3:PutBucketPublicAccessBlock",
                "DELETE": "s3:PutBucketPublicAccessBlock",
            }.get(request.method)
        elif is_bucket_lifecycle:
            action = {
                "GET": "s3:GetLifecycleConfiguration",
                "PUT": "s3:PutLifecycleConfiguration",
                "DELETE": "s3:PutLifecycleConfiguration",
            }.get(request.method)
        elif is_bucket_policy_status:
            action = "s3:GetBucketPolicyStatus" if request.method == "GET" else None
        elif is_bucket_replication:
            action = {
                "GET": "s3:GetBucketReplication",
                "PUT": "s3:PutBucketReplication",
                "DELETE": "s3:DeleteBucketReplication",
            }.get(request.method)
        elif bucket and not separator and "location" in request.query_params:
            action = "s3:GetBucketLocation" if request.method == "GET" else None
        elif mpu_start or mpu_part or mpu_complete:
            action = "s3:PutObject"
        elif is_version_listing:
            action = "s3:ListBucketVersions"
        elif mpu_bucket_list:
            action = "s3:ListBucket"
        elif mpu_abort:
            action = "s3:DeleteObject"
        elif mpu_list:
            action = "s3:GetObject"
        elif "uploads" in request.query_params or "uploadId" in request.query_params:
            return _error("NotImplemented", "This multipart operation is unsupported", 501)
        # A selector on an object path must never silently degrade to a
        # regular object operation (particularly an unexpected DELETE).
        if "lifecycle" in request.query_params and not is_bucket_lifecycle:
            return _error("NotImplemented", "Lifecycle controls require bucket route", 501)
        if "publicAccessBlock" in request.query_params and not is_public_access_block:
            return _error("NotImplemented", "Public access control is bucket-only", 501)
        if "versioning" in request.query_params and not is_bucket_versioning:
            return _error("NotImplemented", "Bucket versioning is a bucket-only operation", 501)
        if action is None or (separator and "partNumber" in request.query_params and not mpu_part):
            return _error("NotImplemented", "This S3 operation is not supported yet", 501)
        # Unknown control-plane query operations must not be misinterpreted as
        # ordinary object reads/writes (e.g. ?tagging, ?versioning, ?acl).
        unsupported = {
            "acl", "versions", "policy",
            "notification", "replication",
            "retention", "legal-hold", "logging",
            "encryption", "object-lock", "versionId",
        }
        active_compat = compat_bucket_read or compat_object_read
        if is_bucket_encryption or is_object_encryption:
            active_compat = "encryption"
        if is_bucket_policy:
            active_compat = "policy"
        elif is_bucket_ownership:
            active_compat = "ownershipControls"
        elif is_bucket_abac:
            active_compat = "abac"
        elif "acl" in request.query_params:
            # Phase D: real ACL controls on both routes; GET is already
            # a compat read, PUT is the new grant-store write.
            active_compat = "acl"
        elif separator and "retention" in request.query_params:
            active_compat = "retention"
        elif separator and "legal-hold" in request.query_params:
            active_compat = "legal-hold"
        elif not separator and "object-lock" in request.query_params:
            active_compat = "object-lock"
        elif is_bucket_replication:
            active_compat = "replication"
        elif is_bucket_notification:
            active_compat = ("notificationConfiguration"
                             if "notificationConfiguration" in request.query_params
                             else "notification")
        elif is_bucket_logging:
            active_compat = "logging"
        if any(parameter in request.query_params and (
            (parameter != "versionId" or not (is_version_read or is_version_tagging or is_version_delete or is_object_restore))
            and (parameter != "versions" or not is_version_listing)
            and parameter != active_compat
        ) for parameter in unsupported):
            return _error("NotImplemented", "This S3 extension is not implemented", 501)

        # SSE-C keys may only reach routes that actually consume them.
        # Every other operation fails closed instead of silently ignoring a
        # key the client believes is protecting the data.
        ssec_requested = any(name in request.headers for name in CUSTOMER_HEADERS)
        copy_source_ssec = any(
            name.startswith(SOURCE_PREFIX + "server-side-encryption-customer")
            for name in request.headers)
        ssec_read = request.method in ("GET", "HEAD") and not (
            is_object_attributes or is_object_tagging or is_object_annotation
            or is_object_restore or is_object_select or is_object_rename
            or is_object_encryption
            or "acl" in request.query_params
            or "retention" in request.query_params
            or "legal-hold" in request.query_params)
        ssec_write = request.method == "PUT" and not (
            is_object_tagging or is_object_annotation or is_object_rename
            or "acl" in request.query_params
            or "retention" in request.query_params
            or "legal-hold" in request.query_params
            or request.headers.get("x-amz-copy-source") is not None)
        ssec_mpu = request.method == "POST" and (mpu_start or mpu_complete)
        ssec_abort = request.method == "DELETE" and mpu_abort
        if copy_source_ssec and not is_object_encryption:
            return _error(
                "NotImplemented",
                "SSE-C copy-source keys are not supported on this operation",
                501)
        if ssec_requested and not (
                separator and (ssec_read or ssec_write or ssec_mpu
                               or ssec_abort)):
            return _error(
                "NotImplemented",
                "SSE-C customer keys are not accepted on this operation", 501)

        master = load_master_key()
        db = db_connect()
        # No schema work before the signature is verified: the constructor's
        # ensure_schema() used to run for every unauthenticated request that
        # reached the gateway, so a stranger could trigger a migration. A
        # missing table makes resolve() return None, which fails closed.
        store = S3CredentialStore(db, master, ensure=False)
        ctx = _S3RequestContext(
            request=request, db=db, store=store, master=master,
            bucket=bucket, key=key,
            multi_delete=multi_delete, mpu_bucket_list=mpu_bucket_list,
            mpu_start=mpu_start, mpu_id=mpu_id, mpu_part=mpu_part,
            mpu_complete=mpu_complete, mpu_abort=mpu_abort, mpu_list=mpu_list,
            is_version_read=is_version_read, is_version_delete=is_version_delete,
            is_version_listing=is_version_listing,
            is_object_attributes=is_object_attributes,
            is_object_tagging=is_object_tagging,
            is_version_tagging=is_version_tagging,
            is_object_annotation=is_object_annotation,
            is_bucket_tagging=is_bucket_tagging, is_bucket_cors=is_bucket_cors,
            is_bucket_versioning=is_bucket_versioning,
            is_public_access_block=is_public_access_block,
            is_bucket_lifecycle=is_bucket_lifecycle,
            is_bucket_notification=is_bucket_notification,
            is_bucket_logging=is_bucket_logging,
            is_bucket_encryption=is_bucket_encryption,
            is_object_encryption=is_object_encryption,
            report_kind=report_kind,
            is_bucket_tiering=is_bucket_tiering,
            metadata_selector=metadata_selector,
            is_bucket_policy_status=is_bucket_policy_status,
            is_bucket_policy=is_bucket_policy,
            is_bucket_ownership=is_bucket_ownership,
            is_bucket_abac=is_bucket_abac,
            is_bucket_replication=is_bucket_replication,
            is_bucket_website=is_bucket_website,
        )
        if form_upload:
            return await _handle_form_upload(ctx)
        owner = verify_header_signature(request, store.resolve, action)
        ctx.owner = owner
        # Every signed S3 method must reject unsupported retention, SSE,
        # requester-payer and governance semantics, including GET/HEAD/DELETE.
        # Ignoring those headers can turn a supposedly protected delete into
        # an ordinary tombstone or pretend to verify a requested checksum.
        _reject_unimplemented_write_options(request)
        if not is_object_attributes and any(
            name in request.headers for name in
            ("x-amz-max-parts", "x-amz-part-number-marker")
        ):
            raise SigV4Error(
                "NotImplemented", "Multipart attributes headers require GetObjectAttributes"
            )
        checksum_mode = request.headers.get("x-amz-checksum-mode")
        if checksum_mode is not None:
            # AWS CLI/botocore send ENABLED by default for standard downloads.
            # Only object GET/HEAD can use the manifest's full-object digest.
            if (request.method not in {"GET", "HEAD"} or not separator
                    or is_object_attributes or is_object_tagging
                    or mpu_list or mpu_abort or mpu_part or mpu_complete):
                raise SigV4Error(
                    "NotImplemented", "ChecksumMode unsupported on this S3 operation",
                )
            if checksum_mode != "ENABLED":
                raise SigV4Error("InvalidArgument", "Unknown checksum mode")
        if request.method == "DELETE" and any(
            name in request.headers for name in ("x-amz-copy-source", "x-amz-tagging")
        ):
            raise SigV4Error("NotImplemented", "Unsupported S3 delete headers")
        inline_tags = _initial_tags(request, owner, store) if (
            separator and request.method == "PUT"
            and not is_object_tagging and not is_object_annotation
        ) else None
        catalog = BucketCatalog(ManifestStore(db))
        ctx.inline_tags = inline_tags
        ctx.checksum_mode = checksum_mode
        ctx.catalog = catalog

        # Phase L single decision point: bucket policy Deny wins, an
        # explicit Allow bypasses the ACL layer, otherwise the Phase D
        # ownership-aware ACL intersection gate applies. The SigV4 scope
        # check above already authenticated the credential's own scopes.
        if bucket:
            allowed, reason = _authorize_resource(
                catalog, store, owner, action, bucket,
                key if separator else None, request)
            if not allowed:
                raise SigV4Error("AccessDenied", reason)

        if not bucket:
            if directory_buckets:
                # True empty listing: TeleDrive has no S3 Express directory
                # buckets, so there is never a bucket or a next token.
                return Response(list_directory_buckets_xml(),
                                media_type="application/xml")
            return Response(
                list_buckets_xml(catalog, request.query_params, master, owner),
                media_type="application/xml",
            )

        if not separator:
            if "object-lock" in request.query_params:
                return await _handle_bucket_object_lock(ctx)
            if "acl" in request.query_params:
                return await _handle_bucket_acl(ctx)
            return await _handle_bucket_route(ctx)
        if bucket not in catalog.list_buckets():
            return _error("NoSuchBucket", "The specified bucket does not exist", 404)
        if not key:
            return _error("InvalidObjectName", "Object key is empty", 400)

        if ("retention" in request.query_params
                or "legal-hold" in request.query_params):
            return await _handle_object_lock_controls(ctx)

        if is_object_rename:
            return await _handle_object_rename(ctx)
        if is_object_encryption:
            return await _handle_object_encryption(ctx)
        if is_object_select:
            return await _handle_select_object_content(ctx)
        if is_object_restore:
            return await _handle_restore_object(ctx)

        if "acl" in request.query_params:
            return await _handle_object_acl(ctx)

        if compat_object_read is not None:
            # The probe must address an existing current object.
            try:
                catalog.get(bucket, key)
            except FileNotFoundError:
                return _error("NoSuchKey", "The requested resource does not exist", 404)
            return _compat_object_read_response(compat_object_read, owner)

        if is_object_annotation:
            return await _handle_object_annotations(ctx)

        if is_object_tagging:
            return await _handle_object_tagging(ctx)

        if mpu_start or mpu_part or mpu_complete or mpu_abort or mpu_list:
            return await _handle_multipart(ctx)
        if is_version_delete:
            return await _handle_version_delete(ctx)

        expected_head = None
        if request.method in ("PUT", "DELETE") and not request.headers.get("x-amz-copy-source"):
            expected_head = check_write_precondition(
                request, catalog, bucket, key, delete=request.method == "DELETE"
            )

        if request.method == "PUT" and request.headers.get("x-amz-copy-source") is not None:
            return await _handle_copy_object(ctx)
        if request.method == "DELETE":
            return await _handle_object_delete(ctx, expected_head)

        if request.method == "PUT":
            return await _handle_object_put(ctx, expected_head)

        response = await _handle_object_read(ctx)
        retain = ctx.retain
        return response
    except WritePreconditionError as exc:
        response = _error(exc.code, str(exc), exc.status)
        if request.method == "PUT":
            # Conditional writes can fail before their request body is read.
            # Never reuse an HTTP/1.1 connection with an unread PUT payload:
            # boto3 otherwise receives an invalid next-request 400 from h11.
            response.headers["Connection"] = "close"
        return response
    except BatchDeleteError as exc:
        return _error(exc.code, str(exc), exc.status)
    except S3QueryError as exc:
        return _error(exc.code, str(exc), exc.status)
    except BucketListingError as exc:
        return _error(exc.code, str(exc), exc.status)
    except LifecycleError as exc:
        return _error(exc.code, str(exc), exc.status)
    except PublicAccessError as exc:
        return _error(exc.code, str(exc), exc.status)
    except PolicyError as exc:
        return _error(exc.code, str(exc), exc.status)
    except OwnershipError as exc:
        return _error(exc.code, str(exc), exc.status)
    except VersioningError as exc:
        return _error(exc.code, str(exc), exc.status)
    except CORSError as exc:
        return _error(exc.code, str(exc), exc.status)
    except ReplicationError as exc:
        return _error(exc.code, str(exc), exc.status)
    except NotificationError as exc:
        return _error(exc.code, str(exc), exc.status)
    except ReportConfigError as exc:
        return _error(exc.code, str(exc), exc.status)
    except TieringError as exc:
        return _error(exc.code, str(exc), exc.status)
    except MetadataConfigurationError as exc:
        return _error(exc.code, str(exc), exc.status)
    except WebsiteError as exc:
        return _error(exc.code, str(exc), exc.status)
    except AnnotationError as exc:
        return _error(exc.code, str(exc), exc.status)
    except BucketFlagError as exc:
        return _error(exc.code, str(exc), exc.status)
    except BucketEncryptionError as exc:
        return _error(exc.code, str(exc), exc.status)
    except SSECError as exc:
        return _error(exc.code, str(exc), exc.status)
    except TaggingError as exc:
        return _error(exc.code, str(exc), exc.status)
    except ObjectLockError as exc:
        return _error(exc.code, str(exc), exc.status)
    except AclError as exc:
        return _error(exc.code, str(exc), exc.status)
    except PermissionError as exc:
        # Object-lock fences (retention/legal hold) surface as 403.
        return _error("AccessDenied", str(exc), 403)
    except ObjectMetadataError as exc:
        return _error(exc.code, str(exc), exc.status)
    except SelectError as exc:
        return _error(exc.code, str(exc), exc.status)
    except RestoreError as exc:
        return _error(exc.code, str(exc), exc.status)
    except MultipartError as exc:
        return _error(exc.code, str(exc), exc.status)
    except SigV4Error as exc:
        return _error(exc.code, exc.message, {
            "RequestTimeTooSkewed": 403, "NotImplemented": 501,
            "InvalidArgument": 400, "InvalidRequest": 400,
            "EntityTooLarge": 413,
            "XAmzContentSHA256Mismatch": 400, "BadDigest": 400,
            "InvalidRange": 416,
        }.get(exc.code, 403))
    except FileNotFoundError:
        return _error("NoSuchKey", "The requested resource does not exist", 404)
    except ValueError:
        return _error("InvalidArgument", "Invalid request parameters", 400)
    except RuntimeError:
        return _error("ServiceUnavailable", "S3 storage backend is unavailable", 503)
    finally:
        if db is not None and not retain:
            db.close()


@app.middleware("http")
async def _s3_audit_log_middleware(request: Request, call_next):
    """Mirror the web http audit log for S3-port traffic.

    S3 client connection attempts — failed signatures, bucket probes,
    even plain browser hits — were previously invisible on the logs
    page because only the web app had an audit middleware. Registered
    after the CORS middleware so it is the OUTERMOST layer and also
    captures its short-circuit responses.
    """
    start = time.time()
    path = request.url.path
    method = request.method
    skip = path == "/__health"
    if not skip:
        client = request.client.host if request.client else "-"
        user = "-"
        auth = request.headers.get("authorization", "")
        if auth.startswith("AWS4-HMAC-SHA256 Credential="):
            # Access key id only; SigV4 never transmits the secret.
            user = auth.split("Credential=", 1)[1].split("/", 1)[0]
        _log(f"{method} {path} from {client}", "http", user=user)
    try:
        response = await call_next(request)
    except Exception as exc:
        if not skip:
            _log(f"{method} {path} -> EXCEPTION: {type(exc).__name__}", "http")
        raise
    elapsed = (time.time() - start) * 1000
    if not skip:
        _log(f"{method} {path} -> {response.status_code} ({elapsed:.0f}ms)",
             "http")
    return response


@app.middleware("http")
async def _route_encoded_control_keys(request: Request, call_next):
    """Preserve S3 opaque keys and enforce bucket CORS independently of SigV4.

    A browser OPTIONS preflight has no AWS signature but cannot read/write
    anything. Actual S3 methods still require the normal signed authorization.
    """
    path = request.scope.get("path", "")
    origin = request.headers.get("origin", "")
    wants_cors = bool(origin and path != "/__health" and path.startswith("/"))
    if wants_cors:
        logical = unquote((request.scope.get("raw_path") or b"/").decode("ascii").lstrip("/"))
        try:
            virtual_bucket = _virtual_host_bucket(request)
        except SigV4Error as exc:
            return _error(exc.code, exc.message, 400)
        bucket = virtual_bucket if virtual_bucket is not None else logical.split("/", 1)[0]
        if bucket:
            connection = None
            try:
                connection = db_connect()
                catalog = BucketCatalog(ManifestStore(connection))
                if bucket in catalog.list_buckets():
                    rules = BucketCORSStore(catalog).get(bucket) or []
                else:
                    rules = []
                is_preflight = request.method == "OPTIONS"
                cors_method = (request.headers.get("access-control-request-method", "")
                               if is_preflight else request.method)
                headers_string = (request.headers.get("access-control-request-headers", "")
                                  if is_preflight else "")
                requested = ([h.strip() for h in headers_string.split(",") if h.strip()]
                             if headers_string else [])
                # Cross-origin browser clients may send many headers; bound
                # their CORS preflight processing without trusting the Origin.
                if (len(headers_string) > 2048 or len(requested) > 32
                        or any(not h.isascii() for h in requested)):
                    return _error("AccessForbidden", "CORS preflight rejected", 403)
                matched = matching_rule(rules, origin, cors_method, requested)
                if is_preflight:
                    if not matched:
                        return _error("AccessForbidden", "CORS preflight rejected", 403)
                    return Response(status_code=200, headers=response_cors_headers(
                        matched, origin, preflight=True, requested_headers=requested
                    ))
            except Exception:
                if request.method == "OPTIONS":
                    return _error("ServiceUnavailable", "CORS lookup unavailable", 503)
                raise
            finally:
                if connection is not None:
                    connection.close()
            # Do not bypass signature validation for actual HTTP methods.
            if path != "/__health" and any(ord(ch) < 32 for ch in path):
                response = await _handle(request)
            else:
                response = await call_next(request)
            if matched:
                for name, value in response_cors_headers(
                    matched, origin, preflight=False
                ).items():
                    response.headers[name] = value
            return response
    if request.method == "OPTIONS":
        return _error("AccessForbidden", "CORS preflight rejected", 403)
    if path != "/__health" and any(ord(character) < 32 for character in path):
        return await _handle(request)
    return await call_next(request)


@app.get("/__health", include_in_schema=False)
def health():
    # Container-local liveness only; no credentials or Telegram calls.
    return {"ok": True}


@app.api_route("/", methods=["GET", "PUT", "POST", "DELETE", "HEAD"])
async def root(request: Request):
    return await _handle(request)


@app.api_route("/{path:path}", methods=["GET", "PUT", "POST", "DELETE", "HEAD"])
async def path_route(request: Request, path: str):
    return await _handle(request)
