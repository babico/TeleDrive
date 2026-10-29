"""Object-level S3 handlers.

Move-only extraction from ``web/s3.py`` (handoff 01, step 5).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import tempfile
import time
import zlib
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, unquote
from xml.etree import ElementTree as ET

from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select

import web.app as _webapp
from teledrive.s3.annotations import AnnotationError
from teledrive.s3.aws_chunked import AwsChunkedDecoder, streaming_mode
from teledrive.s3.checksums import crc32c, crc64nvme
from teledrive.s3.conditions import http_last_modified, read_precondition
from teledrive.s3.multipart import MAX_PARTS, MultipartStore
from teledrive.s3.object_metadata import (
    ObjectMetadataError, ObjectMetadataStore, parse_object_metadata,
    signed_header_names,
)
from teledrive.s3.restore import restore_header as _restore_header
from teledrive.s3.sigv4 import SigV4Error
from teledrive.s3.tagging import ObjectTagStore, TaggingError
from teledrive.s3.write_conditions import ExpectedHead, WritePreconditionError
from teledrive.storage.copy import CopyConflict, copy_object
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.manifest import objects
from teledrive.storage.sse import (
    parse_ssec_headers, verify_chunk_layout, verify_key_md5,
)
from web.app import _secure_mkdir

from web.s3_gateway.authorization import (
    _apply_bucket_owner_preferred, _require_source_acl,
)
from web.s3_gateway.checksums import (
    _effective_object_etag, _ssec_response_headers, _verify_upload_sha256,
)
from web.s3_gateway.common import _chunk_size, _quota_guard, storage_transport
from web.s3_gateway.ranges import _range
from web.s3_gateway.xml import NAMESPACE, _error


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
                chunk_size=_chunk_size(), scratch_directory=scratch,
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
            chunk_size=_chunk_size(), scratch_directory=root,
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
        chunk_size=_chunk_size(), scratch_directory=scratch,
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
