"""Multipart upload handlers.

Move-only extraction from ``web/s3.py`` (handoff 01, step 4).
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
from pathlib import Path
from urllib.parse import quote, unquote
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from fastapi.responses import Response
from sqlalchemy import select

import web.app as _webapp
from teledrive.s3.aws_chunked import AwsChunkedDecoder, streaming_mode
from teledrive.s3.checksums import crc32c, crc64nvme
from teledrive.s3.multipart import MAX_PARTS, MultipartError, MultipartStore
from teledrive.s3.object_metadata import parse_object_metadata, signed_header_names
from teledrive.s3.sigv4 import SigV4Error
from teledrive.s3.write_conditions import check_write_precondition
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.sse import SSECError, parse_ssec_headers
from web.app import _secure_mkdir

from web.s3_gateway.authorization import _require_source_acl
from web.s3_gateway.checksums import _ssec_response_headers, _verify_upload_sha256
from web.s3_gateway.common import _chunk_size, _quota_guard, storage_transport
from web.s3_gateway.xml import NAMESPACE, _error, _xml


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
        chunk_size=_chunk_size(), scratch_directory=scratch,
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
            chunk_size=_chunk_size(), scratch_directory=scratch,
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
            chunk_size=_chunk_size(), scratch_directory=scratch,
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
