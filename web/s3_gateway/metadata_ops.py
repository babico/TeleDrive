"""S3 metadata handlers: ACL, object lock, annotations, tagging, encryption.

Move-only extraction from ``web/s3.py`` (handoff 01, step 6).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from fastapi import Request
from fastapi.responses import Response

import web.app as _webapp
from teledrive.s3.acl import AclError, parse_acl_xml, render_acl_xml
from teledrive.s3.annotations import (
    AnnotationError, AnnotationStore, MAX_ANNOTATION_RESULTS,
    MAX_ANNOTATION_VALUE_BYTES, annotation_etag, annotation_http_date,
    annotations_xml, continuation_token,
    parse_continuation_token, put_annotation_xml, validate_annotation_name,
    validate_annotation_prefix, validate_annotation_value,
)
from teledrive.s3.checksums import crc64nvme
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.object_metadata import signed_header_names
from teledrive.s3.sigv4 import STREAMING_MODES
from teledrive.s3.tagging import ObjectTagStore, TaggingError
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.sse import (
    SOURCE_PREFIX, SSECError, parse_ssec_headers,
)
from web.app import _secure_mkdir

from web.s3_gateway.checksums import (
    _ssec_response_headers, _verify_bucket_control_payload,
    _verify_upload_sha256,
)
from web.s3_gateway.common import (
    _chunk_size, _tag_request_tags, storage_transport,
)
from web.s3_gateway.context import _S3RequestContext
from web.s3_gateway.objects import _read_verified_body
from web.s3_gateway.xml import (
    NAMESPACE, _canned_private_acl_xml, _error, _tag_xml, _xml_ok,
)


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
        chunk_size=_chunk_size(), scratch_directory=scratch,
    )
    digest = await engine.reencrypt(item.id, old_key, new_key)
    headers = _ssec_response_headers(new_key)
    headers["x-amz-version-id"] = item.id
    headers["ETag"] = '"' + digest + '"'
    return Response(status_code=200, headers=headers)

