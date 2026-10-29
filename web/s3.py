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

from web.s3_gateway.checksums import (
    _effective_object_etag, _ssec_response_headers,
    _verify_bucket_control_payload, _verify_upload_sha256,
)
from web.s3_gateway.ranges import (
    _cursor_decode, _cursor_encode, _page, _range, _virtual_host_bucket,
)

from web.s3_gateway.authorization import (
    _ABAC_CONTROL_EXEMPT, _LIST_DEFAULTS, _acl_allows, _apply_bucket_owner_preferred,
    _authorize_resource, _ownership_model, _policy_context, _require_source_acl,
)

from web.s3_gateway.buckets import (
    _handle_batch_delete, _handle_bucket_controls, _handle_bucket_encryption,
    _handle_bucket_metadata_configuration, _handle_bucket_route,
    _handle_form_upload, _list_bucket_versions, _list_objects,
    _replication_destinations,
)
from web.s3_gateway.common import (
    _COMPAT_BUCKET_READS, _COMPAT_OBJECT_READS, _initial_tags,
    _parse_initial_tags, _quota_guard, _reject_unimplemented_write_options,
    _tag_request_tags,
)
from web.s3_gateway.context import _S3RequestContext
from web.s3_gateway.multipart import (
    _handle_multipart, _list_multipart_uploads, _mpu_complete, _mpu_initiate,
    _mpu_list_parts, _mpu_upload_part, _mpu_upload_part_copy,
)
from web.s3_gateway.objects import (
    _handle_copy_object, _handle_object_delete, _handle_object_put,
    _handle_object_read, _handle_version_delete, _headers, _object_attributes,
    _read_verified_body,
)
from web.s3_gateway.xml import (
    _canned_private_acl_xml, _compat_bucket_read_response,
    _compat_object_read_response, _error, _list_xml, _parse_tag_xml,
    _tag_xml, _xml, _xml_ok,
)

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
app = FastAPI(title="TeleDrive S3 (initial compatibility subset)", docs_url=None,
              redoc_url=None, openapi_url=None)


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
