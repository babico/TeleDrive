"""Bucket-level S3 handlers, controls and listings.

Move-only extraction from ``web/s3.py`` (handoff 01, step 5).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

from fastapi.responses import Response
from sqlalchemy import text

import web.app as _webapp
from teledrive.s3.acl import is_public_grant_set
from teledrive.s3.batch_delete import (
    MAX_XML_BYTES, BatchDeleteError, parse_batch, verify_body,
)
from teledrive.s3.bucket_encryption import (
    MAX_ENCRYPTION_XML_BYTES, BucketEncryptionError, BucketEncryptionStore,
    encryption_xml, parse_encryption_xml,
)
from teledrive.s3.bucket_flags import (
    MAX_BUCKET_FLAG_XML_BYTES as MAX_BUCKET_FLAG_XML, BucketFlagError,
    parse_accelerate_xml, parse_request_payment_xml,
)
from teledrive.s3.checksums import crc64nvme
from teledrive.s3.cors import (
    MAX_CORS_XML_BYTES, BucketCORSStore, CORSError, cors_xml, parse_cors_xml,
)
from teledrive.s3.directory_buckets import create_session_error
from teledrive.s3.lifecycle import (
    MAX_XML as MAX_LIFECYCLE_XML, BucketLifecycleStore, LifecycleError,
    lifecycle_xml, parse_lifecycle_xml,
)
from teledrive.s3.metadata_journal import (
    MAX_METADATA_XML_BYTES, MetadataConfigurationError,
    MetadataConfigurationStore,
    configuration_xml as metadata_configuration_xml,
    parse_annotation_update as parse_metadata_annotation_update,
    parse_create_configuration as parse_metadata_create_configuration,
    parse_create_table_configuration as parse_metadata_create_table_configuration,
    parse_inventory_update as parse_metadata_inventory_update,
    parse_journal_update as parse_metadata_journal_update,
    table_configuration_xml as metadata_table_configuration_xml,
)
from teledrive.s3.multipart import MultipartError, MultipartStore
from teledrive.s3.notifications import (
    MAX_LOGGING_XML_BYTES, MAX_NOTIFICATION_XML_BYTES, NotificationError,
    NotificationStore, approved_destinations, destination_is_approved,
    logging_xml, notification_xml, parse_logging_xml, parse_notification_xml,
)
from teledrive.s3.object_metadata import (
    STANDARD_HEADERS, ObjectMetadataStore, parse_object_metadata,
)
from teledrive.s3.ownership import (
    MAX_OWNERSHIP_XML_BYTES, OwnershipError, ownership_xml, parse_ownership_xml,
)
from teledrive.s3.policy import (
    MAX_POLICY_BYTES, BucketAbacStore, BucketPolicyStore, PolicyError,
    parse_abac_document, parse_policy,
)
from teledrive.s3.post_policy import FORM_LIMIT, parse_form, verify_post_policy
from teledrive.s3.public_access import (
    MAX_PUBLIC_ACCESS_XML_BYTES, PublicAccessError, parse_public_access_xml,
    public_access_xml,
)
from teledrive.s3.replication import (
    MAX_REPLICATION_XML_BYTES, BucketReplicationStore, ReplicationError,
    parse_replication_xml, replication_xml,
)
from teledrive.s3.report_configs import (
    MAX_REPORT_XML_BYTES, NO_SUCH_CONFIGURATION, ReportConfigError,
    ReportConfigStore, config_xml as report_config_xml,
    list_xml as report_list_xml, parse_document as parse_report_document,
)
from teledrive.s3.sigv4 import SigV4Error
from teledrive.s3.tagging import BucketTagStore, ObjectTagStore, TaggingError
from teledrive.s3.tiering import (
    MAX_TIERING_XML_BYTES,
    NO_SUCH_CONFIGURATION as NO_SUCH_TIERING_CONFIGURATION,
    TieringError, TieringStore, config_xml as tiering_config_xml,
    list_xml as tiering_list_xml, parse_document as parse_tiering_document,
)
from teledrive.s3.versioning import (
    MAX_VERSIONING_XML_BYTES, VersioningError, parse_versioning_xml,
    versioning_xml,
)
from teledrive.s3.website import (
    MAX_WEBSITE_XML_BYTES, WebsiteConfigStore, WebsiteError, parse_website_xml,
    website_xml,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.sse import CUSTOMER_HEADERS
from web.app import _secure_mkdir

from web.s3_gateway.authorization import (
    _apply_bucket_owner_preferred, _authorize_resource,
)
from web.s3_gateway.checksums import (
    _verify_bucket_control_payload, _verify_upload_sha256,
)
from web.s3_gateway.common import (
    _COMPAT_BUCKET_READS, _chunk_size, _notification_allowlist,
    _parse_initial_tags, _quota_guard, _reject_unimplemented_write_options,
    _tag_request_tags, storage_transport,
)
from web.s3_gateway.multipart import _list_multipart_uploads
from web.s3_gateway.ranges import _cursor_decode, _cursor_encode, _page
from web.s3_gateway.xml import (
    NAMESPACE, _compat_bucket_read_response, _error, _list_xml, _tag_xml, _xml,
)


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
            chunk_size=_chunk_size(),
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
    db = ctx.db
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
        from web.s3_gateway.common import envelope_enabled
        store.replace(
            bucket,
            parse_encryption_xml(bytes(payload),
                                 envelope_enabled=envelope_enabled()),
            ctx.owner)
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
