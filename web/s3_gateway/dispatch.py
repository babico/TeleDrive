"""ASGI dispatcher for the S3 gateway.

Move-only extraction from ``web/s3.py`` (handoff 01, step 6).  ``web/s3.py``
still re-exports ``_handle`` so ``web.s3`` remains the public import path.
"""
from __future__ import annotations

from urllib.parse import unquote

from fastapi import Request
from fastapi.responses import Response

from teledrive.s3.acl import AclError
from teledrive.s3.annotations import AnnotationError
from teledrive.s3.batch_delete import BatchDeleteError
from teledrive.s3.bucket_encryption import BucketEncryptionError
from teledrive.s3.bucket_flags import BucketFlagError
from teledrive.s3.bucket_listing import BucketListingError, list_buckets_xml
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.cors import CORSError
from teledrive.s3.directory_buckets import list_directory_buckets_xml
from teledrive.s3.lifecycle import LifecycleError
from teledrive.s3.metadata_journal import MetadataConfigurationError
from teledrive.s3.multipart import MultipartError
from teledrive.s3.notifications import NotificationError
from teledrive.s3.object_metadata import ObjectMetadataError
from teledrive.s3.ownership import OwnershipError
from teledrive.s3.policy import PolicyError
from teledrive.s3.public_access import PublicAccessError
from teledrive.s3.replication import ReplicationError
from teledrive.s3.report_configs import KINDS as REPORT_KINDS, ReportConfigError
from teledrive.s3.restore import RestoreError
from teledrive.s3.route_guard import (
    S3QueryError, is_directory_bucket_listing, validate_s3_query)
from teledrive.s3.select import SelectError
from teledrive.s3.sigv4 import (
    SigV4Error, signing_service_hint, verify_header_signature)
from teledrive.s3.tagging import TaggingError
from teledrive.s3.tiering import TieringError
from teledrive.s3.versioning import VersioningError
from teledrive.s3.website import WebsiteError
from teledrive.s3.write_conditions import (
    WritePreconditionError, check_write_precondition)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.sse import CUSTOMER_HEADERS, SOURCE_PREFIX, SSECError

from web.s3_gateway.authorization import _authorize_resource
from web.s3_gateway.buckets import (
    _handle_bucket_route, _handle_form_upload,
)
from web.s3_gateway.common import (
    _COMPAT_BUCKET_READS, _COMPAT_OBJECT_READS, _initial_tags,
    _reject_unimplemented_write_options, db_connect, load_master_key,
)
from web.s3_gateway.context import _S3RequestContext
from web.s3_gateway.metadata_ops import (
    ObjectLockError, _handle_bucket_acl, _handle_bucket_object_lock,
    _handle_object_acl, _handle_object_annotations,
    _handle_object_encryption, _handle_object_lock_controls,
    _handle_object_tagging,
)
from web.s3_gateway.multipart import _handle_multipart
from web.s3_gateway.objects import (
    _handle_copy_object, _handle_object_delete, _handle_object_put,
    _handle_object_read, _handle_object_rename, _handle_restore_object,
    _handle_select_object_content, _handle_version_delete,
)
from web.s3_gateway.ranges import _virtual_host_bucket
from web.s3_gateway.xml import _compat_object_read_response, _error


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
        # Only the object PUT can honour AES256 (envelope encryption); the
        # form-upload path keeps rejecting the encryption family outright.
        _reject_unimplemented_write_options(
            request, allow_envelope=(action == "s3:PutObject"))
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

