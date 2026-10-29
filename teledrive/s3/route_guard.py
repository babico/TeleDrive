"""Fail-closed S3 query routing contract.

The actual S3 handler still authenticates every operation with SigV4. This
module prevents *unrecognized* AWS control-plane subresources and ambiguous
query combinations from degrading into a normal bucket/object request.
This is a parameter-level guard, not a claim that all 116 S3 APIs exist.
"""
from __future__ import annotations

from collections.abc import Mapping

# Explicit allowlist of implemented selectors and their concrete parameters.
# SDK ?x-id=OperationName is a non-authoritative hint, not a selector; the
# signed HTTP method and URL are always authoritative for routing/auth.
_ROOT_BUCKET_LIST = frozenset({"max-buckets", "prefix", "bucket-region", "continuation-token"})
# ListDirectoryBuckets (S3 Express One Zone) is ALSO GET / with only
# continuation-token and max-directory-buckets (botocore requestUri "/").
# TeleDrive has no directory buckets, so the only honest answer is a
# permanent empty list; the accepted query surface is still AWS's exact one.
_ROOT_DIRECTORY_LIST = frozenset({"continuation-token", "max-directory-buckets"})
_DIRECTORY_LIST_HINT = "ListDirectoryBuckets"
MAX_DIRECTORY_BUCKETS = 1000
MAX_DIRECTORY_TOKEN_LENGTH = 1024
_BUCKET_GET_V1 = frozenset({
    "prefix", "delimiter", "marker", "max-keys", "encoding-type",
})
_BUCKET_GET_V2 = frozenset({
    "list-type", "prefix", "delimiter", "continuation-token",
    "start-after", "max-keys", "encoding-type", "fetch-owner",
})
_BUCKET_GET_VERSIONS = frozenset({
    "versions", "prefix", "max-keys", "key-marker", "version-id-marker",
    "delimiter", "encoding-type",
})
_BUCKET_GET_MULTIPART = frozenset({
    "uploads", "prefix", "delimiter", "encoding-type",
    "key-marker", "upload-id-marker", "max-uploads",
})
_BUCKET_CONTROL = frozenset({
    "location", "cors", "tagging", "versioning", "publicAccessBlock", "lifecycle",
    "policyStatus",
    # Storage reports (Phase N): configuration CRUD with an optional id.
    "analytics", "inventory", "metrics",
    # Intelligent-Tiering configuration CRUD (AWS query selector).
    "intelligent-tiering",
    # S3 Metadata (Phase O3). Exact AWS selectors, verified against the API
    # reference: V2 uses ?metadataConfiguration, V1 uses ?metadataTable, and
    # each update operation has its own singular table selector.
    "metadataConfiguration", "metadataTable",
    "metadataJournalTable", "metadataInventoryTable",
    "metadataAnnotationTable",
    # CreateSession (S3 Express One Zone). GET /{bucket}?session.
    "session",
    # Read-only AWS compatibility probes (see web/s3.py _COMPAT_BUCKET_READS).
    "acl", "ownershipControls", "policy", "replication", "website", "logging",
    "notification", "notificationConfiguration", "requestPayment", "accelerate",
    "encryption", "object-lock", "abac",
})
_OBJECT_CONTROL = frozenset({"tagging", "annotation", "attributes", "uploads", "uploadId", "versionId", "encryption"})
_EMPTY_FLAG = frozenset({
    "location", "cors", "tagging", "annotation", "versioning", "publicAccessBlock",
    "lifecycle", "policyStatus", "uploads", "versions", "delete", "attributes",
    "acl", "ownershipControls", "policy", "replication", "website", "logging",
    "notification", "notificationConfiguration", "requestPayment", "accelerate",
    "encryption", "object-lock", "retention", "legal-hold", "abac",
    "rename", "renameObject", "select", "restore",
    "analytics", "inventory", "metrics",
    "intelligent-tiering",
    "metadataConfiguration", "metadataTable", "metadataJournalTable",
    "metadataInventoryTable", "metadataAnnotationTable",
    # CreateSession (S3 Express One Zone). GET /{bucket}?session.
    "session",
})
# No upper/lower-case folding for S3 query fields: AWS subresources are
# case-sensitive. A misspelled control may not be silently ignored.


class S3QueryError(ValueError):
    def __init__(self, code: str, message: str, status: int):
        super().__init__(message)
        self.code, self.status = code, status


def _real_params(params) -> set[str]:
    """Drop SigV4 auth fields and the non-authoritative SDK x-id hint."""
    return {key for key in params
            if not key.startswith("X-Amz-") and key != "x-id"}


def is_directory_bucket_listing(method: str, bucket: str, object_path: bool,
                                params, signing_service: str = "s3") -> bool:
    """Which of the two AWS operations that share ``GET /`` is this?

    ``ListBuckets`` and ``ListDirectoryBuckets`` both use the root URI, and
    botocore sends NO query field for a default directory listing, so the
    parameters alone cannot tell them apart. The authoritative discriminator
    is the SigV4 credential scope: ListDirectoryBuckets is always signed with
    the ``s3express`` service, ListBuckets with ``s3``. The scope is part of
    the canonical request, so a forged hint cannot survive signature
    verification. ``max-directory-buckets`` and the SDK ``x-id`` hint are
    also honoured for hand-written clients.

    Every other parameter combination keeps the normal ListBuckets
    interpretation (and its stricter V1/V2 validation).
    """
    if method != "GET" or bucket or object_path:
        return False
    real = _real_params(params)
    if "max-directory-buckets" in real:
        return True
    # ListBuckets-specific fields decide the other way; everything else is
    # disambiguated by the signed scope or the SDK hint so that stray fields
    # become a 400 below instead of silently turning a directory listing into
    # ListBuckets.
    if real & {"max-buckets", "prefix", "bucket-region"}:
        return False
    if params.getlist("x-id") == [_DIRECTORY_LIST_HINT]:
        return True
    return signing_service == "s3express"


def validate_s3_query(method: str, bucket: str, object_path: bool, params,
                      signing_service: str = "s3") -> None:
    """Reject unknown controls before SigV4 resolver/DB/media side effects.

    The only exceptions to the enumerated S3 params are AWS SigV4 X-Amz-*
    query fields, verified downstream, and the SDK's non-authoritative x-id.
    ``signing_service`` is the credential scope's service name; it separates
    ListBuckets from ListDirectoryBuckets, which share ``GET /``.
    """
    keys = set(params)
    if len(keys) > 64:
        raise S3QueryError("InvalidArgument", "Too many query parameters", 400)
    real = {key for key in keys if not key.startswith("X-Amz-") and key != "x-id"}
    if "x-id" in keys:
        hint = params.getlist("x-id")
        if len(hint) != 1 or len(hint[0]) > 128:
            raise S3QueryError("InvalidArgument", "Invalid SDK operation hint", 400)

    directory_listing = is_directory_bucket_listing(
        method, bucket, object_path, params, signing_service)
    if not bucket:
        allowed = (_ROOT_DIRECTORY_LIST if directory_listing else
                   (_ROOT_BUCKET_LIST if method == "GET" else frozenset()))
    elif not object_path:
        control = real & _BUCKET_CONTROL
        if control:
            if len(control) != 1:
                raise S3QueryError("InvalidArgument", "Conflicting bucket controls", 400)
            selector = next(iter(control))
            methods = {
                "location": {"GET"}, "cors": {"GET", "PUT", "DELETE"},
                "tagging": {"GET", "PUT", "DELETE"},
                "versioning": {"GET", "PUT"},
                "publicAccessBlock": {"GET", "PUT", "DELETE"},
                "lifecycle": {"GET", "PUT", "DELETE"},
                "policyStatus": {"GET"},
                # Phase D: real ACL grant store; PUT replaces the ACL.
                "acl": {"GET", "PUT"},
                # Phase L: real policy engine, ownership controls and ABAC.
                "ownershipControls": {"GET", "PUT", "DELETE"},
                "policy": {"GET", "PUT", "DELETE"},
                "abac": {"GET", "PUT"},
                # Phase G: real replication configuration (SQL-backed,
                # prefix-aware, over the existing replica engine).
                "replication": {"GET", "PUT", "DELETE"},
                # Phase I: real website configuration + public read gate
                # (the gate itself is admin-only, outside S3).
                "website": {"GET", "PUT", "DELETE"},
                # Phase F: real notification/logging configuration stores.
                "logging": {"GET", "PUT"},
                "notification": {"GET", "PUT"},
                "notificationConfiguration": {"GET", "PUT"},
                "requestPayment": {"GET", "PUT"}, "accelerate": {"GET", "PUT"},
                # CreateSession is GET /{bucket}?session (botocore model).
                "session": {"GET"},
                "encryption": {"GET", "PUT", "DELETE"}, "object-lock": {"GET", "PUT"},
                # Phase N: report configuration CRUD. The optional `id`
                # query field selects one configuration; list requests have
                # none. Continuation tokens are not needed because the list
                # response is the complete, sorted id set.
                "analytics": {"GET", "PUT", "DELETE"},
                "inventory": {"GET", "PUT", "DELETE"},
                "metrics": {"GET", "PUT", "DELETE"},
                "intelligent-tiering": {"GET", "PUT", "DELETE"},
                # Phase O3: real metadata configuration CRUD. Create is POST
                # (not PUT) in AWS; the update operations are PUT.
                "metadataConfiguration": {"GET", "POST", "DELETE"},
                "metadataTable": {"GET", "POST", "DELETE"},
                "metadataJournalTable": {"PUT"},
                "metadataInventoryTable": {"PUT"},
                "metadataAnnotationTable": {"PUT"},
            }
            if selector in {"analytics", "inventory", "metrics",
                            "intelligent-tiering"}:
                allowed = (frozenset({selector, "id"})
                           if method in methods[selector] else frozenset())
            else:
                allowed = frozenset({selector}) if method in methods[selector] else frozenset()
        elif "object-lock" in real:
            allowed = (frozenset({"object-lock"})
                       if method in {"GET", "PUT"} else frozenset())
        elif method == "GET":
            if "versions" in real:
                allowed = _BUCKET_GET_VERSIONS
            elif "uploads" in real:
                allowed = _BUCKET_GET_MULTIPART
            else:
                allowed = _BUCKET_GET_V2 if "list-type" in real else _BUCKET_GET_V1
        elif method == "POST":
            allowed = frozenset({"delete"}) if "delete" in real else frozenset()
        else:
            # HEAD/PUT/DELETE cannot treat ?policy/?acl/?prefix as regular
            # bucket mutations. An unadorned request remains supported.
            allowed = frozenset()
    else:
        if "uploadId" in real:
            allowed = {
                "PUT": frozenset({"uploadId", "partNumber"}),
                "GET": frozenset({"uploadId", "part-number-marker", "max-parts"}),
                "DELETE": frozenset({"uploadId"}),
                "POST": frozenset({"uploadId"}),
            }.get(method, frozenset())
        elif "uploads" in real:
            allowed = frozenset({"uploads"}) if method == "POST" else frozenset()
        elif "encryption" in real:
            # UpdateObjectEncryption (SSE-C key rotation) is a PUT-only
            # object operation. There is no GetObjectEncryption API.
            allowed = frozenset({"encryption"}) if method == "PUT" else frozenset()
        elif "tagging" in real:
            allowed = (frozenset({"tagging", "versionId"})
                       if method in {"GET", "PUT", "DELETE"} else frozenset())
        elif "annotation" in real:
            # Object annotations (AWS reuses ?annotation for both forms):
            #   singular: ?annotation&annotationName=...   GET/PUT/DELETE
            #   listing:  ?annotation[&annotation-prefix=...]
            #             [&max-annotation-results=...]
            #             [&continuation-token=...]         GET
            # Annotations are attached to the CURRENT object only; a
            # versionId selector stays unsupported (501), matching the
            # storage model where revocation deletes annotations.
            if "annotationName" in real:
                allowed = (frozenset({"annotation", "annotationName"})
                           if method in {"GET", "PUT", "DELETE"} else frozenset())
            else:
                allowed = (frozenset({
                    "annotation", "annotation-prefix",
                    "continuation-token", "max-annotation-results",
                }) if method == "GET" else frozenset())
        elif "acl" in real:
            # Phase D: real ACL controls, GET and PUT (current object
            # only — versioned ACL selectors stay unsupported).
            allowed = (frozenset({"acl"})
                       if method in {"GET", "PUT"} else frozenset())
        elif "retention" in real:
            # Phase C: real retention control, GET and PUT (optional
            # published VersionId selector on reads).
            allowed = (frozenset({"retention", "versionId"})
                       if method in {"GET", "PUT"} else frozenset())
        elif "legal-hold" in real:
            allowed = (frozenset({"legal-hold", "versionId"})
                       if method in {"GET", "PUT"} else frozenset())
        elif "attributes" in real:
            # GetObjectAttributes may address a published historical VersionId.
            # Other object controls still fail closed, even if correctly signed.
            allowed = (frozenset({"attributes", "versionId"})
                       if method == "GET" else frozenset())
        elif "renameObject" in real or "rename" in real:
            # Phase O: the REAL AWS wire shape is
            #   PUT /{bucket}/{destination}?renameObject
            # with the source in the signed x-amz-rename-source header.
            # `?rename` is accepted as an alias so both spellings work.
            selector = "renameObject" if "renameObject" in real else "rename"
            allowed = (frozenset({selector})
                       if method == "PUT" else frozenset())
        elif "select" in real:
            # SelectObjectContent requires both selectors; select-type must
            # be 2 (enforced by the handler).
            allowed = (frozenset({"select", "select-type"})
                       if method == "POST" else frozenset())
        elif "restore" in real:
            # RestoreObject may address a published historical VersionId.
            allowed = (frozenset({"restore", "versionId"})
                       if method == "POST" else frozenset())
        elif "versionId" in real:
            allowed = (frozenset({"versionId"})
                       if method in {"GET", "HEAD", "DELETE"} else frozenset())
        else:
            allowed = frozenset()

    # A recognized ListObjects cursor in the wrong API dialect is an
    # InvalidArgument (400), not an unsupported AWS extension (501).
    # This preserves AWS CLI/boto3 V1/V2 cursor error contracts.
    if (bucket and not object_path and method == "GET"
            and not (real & (_BUCKET_CONTROL | {"versions", "uploads"}))):
        if ("list-type" not in real
                and real & {"continuation-token", "start-after"}):
            raise S3QueryError(
                "InvalidArgument", "V2 cursor requires list-type=2", 400,
            )
        if "list-type" in real and "marker" in real:
            raise S3QueryError(
                "InvalidArgument", "V1 marker cannot be used with V2 listing", 400,
            )

    forbidden = real - allowed
    if forbidden:
        # ListDirectoryBuckets is a supported operation with a strict
        # parameter surface: an unknown field is a malformed request (400),
        # not an unimplemented AWS extension (501).
        if directory_listing:
            raise S3QueryError(
                "InvalidArgument",
                "Unknown ListDirectoryBuckets query parameter", 400,
            )
        # Fail closed: no unexpected list, create, overwrite, delete or
        # anonymous body staging even for a valid signed request.
        raise S3QueryError(
            "NotImplemented", "Unsupported S3 query parameter or selector", 501,
        )

    for name in real:
        values = params.getlist(name)
        if len(values) != 1:
            raise S3QueryError("InvalidArgument", "Duplicate S3 query parameter", 400)
        if name in _EMPTY_FLAG and values[0] != "":
            raise S3QueryError("InvalidArgument", "Unexpected selector value", 400)

    if directory_listing:
        token = params.get("continuation-token")
        if token is not None and not (1 <= len(token) <= MAX_DIRECTORY_TOKEN_LENGTH):
            raise S3QueryError(
                "InvalidArgument",
                "continuation-token must contain 1 to 1024 characters", 400,
            )
        raw_limit = params.get("max-directory-buckets")
        if raw_limit is not None:
            if (not raw_limit.isascii() or not raw_limit.isdecimal()
                    or len(raw_limit) > 4):
                raise S3QueryError(
                    "InvalidArgument",
                    "max-directory-buckets must be an integer from 1 to 1000",
                    400,
                )
            if not 1 <= int(raw_limit) <= MAX_DIRECTORY_BUCKETS:
                raise S3QueryError(
                    "InvalidArgument",
                    "max-directory-buckets must be from 1 to 1000", 400,
                )

    if "uploadId" in real and not params["uploadId"]:
        raise S3QueryError("InvalidArgument", "Missing multipart UploadId", 400)
    if "list-type" in real and params["list-type"] != "2":
        raise S3QueryError("InvalidArgument", "Unsupported bucket listing mode", 400)

    # Not all whitelisted parameter combinations are valid: multipart UploadPart
    # needs BOTH parameters; list cursors may not mix V1 and V2.
    if object_path and method == "PUT" and "uploadId" in real and "partNumber" not in real:
        raise S3QueryError("NotImplemented", "Multipart partNumber required", 501)
