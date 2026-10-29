"""Policy, ABAC and ACL resource-authorization decision point.

Move-only extraction from ``web/s3.py`` (handoff 01, step 2).  The
precedence policy-Deny -> policy-Allow -> ACL must not change.

ListBucket parameters have well-defined DEFAULTS, and omitting them from the
policy context made a Deny silently miss the request it was written to block:
"Deny s3:ListBucket with StringLike {s3:prefix: *}" answered 403 for
?prefix=a but 200 for a bare GET, which enumerated the entire bucket.  A
missing context key fails a positive condition, so the defaults MUST be
present for the request to be evaluated as AWS would evaluate it.
"""
from __future__ import annotations

from urllib.parse import unquote

from sqlalchemy import select

from teledrive.s3.acl import permits as acl_permits
from teledrive.s3.policy import (
    BucketAbacStore, BucketPolicyStore, evaluate as evaluate_policy,
    evaluate_abac,
)
from teledrive.s3.sigv4 import SigV4Error
from teledrive.s3.tagging import object_tags


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


def _ownership_model(catalog, bucket: str) -> str:
    try:
        return catalog.object_ownership(bucket)
    except FileNotFoundError:
        return "BucketOwnerEnforced"


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


_LIST_DEFAULTS = {"prefix": "", "delimiter": "", "max-keys": "1000"}


_ABAC_CONTROL_EXEMPT = frozenset({
    # ABAC is a data-access gate; the owner must remain able to manage
    # the ABAC/policy controls that could otherwise lock the bucket.
    "s3:PutBucketAbac", "s3:GetBucketAbac",
    "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:GetBucketPolicy",
    "s3:PutBucketOwnershipControls", "s3:DeleteBucketOwnershipControls",
    "s3:GetOwnershipControls",
})
