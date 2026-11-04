"""Handoff 09, ACL row: header/grant grammar, canned-ACL strictness and
route-coverage parity against real AWS semantics.

AWS facts verified against the S3 User Guide ("Access control list (ACL)
overview", Canned ACL table):

* the canned ACL set is exactly eight values — anything else is a
  malformed request (400 ``InvalidArgument``), not an unsupported
  feature;
* ``x-amz-grant-*`` headers carry comma-separated ``type="value"``
  grantee pairs and are a valid alternative to the XML body on
  PutBucketAcl/PutObjectAcl;
* ACL grants narrow access; every route that addresses the resource
  must consult them.

The private-only line (no AllUsers/AuthenticatedUsers/email/uri
grantees, no public canned ACLs) is TeleDrive's deliberate product
decision and is asserted here as 501, never as silent acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from tests.s3.test_s3_gateway import service, signed  # noqa: F401
from teledrive.s3.acl import (
    AclError, CANNED_ACLS, GRANT_HEADER_NAMES, parse_grant_header,
)
from teledrive.s3.credentials import DEFAULT_PERMISSIONS, S3CredentialStore

ACL_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

# The eight real canned ACLs (S3 User Guide). aws-exec-read is only
# meaningful for AMI bundles but IS part of AWS's set.
AWS_CANNED_ACLS = {
    "private", "public-read", "public-read-write", "authenticated-read",
    "aws-exec-read", "bucket-owner-read", "bucket-owner-full-control",
    "log-delivery-write",
}


@pytest.fixture
def writer(service):
    """A second credential holding every scope.

    Cross-tenant parity needs a principal whose OWN scopes never deny,
    so every denial below is attributable to the ACL grant layer alone.
    """
    store = S3CredentialStore(service[3](), service[4])
    return store.create("writer", list(DEFAULT_PERMISSIONS))


def _as(credential):
    return {"access": credential.access_key,
            "secret": credential.secret_key}


def _object_writer(service, bucket):
    body = (f'<OwnershipControls xmlns="{ACL_XMLNS}"><Rule>'
            f"<ObjectOwnership>ObjectWriter</ObjectOwnership>"
            f"</Rule></OwnershipControls>").encode()
    reply = signed(service, "PUT", f"/{bucket}?ownershipControls", body)
    assert reply.status_code == 200, reply.text


def _put_object_acl(service, bucket, key, grants_xml: str):
    body = (f'<AccessControlPolicy xmlns="{ACL_XMLNS}">'
            f"<AccessControlList>{grants_xml}</AccessControlList>"
            f"</AccessControlPolicy>").encode()
    return signed(service, "PUT", f"/{bucket}/{key}?acl", body)


def _grant_xml(grantee: str, permission: str) -> str:
    return (f'<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/'
            f'XMLSchema-instance" xsi:type="CanonicalUser">'
            f"<ID>{grantee}</ID></Grantee>"
            f"<Permission>{permission}</Permission></Grant>")


# ---------------------------------------------------------------------------
# Canned ACL strictness
# ---------------------------------------------------------------------------

def test_canned_acl_set_is_exactly_aws_eight():
    assert CANNED_ACLS == AWS_CANNED_ACLS


@pytest.mark.parametrize("value", ["bogus", "Private", "public read", ""])
def test_unknown_canned_acl_is_a_malformed_request_not_501(service, value):
    """AWS answers 400 InvalidArgument for a value outside the set."""
    assert signed(service, "PUT", "/canned-bucket").status_code == 200
    refused = signed(service, "PUT", "/canned-bucket/x.bin", b"x",
                     extra_headers={"x-amz-acl": value})
    assert refused.status_code == 400, refused.text
    assert b"InvalidArgument" in refused.content


@pytest.mark.parametrize(
    "value",
    ["public-read", "public-read-write", "authenticated-read",
     "aws-exec-read", "log-delivery-write", "bucket-owner-read"])
def test_unhonored_canned_acls_stay_private_only_501(service, value):
    """Valid AWS canned ACLs this private gateway cannot honor answer
    501, never a silent private fallback nor a public grant."""
    assert signed(service, "PUT", "/canned-bucket").status_code == 200
    refused = signed(service, "PUT", "/canned-bucket/x.bin", b"x",
                     extra_headers={"x-amz-acl": value})
    assert refused.status_code == 501, refused.text
    assert b"NotImplemented" in refused.content


def test_private_and_bucket_owner_full_control_are_honored(service):
    assert signed(service, "PUT", "/canned-bucket").status_code == 200
    for value in ("private", "bucket-owner-full-control"):
        ok = signed(service, "PUT", f"/canned-bucket/{value}.bin", b"x",
                    extra_headers={"x-amz-acl": value})
        assert ok.status_code == 200, ok.text


# ---------------------------------------------------------------------------
# Grant-header grammar (AWS type="value" pairs)
# ---------------------------------------------------------------------------

def test_grant_header_grammar_rejections():
    with pytest.raises(AclError) as exc:
        parse_grant_header("x-amz-grant-read", "id=ABC")
    assert exc.value.status == 400
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-read", 'foo="ABC"')
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-read", "")
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-read", 'id="ABC",')
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-read", 'id=""')
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-read", 'id="' + "x" * 129 + '"')
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-read", "n" * 4096)
    # email/uri grantees: the private-only line, 501 like the XML form.
    with pytest.raises(AclError) as exc:
        parse_grant_header("x-amz-grant-read", 'emailAddress="a@b.c"')
    assert exc.value.status == 501
    with pytest.raises(AclError) as exc:
        parse_grant_header("x-amz-grant-read",
                           'uri="http://acs.amazonaws.com/groups/global/AllUsers"')
    assert exc.value.status == 501
    # Unknown header name, and the id-pair grammar itself.
    with pytest.raises(AclError):
        parse_grant_header("x-amz-grant-nope", 'id="A"')
    assert parse_grant_header(
        "x-amz-grant-read", 'id="A", id="B"') == ["A", "B"]
    assert parse_grant_header("x-amz-grant-full-control", 'id="A"') == ["A"]


def test_grant_headers_write_bucket_acl_like_the_xml_body(service, writer):
    assert signed(service, "PUT", "/hdr-bucket").status_code == 200
    assert signed(service, "PUT", "/hdr-bucket/data.bin",
                  b"payload").status_code == 200
    reply = signed(service, "PUT", "/hdr-bucket?acl", extra_headers={
        "x-amz-grant-read": f'id="{writer.access_key}"'})
    assert reply.status_code == 200, reply.text
    read = signed(service, "GET", "/hdr-bucket?acl")
    assert read.status_code == 200
    assert f"<ID>{writer.access_key}</ID>".encode() in read.content
    assert b"<Permission>READ</Permission>" in read.content
    # The grant is enforced: writer reads, but cannot write (READ only).
    assert signed(service, "GET", "/hdr-bucket/data.bin",
                  **_as(writer)).content == b"payload"
    denied = signed(service, "PUT", "/hdr-bucket/other.bin", b"x",
                    **_as(writer))
    assert denied.status_code == 403
    # Body and headers are mutually exclusive (AWS accepts exactly one).
    both = signed(service, "PUT", "/hdr-bucket?acl", b"<AccessControlPolicy/>",
                  extra_headers={
                      "x-amz-grant-read": f'id="{writer.access_key}"'})
    assert both.status_code == 400
    # Canned + grant headers together is a 400 as well.
    mixed = signed(service, "PUT", "/hdr-bucket?acl", extra_headers={
        "x-amz-acl": "private",
        "x-amz-grant-read": f'id="{writer.access_key}"'})
    assert mixed.status_code == 400


def test_grant_header_validation_on_acl_routes(service, writer):
    assert signed(service, "PUT", "/hdr-bucket").status_code == 200
    # Malformed grammar -> 400 InvalidArgument.
    for value in ("id=ABC", 'foo="A"', "", 'id="A",', 'id=""'):
        refused = signed(service, "PUT", "/hdr-bucket?acl", extra_headers={
            "x-amz-grant-read": value})
        assert refused.status_code == 400, (value, refused.text)
        assert b"InvalidArgument" in refused.content
    # email/uri grantees and the ACP pair -> 501 private-only.
    for name, value in (
            ("x-amz-grant-read", 'emailAddress="a@b.c"'),
            ("x-amz-grant-read",
             'uri="http://acs.amazonaws.com/groups/global/AllUsers"'),
            ("x-amz-grant-read-acp", 'id="A"'),
            ("x-amz-grant-write-acp", 'id="A"')):
        refused = signed(service, "PUT", "/hdr-bucket?acl", extra_headers={
            name: value})
        assert refused.status_code == 501, (name, refused.text)
        assert b"NotImplemented" in refused.content
    # WRITE is not a valid object-ACL permission.
    assert signed(service, "PUT", "/hdr-bucket/obj.bin", b"x").status_code == 200
    object_write = signed(service, "PUT", "/hdr-bucket/obj.bin?acl",
                          extra_headers={
                              "x-amz-grant-write": f'id="{writer.access_key}"'})
    assert object_write.status_code == 400
    # An unknown grantee is rejected at write time, like the XML path.
    unknown = signed(service, "PUT", "/hdr-bucket?acl", extra_headers={
        "x-amz-grant-read": 'id="TDNOPE"'})
    assert unknown.status_code == 400
    # A header naming no grantee at all is malformed, not a no-op.
    empty = signed(service, "PUT", "/hdr-bucket?acl", extra_headers={
        "x-amz-grant-read": 'id=" "'})
    assert empty.status_code == 400


def test_unsigned_grant_header_is_rejected(service, writer):
    """The header must be covered by the SigV4 signature, like x-amz-acl."""
    assert signed(service, "PUT", "/hdr-bucket").status_code == 200
    reply = signed(service, "PUT", "/hdr-bucket?acl")
    headers = dict(reply.request.headers)
    headers["x-amz-grant-read"] = f'id="{writer.access_key}"'
    stripped = service[0].put("/hdr-bucket?acl", headers=headers)
    assert stripped.status_code == 403
    assert b"AccessDenied" in stripped.content


def test_grant_headers_stay_unsupported_outside_the_acl_routes(service, writer):
    """Every other route keeps answering 501 for grant headers."""
    assert signed(service, "PUT", "/hdr-bucket").status_code == 200
    refused = signed(service, "PUT", "/hdr-bucket/obj.bin", b"x",
                     extra_headers={
                         "x-amz-grant-full-control":
                             f'id="{writer.access_key}"'})
    assert refused.status_code == 501
    assert b"NotImplemented" in refused.content


def test_canned_acl_replaces_the_body_on_acl_put(service, writer):
    assert signed(service, "PUT", "/hdr-bucket").status_code == 200
    assert signed(service, "PUT", "/hdr-bucket/canned.bin",
                  b"x").status_code == 200
    # private with no body: the owner-only baseline.
    reply = signed(service, "PUT", "/hdr-bucket/canned.bin?acl",
                   extra_headers={"x-amz-acl": "private"})
    assert reply.status_code == 200, reply.text
    read = signed(service, "GET", "/hdr-bucket/canned.bin?acl")
    assert read.status_code == 200
    assert read.content.count(b"FULL_CONTROL") == 1

    # bucket-owner-full-control with no body hands the bucket owner
    # FULL_CONTROL on the object (the Phase L5 grant, explicit form).
    _object_writer(service, "hdr-bucket")
    reply = signed(service, "PUT", "/hdr-bucket/canned.bin?acl",
                   extra_headers={"x-amz-acl": "bucket-owner-full-control"})
    assert reply.status_code == 200, reply.text
    read = signed(service, "GET", "/hdr-bucket/canned.bin?acl")
    assert read.status_code == 200
    assert read.content.count(b"FULL_CONTROL") >= 1

    # No body and no headers is still a malformed ACL write.
    neither = signed(service, "PUT", "/hdr-bucket/canned.bin?acl")
    assert neither.status_code == 400
    assert b"MalformedXML" in neither.content


# ---------------------------------------------------------------------------
# Route coverage: every cross-tenant route enforces the same grants
# ---------------------------------------------------------------------------

def _restricted_key(service, writer):
    """Object key whose ACL grants the writer READ (and nothing else),
    under ObjectWriter so object grants participate."""
    bucket = "route-matrix"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    _object_writer(service, bucket)
    assert signed(service, "PUT", f"/{bucket}/restricted.bin",
                  b"restricted-payload").status_code == 200
    reply = _put_object_acl(
        service, bucket, "restricted.bin",
        _grant_xml(writer.access_key, "READ"))
    assert reply.status_code == 200, reply.text
    # A sibling key with no ACL keeps the unrestricted baseline.
    assert signed(service, "PUT", f"/{bucket}/free.bin",
                  b"free-payload").status_code == 200
    return bucket


def test_every_write_route_denies_an_ungranted_cross_tenant_credential(
        service, writer):
    bucket = _restricted_key(service, writer)
    key = f"/{bucket}/restricted.bin"

    # READ is granted: the read routes pass.
    assert signed(service, "GET", key, **_as(writer)).content \
        == b"restricted-payload"
    assert signed(service, "HEAD", key, **_as(writer)).status_code == 200

    # Every WRITE-class route is denied by the grant layer even though
    # the credential itself holds every scope.
    denied_routes = [
        ("PUT", key),                                    # overwrite
        ("DELETE", key),                                 # simple delete
        ("POST", f"{key}?uploads"),                      # multipart initiate
        ("POST", f"{key}?restore"),                      # restore
    ]
    for method, path in denied_routes:
        refused = signed(service, method, path, **_as(writer))
        assert refused.status_code == 403, (method, path, refused.text)
        assert b"AccessDenied" in refused.content

    # COPY onto the restricted key (destination write).
    copy = signed(service, "PUT", key, extra_headers={
        "x-amz-copy-source": f"{bucket}/free.bin"}, **_as(writer))
    assert copy.status_code == 403

    # The un-restricted sibling stays writable (grants are per key).
    sibling = signed(service, "PUT", f"/{bucket}/free.bin", b"again",
                     **_as(writer))
    assert sibling.status_code == 200, sibling.text

    # The owner keeps full control through the implicit grant.
    assert signed(service, "PUT", key, b"owner-write").status_code == 200


def test_rename_route_enforces_the_grant_on_both_sides(service, writer):
    """The rename handler re-checks the SOURCE key the request-level
    gate cannot see (the URI addresses only the destination), exactly
    like AWS read-on-source + write-on-destination."""
    bucket = _restricted_key(service, writer)

    # Destination restricted: the request-level gate denies the write.
    refused = signed(service, "PUT", f"/{bucket}/restricted.bin?rename",
                     extra_headers={
                         "x-amz-rename-source": f"{bucket}/free.bin"},
                     **_as(writer))
    assert refused.status_code == 403

    # Source unreadable: the URI destination is unrestricted, so only
    # the handler's source read-check can deny the move.
    assert signed(service, "PUT", f"/{bucket}/secret.bin",
                  b"secret").status_code == 200
    reply = _put_object_acl(service, bucket, "secret.bin",
                            _grant_xml(service[1].access_key, "FULL_CONTROL"))
    assert reply.status_code == 200, reply.text
    denied = signed(service, "PUT", f"/{bucket}/elsewhere.bin?rename",
                    extra_headers={
                        "x-amz-rename-source": f"{bucket}/secret.bin"},
                    **_as(writer))
    assert denied.status_code == 403
    assert b"AccessDenied" in denied.content
    assert signed(service, "GET", f"/{bucket}/secret.bin"
                  ).content == b"secret"


def test_batch_delete_reports_per_entry_grant_denial(service, writer):
    bucket = _restricted_key(service, writer)
    body = (f'<Delete xmlns="{ACL_XMLNS}">'
            f"<Object><Key>restricted.bin</Key></Object>"
            f"<Object><Key>free.bin</Key></Object>"
            f"</Delete>").encode()
    digest = base64.b64encode(
        hashlib.md5(body, usedforsecurity=False).digest()).decode()
    reply = signed(service, "POST", f"/{bucket}?delete", body,
                   extra_headers={"content-md5": digest}, **_as(writer))
    assert reply.status_code == 200, reply.text
    assert b"<Code>AccessDenied</Code>" in reply.content
    # The restricted key survives; the free sibling was deleted.
    assert signed(service, "GET", f"/{bucket}/restricted.bin"
                  ).status_code == 200
    assert signed(service, "GET", f"/{bucket}/free.bin").status_code == 404


def test_presigned_put_by_an_ungranted_credential_is_denied(service, writer):
    """Presigned URLs run the same grant gate: the signature
    authenticates the writer, the ACL still denies the write."""
    import boto3
    from botocore.config import Config
    from urllib.parse import urlsplit

    bucket = _restricted_key(service, writer)
    payload = b"presigned-cross-tenant"
    checksum = base64.b64encode(hashlib.sha256(payload).digest()).decode()
    client = boto3.client(
        "s3", endpoint_url="http://localhost:9000",
        aws_access_key_id=writer.access_key,
        aws_secret_access_key=writer.secret_key,
        region_name="us-east-1",
        config=Config(signature_version="s3v4",
                      s3={"addressing_style": "path"},
                      request_checksum_calculation="when_required",
                      response_checksum_validation="when_required"),
    )
    url = client.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": "restricted.bin",
                "ChecksumSHA256": checksum},
        ExpiresIn=120, HttpMethod="PUT",
    )
    uri = urlsplit(url)
    refused = service[0].request(
        "PUT", uri.path + "?" + uri.query, content=payload,
        headers={"x-amz-checksum-sha256": checksum})
    assert refused.status_code == 403, refused.text
    assert b"AccessDenied" in refused.content
    assert signed(service, "GET", f"/{bucket}/restricted.bin"
                  ).content == b"restricted-payload"


def test_browser_post_form_by_an_ungranted_credential_is_denied(
        service, writer):
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac

    bucket = _restricted_key(service, writer)
    payload = b"form-cross-tenant"
    # A POST policy signed by the writer for the matrix bucket (the
    # shared make_form helper pins bucket "backup-bucket").
    current = datetime.now(timezone.utc).replace(microsecond=0)
    day = current.strftime("%Y%m%d")
    form = {
        "key": "restricted.bin",
        "x-amz-algorithm": "AWS4-HMAC-SHA256",
        "x-amz-credential": (
            f"{writer.access_key}/{day}/us-east-1/s3/aws4_request"),
        "x-amz-date": current.strftime("%Y%m%dT%H%M%SZ"),
        "x-amz-checksum-sha256": _b64.b64encode(
            _hashlib.sha256(payload).digest()).decode(),
    }
    conditions = [{"bucket": bucket}] + [
        {k: v} for k, v in form.items()] + [["content-length-range", 0, 1048576]]
    document = {
        "expiration": (current + timedelta(seconds=300)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "conditions": conditions,
    }
    encoded = _b64.b64encode(json.dumps(document).encode()).decode()
    form["policy"] = encoded
    secret = _hmac.new(("AWS4" + writer.secret_key).encode(),
                       day.encode(), _hashlib.sha256).digest()
    for label in ("us-east-1", "s3", "aws4_request"):
        secret = _hmac.new(secret, label.encode(), _hashlib.sha256).digest()
    form["x-amz-signature"] = _hmac.new(
        secret, encoded.encode(), _hashlib.sha256).hexdigest()

    refused = service[0].post(
        f"/{bucket}", data=form,
        files={"file": ("blob.bin", payload, "application/octet-stream")},
        follow_redirects=False,
    )
    assert refused.status_code == 403, refused.text
    assert b"AccessDenied" in refused.content
    assert signed(service, "GET", f"/{bucket}/restricted.bin"
                  ).content == b"restricted-payload"


# ---------------------------------------------------------------------------
# PAB / ownership precedence
# ---------------------------------------------------------------------------

def test_ownership_enforced_ignores_object_grants(service, writer):
    """BucketOwnerEnforced (the default) wins over object grants, and
    switching to ObjectWriter lets the same grant take effect."""
    bucket = "precedence"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    assert signed(service, "PUT", f"/{bucket}/obj.bin", b"x").status_code == 200
    # A bucket ACL restricts the bucket to its owner.
    main = service[1]
    reply = signed(service, "PUT", f"/{bucket}?acl", (
        f'<AccessControlPolicy xmlns="{ACL_XMLNS}">'
        f"<Owner><ID>{main.access_key}</ID></Owner><AccessControlList>"
        f"{_grant_xml(main.access_key, 'FULL_CONTROL')}"
        f"</AccessControlList></AccessControlPolicy>").encode())
    assert reply.status_code == 200, reply.text
    # ...and an object ACL grants the writer FULL_CONTROL.
    reply = _put_object_acl(service, bucket, "obj.bin",
                            _grant_xml(writer.access_key, "FULL_CONTROL"))
    assert reply.status_code == 200, reply.text

    # Enforced: the object grant is ignored; the bucket grant layer
    # denies the writer.
    denied = signed(service, "GET", f"/{bucket}/obj.bin", **_as(writer))
    assert denied.status_code == 403

    # ObjectWriter: the same object grant now applies.
    _object_writer(service, bucket)
    allowed = signed(service, "GET", f"/{bucket}/obj.bin", **_as(writer))
    assert allowed.status_code == 200, allowed.text


def test_block_public_acls_restricts_acl_writes_to_the_owner(service, writer):
    bucket = "pab-bucket"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    main = service[1]
    # The writer holds every scope and a bucket FULL_CONTROL grant, so
    # only the PAB rule can stand between it and the ACL write.
    reply = signed(service, "PUT", f"/{bucket}?acl", extra_headers={
        "x-amz-grant-full-control": f'id="{writer.access_key}"'})
    assert reply.status_code == 200, reply.text

    # BlockPublicAcls defaults to on: only the ACL owner may write it.
    refused = signed(service, "PUT", f"/{bucket}?acl", extra_headers={
        "x-amz-grant-full-control": f'id="{writer.access_key}"'},
        **_as(writer))
    assert refused.status_code == 403
    assert b"BlockPublicAcls" in refused.content

    # Turning the flag off is the owner's deliberate decision; the
    # writer (holding every scope) may then author grants, but the
    # stored owner stays immutable.
    pab_off = (f'<PublicAccessBlockConfiguration xmlns="{ACL_XMLNS}">'
               f"<BlockPublicAcls>false</BlockPublicAcls>"
               f"<IgnorePublicAcls>false</IgnorePublicAcls>"
               f"<BlockPublicPolicy>false</BlockPublicPolicy>"
               f"<RestrictPublicBuckets>false</RestrictPublicBuckets>"
               f"</PublicAccessBlockConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  pab_off).status_code == 200
    allowed = signed(service, "PUT", f"/{bucket}?acl", extra_headers={
        "x-amz-grant-read": f'id="{writer.access_key}"'}, **_as(writer))
    assert allowed.status_code == 200, allowed.text
    read = signed(service, "GET", f"/{bucket}?acl")
    assert f"<ID>{main.access_key}</ID>".encode() in read.content
