"""Phase L5/L4: ownership controls actually change authorization and
ABAC forces tag conditions."""
from __future__ import annotations

import json
from xml.etree import ElementTree as ET

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore

BUCKET = "own-bucket"


def _ownership_xml(model: str) -> bytes:
    return (
        '<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Rule><ObjectOwnership>{model}</ObjectOwnership></Rule>"
        "</OwnershipControls>").encode()


def _put_ownership(service, model):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    return signed(service, "PUT", f"/{BUCKET}?ownershipControls",
                  _ownership_xml(model))


def _store(service):
    return S3CredentialStore(service[3](), service[4])


def _as(credential):
    return {"access": credential.access_key,
            "secret": credential.secret_key}


def _acl_owner_only(service, key=None):
    from tests.s3.test_s3_acl import _policy_xml
    main = service[1]
    path = f"/{BUCKET}?acl" if key is None else f"/{BUCKET}/{key}?acl"
    return signed(service, "PUT", path, _policy_xml(main.access_key, []))


# ---------------------------------------------------------------------------
# Ownership controls
# ---------------------------------------------------------------------------

def test_ownership_roundtrip_and_delete_resets(service):
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    read = signed(service, "GET", f"/{BUCKET}?ownershipControls")
    assert read.status_code == 200
    assert b"BucketOwnerEnforced" in read.content
    for model in ("ObjectWriter", "BucketOwnerPreferred"):
        assert _put_ownership(service, model).status_code == 200
        read = signed(service, "GET", f"/{BUCKET}?ownershipControls")
        root = ET.fromstring(read.content)
        assert root.findtext(
            "{http://s3.amazonaws.com/doc/2006-03-01/}Rule/"
            "{http://s3.amazonaws.com/doc/2006-03-01/}ObjectOwnership"
        ) == model
    assert signed(service, "DELETE",
                  f"/{BUCKET}?ownershipControls").status_code == 204
    read = signed(service, "GET", f"/{BUCKET}?ownershipControls")
    assert b"BucketOwnerEnforced" in read.content


def test_ownership_grammar_is_strict(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    bad = [
        b"",
        b"<OwnershipControls/>",
        b"<OwnershipControls><Rule><ObjectOwnership>Public</ObjectOwnership>"
        b"</Rule></OwnershipControls>",
        b"<OwnershipControls><Rule><ObjectOwnership>ObjectWriter"
        b"</ObjectOwnership></Rule><Rule/></OwnershipControls>",
        b"x" * 16385,
    ]
    for payload in bad:
        reply = signed(service, "PUT", f"/{BUCKET}?ownershipControls", payload)
        assert reply.status_code in (400, 501), (payload[:20], reply.text)
    # Empty DELETE body is required.
    assert signed(service, "DELETE", f"/{BUCKET}?ownershipControls",
                  b"unexpected").status_code == 400


def test_ownership_writes_require_permission(service):
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    reader = _store(service).create("own-reader", ["s3:GetOwnershipControls"])
    writer = _store(service).create(
        "own-writer", ["s3:PutBucketOwnershipControls",
                       "s3:DeleteBucketOwnershipControls"])
    denied = signed(service, "PUT", f"/{BUCKET}?ownershipControls",
                    _ownership_xml("ObjectWriter"), **_as(reader))
    assert denied.status_code == 403
    allowed = signed(service, "PUT", f"/{BUCKET}?ownershipControls",
                     _ownership_xml("ObjectWriter"), **_as(writer))
    assert allowed.status_code == 200
    assert signed(service, "DELETE", f"/{BUCKET}?ownershipControls",
                  **_as(writer)).status_code == 204


def test_bucket_owner_enforced_ignores_object_acl_grants(service):
    main = service[1]
    other = _store(service).create("enforced-other", ["s3:GetObject"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/file", b"data").status_code == 200
    # An owner-only object ACL would narrow access under ObjectWriter.
    assert _acl_owner_only(service, "file").status_code == 200
    # BucketOwnerEnforced is the default: the object grant set is ignored.
    assert signed(service, "GET", f"/{BUCKET}/file", **_as(other)).content == b"data"


def test_object_writer_applies_object_acl_grants(service):
    main = service[1]
    other = _store(service).create("writer-other", ["s3:GetObject"])
    assert _put_ownership(service, "ObjectWriter").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/file", b"data").status_code == 200
    assert _acl_owner_only(service, "file").status_code == 200
    denied = signed(service, "GET", f"/{BUCKET}/file", **_as(other))
    assert denied.status_code == 403
    assert b"resource ACL" in denied.content


def test_bucket_owner_preferred_adds_owner_full_control_grant(service):
    main = service[1]
    uploader = _store(service).create("preferred-uploader",
                                      ["s3:PutObject", "s3:GetObject"])
    assert _put_ownership(service, "BucketOwnerPreferred").status_code == 200
    # Establish the bucket owner (main) and let the uploader write.
    from tests.s3.test_s3_acl import _policy_xml
    assert signed(service, "PUT", f"/{BUCKET}?acl", _policy_xml(
        main.access_key, [(uploader.access_key, "FULL_CONTROL", "")])
    ).status_code == 200
    put = signed(service, "PUT", f"/{BUCKET}/shared", b"payload",
                 extra_headers={"x-amz-acl": "bucket-owner-full-control"},
                 **_as(uploader))
    assert put.status_code == 200, put.text
    acl = signed(service, "GET", f"/{BUCKET}/shared?acl")
    assert acl.status_code == 200
    assert f"<ID>{main.access_key}</ID>".encode() in acl.content
    assert b"FULL_CONTROL" in acl.content
    # The bucket owner can read the uploaded object.
    assert signed(service, "GET", f"/{BUCKET}/shared").content == b"payload"


def test_preferred_does_not_grant_without_the_canned_acl(service):
    main = service[1]
    other = _store(service).create("plain-uploader", ["s3:PutObject"])
    assert _put_ownership(service, "BucketOwnerPreferred").status_code == 200
    from tests.s3.test_s3_acl import _policy_xml
    assert signed(service, "PUT", f"/{BUCKET}?acl", _policy_xml(
        main.access_key, [(other.access_key, "FULL_CONTROL", "")])
    ).status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/plain", b"payload",
                  **_as(other)).status_code == 200
    acl = signed(service, "GET", f"/{BUCKET}/plain?acl")
    # No stored object ACL was created; the canned owner answer is used.
    assert f"<ID>{main.access_key}</ID>".encode() in acl.content


def test_delete_public_access_block_restores_all_true(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    relaxed = (b"<PublicAccessBlockConfiguration>"
               b"<BlockPublicAcls>false</BlockPublicAcls>"
               b"<IgnorePublicAcls>false</IgnorePublicAcls>"
               b"<BlockPublicPolicy>false</BlockPublicPolicy>"
               b"<RestrictPublicBuckets>false</RestrictPublicBuckets>"
               b"</PublicAccessBlockConfiguration>")
    assert signed(service, "PUT", f"/{BUCKET}?publicAccessBlock",
                  relaxed).status_code == 200
    assert signed(service, "DELETE",
                  f"/{BUCKET}?publicAccessBlock").status_code == 204
    read = ET.fromstring(
        signed(service, "GET", f"/{BUCKET}?publicAccessBlock").content)
    assert all(child.text == "true" for child in read)


# ---------------------------------------------------------------------------
# ABAC
# ---------------------------------------------------------------------------

def _put_abac(service, document):
    return signed(service, "PUT", f"/{BUCKET}?abac",
                  json.dumps(document).encode())


def test_abac_roundtrip_and_default(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    read = signed(service, "GET", f"/{BUCKET}?abac")
    assert read.status_code == 200
    assert json.loads(read.content) == {"Status": "Disabled"}
    assert _put_abac(service, {"Status": "Enabled"}).status_code == 200
    read = signed(service, "GET", f"/{BUCKET}?abac")
    assert json.loads(read.content)["Status"] == "Enabled"


def test_abac_document_is_strict(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    for document in (
        {},
        {"Status": "On"},
        {"Status": "Enabled", "Unknown": True},
        {"Status": "Enabled", "Conditions": {"s3:prefix": ["x"]}},
        {"Status": "Enabled", "Conditions": {"aws:PrincipalTag/": ["x"]}},
        {"Status": "Enabled", "Conditions": {"aws:PrincipalTag/team": []}},
    ):
        reply = _put_abac(service, document)
        assert reply.status_code == 400, (document, reply.text)
    assert signed(service, "PUT", f"/{BUCKET}?abac",
                  b"x" * (20 * 1024 + 1)).status_code == 400


def test_abac_principal_tag_condition_is_enforced(service):
    store = _store(service)
    tagged = store.create("tagged", ["s3:GetObject"],
                          tags={"team": "eng"})
    untagged = store.create("untagged", ["s3:GetObject"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/file", b"data").status_code == 200
    assert _put_abac(service, {
        "Status": "Enabled",
        "Conditions": {"aws:PrincipalTag/team": ["eng"]},
    }).status_code == 200
    assert signed(service, "GET", f"/{BUCKET}/file", **_as(tagged)).content == b"data"
    denied = signed(service, "GET", f"/{BUCKET}/file", **_as(untagged))
    assert denied.status_code == 403
    assert b"ABAC" in denied.content


def test_abac_existing_object_tag_condition_is_enforced(service):
    store = _store(service)
    reader = store.create("object-tag-reader", ["s3:GetObject"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/public", b"data",
                  extra_headers={"x-amz-tagging": "class=public"}).status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/private", b"data",
                  extra_headers={"x-amz-tagging": "class=private"}).status_code == 200
    assert _put_abac(service, {
        "Status": "Enabled",
        "Conditions": {"s3:ExistingObjectTag/class": ["public"]},
    }).status_code == 200
    assert signed(service, "GET", f"/{BUCKET}/public", **_as(reader)).content == b"data"
    denied = signed(service, "GET", f"/{BUCKET}/private", **_as(reader))
    assert denied.status_code == 403


def test_abac_control_plane_stays_manageable(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert _put_abac(service, {
        "Status": "Enabled",
        "Conditions": {"aws:PrincipalTag/team": ["eng"]},
    }).status_code == 200
    # The untagged owner can still read and disable ABAC (no lockout).
    assert signed(service, "GET", f"/{BUCKET}?abac").status_code == 200
    assert _put_abac(service, {"Status": "Disabled"}).status_code == 200
    assert signed(service, "GET", f"/{BUCKET}/missing").status_code == 404


def test_abac_requires_permission(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    reader = _store(service).create("abac-reader", ["s3:GetBucketAbac"])
    writer = _store(service).create("abac-writer", ["s3:PutBucketAbac"])
    assert signed(service, "GET", f"/{BUCKET}?abac", **_as(reader)).status_code == 200
    denied = signed(service, "PUT", f"/{BUCKET}?abac",
                    json.dumps({"Status": "Enabled"}).encode(), **_as(reader))
    assert denied.status_code == 403
    assert signed(service, "PUT", f"/{BUCKET}?abac",
                  json.dumps({"Status": "Enabled"}).encode(),
                  **_as(writer)).status_code == 200
    assert signed(service, "GET", f"/{BUCKET}?abac", **_as(writer)).status_code == 403
