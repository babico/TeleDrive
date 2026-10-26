"""Phase D: ACL grants mapped onto TeleDrive credentials — the
fail-closed intersection model with real SQL state."""
from __future__ import annotations

import pytest

from tests.s3.test_s3_gateway import service, signed

ACL_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _policy_xml(owner: str | None, grants: list[tuple[str, str, str]],
                 *, grantee_type: str = "CanonicalUser") -> bytes:
    """(owner, grantee, permission) triples → AccessControlPolicy body."""
    owner_xml = f"<Owner><ID>{owner}</ID></Owner>" if owner else ""
    grants_xml = "".join(
        f'<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:type="{grantee_type}"><ID>{grantee}</ID></Grantee>'
        f"<Permission>{permission}</Permission></Grant>"
        for grantee, permission, _ in grants)
    return (f'<AccessControlPolicy xmlns="{ACL_XMLNS}">{owner_xml}'
            f"<AccessControlList>{grants_xml}</AccessControlList>"
            f"</AccessControlPolicy>").encode()


@pytest.fixture
def second(service):
    """A second credential with read/write object scopes."""
    from teledrive.s3.credentials import S3CredentialStore
    store = S3CredentialStore(service[3](), service[4])
    return store.create("second", ["s3:GetObject", "s3:PutObject"])


@pytest.fixture
def readonly(service):
    """A third credential that can only read objects."""
    from teledrive.s3.credentials import S3CredentialStore
    store = S3CredentialStore(service[3](), service[4])
    return store.create("readonly", ["s3:GetObject", "s3:ListBucket"])


def _as(credential):
    return {"access": credential.access_key,
            "secret": credential.secret_key}


def test_bucket_acl_roundtrip_and_baseline(service, second):
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    assert signed(service, "PUT", "/acl-bucket/data.bin",
                  b"payload").status_code == 200
    # Baseline: no ACL written — the second credential can read.
    assert signed(service, "GET", "/acl-bucket/data.bin",
                  **_as(second)).content == b"payload"
    # Canned private answer before any ACL exists.
    canned = signed(service, "GET", "/acl-bucket?acl")
    assert canned.status_code == 200
    assert b"FULL_CONTROL" in canned.content

    # Write a bucket ACL granting the second credential READ.
    main = service[1]
    body = _policy_xml(main.access_key,
                       [(second.access_key, "READ", "")])
    put = signed(service, "PUT", "/acl-bucket?acl", body)
    assert put.status_code == 200, put.text
    read = signed(service, "GET", "/acl-bucket?acl")
    assert read.status_code == 200
    # Owner + grantee rows, AWS-shaped.
    assert f"<ID>{main.access_key}</ID>".encode() in read.content
    assert f"<ID>{second.access_key}</ID>".encode() in read.content
    assert b"<Permission>READ</Permission>" in read.content
    # The owner retains the implicit FULL_CONTROL grant.
    assert read.content.count(b"FULL_CONTROL") == 1

    # The grantee keeps reading; the baseline is narrowed only for
    # principals without a grant.
    assert signed(service, "GET", "/acl-bucket/data.bin",
                  **_as(second)).content == b"payload"


def test_bucket_acl_narrows_for_ungated_credentials(service, second, readonly):
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    assert signed(service, "PUT", "/acl-bucket/secret.bin",
                  b"secret").status_code == 200
    main = service[1]
    body = _policy_xml(main.access_key, [(second.access_key, "READ", "")])
    assert signed(service, "PUT", "/acl-bucket?acl", body).status_code == 200

    # The readonly credential has the scope but NO grant: denied.
    denied = signed(service, "GET", "/acl-bucket/secret.bin", **_as(readonly))
    assert denied.status_code == 403, denied.text
    assert b"AccessDenied" in denied.content
    # The owner keeps full control (implicit FULL_CONTROL row).
    assert signed(service, "GET", "/acl-bucket/secret.bin"
                  ).content == b"secret"
    assert signed(service, "PUT", "/acl-bucket/secret.bin",
                  b"secret2").status_code == 200
    # The granted credential may read but not write (READ only).
    assert signed(service, "GET", "/acl-bucket/secret.bin",
                  **_as(second)).content == b"secret2"
    write = signed(service, "PUT", "/acl-bucket/other.bin", b"x", **_as(second))
    assert write.status_code == 403
    # The owner deletes the object (implicit FULL_CONTROL includes
    # WRITE even though the grant list does not mention the owner).
    assert signed(service, "DELETE", "/acl-bucket/secret.bin"
                  ).status_code == 204


def test_grants_never_expand_scopes(service):
    """A WRITE grant cannot hand a read-only credential write access."""
    from teledrive.s3.credentials import S3CredentialStore
    store = S3CredentialStore(service[3](), service[4])
    readonly = store.create("ro", ["s3:GetObject"])
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    main = service[1]
    body = _policy_xml(main.access_key,
                       [(readonly.access_key, "FULL_CONTROL", "")])
    assert signed(service, "PUT", "/acl-bucket?acl", body).status_code == 200
    # FULL_CONTROL grant, but the credential's own scopes lack
    # s3:PutObject: the SigV4 scope check denies first (no expansion).
    write = signed(service, "PUT", "/acl-bucket/new.bin", b"x",
                   **_as(readonly))
    assert write.status_code == 403
    assert b"AccessDenied" in write.content


def test_object_grants_add_for_the_exact_key_only(service, second):
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    assert signed(service, "PUT", "/acl-bucket/one.bin", b"1").status_code == 200
    assert signed(service, "PUT", "/acl-bucket/two.bin", b"2").status_code == 200
    main = service[1]
    # A restrictive bucket ACL: owner only (empty grant list).
    assert signed(service, "PUT", "/acl-bucket?acl",
                  _policy_xml(main.access_key, [])).status_code == 200
    denied = signed(service, "GET", "/acl-bucket/one.bin", **_as(second))
    assert denied.status_code == 403

    # An object ACL on one.bin adds READ for the second credential —
    # for that exact key only, never the sibling.
    obj_body = _policy_xml(main.access_key,
                           [(second.access_key, "READ", "")])
    put = signed(service, "PUT", "/acl-bucket/one.bin?acl", obj_body)
    assert put.status_code == 200, put.text
    assert signed(service, "GET", "/acl-bucket/one.bin",
                  **_as(second)).content == b"1"
    sibling = signed(service, "GET", "/acl-bucket/two.bin", **_as(second))
    assert sibling.status_code == 403
    # The owner still reads both.
    assert signed(service, "GET", "/acl-bucket/two.bin").content == b"2"

    # GET ?acl on the object renders the stored grants.
    read = signed(service, "GET", "/acl-bucket/one.bin?acl")
    assert read.status_code == 200
    assert f"<ID>{second.access_key}</ID>".encode() in read.content


def test_object_acl_restricts_only_its_key(service, second, readonly):
    """An object ACL opts its exact key into restriction; siblings and
    the bucket keep the unrestricted baseline."""
    assert signed(service, "PUT", "/open-bucket").status_code == 200
    assert signed(service, "PUT", "/open-bucket/gated.bin", b"g").status_code == 200
    assert signed(service, "PUT", "/open-bucket/free.bin", b"f").status_code == 200
    main = service[1]
    body = _policy_xml(main.access_key, [(second.access_key, "READ", "")])
    assert signed(service, "PUT", "/open-bucket/gated.bin?acl",
                  body).status_code == 200

    # The granted credential reads the gated key.
    assert signed(service, "GET", "/open-bucket/gated.bin",
                  **_as(second)).content == b"g"
    # An ungated credential is denied ONLY on the gated key.
    denied = signed(service, "GET", "/open-bucket/gated.bin", **_as(readonly))
    assert denied.status_code == 403
    assert signed(service, "GET", "/open-bucket/free.bin",
                  **_as(readonly)).content == b"f"
    # Bucket-level listing stays unrestricted (no bucket ACL written).
    listing = signed(service, "GET", "/open-bucket?list-type=2",
                     **_as(readonly))
    assert listing.status_code == 200
    assert b"free.bin" in listing.content


def test_block_public_acls_locks_acl_writes_to_the_owner(service):
    """Phase E: with BlockPublicAcls on (default), only the stored
    ACL's owner may replace it; turning the flag off is the owner's
    deliberate decision to allow re-authoring."""
    from teledrive.s3.credentials import S3CredentialStore
    store = S3CredentialStore(service[3](), service[4])
    writer = store.create("acl-writer", ["s3:PutBucketAcl", "s3:GetBucketAcl"])
    main = service[1]
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    # The first write establishes the ACL owner and grants the writer
    # FULL_CONTROL — the writer is ACL-authorized to act on the bucket.
    body = _policy_xml(main.access_key,
                       [(writer.access_key, "FULL_CONTROL", "")])
    assert signed(service, "PUT", "/acl-bucket?acl", body).status_code == 200

    # But with BlockPublicAcls on (the all-true default) even a
    # FULL_CONTROL grantee cannot re-author the ACL: only the stored
    # owner may. The flag keeps the grant store owner-pinned.
    hijack = _policy_xml(writer.access_key, [(writer.access_key, "READ", "")])
    denied = signed(service, "PUT", "/acl-bucket?acl", hijack,
                    access=writer.access_key, secret=writer.secret_key)
    assert denied.status_code == 403, denied.text
    assert b"BlockPublicAcls" in denied.content

    # The owner may still rewrite the ACL.
    assert signed(service, "PUT", "/acl-bucket?acl", body).status_code == 200

    # The owner deliberately turns BlockPublicAcls off; the grantee's
    # stored FULL_CONTROL now covers re-authoring (still no public
    # path — grantees are always validated access keys).
    relaxed = (b"<PublicAccessBlockConfiguration>"
               b"<BlockPublicAcls>false</BlockPublicAcls>"
               b"<IgnorePublicAcls>true</IgnorePublicAcls>"
               b"<BlockPublicPolicy>true</BlockPublicPolicy>"
               b"<RestrictPublicBuckets>true</RestrictPublicBuckets>"
               b"</PublicAccessBlockConfiguration>")
    assert signed(service, "PUT", "/acl-bucket?publicAccessBlock",
                  relaxed).status_code == 200
    allowed = signed(service, "PUT", "/acl-bucket?acl", hijack,
                     access=writer.access_key, secret=writer.secret_key)
    assert allowed.status_code == 200, allowed.text
    # The re-authored ACL answers to its new owner; the previous
    # owner is now fenced out by the same intersection gate.
    read = signed(service, "GET", "/acl-bucket?acl",
                  access=writer.access_key, secret=writer.secret_key)
    assert f"<ID>{writer.access_key}</ID>".encode() in read.content


def test_grantee_validation_and_permission_grammar(service, second):
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    assert signed(service, "PUT", "/acl-bucket/x.bin", b"x").status_code == 200
    main = service[1]
    # Unknown CanonicalUser ID: rejected at write time.
    unknown = _policy_xml(main.access_key, [("TDDEADBEEF0000", "READ", "")])
    reply = signed(service, "PUT", "/acl-bucket?acl", unknown)
    assert reply.status_code == 400
    assert b"InvalidArgument" in reply.content
    # Email grantee: the private-only line, fail-closed 501.
    email = _policy_xml(main.access_key,
                        [("someone@example.com", "READ", "")],
                        grantee_type="AmazonCustomerByEmail")
    reply = signed(service, "PUT", "/acl-bucket?acl", email)
    assert reply.status_code == 501
    assert b"NotImplemented" in reply.content
    # Group grantee: same.
    group = _policy_xml(main.access_key,
                        [("http://acs.amazonaws.com/groups/global/AllUsers",
                          "READ", "")], grantee_type="Group")
    reply = signed(service, "PUT", "/acl-bucket?acl", group)
    assert reply.status_code == 501
    # WRITE is not a valid OBJECT ACL permission.
    obj = _policy_xml(main.access_key, [(second.access_key, "WRITE", "")])
    reply = signed(service, "PUT", "/acl-bucket/x.bin?acl", obj)
    assert reply.status_code == 400
    assert b"InvalidArgument" in reply.content
    # Unknown permission name on a bucket ACL.
    bad = _policy_xml(main.access_key, [(second.access_key, "ADMIN", "")])
    reply = signed(service, "PUT", "/acl-bucket?acl", bad)
    assert reply.status_code == 400


def test_acl_requires_scope_and_existing_resources(service):
    from teledrive.s3.credentials import S3CredentialStore
    store = S3CredentialStore(service[3](), service[4])
    narrow = store.create("narrow", ["s3:PutObject"])
    # Without the PutBucketAcl scope the write is denied at auth.
    main = service[1]
    assert signed(service, "PUT", "/acl-bucket").status_code == 200
    body = _policy_xml(main.access_key, [])
    reply = signed(service, "PUT", "/acl-bucket?acl", body, **_as(narrow))
    assert reply.status_code == 403
    # Missing bucket: NoSuchBucket wins (the gate passes — no grants).
    reply = signed(service, "GET", "/no-such-bucket?acl")
    assert reply.status_code == 404
    assert b"NoSuchBucket" in reply.content
    # Missing object for an object ACL write.
    reply = signed(service, "PUT", "/acl-bucket/missing.bin?acl",
                   _policy_xml(main.access_key, []))
    assert reply.status_code == 404
    assert b"NoSuchKey" in reply.content
