"""Phase L: strict IAM-style bucket policy engine.

Covers every rejection class, glob matching, deny-overrides, condition
evaluation, cache invalidation, principal validation and the interaction
between policy decisions, ACLs and ownership controls.
"""
from __future__ import annotations

import json

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.policy import (
    PolicyError, evaluate, parse_policy, Condition,
)

BUCKET = "policy-bucket"


def _principal(access_key: str) -> dict:
    return {"CanonicalUser": [access_key]}


def _statement(*, effect="Allow", action="s3:GetObject",
               resource="/*", principal=None, condition=None, sid=None):
    statement = {
        "Effect": effect,
        "Principal": principal or {"CanonicalUser": ["TDPLACEHOLDER"]},
        "Action": action,
        "Resource": "arn:aws:s3:::" + BUCKET + resource,
    }
    if condition is not None:
        statement["Condition"] = condition
    if sid is not None:
        statement["Sid"] = sid
    return statement


def _document(*statements, version="2012-10-17") -> bytes:
    return json.dumps({"Version": version,
                       "Statement": list(statements)}).encode()


def _store(service):
    return S3CredentialStore(service[3](), service[4])


def _compiled(service, *statements):
    store = _store(service)
    document = _document(*statements)
    return parse_policy(document, bucket=BUCKET, credential_store=store)


# ---------------------------------------------------------------------------
# Parse / validation
# ---------------------------------------------------------------------------

def test_valid_policy_compiles_and_canonicalises(service):
    main = service[1]
    compiled = _compiled(service, _statement(principal=_principal(main.access_key)))
    assert compiled.bucket == BUCKET
    assert len(compiled.statements) == 1
    assert compiled.statements[0].effect == "Allow"
    parsed = json.loads(compiled.document)
    assert parsed["Version"] == "2012-10-17"


def test_version_is_pinned(service):
    main = service[1]
    # Build an explicitly wrong version.
    document = _document(_statement(principal=_principal(main.access_key)),
                         version="2008-10-17")
    with pytest.raises(PolicyError) as exc:
        parse_policy(document, bucket=BUCKET, credential_store=_store(service))
    assert exc.value.status == 400


def test_oversized_policy_rejected(service):
    payload = (b'{"Version":"2012-10-17","Statement":[],'
               + b" " * (21 * 1024) + b'"_pad":0}')
    with pytest.raises(PolicyError, match="20"):
        parse_policy(payload, bucket=BUCKET, credential_store=_store(service))


def test_more_than_fifty_statements_rejected(service):
    statements = [_statement(principal=_principal(service[1].access_key))
                  for _ in range(51)]
    with pytest.raises(PolicyError, match="50"):
        parse_policy(_document(*statements), bucket=BUCKET,
                     credential_store=_store(service))


def test_sid_length_and_uniqueness(service):
    main = service[1]
    with pytest.raises(PolicyError, match="Sid"):
        _compiled(service, _statement(principal=_principal(main.access_key),
                                      sid="s" * 129))
    with pytest.raises(PolicyError, match="unique"):
        _compiled(service,
                  _statement(principal=_principal(main.access_key), sid="same"),
                  _statement(effect="Deny", principal=_principal(main.access_key),
                             sid="same"))


def test_effect_and_required_fields_are_strict(service):
    main = service[1]
    with pytest.raises(PolicyError, match="Effect"):
        _compiled(service, _statement(effect="allow",
                                      principal=_principal(main.access_key)))
    statement = _statement(principal=_principal(main.access_key))
    del statement["Action"]
    with pytest.raises(PolicyError, match="Action"):
        _compiled(service, statement)
    statement = _statement(principal=_principal(main.access_key))
    statement["Extra"] = True
    with pytest.raises(PolicyError, match="Unsupported statement field"):
        _compiled(service, statement)


def test_public_and_aws_principals_are_not_implemented(service):
    main = service[1]
    statement = _statement(principal="*")
    with pytest.raises(PolicyError) as exc:
        _compiled(service, statement)
    assert exc.value.status == 501
    for name in ("AWS", "Service", "Federated"):
        statement = _statement(principal={name: "*"})
        with pytest.raises(PolicyError) as exc:
            _compiled(service, statement)
        assert exc.value.status == 501


def test_principal_must_be_active_credential(service):
    main = service[1]
    with pytest.raises(PolicyError, match="active credentials"):
        _compiled(service, _statement(principal=_principal("TDDEADBEEF")))
    # Revoking a credential makes an existing principal invalid on rewrite.
    store = _store(service)
    doomed = store.create("doomed", ["s3:GetObject"])
    store.revoke(doomed.id)
    with pytest.raises(PolicyError, match="active credentials"):
        _compiled(service, _statement(principal=_principal(doomed.access_key)))


def test_unknown_action_and_bad_glob_rejected(service):
    main = service[1]
    with pytest.raises(PolicyError, match="known S3 permission"):
        _compiled(service, _statement(action="s3:TeleportObject",
                                      principal=_principal(main.access_key)))
    with pytest.raises(PolicyError, match="known S3 permission"):
        _compiled(service, _statement(action="ec2:RunInstances",
                                      principal=_principal(main.access_key)))
    # A glob that matches no real permission is equally rejected.
    with pytest.raises(PolicyError, match="known S3 permission"):
        _compiled(service, _statement(action="s3:ZZZ*",
                                      principal=_principal(main.access_key)))
    # A real wildcard is accepted.
    _compiled(service, _statement(action="s3:Get*",
                                  principal=_principal(main.access_key)))


def test_resource_partition_and_bucket_are_strict(service):
    main = service[1]
    for resource in (
        "arn:aws-cn:s3:::policy-bucket/*",
        "arn:aws:s3:::other-bucket/*",
        "policy-bucket/*",
    ):
        statement = _statement(principal=_principal(main.access_key))
        statement["Resource"] = resource
        with pytest.raises(PolicyError):
            _compiled(service, statement)


def test_condition_operator_and_key_allowlists(service):
    main = service[1]
    for condition in (
        {"StringEquals": {"s3:Unknown": ["x"]}},
        {"ArnLike": {"s3:prefix": ["x"]}},
        {"StringEquals": {"aws:username": ["x"]}},
    ):
        with pytest.raises(PolicyError):
            _compiled(service, _statement(principal=_principal(main.access_key),
                                          condition=condition))
    # Every documented operator/key is accepted.
    _compiled(service, _statement(
        principal=_principal(main.access_key),
        condition={
            "StringEquals": {"s3:prefix": ["a"]},
            "StringLike": {"s3:delimiter": ["/"]},
            "StringNotEquals": {"s3:max-keys": ["0"]},
            "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
            "NotIpAddress": {"aws:SourceIp": ["192.168.0.0/16"]},
            "Bool": {"s3:x-amz-acl": ["true"]},
            "NumericLessThan": {"s3:max-keys": ["100"]},
            "NumericLessThanEquals": {"s3:max-keys": ["100"]},
            "NumericGreaterThan": {"s3:max-keys": ["1"]},
            "NumericGreaterThanEquals": {"s3:max-keys": ["1"]},
            "StringEquals": {"aws:PrincipalTag/team": ["eng"]},
        }))


def test_condition_value_types_are_validated(service):
    main = service[1]
    for condition in (
        {"Bool": {"s3:x-amz-acl": ["yes"]}},
        {"NumericLessThan": {"s3:max-keys": ["many"]}},
        {"IpAddress": {"aws:SourceIp": ["not-an-ip"]}},
        {"StringEquals": {"s3:prefix": []}},
    ):
        with pytest.raises(PolicyError):
            _compiled(service, _statement(principal=_principal(main.access_key),
                                          condition=condition))


def test_duplicate_json_keys_and_bad_json_rejected(service):
    main = service[1]
    raw = ('{"Version":"2012-10-17","Statement":[],'
           '"Statement":[]}').encode()
    with pytest.raises(PolicyError, match="Duplicate"):
        parse_policy(raw, bucket=BUCKET, credential_store=_store(service))
    with pytest.raises(PolicyError, match="Invalid"):
        parse_policy(b"not-json", bucket=BUCKET,
                     credential_store=_store(service))
    with pytest.raises(PolicyError, match="exactly"):
        parse_policy(json.dumps({"Version": "2012-10-17"}).encode(),
                     bucket=BUCKET, credential_store=_store(service))


def test_empty_and_non_list_statement_rejected(service):
    with pytest.raises(PolicyError, match="non-empty list"):
        parse_policy(json.dumps({"Version": "2012-10-17",
                                 "Statement": []}).encode(),
                     bucket=BUCKET, credential_store=_store(service))
    with pytest.raises(PolicyError, match="non-empty list"):
        parse_policy(json.dumps({"Version": "2012-10-17",
                                 "Statement": {}}).encode(),
                     bucket=BUCKET, credential_store=_store(service))


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _eval(compiled, action, resource, principal, context=None):
    return evaluate(compiled.statements, action, resource, principal,
                    context or {})


def test_deny_overrides_allow(service):
    main = service[1]
    compiled = _compiled(
        service,
        _statement(effect="Allow", principal=_principal(main.access_key)),
        _statement(effect="Deny", principal=_principal(main.access_key)),
    )
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a",
                 main.access_key) == "deny"


def test_allow_and_no_decision(service):
    main = service[1]
    compiled = _compiled(service, _statement(
        principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a",
                 main.access_key) == "allow"
    # Wrong action / resource / principal yields no decision (ACL fallback).
    assert _eval(compiled, "s3:PutObject", f"{BUCKET}/a",
                 main.access_key) is None
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a", "TDSOMEONE") is None
    assert _eval(compiled, "s3:GetObject", BUCKET, main.access_key) is None


def test_action_and_resource_globs(service):
    main = service[1]
    compiled = _compiled(service, _statement(
        action="s3:Get*", resource="/private/*",
        principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/private/a",
                 main.access_key) == "allow"
    assert _eval(compiled, "s3:GetObjectTagging", f"{BUCKET}/private/a",
                 main.access_key) == "allow"
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/public/a",
                 main.access_key) is None
    # '*' spans '/' inside a key.
    compiled = _compiled(service, _statement(
        resource="/logs/*/error", principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/logs/a/b/error",
                 main.access_key) == "allow"
    # '?' matches exactly one character.
    compiled = _compiled(service, _statement(
        resource="/a?c", principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/abc",
                 main.access_key) == "allow"
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/abbc",
                 main.access_key) is None


def test_bucket_level_resource_does_not_match_objects(service):
    main = service[1]
    compiled = _compiled(service, _statement(
        action="s3:ListBucket", resource="",
        principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:ListBucket", BUCKET, main.access_key) == "allow"
    assert _eval(compiled, "s3:ListBucket", f"{BUCKET}/x",
                 main.access_key) is None


def test_string_and_numeric_conditions(service):
    main = service[1]
    compiled = _compiled(service, _statement(
        action="s3:ListBucket", resource="",
        condition={"StringEquals": {"s3:prefix": ["photos/"]},
                   "NumericLessThan": {"s3:max-keys": ["100"]}},
        principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:ListBucket", BUCKET, main.access_key,
                 {"s3:prefix": "photos/", "s3:max-keys": "10"}) == "allow"
    assert _eval(compiled, "s3:ListBucket", BUCKET, main.access_key,
                 {"s3:prefix": "other/", "s3:max-keys": "10"}) is None
    assert _eval(compiled, "s3:ListBucket", BUCKET, main.access_key,
                 {"s3:prefix": "photos/", "s3:max-keys": "500"}) is None


def test_string_like_negation_and_ip_conditions(service):
    main = service[1]
    compiled = _compiled(service, _statement(
        action="s3:ListBucket", resource="",
        condition={"StringLike": {"s3:prefix": ["private/*"]},
                   "StringNotEquals": {"s3:delimiter": ["/"]}},
        principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:ListBucket", BUCKET, main.access_key,
                 {"s3:prefix": "private/x", "s3:delimiter": "|"}) == "allow"
    assert _eval(compiled, "s3:ListBucket", BUCKET, main.access_key,
                 {"s3:prefix": "private/x", "s3:delimiter": "/"}) is None

    compiled = _compiled(service, _statement(
        condition={"IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}},
        principal=_principal(main.access_key)))
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a", main.access_key,
                 {"aws:SourceIp": "10.1.2.3"}) == "allow"
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a", main.access_key,
                 {"aws:SourceIp": "192.168.1.1"}) is None


def test_tag_conditions_and_bool(service):
    main = service[1]
    compiled = _compiled(service, _statement(
        condition={"StringEquals": {"aws:PrincipalTag/team": ["eng"],
                                    "s3:ExistingObjectTag/class": ["public"]},
                   "Bool": {"s3:prefix": ["true"]}},
        principal=_principal(main.access_key)))
    context = {"aws:PrincipalTag/team": "eng",
               "s3:ExistingObjectTag/class": "public",
               "s3:prefix": "true"}
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a",
                 main.access_key, context) == "allow"
    assert _eval(compiled, "s3:GetObject", f"{BUCKET}/a", main.access_key,
                 {**context, "aws:PrincipalTag/team": "ops"}) is None


# ---------------------------------------------------------------------------
# HTTP integration + cache
# ---------------------------------------------------------------------------

def _put_policy(service, statements):
    return signed(service, "PUT", f"/{BUCKET}?policy",
                  _document(*statements))


def _policy_get(service):
    return signed(service, "GET", f"/{BUCKET}?policy")


def test_policy_roundtrip_and_delete(service):
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "GET", f"/{BUCKET}?policy").status_code == 404
    body = _document(_statement(principal=_principal(main.access_key)))
    assert signed(service, "PUT", f"/{BUCKET}?policy", body).status_code == 204
    read = _policy_get(service)
    assert read.status_code == 200
    assert json.loads(read.content)["Version"] == "2012-10-17"
    assert signed(service, "DELETE", f"/{BUCKET}?policy").status_code == 204
    assert signed(service, "GET", f"/{BUCKET}?policy").status_code == 404


def test_policy_writes_require_their_permissions(service):
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    store = _store(service)
    reader = store.create("policy-reader", ["s3:GetBucketPolicy"])
    writer = store.create("policy-writer", ["s3:PutBucketPolicy",
                                            "s3:DeleteBucketPolicy"])
    body = _document(_statement(principal=_principal(main.access_key)))
    assert signed(service, "PUT", f"/{BUCKET}?policy", body,
                  access=reader.access_key,
                  secret=reader.secret_key).status_code == 403
    assert signed(service, "PUT", f"/{BUCKET}?policy", body,
                  access=writer.access_key,
                  secret=writer.secret_key).status_code == 204
    assert signed(service, "GET", f"/{BUCKET}?policy",
                  access=writer.access_key,
                  secret=writer.secret_key).status_code == 403
    assert signed(service, "DELETE", f"/{BUCKET}?policy",
                  access=writer.access_key,
                  secret=writer.secret_key).status_code == 204


def test_policy_checksum_and_grammar_errors_are_rejected(service):
    main = service[1]
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    bad_checksum = signed(service, "PUT", f"/{BUCKET}?policy",
                          _document(_statement(
                              principal=_principal(main.access_key))),
                          extra_headers={"Content-MD5": "AAAA"})
    assert bad_checksum.status_code == 400
    assert signed(service, "PUT", f"/{BUCKET}?policy",
                  b"<xml/>").status_code == 400
    assert signed(service, "PUT", f"/{BUCKET}?policy",
                  b"x" * (20 * 1024 + 1)).status_code == 400


def test_compiled_cache_invalidates_on_replace(service):
    main = service[1]
    other = _store(service).create("cache-other", ["s3:GetObject"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    allow = _document(_statement(principal=_principal(other.access_key)))
    deny = _document(_statement(effect="Deny",
                                principal=_principal(other.access_key)))
    assert signed(service, "PUT", f"/{BUCKET}?policy", allow).status_code == 204
    # second can read with the Allow policy
    assert signed(service, "PUT", f"/{BUCKET}/file", b"data").status_code == 200
    assert signed(service, "GET", f"/{BUCKET}/file",
                  access=other.access_key,
                  secret=other.secret_key).content == b"data"
    # Replacing with Deny must invalidate the cached AST immediately.
    assert signed(service, "PUT", f"/{BUCKET}?policy", deny).status_code == 204
    denied = signed(service, "GET", f"/{BUCKET}/file",
                    access=other.access_key, secret=other.secret_key)
    assert denied.status_code == 403
    assert b"bucket policy" in denied.content


def test_policy_allow_bypasses_acl_and_deny_beats_acl_allow(service):
    main = service[1]
    store = _store(service)
    other = store.create("policy-acl-other", ["s3:GetObject"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/file", b"data").status_code == 200
    # Restrict the bucket ACL to the owner only.
    from tests.s3.test_s3_acl import _policy_xml
    assert signed(service, "PUT", f"/{BUCKET}?acl",
                  _policy_xml(main.access_key, [])).status_code == 200
    denied = signed(service, "GET", f"/{BUCKET}/file",
                    access=other.access_key, secret=other.secret_key)
    assert denied.status_code == 403
    # Explicit Allow bypasses the ACL layer (AWS semantics).
    allow = _document(_statement(principal=_principal(other.access_key)))
    assert signed(service, "PUT", f"/{BUCKET}?policy", allow).status_code == 204
    assert signed(service, "GET", f"/{BUCKET}/file",
                  access=other.access_key,
                  secret=other.secret_key).content == b"data"
    # Explicit Deny wins even over an ACL that grants the key.
    deny = _document(_statement(effect="Deny",
                                principal=_principal(main.access_key)))
    assert signed(service, "PUT", f"/{BUCKET}?policy", deny).status_code == 204
    denied = signed(service, "GET", f"/{BUCKET}/file")
    assert denied.status_code == 403
    assert b"bucket policy" in denied.content


def test_policy_denies_batch_delete_per_entry(service):
    main = service[1]
    store = _store(service)
    other = store.create("batch-policy", ["s3:GetObject", "s3:PutObject",
                                          "s3:DeleteObject"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/a", b"a").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/b", b"b").status_code == 200
    deny = _document({
        **_statement(effect="Deny", action="s3:DeleteObject",
                     resource="/a", principal=_principal(other.access_key)),
    })
    assert signed(service, "PUT", f"/{BUCKET}?policy", deny).status_code == 204
    body = (b"<Delete><Object><Key>a</Key></Object>"
            b"<Object><Key>b</Key></Object></Delete>")
    import base64
    import hashlib
    reply = signed(service, "POST", f"/{BUCKET}?delete", body,
                   extra_headers={"Content-MD5": base64.b64encode(
                       hashlib.md5(body, usedforsecurity=False).digest()
                   ).decode()},
                   access=other.access_key, secret=other.secret_key)
    assert reply.status_code == 200
    assert b"AccessDenied" in reply.content
    assert signed(service, "GET", f"/{BUCKET}/a").status_code == 200
    assert signed(service, "GET", f"/{BUCKET}/b").status_code == 404
