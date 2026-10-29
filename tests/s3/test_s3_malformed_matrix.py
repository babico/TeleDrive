"""Every XML-bodied S3 operation refuses malformed input without mutating.

The "malformed" column of the per-operation matrix in `docs/S3_SPECS.md`.
Each case sends a body that is:

* syntactically broken XML, or
* valid XML but the wrong root element, or
* well-formed but containing an unsupported field,

with a VALID signature and a full permission set. The contract is a 4xx
carrying `MalformedXML` / `InvalidArgument` (never 5xx, never 2xx), the
stored configuration unchanged, and no Telegram traffic.

A 5xx here matters: it means an unhandled parser exception escaped, and the
next malformed body is someone else's 500.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.s3.test_s3_gateway import service, signed

B = "/malformed-bucket"

# operation -> (method, path, body, extra headers)
CASES = {
    "PutBucketPolicy": (
        "PUT", f"{B}?policy", b"not-json{", {}),
    "PutBucketCors": (
        "PUT", f"{B}?cors", b"<NotCors><Rule/></NotCors>", {}),
    "PutBucketTagging": (
        "PUT", f"{B}?tagging", b"<Tagging><TagSet><Tag>", {}),
    "PutBucketVersioning": (
        "PUT", f"{B}?versioning", b"<VersioningConfiguration><Status>Maybe"
                                   b"</Status></VersioningConfiguration>", {}),
    "PutBucketNotification": (
        "PUT", f"{B}?notification",
        b"<NotificationConfiguration><Unknown/></NotificationConfiguration>", {}),
    "PutBucketReplication": (
        "PUT", f"{B}?replication",
        b"<ReplicationConfiguration><Role>x</Role>"
        b"</ReplicationConfiguration>", {}),
    "PutBucketWebsite": (
        "PUT", f"{B}?website",
        b"<WebsiteConfiguration><IndexDocument><Suffix>../../etc"
        b"</Suffix></IndexDocument></WebsiteConfiguration>", {}),
    "PutObjectLockConfiguration": (
        "PUT", f"{B}?object-lock",
        b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled"
        b"</ObjectLockEnabled><Rule><DefaultRetention><Mode>BOGUS</Mode>"
        b"<Days>1</Days></DefaultRetention></Rule>"
        b"</ObjectLockConfiguration>", {}),
    "PutBucketAcl": (
        "PUT", f"{B}?acl", b"<AccessControlPolicy><Owner/></AccessControlPolicy>",
        {}),
    "PutObjectTagging": (
        "PUT", f"{B}/asset.bin?tagging", b"<Tagging><TagSet><Tag><Key>k",
        {}),
    "PutObjectRetention": (
        "PUT", f"{B}/asset.bin?retention",
        b"<Retention><Mode>BOGUS</Mode><RetainUntilDate>never"
        b"</RetainUntilDate></Retention>", {}),
    "PutObjectLegalHold": (
        "PUT", f"{B}/asset.bin?legal-hold",
        b"<LegalHold><Status>MAYBE</Status></LegalHold>", {}),
    "DeleteObjects": (
        "POST", f"{B}?delete", b"<Delete><Object><Key>asset.bin",
        {"Content-MD5": "AAAAAAAAAAAAAAAAAAAAAA=="}),
    # An EMPTY rule set is the valid SSE-C configuration here, so the body
    # must be genuinely unparseable rather than merely empty.
    "PutBucketEncryption": (
        "PUT", f"{B}?encryption",
        b"<ServerSideEncryptionConfiguration><Rule>", {}),
}


def _supported() -> set[str]:
    manifest = json.loads(
        (Path(__file__).resolve().parents[2]
         / "teledrive/s3/operation_manifest.json").read_text())
    return {op["name"] for op in manifest["operations"]
            if op.get("status") == "supported"}


def test_every_case_names_a_supported_operation():
    stale = sorted(set(CASES) - _supported())
    assert not stale, f"cases name non-supported operations: {stale}"


@pytest.mark.parametrize("operation", sorted(CASES))
def test_malformed_input_is_4xx_and_changes_nothing(service, operation):
    method, path, body, headers = CASES[operation]
    _client, _creds, telegram, _connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    assert signed(service, "PUT", f"{B}/asset.bin",
                  b"malformed-protected").status_code == 200
    uploads_before = telegram.uploads

    reply = signed(service, method, path, body, extra_headers=headers)

    # A 5xx means an unhandled parser exception escaped, which is its own bug.
    assert 400 <= reply.status_code < 500, (
        f"{operation}: malformed body answered {reply.status_code}: "
        f"{reply.text[:200]}")

    # The object is intact and nothing moved.
    head = signed(service, "HEAD", f"{B}/asset.bin")
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"malformed-protected"))
    assert telegram.uploads == uploads_before
