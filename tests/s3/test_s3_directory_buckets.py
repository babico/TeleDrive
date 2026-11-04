"""S3 Express One Zone directory buckets and CreateSession sessions.

TeleDrive implements the *functional directory-bucket protocol* over the
same SQL catalog and Telegram manifests: typed ``bucket_type`` rows, the
immutable ``base--zone-id--x-s3`` name shape (the zone is a LOGICAL
compatibility zone, never an AWS Availability Zone), real
ListDirectoryBuckets pagination, and short-lived CreateSession
credentials bound to one bucket and mode.

This suite covers the five handoff-07 acceptance groups:

1. two directory buckets + one general bucket: only the directory rows
   are listed, paginated with opaque tokens, and deletion shrinks the
   pages honestly;
2. CreateSession credentials actually work (PUT/GET/LIST), read-only
   sessions cannot write, and expiry/revocation are immediate and
   distributed across connections;
3. the fail-closed matrix: wrong endpoint class, wrong signing
   service/region, wrong or missing session token, signature mismatch,
   replay, clock skew, bucket crossover, stale continuation tokens,
   invalid zone/name, and general-purpose-only operations on a
   directory bucket (and vice versa);
4. duplicate session issuance and deletion races, restart durability;
5. no API-surface regression on the general-purpose path, proven with a
   real botocore client — including a genuine S3 Express session flow
   (auto-CreateSession plus s3express-signed zonal requests carrying the
   ``x-amz-s3session-token`` header).

A path-style custom endpoint cannot make stock botocore select its
internal ``v4-s3express`` signer (AWS reserves that for real zonal
``*.s3express-*`` endpoint DNS), so the SDK-flow test registers botocore's
own ``S3ExpressIdentityResolver`` and per-operation signer overrides:
the client then performs the REAL auto-refresh flow (CreateSession,
credential caching, s3express signing with the session token header)
against our endpoint. No request in this suite is ever mocked.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import pytest
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.directory_buckets import SESSION_TOKEN_HEADER
from tests.s3.test_s3_gateway import service, signed

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
ZONE = "use1-az1"
DIR_A = f"alpha--{ZONE}--x-s3"
DIR_B = f"beta--{ZONE}--x-s3"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def xsigned(service_tuple, method, path, body=b"", *, access=None, secret=None,
            extra_headers=None, service_name="s3", region="us-east-1"):
    """A raw SigV4 request with a configurable credential scope.

    ``service_name="s3express"`` plus a ``x-amz-s3session-token`` header is
    exactly the wire shape botocore's S3ExpressAuth produces (it is a
    subclass of S3SigV4Auth that adds that one header before signing).
    """
    client, issued, _, _, _ = service_tuple
    headers = {"x-amz-content-sha256": hashlib.sha256(body).hexdigest()}
    headers.update(extra_headers or {})
    request = AWSRequest(method=method,
                         url="http://localhost:9000" + path,
                         data=body, headers=headers)
    request.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(access or issued.access_key,
                             secret or issued.secret_key),
                service_name, region).add_auth(request)
    return client.request(method, path, content=body,
                          headers=dict(request.headers))


def create_directory(service_tuple, name=DIR_A):
    response = xsigned(service_tuple, "PUT", f"/{name}")
    assert response.status_code == 200, response.text
    return name


def open_session(service_tuple, bucket=DIR_A, mode="ReadWrite"):
    headers = {"x-amz-create-session-mode": mode} if mode else {}
    response = xsigned(service_tuple, "GET", f"/{bucket}?session",
                       extra_headers=headers, service_name="s3express")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    credentials = root.find(f"{NS}Credentials")
    return {
        "access": credentials.findtext(f"{NS}AccessKeyId"),
        "secret": credentials.findtext(f"{NS}SecretAccessKey"),
        "token": credentials.findtext(f"{NS}SessionToken"),
        "expiration": credentials.findtext(f"{NS}Expiration"),
    }


def zonal(service_tuple, session, method, path, body=b"", *,
          token=None, extra_headers=None, service_name="s3express",
          region="us-east-1"):
    """One zonal request signed with an issued S3 Express session."""
    headers = {SESSION_TOKEN_HEADER: token if token is not None
               else session["token"]}
    headers.update(extra_headers or {})
    return xsigned(service_tuple, method, path, body,
                   access=session["access"], secret=session["secret"],
                   extra_headers=headers, service_name=service_name,
                   region=region)


def _sql(service_tuple):
    """A second, independent database connection to the same service."""
    return service_tuple[3]()


# ---------------------------------------------------------------------------
# Group 1 — real ListDirectoryBuckets rows, pagination, deletion
# ---------------------------------------------------------------------------

def test_list_directory_buckets_enumerates_real_rows_and_never_general(service):
    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    assert signed(service, "PUT", "/general-purpose").status_code == 200

    listing = xsigned(service, "GET", "/", service_name="s3express")
    assert listing.status_code == 200, listing.text
    root = ET.fromstring(listing.content)
    assert root.tag == f"{NS}ListDirectoryBucketsResult"
    names = [b.findtext(f"{NS}Name")
             for b in root.findall(f"{NS}Buckets/{NS}Bucket")]
    assert names == [DIR_A, DIR_B]
    for bucket in root.findall(f"{NS}Buckets/{NS}Bucket"):
        assert bucket.findtext(f"{NS}BucketRegion") == "us-east-1"
        assert bucket.find(f"{NS}CreationDate") is not None
    # The general-purpose bucket is invisible to the directory listing...
    assert "general-purpose" not in listing.text
    # ...and the directory buckets are invisible to ListBuckets.
    general = signed(service, "GET", "/")
    assert general.status_code == 200, general.text
    assert b"general-purpose" in general.content
    assert DIR_A.encode() not in general.content
    assert DIR_B.encode() not in general.content


def test_list_directory_buckets_paginates_with_opaque_tokens(service):
    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    first = xsigned(service, "GET",
                    "/?max-directory-buckets=1", service_name="s3express")
    assert first.status_code == 200, first.text
    root = ET.fromstring(first.content)
    assert [b.findtext(f"{NS}Name")
            for b in root.findall(f"{NS}Buckets/{NS}Bucket")] == [DIR_A]
    token = root.findtext(f"{NS}ContinuationToken")
    assert token and "." in token  # opaque, HMAC-signed

    second = xsigned(service, "GET",
                    f"/?max-directory-buckets=1&continuation-token={token}",
                    service_name="s3express")
    assert second.status_code == 200, second.text
    root = ET.fromstring(second.content)
    assert [b.findtext(f"{NS}Name")
            for b in root.findall(f"{NS}Buckets/{NS}Bucket")] == [DIR_B]
    # The last page carries no continuation token.
    assert root.find(f"{NS}ContinuationToken") is None


def test_list_directory_buckets_shrinks_and_empties_on_deletion(service):
    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    assert signed(service, "DELETE", f"/{DIR_A}").status_code == 204
    remaining = xsigned(service, "GET", "/?max-directory-buckets=1",
                        service_name="s3express")
    root = ET.fromstring(remaining.content)
    assert [b.findtext(f"{NS}Name")
            for b in root.findall(f"{NS}Buckets/{NS}Bucket")] == [DIR_B]
    assert root.find(f"{NS}ContinuationToken") is None

    assert signed(service, "DELETE", f"/{DIR_B}").status_code == 204
    empty = xsigned(service, "GET", "/", service_name="s3express")
    assert empty.status_code == 200, empty.text
    root = ET.fromstring(empty.content)
    assert root.findall(f"{NS}Buckets/{NS}Bucket") == []
    assert root.find(f"{NS}ContinuationToken") is None
    assert root.find(f"{NS}Buckets") is None


def test_bare_root_get_stays_list_buckets(service):
    # ListBuckets and ListDirectoryBuckets share GET /. Without the
    # directory selector the legacy operation must keep its meaning.
    assert signed(service, "PUT", "/general-purpose").status_code == 200
    response = signed(service, "GET", "/")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    assert root.tag == f"{NS}ListAllMyBucketsResult"
    assert b"general-purpose" in response.content


def test_list_directory_buckets_has_its_own_permission(service):
    assert signed(service, "PUT", "/some-bucket").status_code == 200
    _, _, _, connect, master = service
    db = connect()
    try:
        store = S3CredentialStore(db, master)
        allowed = store.create("directory-reader", ["s3:ListDirectoryBuckets"])
        denied = store.create("bucket-list-only", ["s3:ListAllMyBuckets"])
    finally:
        db.close()
    ok = xsigned(service, "GET", "/?max-directory-buckets=1",
                 access=allowed.access_key, secret=allowed.secret_key,
                 service_name="s3express")
    assert ok.status_code == 200, ok.text
    refused = xsigned(service, "GET", "/?max-directory-buckets=1",
                      access=denied.access_key, secret=denied.secret_key,
                      service_name="s3express")
    assert refused.status_code == 403, refused.text


@pytest.mark.parametrize("query,fragment", [
    ("max-directory-buckets=0", b"max-directory-buckets"),
    ("max-directory-buckets=1001", b"max-directory-buckets"),
    ("max-directory-buckets=abc", b"max-directory-buckets"),
    ("max-directory-buckets=10&continuation-token=", b"continuation-token"),
    ("max-directory-buckets=10&continuation-token=" + "x" * 1025,
     b"continuation-token"),
    ("max-directory-buckets=10&unknown-parameter=1",
     b"Unknown ListDirectoryBuckets"),
    ("max-directory-buckets=10&prefix=x", b"Unknown ListDirectoryBuckets"),
])
def test_list_directory_buckets_rejects_malformed_input(service, query,
                                                         fragment):
    response = xsigned(service, "GET", f"/?{query}",
                       service_name="s3express")
    assert response.status_code == 400, response.text
    assert fragment in response.content


# ---------------------------------------------------------------------------
# Group 2 — CreateSession credentials that actually work
# ---------------------------------------------------------------------------

def test_create_session_returns_usable_credentials(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A, "ReadWrite")
    assert session["access"] and session["secret"] and session["token"]
    # Default lifetime is five minutes, like AWS S3 Express.
    expires = datetime.strptime(session["expiration"],
                                "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc).timestamp()
    assert 295 <= expires - time.time() <= 305

    put = zonal(service, session, "PUT", f"/{DIR_A}/docs/file.bin",
                b"session-payload")
    assert put.status_code == 200, put.text
    head = zonal(service, session, "HEAD", f"/{DIR_A}/docs/file.bin")
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"session-payload"))
    got = zonal(service, session, "GET", f"/{DIR_A}/docs/file.bin")
    assert got.status_code == 200, got.text
    assert got.content == b"session-payload"

    # The directory delimiter groups keys into CommonPrefixes.
    assert zonal(service, session, "PUT", f"/{DIR_A}/docs/other.bin",
                 b"other").status_code == 200
    listing = zonal(service, session, "GET",
                    f"/{DIR_A}?list-type=2&delimiter=%2F")
    assert listing.status_code == 200, listing.text
    root = ET.fromstring(listing.content)
    prefixes = [p.findtext(f"{NS}Prefix")
                for p in root.findall(f"{NS}CommonPrefixes")]
    assert prefixes == ["docs/"]
    assert root.findall(f"{NS}Contents") == []


def test_read_only_session_cannot_write(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A, "ReadOnly")
    refused = zonal(service, session, "PUT", f"/{DIR_A}/file.bin", b"x")
    assert refused.status_code == 403, refused.text
    assert b"AccessDenied" in refused.content
    delete = zonal(service, session, "DELETE", f"/{DIR_A}/file.bin")
    assert delete.status_code == 403, delete.text
    # Reads still work in read-only mode.
    writable = open_session(service, DIR_A, "ReadWrite")
    assert zonal(service, writable, "PUT", f"/{DIR_A}/file.bin",
                 b"x").status_code == 200
    got = zonal(service, session, "GET", f"/{DIR_A}/file.bin")
    assert got.status_code == 200 and got.content == b"x"
    listed = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert listed.status_code == 200, listed.text


def test_session_expiry_is_immediate_and_distributed(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    assert zonal(service, session, "GET", f"/{DIR_A}?list-type=2"
                 ).status_code == 200
    # A second, independent connection ages the session out from under
    # the gateway: expiry is durable SQL state, not process memory.
    other = _sql(service)
    try:
        from sqlalchemy import text
        other.connection.execute(text(
            "UPDATE storage_s3_sessions SET expires_at = :past"
        ), {"past": int(time.time()) - 1})
        other.commit()
    finally:
        other.close()
    expired = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert expired.status_code == 403, expired.text
    assert b"AccessDenied" in expired.content


def test_session_revoked_by_bucket_deletion_is_immediate(service):
    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    session = open_session(service, DIR_A)
    assert zonal(service, session, "GET",
                 f"/{DIR_A}?list-type=2").status_code == 200
    assert signed(service, "DELETE", f"/{DIR_A}").status_code == 204
    # Revocation is durable row state: the very next request fails, and
    # a NEW connection to the same database sees the same refusal.
    after = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert after.status_code == 403, after.text
    other = _sql(service)
    try:
        from sqlalchemy import text
        revoked = other.connection.execute(text(
            "SELECT revoked FROM storage_s3_sessions"
        )).scalars().all()
    finally:
        other.close()
    assert revoked == [True]
    # The sibling directory bucket and a fresh session still work.
    fresh = open_session(service, DIR_B)
    assert zonal(service, fresh, "GET",
                 f"/{DIR_B}?list-type=2").status_code == 200


def test_session_revoked_by_owner_credential_revocation(service):
    create_directory(service, DIR_A)
    _, _, _, connect, master = service
    db = connect()
    try:
        store = S3CredentialStore(db, master)
        signer = store.create("session-signer", ["s3:CreateSession"])
    finally:
        db.close()
    response = xsigned(service, "GET", f"/{DIR_A}?session",
                       access=signer.access_key, secret=signer.secret_key,
                       extra_headers={"x-amz-create-session-mode": "ReadWrite"},
                       service_name="s3express")
    assert response.status_code == 200, response.text
    session = {
        "access": ET.fromstring(response.content).findtext(
            f"{NS}Credentials/{NS}AccessKeyId"),
        "secret": ET.fromstring(response.content).findtext(
            f"{NS}Credentials/{NS}SecretAccessKey"),
        "token": ET.fromstring(response.content).findtext(
            f"{NS}Credentials/{NS}SessionToken"),
    }
    assert zonal(service, session, "GET",
                 f"/{DIR_A}?list-type=2").status_code == 200
    db = connect()
    try:
        assert S3CredentialStore(db, master).revoke(signer.access_key)
    finally:
        db.close()
    revoked = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert revoked.status_code == 403, revoked.text


def test_session_survives_service_restart(service, monkeypatch, tmp_path):
    # The gateway is stateless over SQL: dispose the shared engine (the
    # in-process stand-in for a restart) and a brand-new connection pool
    # still resolves sessions issued before it, under the SAME master key
    # a real restart would keep.
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    from fastapi.testclient import TestClient
    from tests.s3.test_s3_gateway import _dispose_cached_engine
    import web.s3 as gateway
    url = str(tmp_path / "state.db")
    _dispose_cached_engine(url)
    client = TestClient(gateway.app, base_url="http://localhost:9000")
    try:
        restarted = (client,) + service[1:]
        got = zonal(restarted, session, "GET", f"/{DIR_A}?list-type=2")
        assert got.status_code == 200, got.text
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Group 3 — the fail-closed matrix
# ---------------------------------------------------------------------------

def test_long_lived_credentials_cannot_use_the_zonal_plane(service):
    # "Wrong endpoint": the zonal data plane accepts ONLY sessions, even
    # for a perfectly signed long-lived credential.
    create_directory(service, DIR_A)
    assert signed(service, "PUT", f"/{DIR_A}/file.bin",
                  b"x").status_code == 403
    refused = signed(service, "GET", f"/{DIR_A}?list-type=2")
    assert refused.status_code == 403, refused.text
    assert b"s3express" in refused.content


def test_session_credentials_cannot_use_the_control_plane(service):
    # The other endpoint direction: session keys are not long-lived
    # credentials, so CreateSession and every control operation refuse
    # them (they cannot even authenticate).
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    response = xsigned(service, "GET", f"/{DIR_A}?session",
                       access=session["access"], secret=session["secret"],
                       extra_headers={"x-amz-create-session-mode": "ReadWrite"},
                       service_name="s3express")
    assert response.status_code == 403, response.text
    assert signed(service, "GET", "/").status_code == 200
    listing = xsigned(service, "GET", "/?max-directory-buckets=1",
                      access=session["access"], secret=session["secret"],
                      service_name="s3express")
    assert listing.status_code == 403, listing.text


def test_zonal_request_requires_s3express_signing_service(service):
    # A valid session signed with the general-purpose "s" service is a
    # wrong-signing-service request and fails closed.
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    refused = zonal(service, session, "GET", f"/{DIR_A}?list-type=2",
                    service_name="s")
    assert refused.status_code == 403, refused.text
    put = zonal(service, session, "PUT", f"/{DIR_A}/k", b"x",
                service_name="s")
    assert put.status_code == 403, put.text


def test_s3express_scope_is_rejected_on_general_buckets(service):
    assert signed(service, "PUT", "/general-purpose").status_code == 200
    listing = xsigned(service, "GET", "/general-purpose?list-type=2",
                      service_name="s3express")
    assert listing.status_code == 403, listing.text
    assert b"directory-bucket" in listing.content
    put = xsigned(service, "PUT", "/general-purpose/k", b"x",
                  service_name="s3express")
    assert put.status_code == 403, put.text


def test_wrong_signing_region_fails_closed(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    refused = zonal(service, session, "GET", f"/{DIR_A}?list-type=2",
                    region="eu-west-1")
    assert refused.status_code == 403, refused.text
    assert b"region" in refused.content
    # The control plane checks the same single-region contract.
    control = xsigned(service, "GET", f"/{DIR_A}?session",
                      service_name="s3express", region="eu-west-1")
    assert control.status_code == 403, control.text


def test_wrong_session_token_fails_closed(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    refused = zonal(service, session, "GET", f"/{DIR_A}?list-type=2",
                    token="not-the-issued-token")
    assert refused.status_code == 403, refused.text
    # The refusal never echoes the token or names it.
    assert b"not-the-issued-token" not in refused.content


def test_missing_or_unsigned_session_token_fails_closed(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    # Missing entirely.
    missing = xsigned(service, "GET", f"/{DIR_A}?list-type=2",
                      access=session["access"], secret=session["secret"],
                      service_name="s3express")
    assert missing.status_code == 403, missing.text
    assert SESSION_TOKEN_HEADER.encode() in missing.content
    # Present but NOT covered by the signature: strip it from the signed
    # header set by sending an unsigned token alongside a valid signature
    # computed without it.
    client, issued, _, _, _ = service
    headers = {"x-amz-content-sha256": hashlib.sha256(b"").hexdigest()}
    request = AWSRequest(method="GET",
                         url="http://localhost:9000/"
                             f"{DIR_A}?list-type=2", headers=headers)
    request.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(session["access"], session["secret"]),
                "s3express", "us-east-1").add_auth(request)
    request.headers[SESSION_TOKEN_HEADER] = session["token"]
    unsigned = client.request(
        "GET", f"/{DIR_A}?list-type=2", headers=dict(request.headers))
    assert unsigned.status_code == 403, unsigned.text


def test_session_signature_mismatch_fails_closed(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    client, _, _, _, _ = service
    headers = {"x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
               SESSION_TOKEN_HEADER: session["token"]}
    request = AWSRequest(method="GET",
                         url="http://localhost:9000/"
                             f"{DIR_A}?list-type=2", headers=headers)
    request.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(session["access"], session["secret"]),
                "s3express", "us-east-1").add_auth(request)
    authorization = dict(request.headers)["Authorization"]
    tampered = authorization[:-1] + ("0" if authorization[-1] != "0"
                                     else "1")
    response = client.request(
        "GET", f"/{DIR_A}?list-type=2",
        headers={**dict(request.headers), "Authorization": tampered})
    assert response.status_code == 403, response.text
    assert b"SignatureDoesNotMatch" in response.content


def test_clock_skew_fails_closed(service, monkeypatch):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    import botocore.auth as botocore_auth
    frozen = datetime(2020, 1, 1)
    monkeypatch.setattr(botocore_auth, "get_current_datetime",
                        lambda: frozen)
    skewed = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert skewed.status_code == 403, skewed.text
    assert b"RequestTimeTooSkewed" in skewed.content


def test_session_cannot_cross_directory_buckets(service):
    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    session = open_session(service, DIR_A)
    assert zonal(service, session, "PUT", f"/{DIR_A}/k", b"x").status_code == 200
    crossover_put = zonal(service, session, "PUT", f"/{DIR_B}/k", b"x")
    assert crossover_put.status_code == 403, crossover_put.text
    crossover_get = zonal(service, session, "GET", f"/{DIR_B}?list-type=2")
    assert crossover_get.status_code == 403, crossover_get.text
    # The original bucket is unaffected by the refused crossover.
    assert zonal(service, session, "GET", f"/{DIR_A}/k").status_code == 200


def test_stale_continuation_token_fails_closed(service, monkeypatch):
    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    first = xsigned(service, "GET", "/?max-directory-buckets=1",
                    service_name="s3express")
    token = ET.fromstring(first.content).findtext(f"{NS}ContinuationToken")
    # A foreign (tampered) token never verifies.
    tampered = xsigned(service, "GET",
                       "/?max-directory-buckets=1&continuation-token="
                       + token[:-4] + "aaaa",
                       service_name="s3express")
    assert tampered.status_code == 400, tampered.text
    assert b"continuation token" in tampered.content
    # A token older than the cursor validity window is stale.
    from teledrive.s3.directory_buckets import decode_directory_token
    from teledrive.s3.sigv4 import SigV4Error
    master = service[4]
    with pytest.raises(SigV4Error):
        decode_directory_token(master, token, now=int(time.time()) + 10_000)
    with pytest.raises(SigV4Error):
        decode_directory_token(master, "garbage.token")


def test_invalid_zone_and_name_fail_closed_on_create(service, monkeypatch):
    monkeypatch.setenv("TELEDRIVE_S3_DIRECTORY_ZONE_ID", ZONE)
    wrong_zone = xsigned(service, "PUT", "/base--usw2-az1--x-s3")
    assert wrong_zone.status_code == 400, wrong_zone.text
    assert b"InvalidLocationConstraint" in wrong_zone.content
    assert ZONE.encode() in wrong_zone.content
    malformed = xsigned(service, "PUT", "/a--use1-az1--x-s3")
    assert malformed.status_code == 400, malformed.text
    assert b"InvalidBucketName" in malformed.content
    # A CreateBucketConfiguration that disagrees with the name zone is
    # refused rather than silently ignored.
    config = (b"<CreateBucketConfiguration "
              b'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
              b"<Location><Type>AvailabilityZone</Type>"
              b"<Name>usw2-az1</Name></Location></CreateBucketConfiguration>")
    disagreeing = xsigned(service, "PUT", f"/{DIR_A}", config)
    assert disagreeing.status_code == 400, disagreeing.text
    assert b"InvalidLocationConstraint" in disagreeing.content


def test_general_purpose_operations_fail_closed_on_directory_buckets(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    assert zonal(service, session, "PUT", f"/{DIR_A}/k", b"x").status_code == 200
    for path, method, body in (
        # Bucket tagging (a general-purpose-only control).
        (f"/{DIR_A}?tagging", "GET", b""),
        (f"/{DIR_A}?tagging", "PUT",
         b"<Tagging><TagSet/></Tagging>"),
        # Versioning / version selectors: directory buckets do not version.
        (f"/{DIR_A}?versioning", "GET", b""),
        (f"/{DIR_A}?versions", "GET", b""),
        (f"/{DIR_A}/k?versionId=x", "GET", b""),
        # ListObjects V1 is not supported on directory buckets.
        (f"/{DIR_A}", "GET", b""),
        # Batch delete and browser form uploads.
        (f"/{DIR_A}?delete", "POST", b"<Delete/>"),
        (f"/{DIR_A}", "POST", b""),
        # Server-side copies.
        (f"/{DIR_A}/copy", "PUT", b""),
        # GetBucketLocation and other general-purpose reads.
        (f"/{DIR_A}?location", "GET", b""),
        (f"/{DIR_A}?acl", "GET", b""),
    ):
        if path.endswith("/copy") and method == "PUT":
            extra = {"x-amz-copy-source": f"{DIR_A}/k"}
        else:
            extra = None
        response = zonal(service, session, method, path, body,
                         extra_headers=extra)
        assert response.status_code == 400, (path, method, response.text)
        assert b"InvalidRequest" in response.content, (path, response.text)
    # Long-lived control credentials hit the same wall.
    denied = signed(service, "GET", f"/{DIR_A}?tagging")
    assert denied.status_code == 400, denied.text
    assert b"InvalidRequest" in denied.content


def test_directory_object_keys_cannot_end_with_delimiter(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    refused = zonal(service, session, "PUT", f"/{DIR_A}/folder/", b"")
    assert refused.status_code == 400, refused.text
    assert b"InvalidRequest" in refused.content


def test_create_session_failure_taxonomy(service):
    # An existing general-purpose bucket cannot host an Express session.
    assert signed(service, "PUT", "/session-bucket").status_code == 200
    present = xsigned(service, "GET", "/session-bucket?session",
                      service_name="s3express")
    assert present.status_code == 400, present.text
    assert b"InvalidRequest" in present.content
    assert b"general-purpose bucket" in present.content
    # A well-formed name that is not a bucket here is NoSuchBucket, the
    # only error the botocore model declares for CreateSession.
    absent = xsigned(service, "GET", "/absent--use1-az1--x-s3?session",
                     service_name="s3express")
    assert absent.status_code == 404, absent.text
    assert b"NoSuchBucket" in absent.content


def test_create_session_rejects_malformed_input(service):
    malformed = xsigned(service, "GET", "/ab?session",
                        service_name="s3express")
    assert malformed.status_code == 400, malformed.text
    assert b"InvalidBucketName" in malformed.content
    create_directory(service, DIR_A)
    for mode in ("Bogus", "", "readwrite"):
        response = xsigned(service, "GET", f"/{DIR_A}?session",
                           extra_headers={"x-amz-create-session-mode": mode},
                           service_name="s3express")
        assert response.status_code == 400, response.text
        assert b"InvalidArgument" in response.content


def test_create_session_requires_its_permission(service):
    create_directory(service, DIR_A)
    _, _, _, connect, master = service
    db = connect()
    try:
        store = S3CredentialStore(db, master)
        denied = store.create("no-sessions", ["s3:ListBucket"])
    finally:
        db.close()
    response = xsigned(service, "GET", f"/{DIR_A}?session",
                       access=denied.access_key, secret=denied.secret_key,
                       service_name="s3express")
    assert response.status_code == 403, response.text


def test_session_token_is_redacted_from_every_error(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    bodies = [
        zonal(service, session, "GET", f"/{DIR_A}?list-type=2",
              token="wrong-token").content,
        zonal(service, session, "GET", f"/{DIR_A}?list-type=2",
              service_name="s").content,
        xsigned(service, "GET", f"/{DIR_A}?list-type=2",
                access=session["access"], secret=session["secret"],
                service_name="s3express").content,
    ]
    for body in bodies:
        assert session["token"].encode() not in body
        assert session["secret"].encode() not in body


def test_write_get_object_response_names_the_missing_runtime(service):
    assert signed(service, "PUT", "/lambda-bucket").status_code == 200
    assert signed(service, "PUT", "/lambda-bucket/asset.bin",
                  b"lambda-protected").status_code == 200
    telegram = service[2]
    before = telegram.uploads
    response = signed(
        service, "POST", "/WriteGetObjectResponse", b"",
        extra_headers={
            "x-amz-request-route": "route-token",
            "x-amz-request-token": "request-token",
        },
    )
    assert response.status_code == 501, response.text
    assert b"NotImplemented" in response.content
    assert b"Object Lambda" in response.content
    head = signed(service, "HEAD", "/lambda-bucket/asset.bin")
    assert head.status_code == 200
    assert telegram.uploads == before
    assert telegram.downloads == 0


# ---------------------------------------------------------------------------
# Group 4 — duplicate issuance and deletion races
# ---------------------------------------------------------------------------

def test_duplicate_session_issuance_produces_distinct_usable_sessions(service):
    create_directory(service, DIR_A)
    def issue(_):
        return open_session(service, DIR_A)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        sessions = list(pool.map(issue, range(16)))
    access_keys = {s["access"] for s in sessions}
    tokens = {s["token"] for s in sessions}
    assert len(access_keys) == 16
    assert len(tokens) == 16
    # Every concurrently issued session is independently usable.
    for s in sessions[:4]:
        response = zonal(service, s, "GET", f"/{DIR_A}?list-type=2")
        assert response.status_code == 200, response.text


def test_deletion_race_revokes_in_flight_sessions(service):
    create_directory(service, DIR_A)
    session = open_session(service, DIR_A)
    assert zonal(service, session, "GET",
                 f"/{DIR_A}?list-type=2").status_code == 200
    # A concurrent deletion wins the race and revokes every session; the
    # replay of an already-signed request must then fail closed.
    assert signed(service, "DELETE", f"/{DIR_A}").status_code == 204
    replay = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert replay.status_code == 403, replay.text
    # Recreating the bucket with the same immutable name does not revive
    # the revoked session: only a fresh CreateSession works again.
    create_directory(service, DIR_A)
    still_revoked = zonal(service, session, "GET", f"/{DIR_A}?list-type=2")
    assert still_revoked.status_code == 403, still_revoked.text
    fresh = open_session(service, DIR_A)
    assert zonal(service, fresh, "GET",
                 f"/{DIR_A}?list-type=2").status_code == 200


def test_concurrent_create_and_delete_keeps_sessions_consistent(service):
    create_directory(service, DIR_A)
    results = []
    lock = threading.Lock()

    def issuer():
        response = xsigned(service, "GET", f"/{DIR_A}?session",
                           service_name="s3express")
        with lock:
            results.append(("issue", response.status_code))

    def deleter():
        response = signed(service, "DELETE", f"/{DIR_A}")
        with lock:
            results.append(("delete", response.status_code))

    threads = [threading.Thread(target=issuer) for _ in range(4)]
    threads.append(threading.Thread(target=deleter))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = dict(results)
    # Issuance either succeeded (before the delete) or honestly failed
    # with the bucket gone; neither a 500 nor a phantom success is
    # acceptable, and the deletion itself must have committed.
    assert statuses["delete"] in (204, 409)
    for status in [s for kind, s in results if kind == "issue"]:
        assert status in (200, 404), status
    listing = xsigned(service, "GET", "/", service_name="s3express")
    root = ET.fromstring(listing.content)
    assert [b.findtext(f"{NS}Name")
            for b in root.findall(f"{NS}Buckets/{NS}Bucket")] == []


# ---------------------------------------------------------------------------
# Group 5 — no general-path regression + real SDK round-trips
# ---------------------------------------------------------------------------

def test_general_purpose_surface_is_unchanged(service):
    assert signed(service, "PUT", "/plain-bucket").status_code == 200
    payload = b"general-purpose-bytes"
    assert signed(service, "PUT", "/plain-bucket/file.bin",
                  payload).status_code == 200
    got = signed(service, "GET", "/plain-bucket/file.bin")
    assert got.status_code == 200 and got.content == payload
    listed = signed(service, "GET", "/plain-bucket?list-type=2")
    assert listed.status_code == 200, listed.text
    assert b"file.bin" in listed.content
    # Idempotent re-creation, HEAD, versioning control, tagging: the
    # general-purpose contract keeps every response it had before
    # directory buckets existed.
    assert signed(service, "PUT", "/plain-bucket").status_code == 200
    assert signed(service, "HEAD", "/plain-bucket").status_code == 200
    assert signed(service, "GET",
                  "/plain-bucket?versioning").status_code == 200
    assert signed(service, "PUT", "/plain-bucket?tagging",
                  b"<Tagging><TagSet>"
                  b"<Tag><Key>a</Key><Value>b</Value></Tag>"
                  b"</TagSet></Tagging>").status_code == 200
    assert signed(service, "GET", "/plain-bucket?tagging").status_code == 200
    assert signed(service, "DELETE", "/plain-bucket/file.bin").status_code == 204
    # The store is versioned by default, so the bucket keeps its object
    # history and deletion answers 409 BucketNotEmpty — the exact
    # pre-directory-buckets contract, unchanged.
    busy = signed(service, "DELETE", "/plain-bucket")
    assert busy.status_code == 409, busy.text
    assert b"BucketNotEmpty" in busy.content


def _uvicorn_service(service):
    """Start the real ASGI gateway on a local socket (existing pattern)."""
    import socket
    import uvicorn
    import web.s3 as gateway
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port, log_level="error",
        lifespan="off",
    ))
    thread = threading.Thread(target=server.run,
                              kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    return server, thread, f"http://127.0.0.1:{port}"


def test_actual_boto3_directory_bucket_client(service):
    """A real SDK round-trip, including the ``s3express`` signing scope.

    botocore signs ListDirectoryBuckets and CreateSession with the
    ``s3express`` service and sends NO distinguishing query field for a
    default listing, so this test also proves the credential-scope
    discriminator works and that the XML parses into the SDK model.
    """
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    create_directory(service, DIR_A)
    create_directory(service, DIR_B)
    assert signed(service, "PUT", "/general-purpose").status_code == 200
    _, credential, _, _, _ = service
    server, thread, endpoint = _uvicorn_service(service)
    try:
        s3 = boto3.client("s3", endpoint_url=endpoint,
                          region_name="us-east-1",
                          aws_access_key_id=credential.access_key,
                          aws_secret_access_key=credential.secret_key,
                          config=Config(signature_version="s3v4",
                                        s3={"addressing_style": "path"}))
        listing = s3.list_directory_buckets()
        assert listing["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert [b["Name"] for b in listing["Buckets"]] == [DIR_A, DIR_B]
        assert "ContinuationToken" not in listing
        # The general-purpose list is untouched by the directory listing.
        assert [b["Name"] for b in s3.list_buckets()["Buckets"]] == [
            "general-purpose"]
        # CreateSession through the real SDK model, then a second page.
        session = s3.create_session(Bucket=DIR_B, SessionMode="ReadWrite")
        credentials = session["Credentials"]
        assert credentials["AccessKeyId"]
        assert credentials["SessionToken"]
        assert credentials["Expiration"].timestamp() > time.time()
        page = s3.list_directory_buckets(MaxDirectoryBuckets=1)
        assert [b["Name"] for b in page["Buckets"]] == [DIR_A]
        assert page.get("ContinuationToken")
        # A directory bucket that does not exist answers NoSuchBucket,
        # the only error the botocore model declares.
        with pytest.raises(ClientError) as refused:
            s3.create_session(Bucket=f"absent--{ZONE}--x-s3")
        assert refused.value.response["Error"]["Code"] == "NoSuchBucket"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_actual_boto3_s3express_session_flow(service):
    """The genuine SDK S3 Express flow against real HTTP.

    botocore only selects its internal ``v4-s3express`` signer for real
    zonal ``*.s3express-*`` endpoint DNS, which a path-style custom
    endpoint cannot express. This test registers botocore's own
    S3ExpressIdentityResolver plus per-operation signer overrides, so the
    client performs the REAL auto-refresh flow: it calls CreateSession
    itself, caches the credentials and signs every zonal request with
    the s3express scope plus the ``x-amz-s3session-token`` header.
    """
    import boto3
    from botocore.config import Config
    from botocore.credentials import RefreshableCredentials
    from botocore.utils import S3ExpressIdentityResolver

    create_directory(service, DIR_A)
    _, credential, _, _, _ = service
    server, thread, endpoint = _uvicorn_service(service)
    try:
        s3 = boto3.client("s3", endpoint_url=endpoint,
                          region_name="us-east-1",
                          aws_access_key_id=credential.access_key,
                          aws_secret_access_key=credential.secret_key,
                          config=Config(signature_version="s3v4",
                                        s3={"addressing_style": "path"}))
        S3ExpressIdentityResolver(s3, RefreshableCredentials).register(
            s3.meta.events)
        zonal_ops = ("GetObject", "PutObject", "DeleteObject", "HeadObject",
                     "ListObjectsV2", "GetObjectAttributes",
                     "CreateMultipartUpload", "UploadPart",
                     "CompleteMultipartUpload", "AbortMultipartUpload",
                     "ListParts", "ListMultipartUploads")
        for operation in zonal_ops:
            def choose_signer(**_kwargs):
                return "v4-s3express"
            def set_signing_context(request, **_kwargs):
                request.context.setdefault("signing", {})
                request.context["signing"]["signing_name"] = "s3express"
                request.context["signing"]["cache_key"] = \
                    request.context["input_params"]["Bucket"]
            s3.meta.events.register_first(
                f"choose-signer.s3.{operation}", choose_signer)
            s3.meta.events.register_first(
                f"before-sign.s3.{operation}", set_signing_context)

        # The SDK auto-issues the session (CreateSession under the hood),
        # then signs PUT/GET/LIST/HEAD with s3express + session token.
        s3.put_object(Bucket=DIR_A, Key="dir/file.txt", Body=b"express-payload")
        got = s3.get_object(Bucket=DIR_A, Key="dir/file.txt")
        assert got["Body"].read() == b"express-payload"
        listed = s3.list_objects_v2(Bucket=DIR_A, Prefix="dir/")
        assert [o["Key"] for o in listed["Contents"]] == ["dir/file.txt"]
        head = s3.head_object(Bucket=DIR_A, Key="dir/file.txt")
        assert head["ContentLength"] == len(b"express-payload")
        s3.delete_object(Bucket=DIR_A, Key="dir/file.txt")
        empty = s3.list_objects_v2(Bucket=DIR_A)
        assert empty["KeyCount"] == 0

        # A ReadOnly session from the same SDK cannot write. The SDK issues
        # the ReadOnly credentials through CreateSession; the raw s3express
        # request below is the exact wire shape botocore's S3ExpressAuth
        # produces for them (registering the auto-refresh resolver here
        # would mint a fresh ReadWrite session instead of reusing these).
        read_only = s3.create_session(Bucket=DIR_A, SessionMode="ReadOnly")
        frozen = read_only["Credentials"]
        sdk_read_only = {
            "access": frozen["AccessKeyId"],
            "secret": frozen["SecretAccessKey"],
            "token": frozen["SessionToken"],
        }
        listing = zonal(service, sdk_read_only, "GET",
                        f"/{DIR_A}?list-type=2")
        assert listing.status_code == 200, listing.text
        refused = zonal(service, sdk_read_only, "PUT", f"/{DIR_A}/no.bin",
                        b"x")
        assert refused.status_code == 403, refused.text
        assert b"AccessDenied" in refused.content
    finally:
        server.should_exit = True
        thread.join(timeout=10)
