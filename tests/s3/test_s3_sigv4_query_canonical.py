"""SigV4 canonical query strings use the wire bytes as sent.

Earlier TeleDrive releases rebuilt the canonical query by decoding the
wire parameters and re-encoding them (``parse_qsl`` + ``quote``). AWS's
own SDK does not do that when the request URL already carries its query:
botocore's ``_canonical_query_string_url`` splits the raw query on ``&``
and the first ``=``, sorts the pairs and joins them VERBATIM. A client
that sends an unencoded ``/`` in ``response-content-type=text/plain``
signs the literal ``text/plain``; TeleDrive's re-encoding produced
``text%2Fplain`` and answered 403 SignatureDoesNotMatch for a request
real AWS accepts (the percent-encoded spelling kept working, which is
how the quirk hid for so long).

These tests pin both client spellings against the same wire request:

* raw ``signed()`` requests (botocore URL mode) with unencoded ``/``,
  ``=`` and ``+`` (the form-encoded space) inside ``response-*``
  values — the flagged defect;
* hand-built signatures computed the way the AWS SigV4 documentation
  describes (UriEncode every name and value, then sort) over a wire
  query with a RAW SPACE — a spelling httpx re-encodes on the wire and
  which therefore cannot be delivered through the HTTP harness;
* hand-built signatures over the raw as-sent form for the same request;
* tampering with the signed query value still fails closed.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

import pytest
from starlette.requests import Request

from tests.s3.test_s3_gateway import service, signed  # noqa: F401 — fixture
from teledrive.s3.sigv4 import (
    SigV4Error, _canonical_query, _query_candidates, _wire_query,
    verify_header_signature,
)

BUCKET = "canonical-bucket"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def _seed(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    put = signed(service, "PUT", f"/{BUCKET}/override.bin", b"wire-bytes")
    assert put.status_code == 200, put.text


# ---------------------------------------------------------------------------
# The flagged defect: unencoded reserved characters in query values
# ---------------------------------------------------------------------------

def test_unencoded_slash_in_response_content_type_verifies(service):
    """The exact flagged case: ``response-content-type=text/plain`` with
    a raw ``/`` must verify and apply the override (it used to answer
    403 SignatureDoesNotMatch while the percent-encoded form worked)."""
    _seed(service)
    response = signed(service, "GET",
                      f"/{BUCKET}/override.bin?response-content-type=text/plain")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "text/plain"
    assert response.content == b"wire-bytes"


def test_unencoded_equals_inside_query_value_verifies(service):
    _seed(service)
    response = signed(
        service, "GET",
        f"/{BUCKET}/override.bin?response-cache-control=no-cache=nocache")
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-cache=nocache"


def test_form_encoded_space_as_raw_plus_verifies(service):
    """A raw ``+`` is the form-style spelling of a space. botocore signs
    the raw ``+``; the decoded override value is the space."""
    _seed(service)
    response = signed(
        service, "GET",
        f"/{BUCKET}/override.bin?response-content-encoding=x+y")
    assert response.status_code == 200, response.text
    assert response.headers["content-encoding"] == "x y"


def test_percent_encoded_spellings_still_verify(service):
    """The previously working spelling (regression for the fix)."""
    _seed(service)
    response = signed(
        service, "GET",
        f"/{BUCKET}/override.bin?response-content-type=text%2Fplain")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "text/plain"


def test_tampered_query_value_still_fails(service):
    """Accepting the raw as-sent spelling must not weaken tampering
    rejection: a signature made for one query value does not verify a
    request that carries a different one (the sign-then-modify replay,
    exactly like the payload-tampering contract in the gateway suite)."""
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    client, issued, _, _, _ = service
    _seed(service)
    payload = hashlib.sha256(b"").hexdigest()
    good = AWSRequest(
        method="GET",
        url=f"http://localhost:9000/{BUCKET}/override.bin"
            "?response-content-type=text/plain",
        headers={"x-amz-content-sha256": payload})
    good.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(issued.access_key, issued.secret_key),
                "s3", "us-east-1").add_auth(good)
    # Replay the stolen Authorization headers against a different query
    # value on the same wire form (raw slash in both).
    replayed = client.get(
        f"/{BUCKET}/override.bin?response-content-type=text/evil",
        headers=dict(good.headers))
    assert replayed.status_code == 403, replayed.text
    assert b"SignatureDoesNotMatch" in replayed.content


# ---------------------------------------------------------------------------
# Canonicalization unit behaviour
# ---------------------------------------------------------------------------

def test_wire_query_keeps_raw_bytes_and_spec_form_reencodes():
    raw = b"response-content-type=text/plain&partNumber=2"
    # Raw as-sent tokens, sorted, joined verbatim (botocore URL mode).
    assert _wire_query(raw) == "partNumber=2&response-content-type=text/plain"
    # Spec-literal form: UriEncode of the decoded values.
    assert _canonical_query(raw) == (
        "partNumber=2&response-content-type=text%2Fplain")
    # Both candidates are derived for the verifier.
    assert _query_candidates(raw) == {
        "partNumber=2&response-content-type=text/plain",
        "partNumber=2&response-content-type=text%2Fplain",
    }


def test_fully_encoded_wire_produces_one_candidate():
    raw = b"partNumber=2&response-content-type=text%2Fplain"
    assert _query_candidates(raw) == {
        "partNumber=2&response-content-type=text%2Fplain"}


def test_candidates_drop_the_presign_signature_parameter():
    raw = (b"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=" + b"a" * 64
           + b"&response-content-type=text/plain")
    candidates = _query_candidates(raw, drop="X-Amz-Signature")
    assert candidates == {
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&response-content-type=text/plain",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&response-content-type=text%2Fplain",
    }


# ---------------------------------------------------------------------------
# Hand-built signatures: both AWS client spellings over a raw-space wire
# ---------------------------------------------------------------------------

def _hand_signed_request(service, query: bytes, canonical_query: str,
                         *, method: str = "GET",
                         path: str = f"/{BUCKET}/override.bin") -> Request:
    """An ASGI request whose Authorization header was computed by hand
    over ``canonical_query`` — exactly the two-step recipe of the AWS
    SigV4 documentation (canonical request -> string to sign -> HMAC
    chain), for an arbitrary canonical query spelling."""
    _, issued, _, _, _ = service
    payload = hashlib.sha256(b"").hexdigest()
    stamp = "20261104T120000Z"
    headers = [
        (b"host", b"localhost:9000"),
        (b"x-amz-date", stamp.encode("ascii")),
        (b"x-amz-content-sha256", payload.encode("ascii")),
    ]
    canonical = (
        f"{method}\n{path}\n{canonical_query}\n"
        f"host:localhost:9000\n"
        f"x-amz-content-sha256:{payload}\n"
        f"x-amz-date:{stamp}\n"
        f"\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
    )
    scope = "20261104/us-east-1/s3/aws4_request"
    to_sign = (f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n"
               + hashlib.sha256(canonical.encode()).hexdigest())
    key = ("AWS4" + issued.secret_key).encode("utf-8")
    for word in ("20261104", "us-east-1", "s3", "aws4_request"):
        key = hmac.new(key, word.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={issued.access_key}/{scope}, "
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        f"Signature={signature}"
    )
    return Request({
        "type": "http", "method": method,
        "scheme": "http", "server": ("localhost", 9000),
        "path": path, "raw_path": path.encode("ascii"),
        "query_string": query,
        "headers": headers + [(b"authorization", authorization.encode())],
    })


def _lookup(service):
    client, issued, _, _, _ = service
    secrets = {issued.access_key: issued.secret_key}

    def lookup(access_key, permission):
        return secrets.get(access_key)

    return lookup


def test_raw_space_wire_accepts_the_raw_as_sent_signature(service):
    """A wire query with a RAW space (httpx would re-encode it, so the
    request is built at the ASGI level) signed the way botocore signs
    URL-embedded queries: the raw bytes as sent."""
    _seed(service)
    request = _hand_signed_request(
        service, b"response-content-type=text plain",
        "response-content-type=text plain")
    access_key = verify_header_signature(
        request, _lookup(service), "s3:GetObject", now=NOW)
    assert access_key


def test_raw_space_wire_accepts_the_spec_literal_signature(service):
    """The same wire request signed per the AWS SigV4 documentation:
    UriEncode every parameter name and value (space -> %20), sort after
    encoding. Both client spellings authenticate the same wire bytes."""
    _seed(service)
    request = _hand_signed_request(
        service, b"response-content-type=text plain",
        "response-content-type=text%20plain")
    access_key = verify_header_signature(
        request, _lookup(service), "s3:GetObject", now=NOW)
    assert access_key


def test_raw_space_wire_rejects_a_wrong_value_signature(service):
    _seed(service)
    request = _hand_signed_request(
        service, b"response-content-type=text plain",
        "response-content-type=evil%20plain")
    with pytest.raises(SigV4Error) as error:
        verify_header_signature(
            request, _lookup(service), "s3:GetObject", now=NOW)
    assert error.value.code == "SignatureDoesNotMatch"
