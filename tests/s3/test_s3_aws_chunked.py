"""aws-chunked streaming uploads: decode, signature chain and trailers.

Hand-built streaming requests (the exact wire format real SDKs and the
AWS CLI produce) verify the full contract: chunk-signature chains
seeded by the request's own Authorization signature, trailer checksums,
decoded-length accounting and fail-closed tampering rejection.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import re
import zlib

import pytest
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from tests.s3.test_s3_gateway import service, signed

SIGNED_MODE = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
UNSIGNED_TRAILER_MODE = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"


def _hmac_hex(key: bytes, data: str) -> str:
    return _hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def _signing_key(secret: str, date: str, region: str) -> bytes:
    key = _hmac.new(("AWS4" + secret).encode(), date.encode(),
                    hashlib.sha256).digest()
    for part in (region, "s3", "aws4_request"):
        key = _hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


def _signed_headers_for(method: str, url: str, extra_headers: dict):
    """Manually sign exactly like the gateway's S3SigV4 verification.

    Returns (headers, seed signature, date, region). Signing manually
    keeps the streaming payload-hash literal under our control —
    botocore replaces it with the empty-body hash.
    """
    import datetime
    from urllib.parse import urlsplit as _split

    path = _split(url).path
    access, secret = _CREDENTIALS
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    region = "us-east-1"

    values = {"host": "localhost:9000", "x-amz-date": amz_date}
    for name, value in extra_headers.items():
        values[name.lower()] = value.strip()
    signed = sorted(values)
    headers_part = ";".join(signed)
    payload = values["x-amz-content-sha256"]
    canonical = (
        f"{method}\n{path}\n"
        "\n"
        + "".join(f"{name}:{values[name]}\n" for name in signed)
        + f"\n{headers_part}\n{payload}"
    )
    scope = f"{date}/{region}/s3/aws4_request"
    to_sign = (f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
               + hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    key = _hmac.new(("AWS4" + secret).encode("utf-8"), date.encode(),
                    hashlib.sha256).digest()
    for word in (region, "s3", "aws4_request"):
        key = _hmac.new(key, word.encode(), hashlib.sha256).digest()
    signature = _hmac.new(key, to_sign.encode("utf-8"),
                          hashlib.sha256).hexdigest()
    headers = dict(values)
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
        f"SignedHeaders={headers_part}, Signature={signature}")
    return headers, signature, date, region


_CREDENTIALS: tuple[str, str] = ("", "")


def _wire_body(secret: str, seed: str, date: str, region: str,
               payload: bytes, chunk_size: int, *, signed_mode: bool,
               amz_date: str = "",
               trailer: dict[str, str] | None = None,
               tamper_chunk: int | None = None) -> bytes:
    """Build the aws-chunked wire body with a valid signature chain."""
    key = _signing_key(secret, date, region)
    previous = seed
    scope = f"{date}/{region}/s3/aws4_request"
    out = bytearray()
    chunk_index = 0
    for start in range(0, len(payload), chunk_size):
        data = payload[start:start + chunk_size]
        wire_data = data
        if tamper_chunk == chunk_index:
            # Tamper AFTER signing: the signature covers the ORIGINAL
            # bytes, the wire carries corrupted ones (a real
            # man-in-the-middle flip).
            wire_data = bytes(b ^ 0xFF for b in data)
        if signed_mode:
            string_to_sign = "\n".join((
                "AWS4-HMAC-SHA256-PAYLOAD", amz_date, scope, previous,
                hashlib.sha256(b"").hexdigest(),
                hashlib.sha256(data).hexdigest(),
            ))
            signature = _hmac_hex(key, string_to_sign)
            previous = signature
            out += f"{len(data):x};chunk-signature={signature}\r\n".encode()
        else:
            out += f"{len(data):x}\r\n".encode()
        out += wire_data + b"\r\n"
        chunk_index += 1
    if signed_mode:
        string_to_sign = "\n".join((
            "AWS4-HMAC-SHA256-PAYLOAD", amz_date, scope, previous,
            hashlib.sha256(b"").hexdigest(),
            hashlib.sha256(b"").hexdigest(),
        ))
        out += (f"0;chunk-signature={_hmac_hex(key, string_to_sign)}\r\n"
                ).encode()
    else:
        out += b"0\r\n"
    for name, value in (trailer or {}).items():
        out += f"{name}:{value}\r\n".encode()
    out += b"\r\n"
    return bytes(out)


def _streaming_put(service, key: str, payload: bytes, mode: str,
                   *, chunk_size: int = 7, trailer_headers: dict | None = None,
                   trailer_values: dict | None = None,
                   tamper_chunk: int | None = None,
                   decoded_length: int | None = None):
    client, issued, _, _, _ = service
    global _CREDENTIALS
    _CREDENTIALS = (issued.access_key, issued.secret_key)
    headers = {
        "x-amz-content-sha256": mode,
        "content-encoding": "aws-chunked",
    }
    if trailer_headers is not None:
        headers.update(trailer_headers)
    if decoded_length is not None:
        headers["x-amz-decoded-content-length"] = str(decoded_length)
    elif mode in (SIGNED_MODE, UNSIGNED_TRAILER_MODE):
        headers["x-amz-decoded-content-length"] = str(len(payload))
    url = "http://localhost:9000/chunked-bucket/" + key
    auth_headers, seed, date, region = _signed_headers_for(
        "PUT", url, headers)
    wire = _wire_body(issued.secret_key, seed, date, region, payload,
                      chunk_size, signed_mode=(mode == SIGNED_MODE),
                      amz_date=auth_headers["x-amz-date"],
                      trailer=trailer_values, tamper_chunk=tamper_chunk)
    # auth_headers already carries every signed header (including the
    # streaming payload hash) with exactly one value per name.
    return client.request("PUT", "/chunked-bucket/" + key,
                          content=wire, headers=auth_headers)


@pytest.fixture(autouse=True)
def _chunked_bucket(service):
    assert signed(service, "PUT", "/chunked-bucket").status_code == 200
    yield


def test_signed_streaming_upload_round_trip(service):
    payload = b"streaming-payload-" * 64  # exactly split by 7-byte chunks
    reply = _streaming_put(service, "signed.bin", payload, SIGNED_MODE)
    assert reply.status_code == 200, reply.text
    got = signed(service, "GET", "/chunked-bucket/signed.bin")
    assert got.status_code == 200
    assert got.content == payload


def test_signed_streaming_tampered_chunk_fails_closed(service):
    payload = b"integrity-protected-body" * 32
    reply = _streaming_put(service, "tampered.bin", payload, SIGNED_MODE,
                           tamper_chunk=2)
    assert reply.status_code == 403, reply.text
    assert b"SignatureDoesNotMatch" in reply.content
    # The object was never created.
    assert signed(service, "GET", "/chunked-bucket/tampered.bin"
                  ).status_code == 404


def test_unsigned_trailer_upload_with_checksum(service):
    payload = b"trailer-checked-body" * 48
    crc32 = base64.b64encode(
        (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")).decode()
    reply = _streaming_put(
        service, "trailer.bin", payload, UNSIGNED_TRAILER_MODE,
        trailer_headers={"x-amz-trailer": "x-amz-checksum-crc32"},
        trailer_values={"x-amz-checksum-crc32": crc32})
    assert reply.status_code == 200, reply.text
    got = signed(service, "GET", "/chunked-bucket/trailer.bin")
    assert got.content == payload


def test_unsigned_trailer_bad_checksum_fails_closed(service):
    payload = b"bad-checksum-body" * 48
    wrong = base64.b64encode((zlib.crc32(b"other") &
                              0xFFFFFFFF).to_bytes(4, "big")).decode()
    reply = _streaming_put(
        service, "badsum.bin", payload, UNSIGNED_TRAILER_MODE,
        trailer_headers={"x-amz-trailer": "x-amz-checksum-crc32"},
        trailer_values={"x-amz-checksum-crc32": wrong})
    assert reply.status_code == 400, reply.text
    assert b"BadDigest" in reply.content
    assert signed(service, "GET", "/chunked-bucket/badsum.bin"
                  ).status_code == 404


def test_declared_trailer_must_actually_arrive(service):
    payload = b"missing-trailer-body" * 16
    reply = _streaming_put(
        service, "notrailer.bin", payload, UNSIGNED_TRAILER_MODE,
        trailer_headers={"x-amz-trailer": "x-amz-checksum-crc32"},
        trailer_values={})
    assert reply.status_code == 400, reply.text
    assert signed(service, "GET", "/chunked-bucket/notrailer.bin"
                  ).status_code == 404


def test_decoded_length_mismatch_fails_closed(service):
    payload = b"length-accounting" * 32
    reply = _streaming_put(service, "badlen.bin", payload, SIGNED_MODE,
                           decoded_length=len(payload) + 5)
    assert reply.status_code == 400, reply.text
    assert signed(service, "GET", "/chunked-bucket/badlen.bin"
                  ).status_code == 404


def test_unsigned_trailer_requires_signed_declaration(service):
    payload = b"unsigned-no-declaration" * 8
    # No signed x-amz-trailer header at all: header-mode SigV4 must
    # reject the request before any body work.
    reply = _streaming_put(service, "nodecl.bin", payload,
                           UNSIGNED_TRAILER_MODE)
    assert reply.status_code == 400, reply.text
    assert signed(service, "GET", "/chunked-bucket/nodecl.bin"
                  ).status_code == 404
