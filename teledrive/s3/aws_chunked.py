"""AWS streaming chunked payload decoding (aws-chunked).

Real SDKs and CLIs upload with `x-amz-content-sha256:
STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (signed chunks),
STREAMING-UNSIGNED-PAYLOAD-TRAILER (unsigned chunks, trailer
checksums) or STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER (both). The
wire format is:

    <hex-size>[;chunk-signature=<hex64>] CRLF
    <payload bytes of <hex-size>> CRLF
    ... repeated ...
    0[;chunk-signature=<hex64>] CRLF
    [trailer headers "name:value" CRLF]*     (TRAILER variants only)
    CRLF

Every chunk signature is verified against the SigV4 chain seeded by
the request's own Authorization signature (the secret never leaves
the credential store), and every declared trailer checksum must be
present. Decoding is strict: any malformed framing, signature
mismatch, size inconsistency or missing trailer fails closed before
the payload is used.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import re
from typing import AsyncIterator

from .sigv4 import (
    SIGNED_STREAMING, SIGNED_STREAMING_TRAILER, UNSIGNED_STREAMING_TRAILER,
    STREAMING_MODES, SigV4Error,
)

_AUTH = re.compile(
    r"AWS4-HMAC-SHA256 Credential=([^\s,/]{1,64})/(\d{8})/([a-z0-9-]{1,32})"
    r"/s3/aws4_request,\s*SignedHeaders=[a-z0-9;\-]+,\s*Signature=([0-9a-f]{64})"
)
_CHUNK_HEADER = re.compile(
    rb"([0-9a-fA-F]{1,16})(;chunk-signature=([0-9a-f]{64}))?\r\n")
_TRAILER_LINE = re.compile(rb"([a-z0-9-]{1,64}):([^\r\n]{1,256})\r\n")

MAX_WIRE_BUFFER = 64 * 1024 * 1024  # a single chunk cannot exceed the cap


def _hmac_sha256(key: bytes, data: str) -> bytes:
    return _hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str) -> bytes:
    key = _hmac_sha256(("AWS4" + secret).encode("utf-8"), date)
    key = _hmac_sha256(key, region)
    key = _hmac_sha256(key, "s3")
    return _hmac_sha256(key, "aws4_request")


def streaming_mode(request) -> str | None:
    """The aws-chunked variant selected by this request, if any."""
    value = request.headers.get("x-amz-content-sha256", "")
    return value if value in STREAMING_MODES else None


class AwsChunkedDecoder:
    """Decodes one aws-chunked request body, verifying everything."""

    def __init__(self, request, lookup_secret, permission: str):
        self.request = request
        self.lookup_secret = lookup_secret
        self.permission = permission
        self.trailer: dict[str, str] = {}
        self.decoded_length = 0
        mode = streaming_mode(request)
        if mode is None:
            raise SigV4Error("InvalidRequest", "Not an aws-chunked request")
        self.mode = mode
        self._signed = mode in (SIGNED_STREAMING, SIGNED_STREAMING_TRAILER)

    def _prepare(self) -> None:
        """Resolve the signing material for chunk-signature verification."""
        if not self._signed:
            return
        match = _AUTH.fullmatch(self.request.headers.get("authorization", ""))
        if match is None:
            raise SigV4Error("AccessDenied",
                             "Streaming signed payload requires Authorization")
        access_key, date, region, seed = match.groups()
        secret = self.lookup_secret(access_key, self.permission)
        if secret is None:
            raise SigV4Error("AccessDenied",
                             "Streaming signer is not authorized")
        self._chain_key = _signing_key(secret, date, region)
        self._previous_signature = seed
        self._amz_date = self.request.headers.get("x-amz-date", "")
        self._scope = f"{date}/{region}/s3/aws4_request"

    def _verify_chunk_signature(self, chunk_signature: str,
                                chunk_sha_hex: str) -> None:
        string_to_sign = "\n".join((
            "AWS4-HMAC-SHA256-PAYLOAD",
            self._amz_date,
            self._scope,
            self._previous_signature,
            hashlib.sha256(b"").hexdigest(),
            chunk_sha_hex,
        ))
        expected = _hmac_sha256(self._chain_key, string_to_sign).hex()
        if not _hmac.compare_digest(expected, chunk_signature):
            raise SigV4Error(
                "SignatureDoesNotMatch",
                "Streaming chunk signature does not match")
        self._previous_signature = expected

    async def blocks(self) -> AsyncIterator[bytes]:
        """Yield decoded payload blocks; populate trailer when complete."""
        self._prepare()
        buffer = bytearray()
        wire = self.request.stream()
        exhausted = False

        async def _read_more() -> bool:
            nonlocal exhausted
            if exhausted:
                return False
            try:
                block = await wire.__anext__()
            except StopAsyncIteration:
                exhausted = True
                return False
            if len(buffer) + len(block) > MAX_WIRE_BUFFER:
                raise SigV4Error("EntityTooLarge",
                                 "aws-chunked framing exceeds size bound")
            buffer.extend(block)
            return True

        while True:
            # Find the chunk header line within the buffered bytes.
            header = _CHUNK_HEADER.match(buffer)
            while header is None:
                if len(buffer) > 128 or not await _read_more():
                    raise SigV4Error("InvalidRequest",
                                     "Malformed aws-chunked framing")
                header = _CHUNK_HEADER.match(buffer)
            size = int(header.group(1), 16)
            chunk_signature = (header.group(3).decode("ascii")
                               if header.group(3) else None)
            if self._signed and chunk_signature is None:
                raise SigV4Error(
                    "InvalidRequest", "Signed chunks require a signature")
            if not self._signed and chunk_signature is not None:
                raise SigV4Error(
                    "InvalidRequest", "Unsigned chunks cannot carry signatures")
            del buffer[:header.end()]
            if size == 0:
                # The final zero chunk carries no data and no trailing
                # CRLF: trailer headers (or end of stream) follow the
                # header line directly. Its signature covers empty data.
                if self._signed:
                    self._verify_chunk_signature(
                        chunk_signature, hashlib.sha256(b"").hexdigest())
                break
            # Read exactly the chunk data plus the trailing CRLF.
            needed = size + 2
            while len(buffer) < needed:
                if not await _read_more():
                    raise SigV4Error("InvalidRequest",
                                     "Truncated aws-chunked chunk")
            data = bytes(buffer[:size])
            del buffer[:needed]
            if self._signed:
                self._verify_chunk_signature(
                    chunk_signature, hashlib.sha256(data).hexdigest())
            self.decoded_length += len(data)
            yield data

        # After the final zero chunk: optional trailer headers, then the
        # terminating blank line (some clients omit it at end of stream).
        declared = [name.strip().lower() for name in (
            self.request.headers.get("x-amz-trailer", "").split(",")
            if "x-amz-trailer" in self.request.headers else []) if name.strip()]
        while True:
            if buffer[:2] == b"\r\n":
                del buffer[:2]
                break
            match = _TRAILER_LINE.match(buffer)
            if match is not None:
                # Extract groups BEFORE mutating the bytearray: re match
                # objects hold a LIVE view of a bytearray subject, so
                # deleting the matched prefix would shift every group.
                name = match.group(1).decode("ascii")
                value = match.group(2).decode("latin-1").strip()
                end = match.end()
                del buffer[:end]
                self.trailer[name] = value
                continue
            if len(buffer) > 1024:
                raise SigV4Error("InvalidRequest",
                                 "Malformed aws-chunked trailer")
            if not await _read_more():
                break

        for name in declared:
            if name not in self.trailer:
                raise SigV4Error(
                    "InvalidRequest",
                    f"Declared trailer {name} is missing")

        decoded_header = self.request.headers.get("x-amz-decoded-content-length")
        if decoded_header is not None:
            try:
                expected_length = int(decoded_header)
            except ValueError as exc:
                raise SigV4Error("InvalidArgument",
                                 "Invalid decoded content length") from exc
            if expected_length != self.decoded_length:
                raise SigV4Error(
                    "XAmzContentSHA256Mismatch",
                    "Decoded length does not match x-amz-decoded-content-length")
