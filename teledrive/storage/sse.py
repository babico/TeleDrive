"""SSE-C (customer-supplied key) primitives.

The client key exists only in request memory.  Nothing in this module
persists, logs or embeds key material: chunks are encrypted with AES-256-GCM
and the key is dropped when the request finishes.

Wire contract (exact AWS header names, all three required together and all
three signed):

* ``x-amz-server-side-encryption-customer-algorithm`` = ``AES256``
* ``x-amz-server-side-encryption-customer-key``       = base64(32 bytes)
* ``x-amz-server-side-encryption-customer-key-MD5``   = base64(MD5(raw key))

Per-chunk layout: a fresh 12-byte random nonce, AES-256-GCM, and an AAD that
binds the ciphertext to its identity::

    AAD = object_id.encode("ascii")            # exactly 36 bytes (UUID)
          || ordinal.to_bytes(8, "big")        # unsigned big-endian

``object_id`` is the immutable manifest object the chunk was encrypted for.
For single-PUT objects it is the published object id.  Multipart parts are
encrypted for their own immutable staged part object, so each chunk records
the AAD identity it was created with (``a`` = object id, ``o`` = ordinal)
alongside the nonce and tag.  Completion renumbers the chunks' *manifest*
ordinals while moving them, which is why the authenticated ordinal lives in
the metadata rather than being taken from the final layout.  Splicing a
ciphertext/nonce/tag set from another chunk or another object therefore fails
GCM authentication.  Whole-row SQL swaps (including the metadata) are a
database-integrity event, not an S3-visible one: the SQL journal is the trust
anchor for assembled chunk order.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES256"
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
CUSTOMER_ALGORITHM = "x-amz-server-side-encryption-customer-algorithm"
CUSTOMER_KEY = "x-amz-server-side-encryption-customer-key"
CUSTOMER_KEY_MD5 = "x-amz-server-side-encryption-customer-key-md5"
CUSTOMER_HEADERS = (CUSTOMER_ALGORITHM, CUSTOMER_KEY, CUSTOMER_KEY_MD5)
SOURCE_PREFIX = "x-amz-copy-source-"


class SSECError(ValueError):
    """An S3-visible SSE-C failure.  Never carries key material."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class SSECKey:
    """In-request key material plus its non-secret MD5 fingerprint."""

    raw: bytes
    key_md5_b64: str
    algorithm: str = ALGORITHM

    @property
    def key_md5_bytes(self) -> bytes:
        return base64.b64decode(self.key_md5_b64, validate=True)


def key_from_raw(raw: bytes) -> SSECKey:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != KEY_BYTES:
        raise SSECError("InvalidArgument", "SSE-C customer key must be 32 bytes")
    material = bytes(raw)
    return SSECKey(material,
                   base64.b64encode(hashlib.md5(
                       material, usedforsecurity=False).digest()).decode("ascii"))


def _decode_header(value: str, *, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise SSECError("InvalidArgument",
                        f"SSE-C {what} is not valid base64") from None


def parse_ssec_headers(headers, signed: set[str],
                       *, prefix: str = "") -> SSECKey | None:
    """Parse one SSE-C header family, or return None when absent.

    ``prefix`` is used for the old-key family on UpdateObjectEncryption
    (``x-amz-copy-source-``).  A partial family, an unsigned family, a wrong
    algorithm or a mismatched key MD5 is a 400.  Key values never appear in
    an error message.
    """
    names = tuple(prefix + name for name in CUSTOMER_HEADERS)
    present = [name for name in names if headers.get(name) is not None]
    if not present:
        return None
    if len(present) != len(names):
        raise SSECError(
            "InvalidArgument",
            "SSE-C requires algorithm, key and key-MD5 headers together")
    if any(name not in signed for name in names):
        raise SSECError("InvalidArgument", "SSE-C headers must be signed")
    algorithm = headers.get(names[0])
    if algorithm != ALGORITHM:
        raise SSECError("InvalidArgument",
                        "SSE-C algorithm must be AES256")
    raw = _decode_header(headers.get(names[1]), what="customer key")
    if len(raw) != KEY_BYTES:
        raise SSECError("InvalidArgument",
                        "SSE-C customer key must decode to 32 bytes")
    declared_md5 = _decode_header(headers.get(names[2]), what="key MD5")
    actual_md5 = hashlib.md5(raw, usedforsecurity=False).digest()
    if len(declared_md5) != len(actual_md5) or not hmac.compare_digest(
            declared_md5, actual_md5):
        raise SSECError("InvalidArgument", "SSE-C key MD5 does not match the key")
    return SSECKey(raw, base64.b64encode(actual_md5).decode("ascii"))


def aad_for(object_id: str, ordinal: int) -> bytes:
    """Exact AAD layout: 36 ASCII UUID bytes || 8-byte big-endian ordinal."""
    encoded = object_id.encode("ascii")
    if len(encoded) != 36 or ordinal < 0:
        raise ValueError("Invalid SSE-C AAD identity")
    return encoded + ordinal.to_bytes(8, "big")


def encrypt_chunk(key: SSECKey, object_id: str, ordinal: int,
                  plaintext: bytes) -> tuple[bytes, dict]:
    """Return (ciphertext_with_tag, metadata) for one plaintext chunk."""
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key.raw).encrypt(nonce, plaintext,
                                         aad_for(object_id, ordinal))
    return ciphertext, {
        "v": 1,
        "n": base64.b64encode(nonce).decode("ascii"),
        "t": base64.b64encode(ciphertext[-TAG_BYTES:]).decode("ascii"),
        "cs": len(ciphertext),
        "a": object_id,
        "o": ordinal,
    }


def decrypt_chunk(key: SSECKey, ciphertext: bytes, metadata: dict) -> bytes:
    """Decrypt one stored chunk, authenticating its identity.

    The AAD object id and ordinal come from the chunk's own authenticated
    metadata, because multipart completion renumbers manifest ordinals after
    encryption.  A tag failure (wrong key, spliced chunk, cross-object copy,
    corrupt metadata) is reported as ``InvalidRequest`` with no plaintext
    detail.
    """
    try:
        nonce = base64.b64decode(metadata["n"], validate=True)
        tag = base64.b64decode(metadata["t"], validate=True)
        aad_id = metadata["a"]
        aad_ordinal = int(metadata["o"])
        expected_size = int(metadata["cs"])
        version = int(metadata["v"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise SSECError("InvalidRequest",
                        "Encrypted object metadata is invalid") from None
    if (version != 1 or len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES
            or aad_ordinal < 0 or not isinstance(aad_id, str)):
        raise SSECError("InvalidRequest", "Encrypted object metadata is invalid")
    if len(ciphertext) != expected_size or not ciphertext.endswith(tag):
        raise SSECError("InvalidRequest",
                        "Encrypted object metadata does not match the ciphertext")
    try:
        aad = aad_for(aad_id, aad_ordinal)
    except ValueError:
        raise SSECError("InvalidRequest",
                        "Encrypted object metadata is invalid") from None
    try:
        return AESGCM(key.raw).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise SSECError("InvalidRequest",
                        "The supplied customer key cannot decrypt this object") from None


def verify_key_md5(info: dict, key: SSECKey) -> None:
    """HEAD/GET key check against the stored non-secret MD5 fingerprint."""
    expected = info.get("key_md5")
    if not expected or not hmac.compare_digest(str(expected), key.key_md5_b64):
        raise SSECError("InvalidRequest",
                        "The supplied customer key cannot decrypt this object")


def verify_chunk_layout(parts, content_id: str) -> None:
    """Fail closed unless the chunk identities form one continuous layout.

    GCM authenticates *what* was encrypted, not *where the row sits*.  Each
    ciphertext therefore carries its AAD identity in its own metadata, and
    that alone cannot detect two whole chunk rows swapped in SQL.  The
    journal order is then checked structurally:

    * for a single-PUT object the AAD id is the object id and the
      authenticated ordinal must equal the manifest ordinal;
    * for a multipart object each staged part forms one AAD group, groups
      are contiguous in manifest order (completion moves them in order)
      and the authenticated ordinals inside a group are exactly 0..n-1.

    A swapped pair of chunk rows (ciphertext, nonce, tag and metadata
    together) therefore breaks monotonicity and is rejected before any
    plaintext is produced.
    """
    current_group: str | None = None
    expected_ordinal = 0
    seen_groups: set[str] = set()
    for part in parts:
        metadata = getattr(part, "encryption", None)
        if not isinstance(metadata, dict):
            raise SSECError("InvalidRequest",
                            "Encrypted object metadata is invalid")
        try:
            group = metadata["a"]
            ordinal = int(metadata["o"])
        except (KeyError, TypeError, ValueError):
            raise SSECError("InvalidRequest",
                            "Encrypted object metadata is invalid") from None
        if group == content_id:
            if ordinal != part.ordinal:
                raise SSECError(
                    "InvalidRequest",
                    "Encrypted chunk identity disagrees with the object layout")
            continue
        if group != current_group:
            if group in seen_groups:
                # Completion moves each staged part's chunks contiguously;
                # a reappearing group means rows were reordered.
                raise SSECError(
                    "InvalidRequest",
                    "Encrypted chunk identity disagrees with the object layout")
            seen_groups.add(group)
            current_group = group
            expected_ordinal = 0
        if ordinal != expected_ordinal:
            raise SSECError(
                "InvalidRequest",
                "Encrypted chunk identity disagrees with the object layout")
        expected_ordinal += 1
