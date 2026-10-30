"""Envelope encryption (server-side, deployment-held master key).

This is the S3 **SSE-S3** shape: the server holds the key, the client sends
plaintext and never manages key material. It is deliberately built on the
same primitive as SSE-C (`teledrive.storage.sse`), because that path is
already audited and tested: every Telegram chunk is AES-256-GCM under a fresh
nonce with an AAD binding the object identity and the chunk ordinal.

How the keys nest:

* one **KEK** (key-encryption key) is derived from the deployment master key
  (`TELEDRIVE_S3_MASTER_KEY` / `s3_master_key_file`) with HKDF-SHA256 and a
  fixed info string, so the same secret the S3 credential store already needs
  is reused and no second key file appears;
* one **DEK** (data-encryption key) is generated per object, used exactly like
  an SSE-C customer key to encrypt that object's chunks, and then **wrapped**
  by the KEK with AES-256-GCM where the object id is the AAD;
* only the wrapped DEK is persisted. A database leak alone yields ciphertext:
  the master key is not in the database.

Why an operator might choose this over SSE-C: SSE-C puts key management on
every client, which many tools do not implement. Envelope encryption makes
"encrypted at rest" a server property, at a cost the operator must accept:

* **content-addressed dedup is off** for encrypted objects (identical
  plaintext must not share Telegram ciphertext, and a dedup hit would leak
  equality);
* **replication is off** for encrypted objects (the replica would need the
  wrapped key on another account, and a partial replica is worse than none);
* **content search is off** for encrypted objects (the index is plaintext
  text; indexing it would defeat the point).

Those three are reported by `capabilities()` so the UI and the docs can state
them instead of leaving the operator to discover them. The mode is opt-in:
`storage.encryption` is `none` by default, and nothing changes for a
deployment that does not set it.
"""
from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from teledrive.storage.sse import KEY_BYTES, NONCE_BYTES, SSECKey, key_from_raw

MODE = "SSE-S3"
# The AWS algorithm name an SSE-S3 object reports.
ALGORITHM = "AES256"
MODE_NONE = "none"
MODE_ENVELOPE = "envelope"
VALID_MODES = (MODE_NONE, MODE_ENVELOPE)

_HKDF_INFO = b"teledrive-envelope-v1"


class EnvelopeError(ValueError):
    """An S3-visible envelope failure. Never carries key material."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def derive_kek(master_key: bytes) -> bytes:
    """The KEK: HKDF-SHA256 over the deployment master key.

    Separate from the value used to encrypt S3 credential secrets, so a
    compromise of one does not hand over the other.
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 16:
        raise EnvelopeError(
            "InternalError", "Envelope encryption needs a master key", 500)
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None,
                info=_HKDF_INFO).derive(bytes(master_key))


def _aad(object_id: str) -> bytes:
    if not isinstance(object_id, str) or not object_id:
        raise EnvelopeError("InternalError", "Envelope key needs an object id",
                            500)
    return object_id.encode("ascii")


def wrap_key(kek: bytes, data_key: bytes, object_id: str) -> str:
    """Wrap a DEK for one object; the object id is the AAD."""
    if len(data_key) != KEY_BYTES:
        raise EnvelopeError("InternalError", "Invalid data key", 500)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(kek).encrypt(nonce, bytes(data_key), _aad(object_id))
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def unwrap_key(kek: bytes, wrapped: str, object_id: str) -> bytes:
    if not isinstance(wrapped, str) or not wrapped:
        raise EnvelopeError(
            "InvalidRequest",
            "The object is envelope-encrypted but its wrapped key is missing",
            400)
    try:
        blob = base64.b64decode(wrapped, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EnvelopeError(
            "InvalidRequest", "Stored wrapped key is not valid base64", 400) from exc
    if len(blob) <= NONCE_BYTES:
        raise EnvelopeError("InvalidRequest", "Stored wrapped key is truncated",
                            400)
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    try:
        return AESGCM(kek).decrypt(nonce, ciphertext, _aad(object_id))
    except InvalidTag as exc:
        raise EnvelopeError(
            "InvalidRequest",
            "The object cannot be decrypted with this deployment's master "
            "key (was the master key rotated or replaced?)", 400) from exc


@dataclass(frozen=True)
class ObjectKey:
    """One object's DEK plus the wrapped form that is persisted."""

    sse_key: SSECKey
    wrapped: str
    algorithm: str = ALGORITHM
    mode: str = MODE


def new_object_key(kek: bytes, object_id: str) -> ObjectKey:
    data_key = os.urandom(KEY_BYTES)
    return ObjectKey(
        sse_key=key_from_raw(data_key),
        wrapped=wrap_key(kek, data_key, object_id),
    )


def open_object_key(kek: bytes, wrapped: str, object_id: str) -> SSECKey:
    return key_from_raw(unwrap_key(kek, wrapped, object_id))


def capabilities() -> dict:
    """What an operator gives up by turning envelope encryption on.

    Stated as data rather than prose so the UI, the docs and the tests all
    read the same answer.
    """
    return {
        "mode": MODE_ENVELOPE,
        "algorithm": ALGORITHM,
        "deduplication": False,
        "replication": False,
        "content_search": False,
        "reason": (
            "Encrypted objects are stored as ciphertext specific to their own "
            "data key, so identical content is not deduplicated, replicas are "
            "not written, and the plaintext is not content-indexed."
        ),
    }
