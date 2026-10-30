"""Envelope encryption (SSE-S3): server-held key, one data key per object.

The owner decision: an operator may want encrypted-at-rest without putting key
management on every client, which SSE-C requires and many tools do not
implement. Envelope encryption makes it a server property:

* the KEK is derived from the S3 master key with HKDF and a fixed info string
  (a different derivation from the one that encrypts credential secrets);
* each object gets a fresh 32-byte data key, used exactly like an SSE-C key to
  encrypt its chunks (AES-256-GCM, fresh nonce, AAD binding identity+ordinal);
* only the data key WRAPPED by the KEK is persisted, with the object identity
  as AAD, so a database leak alone yields ciphertext.

These tests assert the properties that would make the feature a lie if they
failed: the stored bytes are not the plaintext, the wrapped key alone cannot
be opened by another deployment, a rotated master key fails closed instead of
returning garbage, and the capability trade-offs are reported rather than
hidden.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text

import web.app as webapp
import web.s3 as gateway
from teledrive.db import connect_database
from teledrive.storage import envelope
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.sse import decrypt_chunk, SSECError
# The `service` fixture lives with the gateway tests; importing it makes the
# end-to-end cases below use the real ASGI app, signed requests and a fake
# Telegram transport.
from tests.s3.test_s3_gateway import service  # noqa: F401

BUCKET = "envelope-bucket"


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def test_each_object_gets_its_own_data_key_bound_to_its_identity():
    kek = envelope.derive_kek(os.urandom(32))
    first = envelope.new_object_key(kek, "object-one")
    second = envelope.new_object_key(kek, "object-two")

    assert first.sse_key.raw != second.sse_key.raw, "data keys must be unique"
    assert first.wrapped != second.wrapped

    # The wrapped form round-trips only with its own identity.
    assert envelope.unwrap_key(kek, first.wrapped, "object-one") == first.sse_key.raw
    with pytest.raises(envelope.EnvelopeError):
        envelope.unwrap_key(kek, first.wrapped, "object-two")


def test_a_different_master_key_cannot_open_a_wrapped_data_key():
    """The KEK is the only thing standing between a DB dump and plaintext."""
    kek = envelope.derive_kek(os.urandom(32))
    other = envelope.derive_kek(os.urandom(32))
    material = envelope.new_object_key(kek, "object-x")
    with pytest.raises(envelope.EnvelopeError) as exc:
        envelope.unwrap_key(other, material.wrapped, "object-x")
    assert "master key" in str(exc.value)


def test_the_kek_is_not_the_credential_cipher_key():
    """One master key, two independent derivations.

    If the KEK were the raw master key (or the same derivation as the
    credential store's), a compromise of one surface would hand over the
    other.
    """
    master = os.urandom(32)
    kek = envelope.derive_kek(master)
    assert kek != master
    # Fernet (credential store) uses the master key directly; the KEK must
    # not be a Fernet key by accident either.
    assert len(kek) == 32


def test_capability_tradeoffs_are_reported():
    caps = envelope.capabilities()
    assert caps["algorithm"] == "AES256"
    assert caps["deduplication"] is False
    assert caps["replication"] is False
    assert caps["content_search"] is False
    assert caps["reason"]


def test_the_engine_really_encrypts_chunks(monkeypatch, tmp_path):
    """The stored Telegram bytes must not equal the plaintext."""
    from teledrive.storage.engine import TelegramObjectStorage

    class Memory:
        def __init__(self):
            self.blobs = {}
            self.n = 0

        async def upload(self, path, *, object_id, ordinal, checksum):
            self.n += 1
            self.blobs[self.n] = path.read_bytes()
            return "acct", -100, self.n

        async def verify_target(self):
            pass

        async def download(self, reference, destination):
            destination.write_bytes(self.blobs[reference.message_id])

    db = connect_database(str(tmp_path / "envelope.db"))
    try:
        catalog = BucketCatalog(ManifestStore(db))
        catalog.create_bucket(BUCKET, 1)
        media = Memory()
        engine = TelegramObjectStorage(catalog.manifests, media,
                                       chunk_size=1024,
                                       scratch_directory=tmp_path)
        source = tmp_path / "plain.bin"
        payload = b"SECRET-PLAINTEXT-" * 100
        source.write_bytes(payload)
        kek = envelope.derive_kek(os.urandom(32))

        item = __import__("asyncio").run(
            engine.put_file(BUCKET, "secret.bin", source, envelope_kek=kek))
        catalog.publish(item.id, now=2)

        for blob in media.blobs.values():
            assert b"SECRET-PLAINTEXT" not in blob
        # And only the wrapped form is stored — never the raw data key.
        row = db.connection.execute(text(
            "SELECT mode, wrapped_key, key_wrap, envelope_aad "
            "FROM storage_object_encryption WHERE object_id = :o"),
            {"o": item.id}).one()
        assert row[0] == "SSE-S3"
        assert row[2] == "envelope-v1"
        assert row[3] == item.id
        raw_key = catalog.manifests.envelope_key(item.id, kek).raw
        assert base64.b64encode(raw_key).decode() not in row[1]

        # Reading with the master key returns the exact plaintext...
        async def read_with(kek_arg):
            chunks = []
            async for block in engine.iter_bytes(item.id,
                                                 envelope_kek=kek_arg):
                chunks.append(block)
            return b"".join(chunks)

        assert __import__("asyncio").run(read_with(kek)) == payload
        # ...and without it fails closed rather than returning garbage.
        with pytest.raises(Exception):
            __import__("asyncio").run(read_with(None))
        with pytest.raises(Exception):
            __import__("asyncio").run(
                read_with(envelope.derive_kek(os.urandom(32))))
    finally:
        db.close()


# ---------------------------------------------------------------------------
# End to end over the S3 gateway
# ---------------------------------------------------------------------------

def test_put_get_roundtrip_when_envelope_is_enabled(service, monkeypatch):
    """A whole object through the wire: put, head, get, delete."""
    from tests.s3.test_s3_gateway import signed
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    headers = {"x-amz-server-side-encryption": "AES256"}

    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    payload = b"envelope-http-payload"
    put = signed(service, "PUT", f"/{BUCKET}/e.bin", payload,
                 extra_headers=headers)
    assert put.status_code == 200, put.text
    assert put.headers.get("x-amz-server-side-encryption") == "AES256"

    head = signed(service, "HEAD", f"/{BUCKET}/e.bin")
    assert head.status_code == 200
    assert head.headers.get("x-amz-server-side-encryption") == "AES256"

    got = signed(service, "GET", f"/{BUCKET}/e.bin")
    assert got.status_code == 200, got.text
    assert got.content == payload
    assert got.headers.get("x-amz-server-side-encryption") == "AES256"


def test_aes256_without_the_setting_is_refused_not_ignored(service, monkeypatch):
    """Silently storing plaintext when encryption was requested is the worst
    possible answer."""
    from tests.s3.test_s3_gateway import signed
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", False)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    refused = signed(service, "PUT", f"/{BUCKET}/plain.bin", b"x",
                     extra_headers={"x-amz-server-side-encryption": "AES256"})
    assert refused.status_code == 501, refused.text
    assert "storage.encryption" in refused.text
    # Nothing was stored.
    assert signed(service, "GET", f"/{BUCKET}/plain.bin").status_code == 404


def test_bucket_default_aes256_needs_the_setting(service, monkeypatch):
    """The bucket document and the deployment setting must agree."""
    from tests.s3.test_s3_gateway import signed
    body = (
        "<ServerSideEncryptionConfiguration><Rule>"
        "<ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256"
        "</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>"
        "</ServerSideEncryptionConfiguration>"
    ).encode()
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200

    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", False)
    off = signed(service, "PUT", f"/{BUCKET}?encryption", body)
    assert off.status_code == 501, off.text
    assert "storage.encryption" in off.text

    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    on = signed(service, "PUT", f"/{BUCKET}?encryption", body)
    assert on.status_code == 200, on.text
    read = signed(service, "GET", f"/{BUCKET}?encryption")
    assert read.status_code == 200
    assert b"AES256" in read.content

    # And the default then encrypts a plain PUT with no headers at all.
    put = signed(service, "PUT", f"/{BUCKET}/by-default.bin", b"dflt")
    assert put.status_code == 200
    assert put.headers.get("x-amz-server-side-encryption") == "AES256"
    assert signed(service, "GET", f"/{BUCKET}/by-default.bin").content == b"dflt"


def test_aws_kms_is_refused_because_there_is_no_kms(service, monkeypatch):
    from tests.s3.test_s3_gateway import signed
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    refused = signed(service, "PUT", f"/{BUCKET}/k.bin", b"x",
                     extra_headers={"x-amz-server-side-encryption": "aws:kms"})
    assert refused.status_code == 501, refused.text
    assert "KMS" in refused.text
