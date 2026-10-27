"""SSE-C (customer-supplied key) end-to-end contract tests.

The gateway must encrypt every Telegram chunk with AES-256-GCM under a fresh
nonce, bind the ciphertext to its identity through the AAD, and never retain
the client key anywhere (SQL, logs, audit entries or error bodies).

Every test goes through the real SigV4 HTTP app, the real SQLite catalog and
the deterministic in-memory Telegram transport used by the gateway tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import xml.etree.ElementTree as ET

import pytest
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from sqlalchemy import text

import web.app as admin
import web.s3 as gateway
from teledrive.s3.route_guard import S3QueryError, validate_s3_query
from teledrive.storage.sse import aad_for, parse_ssec_headers
from tests.s3.test_s3_gateway import service, signed  # noqa: F401 — fixtures

ALGORITHM = "AES256"
KEY_HEADER = "x-amz-server-side-encryption-customer-key"
MD5_HEADER = "x-amz-server-side-encryption-customer-key-md5"
ALG_HEADER = "x-amz-server-side-encryption-customer-algorithm"
COPY_PREFIX = "x-amz-copy-source-"


def raw_key(seed: int = 0) -> bytes:
    return bytes((seed + index) % 256 for index in range(32))


KEY_A = raw_key(1)
KEY_B = raw_key(2)
KEY_WRONG = raw_key(99)


def fingerprint(raw: bytes) -> str:
    return base64.b64encode(
        hashlib.md5(raw, usedforsecurity=False).digest()).decode("ascii")


def ssec_headers(raw: bytes, *, prefix: str = "") -> dict[str, str]:
    return {
        prefix + ALG_HEADER: ALGORITHM,
        prefix + KEY_HEADER: base64.b64encode(raw).decode("ascii"),
        prefix + MD5_HEADER: fingerprint(raw),
    }


def rows(connection, sql: str, params: dict | None = None):
    db = connection()
    try:
        return db.connection.execute(text(sql), params or {}).all()
    finally:
        db.close()


def scalar(connection, sql: str, params: dict | None = None):
    result = rows(connection, sql, params)
    return result[0][0] if result else None


def all_database_text(connection) -> str:
    """Flatten every SQL table (SQLite) into one searchable string."""
    db = connection()
    try:
        tables = [row[0] for row in db.connection.execute(text(
            "SELECT name FROM sqlite_master WHERE type = 'table'"))]
        parts = []
        for name in tables:
            safe = name.replace('"', '""')
            for row in db.connection.execute(text(f'SELECT * FROM "{safe}"')):
                parts.append(repr(tuple(row)))
        return "\n".join(parts)
    finally:
        db.close()


def make_bucket(service, name: str = "sse-bucket") -> None:
    assert signed(service, "PUT", f"/{name}").status_code in (200, 409)


def assert_no_key_material(connection, *raw_keys: bytes) -> None:
    dump = all_database_text(connection)
    for raw in raw_keys:
        assert base64.b64encode(raw).decode("ascii") not in dump
        assert raw.hex() not in dump
        assert repr(raw) not in dump


def assert_no_key_in_logs(*raw_keys: bytes) -> None:
    joined = "\n".join(admin.LOG_BUFFER)
    for raw in raw_keys:
        assert base64.b64encode(raw).decode("ascii") not in joined
        assert raw.hex() not in joined


# ---------------------------------------------------------------------------
# Header validation matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("missing", [ALG_HEADER, KEY_HEADER, MD5_HEADER])
def test_missing_any_required_header_is_invalid_argument(service, missing):
    make_bucket(service)
    headers = ssec_headers(KEY_A)
    headers.pop(missing)
    before = service[2].uploads
    reply = signed(service, "PUT", "/sse-bucket/partial.bin", b"data",
                   extra_headers=headers)
    assert reply.status_code == 400, reply.text
    assert b"InvalidArgument" in reply.content
    assert service[2].uploads == before
    assert signed(service, "GET", "/sse-bucket/partial.bin").status_code == 404


def test_wrong_algorithm_is_rejected(service):
    make_bucket(service)
    headers = ssec_headers(KEY_A)
    headers[ALG_HEADER] = "AES128"
    reply = signed(service, "PUT", "/sse-bucket/bad-alg", b"data",
                   extra_headers=headers)
    assert reply.status_code == 400
    assert b"InvalidArgument" in reply.content


def test_key_md5_mismatch_is_rejected(service):
    make_bucket(service)
    headers = ssec_headers(KEY_A)
    headers[MD5_HEADER] = fingerprint(KEY_B)
    before = service[2].uploads
    reply = signed(service, "PUT", "/sse-bucket/bad-md5", b"data",
                   extra_headers=headers)
    assert reply.status_code == 400
    assert b"InvalidArgument" in reply.content
    assert service[2].uploads == before


@pytest.mark.parametrize("value", ["not-base64!!", base64.b64encode(b"short").decode()])
def test_malformed_or_short_key_is_rejected(service, value):
    make_bucket(service)
    headers = ssec_headers(KEY_A)
    headers[KEY_HEADER] = value
    reply = signed(service, "PUT", "/sse-bucket/bad-key", b"data",
                   extra_headers=headers)
    assert reply.status_code == 400
    assert b"InvalidArgument" in reply.content


def test_unsigned_ssec_headers_are_rejected(service):
    """A key the signature does not cover must never be trusted."""
    make_bucket(service)
    client, issued, bot, _, _ = service
    body = b"signed-body"
    request = AWSRequest(
        method="PUT", url="http://localhost:9000/sse-bucket/unsigned.bin",
        data=body,
        headers={"x-amz-content-sha256": hashlib.sha256(body).hexdigest()},
    )
    request.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(issued.access_key, issued.secret_key),
                "s3", "us-east-1").add_auth(request)
    headers = dict(request.headers)
    headers.update(ssec_headers(KEY_A))
    before = bot.uploads
    reply = client.put("/sse-bucket/unsigned.bin", content=body, headers=headers)
    assert reply.status_code == 400, reply.text
    assert b"InvalidArgument" in reply.content
    assert bot.uploads == before


def test_ssec_headers_on_unsupported_operations_fail_closed(service):
    make_bucket(service)
    assert signed(service, "PUT", "/sse-bucket/plain.bin", b"plain").status_code == 200
    for method, path in (
        ("DELETE", "/sse-bucket/plain.bin"),
        ("PUT", "/sse-bucket/plain.bin?tagging"),
        ("GET", "/sse-bucket?encryption"),
        ("GET", "/sse-bucket/plain.bin?acl"),
    ):
        reply = signed(service, method, path,
                       extra_headers=ssec_headers(KEY_A))
        assert reply.status_code == 501, (method, path, reply.text)


def test_server_side_encryption_headers_are_still_rejected(service):
    """SSE-S3/SSE-KMS are NOT implemented and must never be acknowledged."""
    make_bucket(service)
    before = service[2].uploads
    for header, value in (
        ("x-amz-server-side-encryption", "AES256"),
        ("x-amz-server-side-encryption", "aws:kms"),
        ("x-amz-server-side-encryption-aws-kms-key-id", "alias/tele"),
        ("x-amz-bucket-key-enabled", "true"),
    ):
        reply = signed(service, "PUT", "/sse-bucket/sse-s3.bin", b"data",
                       extra_headers={header: value})
        assert reply.status_code == 501, (header, reply.text)
        assert b"NotImplemented" in reply.content
    assert service[2].uploads == before
    assert signed(service, "GET", "/sse-bucket/sse-s3.bin").status_code == 404


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_small_round_trip_is_byte_exact_and_returns_ssec_headers(service):
    make_bucket(service)
    payload = b"top-secret-\x00\x01\x02 payload" * 7
    put = signed(service, "PUT", "/sse-bucket/small.bin", payload,
                 extra_headers=ssec_headers(KEY_A))
    assert put.status_code == 200, put.text
    assert put.headers[ALG_HEADER] == ALGORITHM
    assert put.headers[MD5_HEADER] == fingerprint(KEY_A)
    assert KEY_HEADER not in {name.lower() for name in put.headers}
    etag = put.headers["ETag"].strip('"')
    # ETag is the digest of the stored ciphertext, never the plaintext MD5.
    assert etag != hashlib.sha256(payload).hexdigest()

    got = signed(service, "GET", "/sse-bucket/small.bin",
                 extra_headers=ssec_headers(KEY_A))
    assert got.status_code == 200, got.text
    assert got.content == payload
    assert got.headers[MD5_HEADER] == fingerprint(KEY_A)
    assert got.headers["ETag"].strip('"') == etag


def test_multi_chunk_round_trip(service, monkeypatch):
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 1024)
    make_bucket(service)
    payload = os.urandom(3000)
    put = signed(service, "PUT", "/sse-bucket/multi.bin", payload,
                 extra_headers=ssec_headers(KEY_A))
    assert put.status_code == 200, put.text
    chunk_count = scalar(
        service[3], "SELECT COUNT(*) FROM storage_chunks WHERE object_id = "
                    "(SELECT object_id FROM storage_object_encryption LIMIT 1)")
    assert chunk_count == 3
    got = signed(service, "GET", "/sse-bucket/multi.bin",
                 extra_headers=ssec_headers(KEY_A))
    assert got.status_code == 200
    assert got.content == payload


def test_each_chunk_uses_a_fresh_nonce(service, monkeypatch):
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 512)
    make_bucket(service)
    assert signed(service, "PUT", "/sse-bucket/nonce.bin", os.urandom(2048),
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    encrypted = rows(
        service[3],
        "SELECT encryption FROM storage_chunks WHERE encryption IS NOT NULL")
    nonces = [json.loads(row[0])["n"] for row in encrypted]
    assert len(nonces) >= 4
    assert len(set(nonces)) == len(nonces)


@pytest.mark.parametrize("start,end", [
    (0, 10),            # first chunk
    (1100, 1200),       # inside the middle chunk
    (2900, 3000),       # last chunk
    (1000, 2100),       # spans a chunk boundary
    (1023, 1025),       # exactly across the first boundary
    (0, 3000),          # whole object
    (2999, 3000),       # final single byte
])
def test_range_reads_are_byte_exact(service, monkeypatch, start, end):
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 1024)
    make_bucket(service)
    payload = os.urandom(3000)
    assert signed(service, "PUT", "/sse-bucket/range.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    reply = signed(service, "GET", "/sse-bucket/range.bin",
                   extra_headers={"Range": f"bytes={start}-{end - 1}",
                                  **ssec_headers(KEY_A)})
    assert reply.status_code == 206, reply.text
    assert reply.content == payload[start:end]
    assert reply.headers["Content-Range"] == f"bytes {start}-{end - 1}/{len(payload)}"


# ---------------------------------------------------------------------------
# Key enforcement
# ---------------------------------------------------------------------------

def test_wrong_key_get_is_400_and_leaks_no_plaintext(service):
    make_bucket(service)
    marker = b"PLAINTEXT-MUST-NOT-LEAK"
    assert signed(service, "PUT", "/sse-bucket/secret.bin", marker * 4,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    reply = signed(service, "GET", "/sse-bucket/secret.bin",
                   extra_headers=ssec_headers(KEY_WRONG))
    assert reply.status_code == 400, reply.text
    assert b"InvalidRequest" in reply.content
    assert marker not in reply.content
    assert base64.b64encode(KEY_WRONG).decode() not in reply.text
    assert base64.b64encode(KEY_A).decode() not in reply.text


def test_get_without_key_on_encrypted_object_fails_closed(service):
    make_bucket(service)
    assert signed(service, "PUT", "/sse-bucket/needkey.bin", b"secret",
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    reply = signed(service, "GET", "/sse-bucket/needkey.bin")
    assert reply.status_code == 400
    assert b"InvalidRequest" in reply.content
    assert b"secret" not in reply.content


def test_head_requires_matching_key(service):
    make_bucket(service)
    assert signed(service, "PUT", "/sse-bucket/head.bin", b"payload",
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    good = signed(service, "HEAD", "/sse-bucket/head.bin",
                  extra_headers=ssec_headers(KEY_A))
    assert good.status_code == 200
    assert good.headers[MD5_HEADER] == fingerprint(KEY_A)
    bad = signed(service, "HEAD", "/sse-bucket/head.bin",
                 extra_headers=ssec_headers(KEY_WRONG))
    assert bad.status_code == 400


def test_key_on_plaintext_object_is_rejected(service):
    make_bucket(service)
    assert signed(service, "PUT", "/sse-bucket/plain.bin", b"plain").status_code == 200
    reply = signed(service, "GET", "/sse-bucket/plain.bin",
                   extra_headers=ssec_headers(KEY_A))
    assert reply.status_code == 400
    assert b"InvalidRequest" in reply.content
    assert reply.content != b"plain"


# ---------------------------------------------------------------------------
# Tamper / splice resistance
# ---------------------------------------------------------------------------

def test_swapping_chunk_nonce_and_tag_fails_closed(service, monkeypatch):
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 64)
    make_bucket(service)
    payload = os.urandom(256)
    assert signed(service, "PUT", "/sse-bucket/splice.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    object_id = scalar(service[3],
                       "SELECT object_id FROM storage_object_encryption LIMIT 1")
    chunk_rows = rows(
        service[3],
        "SELECT ordinal, encryption FROM storage_chunks "
        "WHERE object_id = :oid ORDER BY ordinal", {"oid": object_id})
    first = json.loads(chunk_rows[0][1])
    second = json.loads(chunk_rows[1][1])
    first["n"], second["n"] = second["n"], first["n"]
    first["t"], second["t"] = second["t"], first["t"]
    db = service[3]()
    try:
        for ordinal, metadata in ((chunk_rows[0][0], first),
                                  (chunk_rows[1][0], second)):
            db.connection.execute(text(
                "UPDATE storage_chunks SET encryption = :e "
                "WHERE object_id = :oid AND ordinal = :o"),
                {"e": json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                 "oid": object_id, "o": ordinal})
        db.connection.commit()
    finally:
        db.close()
    # Swapping nonce/tag while the ciphertext stays put can only be detected
    # by GCM itself, i.e. while the chunk is authenticated. The response is
    # therefore aborted rather than completed — and no plaintext of the
    # tampered chunk is ever emitted.
    with pytest.raises(Exception) as failure:
        signed(service, "GET", "/sse-bucket/splice.bin",
               extra_headers=ssec_headers(KEY_A))
    assert payload[:64] not in repr(failure.value).encode("utf-8", "replace")


def test_swapping_whole_chunk_identity_fails_closed(service, monkeypatch):
    """A full row swap (ciphertext + nonce + tag + AAD) must also fail."""
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 64)
    make_bucket(service)
    payload = os.urandom(256)
    assert signed(service, "PUT", "/sse-bucket/reseat.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    object_id = scalar(service[3],
                       "SELECT object_id FROM storage_object_encryption LIMIT 1")
    chunk_rows = rows(
        service[3],
        "SELECT ordinal, encryption, message_id FROM storage_chunks "
        "WHERE object_id = :oid ORDER BY ordinal", {"oid": object_id})
    first_meta = json.loads(chunk_rows[0][1])
    second_meta = json.loads(chunk_rows[1][1])
    db = service[3]()
    try:
        for ordinal, metadata in ((chunk_rows[0][0], second_meta),
                                  (chunk_rows[1][0], first_meta)):
            db.connection.execute(text(
                "UPDATE storage_chunks SET encryption = :e "
                "WHERE object_id = :oid AND ordinal = :o"),
                {"e": json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                 "oid": object_id, "o": ordinal})
        db.connection.commit()
    finally:
        db.close()
    reply = signed(service, "GET", "/sse-bucket/reseat.bin",
                   extra_headers=ssec_headers(KEY_A))
    assert reply.status_code == 400, reply.text
    assert b"InvalidRequest" in reply.content


def test_tampered_ciphertext_in_telegram_fails_closed(service):
    make_bucket(service)
    payload = b"integrity-bound-payload"
    assert signed(service, "PUT", "/sse-bucket/corrupt.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    telegram = service[2]
    first = next(iter(telegram.parts))
    telegram.parts[first] = bytes(len(telegram.parts[first]))
    # A stored-byte digest mismatch aborts the response instead of serving
    # unauthenticated bytes. The client sees a 5xx S3 error or an aborted
    # body depending on where the integrity check trips.
    try:
        reply = signed(service, "GET", "/sse-bucket/corrupt.bin",
                       extra_headers=ssec_headers(KEY_A))
    except Exception as failure:  # aborted stream is fail-closed
        assert payload not in repr(failure).encode("utf-8", "replace")
        return
    assert reply.status_code in (500, 503), reply.text
    assert payload not in reply.content


def test_upload_checksum_is_verified_before_encryption(service):
    make_bucket(service)
    before = service[2].uploads
    reply = signed(
        service, "PUT", "/sse-bucket/bad-digest", b"payload",
        extra_headers={**ssec_headers(KEY_A),
                       "Content-MD5": base64.b64encode(b"0" * 16).decode()})
    assert reply.status_code == 400
    assert b"BadDigest" in reply.content
    assert service[2].uploads == before


def test_stored_chunk_digests_are_ciphertext_digests(service, monkeypatch):
    """Every journaled chunk digest/size describes the CIPHERTEXT Telegram holds."""
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 128)
    make_bucket(service)
    payload = os.urandom(500)
    assert signed(service, "PUT", "/sse-bucket/digest.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    object_id = scalar(service[3],
                       "SELECT object_id FROM storage_object_encryption LIMIT 1")
    chunk_rows = rows(
        service[3],
        "SELECT ordinal, sha256, size, message_id, encryption FROM storage_chunks "
        "WHERE object_id = :oid ORDER BY ordinal", {"oid": object_id})
    assert len(chunk_rows) == 4
    telegram = service[2]
    for _ordinal, digest, size, message_id, metadata in chunk_rows:
        stored = telegram.parts[f"file-{message_id}"]
        assert hashlib.sha256(stored).hexdigest() == digest
        assert len(stored) == size + 16          # GCM tag appended
        assert json.loads(metadata)["cs"] == len(stored)
        assert payload.find(stored) == -1         # plaintext is not stored


def test_aad_binds_object_identity_and_ordinal():
    from teledrive.storage.sse import SSECKey, decrypt_chunk, encrypt_chunk

    key = SSECKey(KEY_A, fingerprint(KEY_A))
    object_id = "11111111-2222-3333-4444-555555555555"
    ciphertext, metadata = encrypt_chunk(key, object_id, 3, b"payload")
    assert metadata["a"] == object_id and metadata["o"] == 3
    assert decrypt_chunk(key, ciphertext, metadata) == b"payload"
    # AAD covers both the object id and the ordinal: changing either fails.
    for wrong_id, wrong_ordinal in (
        ("99999999-2222-3333-4444-555555555555", 3),
        (object_id, 2),
    ):
        spliced = dict(metadata, a=wrong_id, o=wrong_ordinal)
        with pytest.raises(Exception) as failure:
            decrypt_chunk(key, ciphertext, spliced)
        assert getattr(failure.value, "code", "") == "InvalidRequest"
    assert aad_for(object_id, 3) == object_id.encode() + (3).to_bytes(8, "big")


# ---------------------------------------------------------------------------
# Multipart
# ---------------------------------------------------------------------------

def test_multipart_with_ssec(service):
    make_bucket(service)
    first = os.urandom(5 * 1024 * 1024)
    second = b"tail-part"
    start = signed(service, "POST", "/sse-bucket/mpu.bin?uploads",
                   extra_headers=ssec_headers(KEY_A))
    assert start.status_code == 200, start.text
    assert start.headers[MD5_HEADER] == fingerprint(KEY_A)
    upload_id = ET.fromstring(start.content).findtext("{*}UploadId")

    part_etags = {}
    for number, data in ((1, first), (2, second)):
        part = signed(
            service, "PUT",
            f"/sse-bucket/mpu.bin?partNumber={number}&uploadId={upload_id}",
            data, extra_headers=ssec_headers(KEY_A))
        assert part.status_code == 200, part.text
        assert part.headers[MD5_HEADER] == fingerprint(KEY_A)
        part_etags[number] = part.headers["ETag"]

    # Listing parts requires the same key and leaks no plaintext digest.
    listed = signed(service, "GET",
                    f"/sse-bucket/mpu.bin?uploadId={upload_id}",
                    extra_headers=ssec_headers(KEY_A))
    assert listed.status_code == 200, listed.text
    assert b"Part" in listed.content
    no_key = signed(service, "GET", f"/sse-bucket/mpu.bin?uploadId={upload_id}")
    assert no_key.status_code == 400

    body = ("<CompleteMultipartUpload>" + "".join(
        f"<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
        for number, etag in part_etags.items()) +
        "</CompleteMultipartUpload>").encode()
    complete = signed(service, "POST",
                      f"/sse-bucket/mpu.bin?uploadId={upload_id}", body,
                      extra_headers=ssec_headers(KEY_A))
    assert complete.status_code == 200, complete.text

    got = signed(service, "GET", "/sse-bucket/mpu.bin",
                 extra_headers=ssec_headers(KEY_A))
    assert got.status_code == 200, got.text
    assert got.content == first + second
    wrong = signed(service, "GET", "/sse-bucket/mpu.bin",
                   extra_headers=ssec_headers(KEY_WRONG))
    assert wrong.status_code == 400


def test_multipart_completion_requires_the_original_key(service):
    make_bucket(service)
    start = signed(service, "POST", "/sse-bucket/mpu2.bin?uploads",
                   extra_headers=ssec_headers(KEY_A))
    upload_id = ET.fromstring(start.content).findtext("{*}UploadId")
    part = signed(
        service, "PUT",
        f"/sse-bucket/mpu2.bin?partNumber=1&uploadId={upload_id}",
        b"only-part", extra_headers=ssec_headers(KEY_A))
    assert part.status_code == 200
    body = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
            f"<ETag>{part.headers['ETag']}</ETag></Part>"
            "</CompleteMultipartUpload>").encode()
    wrong = signed(service, "POST",
                   f"/sse-bucket/mpu2.bin?uploadId={upload_id}", body,
                   extra_headers=ssec_headers(KEY_B))
    assert wrong.status_code == 400, wrong.text
    assert b"InvalidRequest" in wrong.content
    # The upload survives a failed completion and still completes with A.
    ok = signed(service, "POST",
                f"/sse-bucket/mpu2.bin?uploadId={upload_id}", body,
                extra_headers=ssec_headers(KEY_A))
    assert ok.status_code == 200, ok.text


def test_multipart_abort_requires_the_original_key(service):
    make_bucket(service)
    start = signed(service, "POST", "/sse-bucket/mpu3.bin?uploads",
                   extra_headers=ssec_headers(KEY_A))
    upload_id = ET.fromstring(start.content).findtext("{*}UploadId")
    wrong = signed(service, "DELETE",
                   f"/sse-bucket/mpu3.bin?uploadId={upload_id}",
                   extra_headers=ssec_headers(KEY_B))
    assert wrong.status_code == 400, wrong.text
    assert signed(service, "DELETE",
                  f"/sse-bucket/mpu3.bin?uploadId={upload_id}").status_code == 400
    ok = signed(service, "DELETE",
                f"/sse-bucket/mpu3.bin?uploadId={upload_id}",
                extra_headers=ssec_headers(KEY_A))
    assert ok.status_code == 204, ok.text


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

def test_update_object_encryption_rotates_the_key(service):
    make_bucket(service)
    payload = os.urandom(1500)
    assert signed(service, "PUT", "/sse-bucket/rotate.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    rotation = signed(
        service, "PUT", "/sse-bucket/rotate.bin?encryption", b"",
        extra_headers={**ssec_headers(KEY_B),
                       **ssec_headers(KEY_A, prefix=COPY_PREFIX)})
    assert rotation.status_code == 200, rotation.text
    assert rotation.headers[MD5_HEADER] == fingerprint(KEY_B)

    new_read = signed(service, "GET", "/sse-bucket/rotate.bin",
                      extra_headers=ssec_headers(KEY_B))
    assert new_read.status_code == 200
    assert new_read.content == payload
    old_read = signed(service, "GET", "/sse-bucket/rotate.bin",
                      extra_headers=ssec_headers(KEY_A))
    assert old_read.status_code == 400


def test_update_object_encryption_can_encrypt_a_plaintext_object(service):
    make_bucket(service)
    payload = b"plain-to-encrypted"
    assert signed(service, "PUT", "/sse-bucket/upgrade.bin",
                  payload).status_code == 200
    rotation = signed(service, "PUT", "/sse-bucket/upgrade.bin?encryption",
                      b"", extra_headers=ssec_headers(KEY_A))
    assert rotation.status_code == 200, rotation.text
    assert signed(service, "GET", "/sse-bucket/upgrade.bin").status_code == 400
    got = signed(service, "GET", "/sse-bucket/upgrade.bin",
                 extra_headers=ssec_headers(KEY_A))
    assert got.status_code == 200 and got.content == payload


# ---------------------------------------------------------------------------
# Dedup and content index
# ---------------------------------------------------------------------------

def test_encrypted_objects_do_not_dedup_against_plaintext(service):
    make_bucket(service)
    payload = b"identical-bytes-used-twice"
    plain = signed(service, "PUT", "/sse-bucket/dedup-plain.bin", payload)
    assert plain.status_code == 200
    uploads_after_plain = service[2].uploads
    encrypted = signed(service, "PUT", "/sse-bucket/dedup-crypt.bin", payload,
                       extra_headers=ssec_headers(KEY_A))
    assert encrypted.status_code == 200
    assert service[2].uploads > uploads_after_plain
    assert encrypted.headers["x-amz-version-id"] != plain.headers["x-amz-version-id"]
    encrypted_id = encrypted.headers["x-amz-version-id"]
    aliases = scalar(service[3],
                     "SELECT COUNT(*) FROM storage_object_aliases "
                     "WHERE object_id = :oid", {"oid": encrypted_id})
    assert aliases == 0


def test_encrypted_objects_are_excluded_from_the_content_index(service):
    make_bucket(service)
    text_payload = b"searchable plaintext sentence " * 40
    plain = signed(service, "PUT", "/sse-bucket/text-plain.txt", text_payload,
                   extra_headers={"Content-Type": "text/plain"})
    assert plain.status_code == 200
    plain_id = plain.headers["x-amz-version-id"]
    assert scalar(service[3],
                  "SELECT COUNT(*) FROM object_content_index "
                  "WHERE object_id = :oid", {"oid": plain_id}) == 1

    encrypted = signed(service, "PUT", "/sse-bucket/text-crypt.txt",
                       text_payload,
                       extra_headers={"Content-Type": "text/plain",
                                      **ssec_headers(KEY_A)})
    assert encrypted.status_code == 200
    encrypted_id = encrypted.headers["x-amz-version-id"]
    assert scalar(service[3],
                  "SELECT COUNT(*) FROM object_content_index "
                  "WHERE object_id = :oid", {"oid": encrypted_id}) == 0


# ---------------------------------------------------------------------------
# Bucket encryption configuration (SSE-C only; no SSE-S3 / SSE-KMS)
# ---------------------------------------------------------------------------

EMPTY_CONFIG = (b"<ServerSideEncryptionConfiguration "
                b"xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>")
AES256_CONFIG = (
    b"<ServerSideEncryptionConfiguration "
    b"xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule>"
    b"<ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256"
    b"</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>"
    b"</ServerSideEncryptionConfiguration>")
KMS_CONFIG = AES256_CONFIG.replace(b"AES256", b"aws:kms")


def test_bucket_encryption_configuration_crud(service):
    make_bucket(service)
    missing = signed(service, "GET", "/sse-bucket?encryption")
    assert missing.status_code == 404
    assert b"ServerSideEncryptionConfigurationNotFoundError" in missing.content

    put = signed(service, "PUT", "/sse-bucket?encryption", EMPTY_CONFIG)
    assert put.status_code == 200, put.text
    got = signed(service, "GET", "/sse-bucket?encryption")
    assert got.status_code == 200
    assert ET.fromstring(got.content).tag.endswith(
        "ServerSideEncryptionConfiguration")

    delete = signed(service, "DELETE", "/sse-bucket?encryption")
    assert delete.status_code == 204
    assert signed(service, "GET", "/sse-bucket?encryption").status_code == 404


@pytest.mark.parametrize("payload,needle", [
    (AES256_CONFIG, b"SSE-S3"),
    (KMS_CONFIG, b"aws:kms"),
])
def test_bucket_level_default_encryption_is_rejected_501(service, payload, needle):
    make_bucket(service)
    reply = signed(service, "PUT", "/sse-bucket?encryption", payload)
    assert reply.status_code == 501, reply.text
    assert b"NotImplemented" in reply.content
    assert needle in reply.content
    assert signed(service, "GET", "/sse-bucket?encryption").status_code == 404


def test_bucket_key_enabled_is_rejected_501(service):
    make_bucket(service)
    payload = (
        b"<ServerSideEncryptionConfiguration "
        b"xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule>"
        b"<BucketKeyEnabled>true</BucketKeyEnabled></Rule>"
        b"</ServerSideEncryptionConfiguration>")
    reply = signed(service, "PUT", "/sse-bucket?encryption", payload)
    assert reply.status_code == 501
    assert b"NotImplemented" in reply.content


def test_malformed_bucket_encryption_xml_is_rejected(service):
    make_bucket(service)
    for payload in (b"", b"<NotEncryption/>", b"<a><b></a>"):
        reply = signed(service, "PUT", "/sse-bucket?encryption", payload)
        assert reply.status_code == 400, (payload, reply.text)
        assert (b"MalformedXML" in reply.content
                or b"InvalidArgument" in reply.content)


# ---------------------------------------------------------------------------
# Permissions and route guard
# ---------------------------------------------------------------------------

def test_permission_separation_for_encryption_controls(service):
    from teledrive.s3.credentials import S3CredentialStore

    make_bucket(service)
    db = service[3]()
    try:
        reader = S3CredentialStore(db, service[4]).create(
            "reader", ["s3:GetObject", "s3:ListBucket"])
        rotator = S3CredentialStore(db, service[4]).create(
            "rotator", ["s3:GetObject", "s3:PutObject",
                        "s3:PutObjectEncryption"])
    finally:
        db.close()
    payload = b"perm-payload"
    assert signed(service, "PUT", "/sse-bucket/perm.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    assert signed(service, "GET", "/sse-bucket/perm.bin",
                  access=reader.access_key, secret=reader.secret_key,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    # No PutObjectEncryption scope -> rotation denied, bytes untouched.
    denied = signed(service, "PUT", "/sse-bucket/perm.bin?encryption", b"",
                    access=reader.access_key, secret=reader.secret_key,
                    extra_headers={**ssec_headers(KEY_B),
                                   **ssec_headers(KEY_A, prefix=COPY_PREFIX)})
    assert denied.status_code == 403
    assert b"AccessDenied" in denied.content
    allowed = signed(service, "PUT", "/sse-bucket/perm.bin?encryption", b"",
                     access=rotator.access_key, secret=rotator.secret_key,
                     extra_headers={**ssec_headers(KEY_B),
                                    **ssec_headers(KEY_A, prefix=COPY_PREFIX)})
    assert allowed.status_code == 200, allowed.text
    # Bucket encryption configuration needs its own scopes.
    assert signed(service, "GET", "/sse-bucket?encryption",
                  access=reader.access_key,
                  secret=reader.secret_key).status_code == 403
    assert signed(service, "PUT", "/sse-bucket?encryption", EMPTY_CONFIG,
                  access=reader.access_key,
                  secret=reader.secret_key).status_code == 403


def test_route_guard_accepts_supported_encryption_routes_only():
    from starlette.datastructures import QueryParams

    validate_s3_query("PUT", "b", False, QueryParams("encryption"))
    validate_s3_query("GET", "b", False, QueryParams("encryption"))
    validate_s3_query("DELETE", "b", False, QueryParams("encryption"))
    validate_s3_query("PUT", "b", True, QueryParams("encryption"))
    for method, object_path in (
        ("GET", True), ("DELETE", True), ("POST", True),
        ("HEAD", False), ("POST", False),
    ):
        with pytest.raises(S3QueryError) as denied:
            validate_s3_query(method, "b", object_path,
                              QueryParams("encryption"))
        assert denied.value.code == "NotImplemented"


# ---------------------------------------------------------------------------
# Copy paths
# ---------------------------------------------------------------------------

def test_copy_of_encrypted_object_stays_encrypted(service):
    make_bucket(service)
    payload = os.urandom(700)
    assert signed(service, "PUT", "/sse-bucket/copy-src.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    copied = signed(service, "PUT", "/sse-bucket/copy-dst.bin", b"",
                    extra_headers={"x-amz-copy-source":
                                   "/sse-bucket/copy-src.bin"})
    assert copied.status_code == 200, copied.text
    # The copy is an alias of the ciphertext: it still demands the key.
    assert signed(service, "GET", "/sse-bucket/copy-dst.bin").status_code == 400
    got = signed(service, "GET", "/sse-bucket/copy-dst.bin",
                 extra_headers=ssec_headers(KEY_A))
    assert got.status_code == 200 and got.content == payload
    assert signed(service, "GET", "/sse-bucket/copy-dst.bin",
                  extra_headers=ssec_headers(KEY_WRONG)).status_code == 400


def test_ssec_headers_on_copy_and_part_copy_fail_closed(service):
    make_bucket(service)
    payload = os.urandom(600)
    assert signed(service, "PUT", "/sse-bucket/pc-src.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    # Specifying a destination key on CopyObject is not implemented.
    reply = signed(service, "PUT", "/sse-bucket/pc-dst.bin", b"",
                   extra_headers={"x-amz-copy-source":
                                  "/sse-bucket/pc-src.bin",
                                  **ssec_headers(KEY_B)})
    assert reply.status_code == 501, reply.text
    # UploadPartCopy of an encrypted source cannot decrypt without the key
    # and must fail rather than copy ciphertext as if it were plaintext.
    start = signed(service, "POST", "/sse-bucket/pc-mpu.bin?uploads")
    assert start.status_code == 200
    upload_id = ET.fromstring(start.content).findtext("{*}UploadId")
    part_copy = signed(
        service, "PUT",
        f"/sse-bucket/pc-mpu.bin?partNumber=1&uploadId={upload_id}", b"",
        extra_headers={"x-amz-copy-source": "/sse-bucket/pc-src.bin"})
    assert part_copy.status_code == 400, part_copy.text
    assert payload[:16] not in part_copy.content


# ---------------------------------------------------------------------------
# No key leakage
# ---------------------------------------------------------------------------

def test_client_key_never_reaches_sql_logs_or_error_bodies(service, monkeypatch):
    monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", 64)
    make_bucket(service)
    payload = b"leak-canary-" * 20
    key_headers = ssec_headers(KEY_A)
    put = signed(service, "PUT", "/sse-bucket/leak.bin", payload,
                 extra_headers=key_headers)
    assert put.status_code == 200
    assert signed(service, "GET", "/sse-bucket/leak.bin",
                  extra_headers=key_headers).status_code == 200
    wrong = signed(service, "GET", "/sse-bucket/leak.bin",
                   extra_headers=ssec_headers(KEY_WRONG))
    assert wrong.status_code == 400
    malformed = signed(service, "PUT", "/sse-bucket/leak2.bin", payload,
                       extra_headers={**key_headers, MD5_HEADER: fingerprint(KEY_B)})
    assert malformed.status_code == 400
    assert b"leak-canary" not in wrong.content
    assert b"leak-canary" not in malformed.content
    encoded_a = base64.b64encode(KEY_A).decode("ascii")
    encoded_wrong = base64.b64encode(KEY_WRONG).decode("ascii")
    for body in (put, wrong, malformed):
        assert encoded_a not in body.text
        assert encoded_wrong not in body.text
    assert_no_key_material(service[3], KEY_A, KEY_WRONG)
    assert_no_key_in_logs(KEY_A, KEY_WRONG)
    # The non-secret fingerprint (AWS key-MD5) IS stored, deliberately.
    assert fingerprint(KEY_A) in all_database_text(service[3])


def test_ssec_headers_are_parsed_without_retaining_key_material():
    class Headers(dict):
        pass

    headers = Headers(ssec_headers(KEY_A))
    parsed = parse_ssec_headers(headers, set(headers))
    assert parsed.raw == KEY_A
    assert parsed.key_md5_b64 == fingerprint(KEY_A)
    # Nothing in the parsed object stringifies the raw key.
    assert base64.b64encode(KEY_A).decode() not in repr(parsed)
