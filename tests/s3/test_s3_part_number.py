"""S3 GetObject ``?partNumber`` contract tests (handoff 06, Task A).

Every test drives the real SigV4 HTTP gateway over the real SQLite catalog
and the deterministic fake Telegram transport, exactly like the gateway
and multipart suites. Where practical the reads go through real boto3
``get_object(PartNumber=N)`` against a uvicorn server, so the wire
contract (206/Content-Range/x-amz-mp-parts-count and the parsed error
codes) is what an AWS SDK actually sees.

Behavioral decisions verified here were pinned from evidence, not
guesswork (see the comments in ``web/s3_gateway/objects.py``):
* partNumber is documented by AWS as a decimal 1..10000 "ranged GET";
* a nonexistent/in-range-but-absent part answers 416 InvalidPartNumber;
* Range and partNumber together answer 400 InvalidRequest;
* a single-PUT object is its own part 1 and never reports a parts count;
* zero-byte parts answer an empty 200 with no Content-Range.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import threading
import time
import xml.etree.ElementTree as ET

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import text

import web.s3 as gateway
from teledrive.s3.credentials import S3CredentialStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed  # noqa: F401 — fixture

BUCKET = "backup-bucket"
KEY = "part-reads.bin"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
MIB = 1024 * 1024


def error_code(response) -> str:
    return ET.fromstring(response.content).findtext("Code")


def begin(svc, key=KEY, headers=None):
    response = signed(svc, "POST", f"/{BUCKET}/{key}?uploads",
                      extra_headers=headers)
    assert response.status_code == 200, response.text
    return ET.fromstring(response.content).findtext(NS + "UploadId")


def part(svc, upload_id, number, payload, *, key=KEY, headers=None):
    response = signed(svc, "PUT",
                      f"/{BUCKET}/{key}?partNumber={number}&uploadId={upload_id}",
                      payload, extra_headers=headers)
    assert response.status_code == 200, response.text
    return response.headers["etag"]


def complete(svc, upload_id, selection, *, key=KEY, headers=None):
    root = ET.Element("CompleteMultipartUpload")
    for number, etag in selection:
        node = ET.SubElement(root, "Part")
        ET.SubElement(node, "PartNumber").text = str(number)
        ET.SubElement(node, "ETag").text = etag
    response = signed(svc, "POST", f"/{BUCKET}/{key}?uploadId={upload_id}",
                      ET.tostring(root), extra_headers=headers)
    assert response.status_code == 200, response.text
    return response


def mpu(svc, payloads, *, key=KEY, numbered=None):
    """Upload and complete an MPU from ``payloads`` (part numbers 1..n,
    or the explicit ``numbered`` mapping part number -> payload)."""
    numbered = numbered or {index + 1: body for index, body in enumerate(payloads)}
    upload_id = begin(svc, key)
    etags = {}
    for number, payload in numbered.items():
        etags[number] = part(svc, upload_id, number, payload, key=key)
    response = complete(svc, upload_id, sorted(etags.items()), key=key)
    etag = ET.fromstring(response.content).findtext(NS + "ETag")
    return response.headers["x-amz-version-id"], etag


def table_counts(service):
    """Row counts of every SQL table, for catalog-mutation assertions."""
    db = service[3]()
    try:
        names = [row[0] for row in db.connection.execute(text(
            "SELECT name FROM sqlite_master WHERE type = 'table'"))]
        return {
            name: db.connection.execute(
                text(f'SELECT COUNT(*) FROM "{name}"')).scalar()
            for name in sorted(names)
        }
    finally:
        db.close()


def layout_digests(service, version_id):
    """The immutable per-part SHA-256 layout of a completed version."""
    from teledrive.s3.multipart import MultipartStore

    catalog = BucketCatalog(ManifestStore(service[3]()))
    try:
        item = catalog.manifests.get(version_id)
        layout = MultipartStore(catalog).object_parts_for_version(
            item.id, item.size)
        assert layout is not None, "expected a multipart object"
        return {number: digest for number, _size, digest, _etag in layout}
    finally:
        catalog.db.close()


def boto_client(service):
    import boto3
    import uvicorn
    from botocore.config import Config

    _, credential, _, _, _ = service
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port, lifespan="off",
        log_level="error",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]},
                              daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started

    def stop():
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive()

    client = boto3.client(
        "s3", endpoint_url=f"http://127.0.0.1:{port}",
        aws_access_key_id=credential.access_key,
        aws_secret_access_key=credential.secret_key,
        region_name="us-east-1",
        config=Config(signature_version="s3v4",
                      s3={"addressing_style": "path",
                          "payload_signing_enabled": True},
                      request_checksum_calculation="when_required",
                      response_checksum_validation="when_required",
                      retries={"max_attempts": 0}),
    )
    return client, stop


# ---------------------------------------------------------------------------
# Real boto3 wire contract: first/middle/last part, exact bytes, headers.
# ---------------------------------------------------------------------------

def test_boto3_part_number_reads_first_middle_and_last_part(service):
    client, stop = boto_client(service)
    try:
        client.create_bucket(Bucket="sdk-parts")
        first = os.urandom(5 * MIB)
        middle = os.urandom(5 * MIB)
        last = b"tail-part-bytes" * 41
        created = client.create_multipart_upload(
            Bucket="sdk-parts", Key="multi.bin")
        upload_id = created["UploadId"]
        etags = [
            client.upload_part(Bucket="sdk-parts", Key="multi.bin",
                               UploadId=upload_id, PartNumber=n, Body=body)
            for n, body in ((1, first), (2, middle), (3, last))
        ]
        done = client.complete_multipart_upload(
            Bucket="sdk-parts", Key="multi.bin", UploadId=upload_id,
            MultipartUpload={"Parts": [
                {"PartNumber": n, "ETag": etags[n - 1]["ETag"]}
                for n in (1, 2, 3)
            ]},
        )
        total = len(first) + len(middle) + len(last)
        offset = 0
        for number, body in ((1, first), (2, middle), (3, last)):
            response = client.get_object(
                Bucket="sdk-parts", Key="multi.bin", PartNumber=number)
            assert response["Body"].read() == body
            meta = response["ResponseMetadata"]["HTTPStatusCode"]
            assert meta == 206
            assert response["PartsCount"] == 3
            assert response["ETag"] == done["ETag"]
            assert response["ContentRange"] == (
                f"bytes {offset}-{offset + len(body) - 1}/{total}")
            assert response["ContentLength"] == len(body)
            offset += len(body)

        # A part the completed object does not have: 416 InvalidPartNumber
        # is what botocore parses off the wire.
        with pytest.raises(ClientError) as missing:
            client.get_object(Bucket="sdk-parts", Key="multi.bin",
                              PartNumber=4)
        assert missing.value.response["Error"]["Code"] == "InvalidPartNumber"
        assert missing.value.response["ResponseMetadata"][
            "HTTPStatusCode"] == 416

        # Range and partNumber cannot select bytes together.
        with pytest.raises(ClientError) as clash:
            client.get_object(Bucket="sdk-parts", Key="multi.bin",
                              PartNumber=1, Range="bytes=0-9")
        assert clash.value.response["Error"]["Code"] == "InvalidRequest"
        assert clash.value.response["ResponseMetadata"][
            "HTTPStatusCode"] == 400

        # Out-of-domain part numbers are malformed parameters.
        for bad in (0, -1, 10001):
            with pytest.raises(ClientError) as domain:
                client.get_object(Bucket="sdk-parts", Key="multi.bin",
                                  PartNumber=bad)
            assert domain.value.response["Error"]["Code"] == "InvalidArgument"
            assert domain.value.response["ResponseMetadata"][
                "HTTPStatusCode"] == 400
    finally:
        stop()


def test_boto3_part_number_single_put_object_is_its_own_part_one(service):
    client, stop = boto_client(service)
    try:
        client.create_bucket(Bucket="sdk-single")
        payload = os.urandom(4096)
        client.put_object(Bucket="sdk-single", Key="one.bin", Body=payload)
        response = client.get_object(Bucket="sdk-single", Key="one.bin",
                                     PartNumber=1)
        assert response["Body"].read() == payload
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 206
        assert response["ContentRange"] == (
            f"bytes 0-{len(payload) - 1}/{len(payload)}")
        # AWS reports the parts count only for multipart uploads.
        assert "PartsCount" not in response
        assert response["ETag"] == client.head_object(
            Bucket="sdk-single", Key="one.bin")["ETag"]
        with pytest.raises(ClientError) as missing:
            client.get_object(Bucket="sdk-single", Key="one.bin", PartNumber=2)
        assert missing.value.response["Error"]["Code"] == "InvalidPartNumber"
        assert missing.value.response["ResponseMetadata"][
            "HTTPStatusCode"] == 416
    finally:
        stop()


# ---------------------------------------------------------------------------
# Raw signed requests: routing, validation and fail-closed behavior.
# ---------------------------------------------------------------------------

def test_part_number_sparse_completion_uses_stored_order(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    third = b"sparse-tail" * 97
    # Parts 1 and 3 only: completion order is what places the bytes, and
    # part 2 simply does not exist in the object.
    version, _etag = mpu(service, None, numbered={1: first, 3: third})
    total = len(first) + len(third)

    one = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1")
    assert one.status_code == 206
    assert one.content == first
    assert one.headers["content-range"] == f"bytes 0-{len(first)-1}/{total}"
    assert one.headers["x-amz-mp-parts-count"] == "2"

    three = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=3")
    assert three.status_code == 206
    assert three.content == third
    # The offset is the sum of PRIOR part sizes in completion order, not
    # part-number arithmetic: part 3 begins right after part 1.
    assert three.headers["content-range"] == (
        f"bytes {len(first)}-{total - 1}/{total}")

    gap = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=2")
    assert gap.status_code == 416
    assert error_code(gap) == "InvalidPartNumber"
    root = ET.fromstring(gap.content)
    assert root.findtext("PartNumberRequested") == "2"
    assert root.findtext("ActualPartCount") == "2"

    # Each returned slice still hashes to the immutable part digest.
    digests = layout_digests(service, version)
    assert hashlib.sha256(one.content).hexdigest() == digests[1]
    assert hashlib.sha256(three.content).hexdigest() == digests[3]


def test_part_number_invalid_input_never_reaches_telegram(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    payload = os.urandom(2048)
    assert signed(service, "PUT", f"/{BUCKET}/{KEY}", payload).status_code == 200
    before = service[2].downloads
    url = f"/{BUCKET}/{KEY}"
    for query, status, code in (
        ("partNumber=0", 400, "InvalidArgument"),
        ("partNumber=-1", 400, "InvalidArgument"),
        ("partNumber=10001", 400, "InvalidArgument"),
        ("partNumber=abc", 400, "InvalidArgument"),
        ("partNumber=1e3", 400, "InvalidArgument"),
        ("partNumber=" + "9" * 21, 400, "InvalidArgument"),
        ("partNumber=1&partNumber=2", 400, "InvalidArgument"),
        # A leading zero is still a decimal parse: part 05 == part 5,
        # which this single-PUT object does not have.
        ("partNumber=05", 416, "InvalidPartNumber"),
    ):
        response = signed(service, "GET", f"{url}?{query}")
        assert response.status_code == status, (query, response.text)
        if code is not None:
            assert error_code(response) == code, query
    # Range + partNumber never selects bytes together.
    clash = signed(service, "GET", f"{url}?partNumber=1",
                   extra_headers={"Range": "bytes=0-9"})
    assert clash.status_code == 400
    assert error_code(clash) == "InvalidRequest"
    # No rejected request may read a single Telegram chunk.
    assert service[2].downloads == before


def test_part_number_rejected_on_head_and_other_selectors(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/{KEY}", b"body").status_code == 200
    upload_id = begin(service)
    head = signed(service, "HEAD", f"/{BUCKET}/{KEY}?partNumber=1")
    assert head.status_code == 501
    listing = signed(service, "GET",
                     f"/{BUCKET}/{KEY}?partNumber=1&uploadId={upload_id}")
    assert listing.status_code == 501
    tagged = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1&tagging")
    assert tagged.status_code == 501
    delete = signed(service, "DELETE", f"/{BUCKET}/{KEY}?partNumber=1")
    assert delete.status_code == 501
    put = signed(service, "PUT", f"/{BUCKET}/{KEY}?partNumber=1", b"x")
    assert put.status_code == 501


def test_part_number_versioned_old_object(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}?versioning",
                  b"<VersioningConfiguration><Status>Enabled</Status>"
                  b"</VersioningConfiguration>").status_code == 200
    old_first = os.urandom(5 * MIB)
    old_last = b"old-tail" * 13
    old_version, _ = mpu(service, [old_first, old_last])
    new_first = os.urandom(5 * MIB)
    new_last = b"new-tail" * 29
    mpu(service, [new_first, new_last])

    current = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=2")
    assert current.status_code == 206 and current.content == new_last

    historical = signed(
        service, "GET",
        f"/{BUCKET}/{KEY}?partNumber=2&versionId={old_version}")
    assert historical.status_code == 206
    assert historical.content == old_last
    assert historical.headers["x-amz-version-id"] == old_version
    assert historical.headers["x-amz-mp-parts-count"] == "2"

    missing_version = signed(
        service, "GET", f"/{BUCKET}/{KEY}?partNumber=1&versionId=does-not-exist")
    assert missing_version.status_code == 404
    assert error_code(missing_version) == "NoSuchVersion"


def test_part_number_copy_of_completed_mpu_keeps_layout(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    second = b"copied-tail" * 53
    mpu(service, [first, second])
    copied = signed(
        service, "PUT", f"/{BUCKET}/copy.bin",
        extra_headers={"x-amz-copy-source": f"/{BUCKET}/{KEY}"})
    assert copied.status_code == 200, copied.text

    part_two = signed(service, "GET", f"/{BUCKET}/copy.bin?partNumber=2")
    assert part_two.status_code == 206
    assert part_two.content == second
    assert part_two.headers["x-amz-mp-parts-count"] == "2"
    assert part_two.headers["content-range"] == (
        f"bytes {len(first)}-{len(first) + len(second) - 1}/"
        f"{len(first) + len(second)}")


def test_part_number_zero_byte_parts_answer_empty_200(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    # A completed MPU may end with an empty part, and an empty object is
    # its own (empty) part 1: no byte range can describe zero bytes, so
    # both answer an empty 200 without Content-Range.
    mpu(service, [first, b""])
    empty_part = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=2")
    assert empty_part.status_code == 200
    assert empty_part.content == b""
    assert empty_part.headers["content-length"] == "0"
    assert "content-range" not in empty_part.headers
    assert empty_part.headers["x-amz-mp-parts-count"] == "2"

    nonempty = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1")
    assert nonempty.status_code == 206 and nonempty.content == first

    assert signed(service, "PUT", f"/{BUCKET}/empty.bin", b"").status_code == 200
    empty_object = signed(service, "GET", f"/{BUCKET}/empty.bin?partNumber=1")
    assert empty_object.status_code == 200
    assert empty_object.content == b""
    assert "content-range" not in empty_object.headers
    assert "x-amz-mp-parts-count" not in empty_object.headers


def test_part_number_single_part_mpu_reports_parts_count(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    only = os.urandom(5 * MIB)
    mpu(service, [only])
    response = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1")
    assert response.status_code == 206
    assert response.content == only
    assert response.headers["x-amz-mp-parts-count"] == "1"
    assert response.headers["content-range"] == (
        f"bytes 0-{len(only) - 1}/{len(only)}")


def test_part_number_corrupt_snapshot_fails_closed(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    last = b"guarded-tail" * 11
    version, _ = mpu(service, [first, last])
    db = service[3]()
    try:
        # Corrupt the immutable snapshot: one part row goes missing.
        db.connection.execute(text(
            "DELETE FROM storage_multipart_object_parts "
            "WHERE object_id = :id AND number = 2"), {"id": version})
        db.commit()
    finally:
        db.close()
    before = service[2].downloads
    response = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1")
    assert response.status_code == 409
    assert error_code(response) == "InvalidObjectState"
    # Fail closed: never synthesize logical parts, never read Telegram.
    assert service[2].downloads == before


def test_part_number_legacy_journal_snapshot_is_still_exact(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    last = b"legacy-tail" * 17
    version, _ = mpu(service, [first, last])
    db = service[3]()
    try:
        # Simulate a pre-snapshot-table completion: the additive layout
        # rows vanish and only the SQL completion journal remains.
        db.connection.execute(text(
            "DELETE FROM storage_multipart_object_parts "
            "WHERE object_id = :id"), {"id": version})
        db.commit()
    finally:
        db.close()
    one = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1")
    assert one.status_code == 206 and one.content == first
    two = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=2")
    assert two.status_code == 206 and two.content == last
    assert two.headers["x-amz-mp-parts-count"] == "2"


def test_part_number_requires_object_read_authorization(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/{KEY}", b"private").status_code == 200
    db = service[3]()
    try:
        denied_credential = S3CredentialStore(db, service[4]).create(
            "no-object-read", ["s3:ListBucket"])
    finally:
        db.close()
    before = service[2].downloads
    denied = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1",
                    access=denied_credential.access_key,
                    secret=denied_credential.secret_key)
    assert denied.status_code == 403
    assert error_code(denied) == "AccessDenied"
    assert service[2].downloads == before


def test_part_number_archived_object_is_gated_like_a_full_read(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    put = signed(service, "PUT", f"/{BUCKET}/{KEY}", b"cold-bytes")
    version = put.headers["x-amz-version-id"]
    catalog = BucketCatalog(ManifestStore(service[3]()))
    try:
        catalog.db.connection.execute(text(
            "UPDATE storage_objects SET storage_class = 'ARCHIVE_ACCESS' "
            "WHERE id = :id"), {"id": version})
        catalog.db.commit()
    finally:
        catalog.db.close()
    response = signed(service, "GET", f"/{BUCKET}/{KEY}?partNumber=1")
    assert response.status_code == 403
    assert error_code(response) == "InvalidObjectState"


def test_part_number_checksum_and_response_override_contract(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    last = b"checksummed" * 7
    mpu(service, [first, last])

    # A part read is a 206: AWS never advertises the whole-object
    # checksum beside a byte slice.
    partial = signed(
        service, "GET", f"/{BUCKET}/{KEY}?partNumber=2",
        extra_headers={"x-amz-checksum-mode": "ENABLED"})
    assert partial.status_code == 206
    assert "x-amz-checksum-sha256" not in partial.headers
    assert "x-amz-checksum-type" not in partial.headers

    # The signed response-* overrides work on part reads exactly as they
    # do on full reads (presigned part downloads rely on them). The value
    # is percent-encoded: a raw "/" in a query value changes botocore's
    # canonical request (a pre-existing quirk unrelated to partNumber).
    overridden = signed(
        service, "GET",
        f"/{BUCKET}/{KEY}?partNumber=2&response-content-type=text%2Fplain")
    assert overridden.status_code == 206
    assert overridden.headers["content-type"] == "text/plain"


def test_part_number_sse_c_single_put_and_mpu(service):
    raw = bytes(index % 256 for index in range(32))
    key_md5 = base64.b64encode(
        hashlib.md5(raw, usedforsecurity=False).digest()).decode("ascii")
    ssec = {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key":
            base64.b64encode(raw).decode("ascii"),
        "x-amz-server-side-encryption-customer-key-md5": key_md5,
    }
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200

    payload = os.urandom(6144)
    put = signed(service, "PUT", f"/{BUCKET}/secret.bin", payload,
                 extra_headers=ssec)
    assert put.status_code == 200, put.text
    part_one = signed(service, "GET", f"/{BUCKET}/secret.bin?partNumber=1",
                      extra_headers=ssec)
    assert part_one.status_code == 206
    assert part_one.content == payload
    assert part_one.headers["content-range"] == (
        f"bytes 0-{len(payload) - 1}/{len(payload)}")
    wrong = dict(ssec)
    wrong["x-amz-server-side-encryption-customer-key-md5"] = (
        base64.b64encode(hashlib.md5(b"other", usedforsecurity=False)
                         .digest()).decode("ascii"))
    rejected = signed(service, "GET", f"/{BUCKET}/secret.bin?partNumber=1",
                      extra_headers=wrong)
    assert rejected.status_code == 400

    # An SSE-C multipart object: the immutable layout snapshot cannot be
    # verified (the multipart ETag record for SSE-C uploads is the full
    # ciphertext SHA-256 without a part-count suffix, which
    # object_parts_for_version rejects). This is a PRE-EXISTING
    # limitation shared with GetObjectAttributes(ObjectParts) on the same
    # objects -- teledrive/s3/multipart.py is outside this task's file
    # ownership -- and the honest answer is to fail closed (409) rather
    # than serve parts from an unverifiable layout. The full-body read
    # keeps working.
    upload_id = begin(service, "mpu-secret.bin", headers=ssec)
    first = os.urandom(5 * MIB)
    last = b"secret-tail" * 31
    etags = {
        number: part(service, upload_id, number, body,
                     key="mpu-secret.bin", headers=ssec)
        for number, body in ((1, first), (2, last))
    }
    finished = complete(service, upload_id, sorted(etags.items()),
                        key="mpu-secret.bin", headers=ssec)
    assert finished.status_code == 200, finished.text
    before = service[2].downloads
    denied = signed(service, "GET", f"/{BUCKET}/mpu-secret.bin?partNumber=1",
                    extra_headers=ssec)
    assert denied.status_code == 409
    assert error_code(denied) == "InvalidObjectState"
    full = signed(service, "GET", f"/{BUCKET}/mpu-secret.bin",
                  extra_headers=ssec)
    assert full.status_code == 200 and full.content == first + last
    assert service[2].downloads > before


def test_part_number_envelope_object_part_one(service, monkeypatch):
    monkeypatch.setattr(gateway, "ENVELOPE_ENABLED", True)
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    payload = b"envelope-part-bytes" * 64
    put = signed(service, "PUT", f"/{BUCKET}/wrapped.bin", payload,
                 extra_headers={"x-amz-server-side-encryption": "AES256"})
    assert put.status_code == 200, put.text
    response = signed(service, "GET", f"/{BUCKET}/wrapped.bin?partNumber=1")
    assert response.status_code == 206
    assert response.content == payload
    assert response.headers["x-amz-server-side-encryption"] == "AES256"
    assert response.headers["content-range"] == (
        f"bytes 0-{len(payload) - 1}/{len(payload)}")
    assert "x-amz-mp-parts-count" not in response.headers


def test_part_number_reads_never_mutate_the_catalog(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    first = os.urandom(5 * MIB)
    last = b"stable-tail" * 19
    mpu(service, [first, last])
    assert signed(service, "PUT", f"/{BUCKET}/single.bin", b"single").status_code == 200

    # Access accounting (objects.access_count) is expected to advance on
    # SUCCESSFUL reads; the structural catalog must not change at all.
    catalog_before = table_counts(service)
    heads_before = service[3]().connection.execute(text(
        "SELECT bucket, key_hash, object_id, generation "
        "FROM storage_object_heads ORDER BY bucket, key_hash")).all()
    uploads_before = service[2].uploads

    for query in ("partNumber=1", "partNumber=2", "partNumber=9",
                  "partNumber=abc", "partNumber=0"):
        assert signed(service, "GET", f"/{BUCKET}/{KEY}?{query}") is not None
    assert signed(service, "GET", f"/{BUCKET}/single.bin?partNumber=1")

    assert table_counts(service) == catalog_before
    db = service[3]()
    try:
        heads_after = db.connection.execute(text(
            "SELECT bucket, key_hash, object_id, generation "
            "FROM storage_object_heads ORDER BY bucket, key_hash")).all()
    finally:
        db.close()
    assert heads_after == heads_before
    assert service[2].uploads == uploads_before
