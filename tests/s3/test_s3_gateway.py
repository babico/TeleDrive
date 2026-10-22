"""S3 SigV4 and Telegram-backed HTTP behavior tests.

Botocore signs real HTTP wire requests; a deterministic fake USER MTProto
transport holds real bytes while SQLite stores only metadata and encrypted keys.
"""
from __future__ import annotations

import hashlib
import os
import time
from urllib.parse import quote

import pytest
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import web.app as admin
import web.s3 as gateway
from teledrive.db import connect_database
from teledrive.s3.credentials import S3CredentialStore, DEFAULT_PERMISSIONS


class FakeTelegram:
    """Disk-backed USER MTProto stand-in with the engine transport contract."""

    def __init__(self):
        self.parts = {}
        self.uploads = 0
        self.downloads = 0

    async def upload(self, path, *, object_id, ordinal, checksum):
        self.uploads += 1
        fid = f"file-{self.uploads}"
        self.parts[fid] = path.read_bytes()
        return "mtproto-user", -1001234567890, self.uploads

    async def verify_target(self):
        pass

    async def download(self, reference, destination):
        self.downloads += 1
        destination.write_bytes(self.parts[f"file-{reference.message_id}"])


@pytest.fixture
def service(monkeypatch, tmp_path):
    key = Fernet.generate_key()
    database_path = tmp_path / "state.db"
    db = connect_database(str(database_path))
    cred_store = S3CredentialStore(db, key)
    issued = cred_store.create("S3 integration", list(DEFAULT_PERMISSIONS))
    db.close()
    telegram = FakeTelegram()
    connection = lambda: connect_database(str(database_path))
    factory = lambda db: telegram
    monkeypatch.setattr(gateway, "db_connect", connection)
    monkeypatch.setattr(gateway, "storage_transport", factory)
    monkeypatch.setattr(gateway, "load_master_key", lambda: key)
    monkeypatch.setattr(admin, "STORAGE_SCRATCH_DIR", str(tmp_path / "staging"))
    monkeypatch.setattr(admin, "REST_MAX_UPLOAD_BYTES", 8 * 1024 * 1024)
    client = TestClient(gateway.app, base_url="http://localhost:9000")
    try:
        yield client, issued, telegram, connection, key
    finally:
        client.close()


def signed(service, method, path, body=b"", *, extra_headers=None, access=None, secret=None, date=None):
    client, issued, _, _, _ = service
    headers = {"x-amz-content-sha256": hashlib.sha256(body).hexdigest()}
    headers.update(extra_headers or {})
    url = "http://localhost:9000" + path
    request = AWSRequest(method=method, url=url, data=body, headers=headers)
    request.context["payload_signing_enabled"] = headers["x-amz-content-sha256"] != "UNSIGNED-PAYLOAD"
    S3SigV4Auth(Credentials(access or issued.access_key,
                            secret or issued.secret_key), "s3", "us-east-1").add_auth(request)
    if date:
        request.headers["X-Amz-Date"] = date
    return client.request(method, path, content=body, headers=dict(request.headers))


def test_s3_basic_bucket_object_crud_and_range(service):
    client, creds, telegram, _, _ = service
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    buckets = signed(service, "GET", "/")
    assert buckets.status_code == 200 and b"backup-bucket" in buckets.content
    payload = os.urandom(8193)
    uploaded = signed(service, "PUT", "/backup-bucket/file.bin", payload)
    assert uploaded.status_code == 200, uploaded.text
    assert telegram.uploads == 1
    meta = signed(service, "HEAD", "/backup-bucket/file.bin")
    assert meta.status_code == 200
    assert meta.headers["content-length"] == str(len(payload))
    assert telegram.downloads == 0
    response = signed(service, "GET", "/backup-bucket/file.bin")
    assert response.status_code == 200
    assert response.content == payload
    rng = signed(service, "GET", "/backup-bucket/file.bin",
                 extra_headers={"Range": "bytes=8190-8192"})
    assert rng.status_code == 206 and rng.content == payload[-3:]
    listed = signed(service, "GET", "/backup-bucket?list-type=2&prefix=file")
    assert listed.status_code == 200 and b"file.bin" in listed.content
    assert signed(service, "DELETE", "/backup-bucket/file.bin").status_code == 204
    missing = signed(service, "GET", "/backup-bucket/file.bin")
    assert missing.status_code == 404 and b"NoSuchKey" in missing.content
    # Physical Telegram parts are deliberately retained for future GC.
    assert telegram.uploads == 1


def test_signature_required_tampering_rejected_before_upload(service):
    client, issued, bot, _, _ = service
    assert client.get("/").status_code == 403
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    wrong_key = signed(service, "GET", "/", secret="incorrect")
    assert wrong_key.status_code == 403
    assert b"SignatureDoesNotMatch" in wrong_key.content
    good = AWSRequest(method="PUT", url="http://localhost:9000/backup-bucket/tamper",
                      data=b"original",
                      headers={"x-amz-content-sha256": hashlib.sha256(b"original").hexdigest()})
    good.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(issued.access_key, issued.secret_key),
                "s3", "us-east-1").add_auth(good)
    before = bot.uploads
    modified = client.put("/backup-bucket/tamper", content=b"changed",
                          headers=dict(good.headers))
    assert modified.status_code == 400
    assert bot.uploads == before
    assert b"XAmzContentSHA256Mismatch" in modified.content


def test_revoke_and_scope_are_enforced_independently(service):
    _, issued, _, connection, key = service
    assert signed(service, "GET", "/").status_code == 200
    db = connection()
    try:
        restricted = S3CredentialStore(db, key).create("reader", ["s3:GetObject"])
        assert S3CredentialStore(db, key).revoke(issued.id)
    finally:
        db.close()
    assert signed(service, "GET", "/").status_code == 403
    assert signed(service, "PUT", "/new-bucket", access=restricted.access_key,
                  secret=restricted.secret_key).status_code == 403


def test_unsigned_payload_and_unsupported_operations_fail_closed(service):
    client, _, bot, _, _ = service
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    # Botocore's S3SigV4Auth always replaces UNSIGNED-PAYLOAD with a
    # SHA-256 for PUT. Mutate the actual signed wire request to verify the
    # gateway rejects the unsigned upload before touching Telegram.
    req = AWSRequest(method="PUT", url="http://localhost:9000/backup-bucket/unsafe",
                     data=b"stuff", headers={
                         "x-amz-content-sha256": hashlib.sha256(b"stuff").hexdigest(),
                     })
    req.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(service[1].access_key, service[1].secret_key),
                "s3", "us-east-1").add_auth(req)
    bad_headers = dict(req.headers)
    bad_headers["X-Amz-Content-SHA256"] = "UNSIGNED-PAYLOAD"
    response = client.put("/backup-bucket/unsafe", content=b"stuff", headers=bad_headers)
    assert response.status_code == 400
    assert bot.uploads == 0
    initiated = signed(service, "POST", "/backup-bucket/object?uploads")
    assert initiated.status_code == 200
    assert b"UploadId" in initiated.content
    listed = signed(service, "GET", "/backup-bucket?uploads")
    assert listed.status_code == 200
    assert b"ListMultipartUploadsResult" in listed.content
    # GetBucketPolicy is a read-only compatibility probe: an AWS-shaped
    # 404 (no policy exists), never bucket data.
    unsupported = signed(service, "GET", "/backup-bucket?policy")
    assert unsupported.status_code == 404
    assert b"NoSuchBucketPolicy" in unsupported.content
    # Configuration attempts on optional features still fail closed.
    blocked = signed(service, "PUT", "/backup-bucket?policy")
    assert blocked.status_code == 501
    assert b"NotImplemented" in blocked.content


def test_catalog_pagination_with_signed_s3_queries(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    for name in ("a.txt", "b.txt", "c.txt"):
        assert signed(service, "PUT", f"/backup-bucket/{name}", name.encode()).status_code == 200
    first = signed(service, "GET", "/backup-bucket?list-type=2&max-keys=2")
    assert first.status_code == 200
    import xml.etree.ElementTree as ET
    root = ET.fromstring(first.content)
    tag = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    assert root.findtext(tag+"IsTruncated") == "true"
    token = root.findtext(tag+"NextContinuationToken")
    second = signed(service, "GET",
                    "/backup-bucket?list-type=2&max-keys=2&continuation-token="+quote(token))
    assert second.status_code == 200
    keys = [item.findtext(tag+"Key") for item in ET.fromstring(second.content).findall(tag+"Contents")]
    assert keys == ["c.txt"]


def test_real_boto3_sdk_over_http_loopback(service):
    """Exercise an actual boto3 S3 client rather than only hand-built requests."""
    import socket
    import threading
    import time
    import boto3
    import uvicorn
    from botocore.config import Config

    _, issued, bot, _, _ = service
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    settings = uvicorn.Config(gateway.app, host="127.0.0.1", port=port,
                              log_level="error", lifespan="off")
    server = uvicorn.Server(settings)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "ASGI S3 server did not start"
        sdk = boto3.client(
            "s3", endpoint_url=f"http://127.0.0.1:{port}",
            aws_access_key_id=issued.access_key, aws_secret_access_key=issued.secret_key,
            region_name="us-east-1",
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path", "payload_signing_enabled": True},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                retries={"max_attempts": 0},
            ),
        )
        assert sdk.create_bucket(Bucket="sdk-bucket")["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert any(b["Name"] == "sdk-bucket" for b in sdk.list_buckets()["Buckets"])
        body = os.urandom(6003)
        put_result = sdk.put_object(Bucket="sdk-bucket", Key="nested/data.bin", Body=body)
        assert put_result["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert sdk.head_object(Bucket="sdk-bucket", Key="nested/data.bin")["ContentLength"] == len(body)
        read = sdk.get_object(Bucket="sdk-bucket", Key="nested/data.bin")["Body"].read()
        assert read == body
        keys = [item["Key"] for item in sdk.list_objects_v2(
            Bucket="sdk-bucket", Prefix="nested/"
        )["Contents"]]
        assert keys == ["nested/data.bin"]
        sdk.delete_object(Bucket="sdk-bucket", Key="nested/data.bin")
        assert bot.uploads >= 1 and bot.downloads >= 1
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "ASGI S3 server did not stop"


@pytest.mark.parametrize("raw_key", [
    "a%20file.txt", "caf%C3%A9.txt", "folder%2Fencoded-slash.bin",
    "x%2525literal-percent.txt",
])
def test_url_encoded_keys_preserve_s3_sigv4_semantics(service, raw_key):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    content = b"encoded-key-content:" + raw_key.encode("ascii")
    uri = "/backup-bucket/" + raw_key
    uploaded = signed(service, "PUT", uri, content)
    assert uploaded.status_code == 200, uploaded.text
    retrieved = signed(service, "GET", uri)
    assert retrieved.status_code == 200, retrieved.text
    assert retrieved.content == content


def test_encoded_path_tampering_invalidates_signature(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    payload = b"same-body"
    req = AWSRequest(method="PUT", url="http://localhost:9000/backup-bucket/a%20b.txt",
                     data=payload, headers={
                         "x-amz-content-sha256": hashlib.sha256(payload).hexdigest(),
                     })
    req.context["payload_signing_enabled"] = True
    S3SigV4Auth(Credentials(service[1].access_key, service[1].secret_key),
                "s3", "us-east-1").add_auth(req)
    tampered = service[0].put("/backup-bucket/a%20c.txt", headers=dict(req.headers),
                              content=payload)
    assert tampered.status_code == 403
    assert b"SignatureDoesNotMatch" in tampered.content


def test_s3_delimiter_common_prefixes_and_safe_pagination(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    for key in ("dir-a/1", "dir-a/2", "dir-a/3", "dir-b/one", "root.txt"):
        result = signed(service, "PUT", "/backup-bucket/" + key, key.encode())
        assert result.status_code == 200, result.text
    import xml.etree.ElementTree as ET
    ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    token = None
    all_objects = []
    all_prefixes = []
    for _ in range(5):
        query = "/backup-bucket?list-type=2&delimiter=%2F&max-keys=1"
        if token:
            query += "&continuation-token=" + quote(token)
        response = signed(service, "GET", query)
        assert response.status_code == 200, response.text
        root = ET.fromstring(response.content)
        all_objects.extend(c.findtext(ns+"Key") for c in root.findall(ns+"Contents"))
        all_prefixes.extend(c.findtext(ns+"Prefix") for c in root.findall(ns+"CommonPrefixes"))
        token = root.findtext(ns+"NextContinuationToken")
        if root.findtext(ns+"IsTruncated") == "false":
            break
    else:
        pytest.fail("S3 continuation token did not terminate")
    assert all_prefixes == ["dir-a/", "dir-b/"]
    assert all_objects == ["root.txt"]
    assert token is None


def test_s3_cursor_cannot_be_modified_or_reused_with_a_different_prefix(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    for key in ("a/one", "b/two", "c/three"):
        assert signed(service, "PUT", "/backup-bucket/" + key, b"data").status_code == 200
    import xml.etree.ElementTree as ET
    ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    first = signed(service, "GET", "/backup-bucket?list-type=2&max-keys=1")
    token = ET.fromstring(first.content).findtext(ns+"NextContinuationToken")
    assert token
    corrupted = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
    result = signed(service, "GET",
                    "/backup-bucket?list-type=2&max-keys=1&continuation-token="+quote(corrupted))
    assert result.status_code == 400
    assert b"InvalidArgument" in result.content
    second = signed(service, "GET",
                    "/backup-bucket?list-type=2&prefix=a%2F&max-keys=1&continuation-token="+quote(token))
    assert second.status_code == 400


def test_s3_folder_larger_than_backend_page_is_not_repeated():
    """A single CommonPrefixes entry spanning >1000 raw keys still counts once."""
    from types import SimpleNamespace
    from web.s3 import _page
    names = [f"huge/{n:04d}" for n in range(1201)] + ["next/item", "root"]
    class FakeCatalog:
        def list_objects(self, bucket, *, prefix, after, limit):
            selected = [name for name in names if name.startswith(prefix) and name > after][:limit]
            return [SimpleNamespace(item=SimpleNamespace(key=key)) for key in selected]
    catalog = FakeCatalog()
    keys, common, after, skip, more = _page(catalog, "bucket", "", "/", "", 1, "")
    assert keys == [] and common == ["huge/"] and more
    keys2, common2, after2, skip2, more2 = _page(catalog, "bucket", "", "/", after, 1, skip)
    assert common2 == ["next/"] and keys2 == []
    keys3, common3, _, _, more3 = _page(catalog, "bucket", "", "/", after2, 1, skip2)
    assert [x.item.key for x in keys3] == ["root"]
    assert common3 == [] and not more3


def test_signed_md5_allows_standard_unsigned_payload_without_sacrificing_integrity(service):
    """The rclone/aws-sdk variant must sign Content-MD5 and verify actual bytes.

    A mutated body or an omitted signed checksum is rejected *before* upload.
    Presigned PUT still requires its SHA-256 checksum-binding policy.
    """
    import base64
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    body = b"standard-unsigned-payload-with-content-md5" * 37
    digest = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()
    url = "http://localhost:9000/backup-bucket/rclone-compatible.bin"
    request = AWSRequest(
        method="PUT", url=url, data=body, headers={"Content-MD5": digest},
    )
    class RcloneStyleUnsignedSigner(S3SigV4Auth):
        # S3SigV4Auth calculates SHA-256 even if payload_signing_enabled=False;
        # override the body canonicalization for rclone's actual wire shape.
        def payload(self, request):
            return "UNSIGNED-PAYLOAD"

    RcloneStyleUnsignedSigner(
        Credentials(service[1].access_key, service[1].secret_key),
        "s3", "us-east-1",
    ).add_auth(request)
    headers = dict(request.headers)
    assert headers.get("X-Amz-Content-SHA256") == "UNSIGNED-PAYLOAD"
    assert "content-md5" in headers["Authorization"].lower()
    before = service[2].uploads
    denied = service[0].put("/backup-bucket/rclone-compatible.bin",
                            content=b"replaced-body", headers=headers)
    assert denied.status_code == 400
    assert service[2].uploads == before
    allowed = service[0].put("/backup-bucket/rclone-compatible.bin",
                             content=body, headers=headers)
    assert allowed.status_code == 200, allowed.text
    assert service[2].uploads == before + 1
    assert signed(service, "GET", "/backup-bucket/rclone-compatible.bin").content == body

    unsigned = AWSRequest(method="PUT", url="http://localhost:9000/backup-bucket/no-checksum",
                          data=body)
    RcloneStyleUnsignedSigner(
        Credentials(service[1].access_key, service[1].secret_key),
        "s3", "us-east-1",
    ).add_auth(unsigned)
    assert dict(unsigned.headers)["X-Amz-Content-SHA256"] == "UNSIGNED-PAYLOAD"
    denied = service[0].put("/backup-bucket/no-checksum",
                            content=body, headers=dict(unsigned.headers))
    assert denied.status_code == 400
    assert service[2].uploads == before + 1


def test_private_acl_and_standard_class_hints_do_not_weaken_private_storage(service):
    """Only the default private/standard hints map to actual gateway behavior."""
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    value = b"retained-in-telegram"
    before = service[2].uploads
    ok = signed(service, "PUT", "/backup-bucket/default-hints.txt", value,
                extra_headers={"x-amz-acl": "private",
                               "x-amz-storage-class": "STANDARD"})
    assert ok.status_code == 200, ok.text
    assert signed(service, "GET", "/backup-bucket/default-hints.txt").content == value
    assert service[2].uploads == before + 1

    for name, bad in [
        ("x-amz-acl", "public-read"),
        ("x-amz-acl", "authenticated-read"),
        ("x-amz-storage-class", "GLACIER"),
        ("x-amz-storage-class", "STANDARD_IA"),
    ]:
        refused = signed(service, "PUT", "/backup-bucket/refused",
                         value, extra_headers={name: bad})
        assert refused.status_code == 501
        assert b"NotImplemented" in refused.content
    assert service[2].uploads == before + 1
    assert signed(service, "GET", "/backup-bucket/refused").status_code == 404


def test_s3_port_traffic_is_logged(service, monkeypatch):
    """S3 requests must reach the audit log — even unsigned probes.

    The S3 ASGI app had no logging middleware, so S3 client connection
    attempts were invisible on the logs page.
    """
    client, issued, telegram, connection, key = service
    captured = []
    monkeypatch.setattr(
        gateway, "_log",
        lambda msg, source, user=None: captured.append((source, msg, user)))

    # Unsigned probe (403) — still logged with method, path and client.
    r = client.get("/some-bucket/some-key")
    assert r.status_code in (400, 401, 403)
    assert any(source == "http" and "GET /some-bucket/some-key from" in msg
               for source, msg, _ in captured)
    assert any("-> 40" in msg for _, msg, _ in captured)

    # Signed request logs the access key id as the user.
    captured.clear()
    signed(service, "GET", "/")
    assert any(source == "http" and user not in (None, "-", "")
               for source, msg, user in captured)

    # Health checks stay quiet.
    captured.clear()
    client.get("/__health")
    assert not captured


def test_presigned_url_round_trip(service):
    """The generator's URLs must verify against the live gateway."""
    client, issued, telegram, connection, key = service
    # Create the bucket, then seed one object through the signed PUT path.
    r = signed(service, "PUT", "/roundtrip-bucket")
    assert r.status_code == 200, r.text
    body = b"presign-me-payload"
    r = signed(service, "PUT", "/roundtrip-bucket/presign/key.txt", body)
    assert r.status_code == 200, r.text

    from teledrive.s3.sigv4 import presign_get_url
    secret = client.app  # not needed; use the issued secret directly
    url = presign_get_url("http://localhost:9000", "roundtrip-bucket",
                          "presign/key.txt", issued.access_key,
                          issued.secret_key, expires=300)
    assert "X-Amz-Signature" in url and "X-Amz-Expires=300" in url

    # GET via the presigned URL: no Authorization header at all.
    from urllib.parse import urlparse
    parsed = urlparse(url)
    r = client.get(parsed.path + "?" + parsed.query,
                   headers={"host": "localhost:9000"})
    assert r.status_code == 200, r.text
    assert r.content == body

    # Tampering with the expiry invalidates the signature.
    r = client.get(parsed.path + "?" + parsed.query.replace("300", "9999"),
                   headers={"host": "localhost:9000"})
    assert r.status_code in (400, 401, 403)


def test_upload_part_copy(service):
    """UploadPartCopy: a part sourced from another object, no re-upload."""
    client, issued, telegram, connection, key = service
    # Source object with a distinctive payload.
    source_body = b"upload-part-copy-source-payload" * 200_000  # ~6.6 MB
    r = signed(service, "PUT", "/copy-src-bucket")
    assert r.status_code == 200, r.text
    r = signed(service, "PUT", "/copy-src-bucket/original.bin", source_body)
    assert r.status_code == 200, r.text

    # boto3 drives the full MPU flow with UploadPartCopy for part 1 and
    # a real uploaded part for part 2.
    # boto3 needs a real TCP endpoint: boot the (fixture-patched) gateway
    # app on an ephemeral port.
    import socket
    import threading

    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(64)
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port,
        lifespan="off", log_level="error"))
    thread = threading.Thread(target=server.run, args=([sock],), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started

    import boto3
    from botocore.client import Config as BotoConfig
    s3 = boto3.client(
        "s3", endpoint_url=f"http://127.0.0.1:{port}",
        aws_access_key_id=issued.access_key,
        aws_secret_access_key=issued.secret_key,
        region_name="us-east-1",
        config=BotoConfig(s3={"addressing_style": "path"},
                          retries={"max_attempts": 1}),
    )
    try:
        # Both buckets must exist before the MPU flow starts.
        r = signed(service, "PUT", "/copy-dst-bucket")
        assert r.status_code == 200
        mpu = s3.create_multipart_upload(Bucket="copy-dst-bucket",
                                         Key="assembled.bin")
        upload_id = mpu["UploadId"]
        part1 = s3.upload_part_copy(
            Bucket="copy-dst-bucket", Key="assembled.bin",
            UploadId=upload_id, PartNumber=1,
            CopySource={"Bucket": "copy-src-bucket", "Key": "original.bin"},
        )
        assert "CopyPartResult" in part1 and "ETag" in part1["CopyPartResult"]
        part2 = s3.upload_part(Bucket="copy-dst-bucket", Key="assembled.bin",
                               UploadId=upload_id, PartNumber=2,
                               Body=b"tail-part-payload")
        completed = s3.complete_multipart_upload(
            Bucket="copy-dst-bucket", Key="assembled.bin", UploadId=upload_id,
            MultipartUpload={"Parts": [
                {"PartNumber": 1, "ETag": part1["CopyPartResult"]["ETag"]},
                {"PartNumber": 2, "ETag": part2["ETag"]},
            ]},
        )
        assert "ETag" in completed

        # The assembled object is byte-identical to source + tail.
        got = s3.get_object(Bucket="copy-dst-bucket", Key="assembled.bin")
        assert got["Body"].read() == source_body + b"tail-part-payload"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_upload_part_copy_ranges(service):
    """Ranged UploadPartCopy: an inclusive byte slice becomes the part."""
    client, issued, telegram, connection, key = service
    source_body = bytes(range(256)) * 24 * 1024  # 6 MiB
    r = signed(service, "PUT", "/range-src-bucket")
    assert r.status_code == 200, r.text
    r = signed(service, "PUT", "/range-src-bucket/original.bin", source_body)
    assert r.status_code == 200, r.text

    import socket
    import threading

    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(64)
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port,
        lifespan="off", log_level="error"))
    thread = threading.Thread(target=server.run, args=([sock],), daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started

    import boto3
    from botocore.client import Config as BotoConfig
    s3 = boto3.client(
        "s3", endpoint_url=f"http://127.0.0.1:{port}",
        aws_access_key_id=issued.access_key,
        aws_secret_access_key=issued.secret_key,
        region_name="us-east-1",
        config=BotoConfig(s3={"addressing_style": "path"},
                          retries={"max_attempts": 1}),
    )
    try:
        r = signed(service, "PUT", "/range-dst-bucket")
        assert r.status_code == 200
        mpu = s3.create_multipart_upload(Bucket="range-dst-bucket",
                                         Key="sliced.bin")
        upload_id = mpu["UploadId"]
        # AWS ranges are INCLUSIVE: bytes=16-(16+5MiB-1) is exactly 5 MiB
        # (the minimum for a non-final part).
        five_mib = 5 * 1024 * 1024
        part1 = s3.upload_part_copy(
            Bucket="range-dst-bucket", Key="sliced.bin",
            UploadId=upload_id, PartNumber=1,
            CopySource={"Bucket": "range-src-bucket", "Key": "original.bin"},
            CopySourceRange=f"bytes=16-{16 + five_mib - 1}",
        )
        assert "CopyPartResult" in part1
        part2 = s3.upload_part_copy(
            Bucket="range-dst-bucket", Key="sliced.bin",
            UploadId=upload_id, PartNumber=2,
            CopySource={"Bucket": "range-src-bucket", "Key": "original.bin"},
            CopySourceRange=f"bytes={len(source_body)-8}-{len(source_body)-1}",
        )
        completed = s3.complete_multipart_upload(
            Bucket="range-dst-bucket", Key="sliced.bin", UploadId=upload_id,
            MultipartUpload={"Parts": [
                {"PartNumber": 1, "ETag": part1["CopyPartResult"]["ETag"]},
                {"PartNumber": 2, "ETag": part2["CopyPartResult"]["ETag"]},
            ]},
        )
        assert "ETag" in completed
        got = s3.get_object(Bucket="range-dst-bucket", Key="sliced.bin")
        assert got["Body"].read() == (
            source_body[16:16 + five_mib] + source_body[-8:])

        # Out-of-range slices are rejected before any staging work.
        mpu2 = s3.create_multipart_upload(Bucket="range-dst-bucket",
                                          Key="bad.bin")
        try:
            s3.upload_part_copy(
                Bucket="range-dst-bucket", Key="bad.bin",
                UploadId=mpu2["UploadId"], PartNumber=1,
                CopySource={"Bucket": "range-src-bucket",
                            "Key": "original.bin"},
                CopySourceRange=f"bytes=0-{len(source_body)}",
            )
            raise AssertionError("out-of-range copy-source was accepted")
        except s3.exceptions.ClientError as exc:
            assert exc.response["Error"]["Code"] in ("InvalidRange",
                                                     "InvalidArgument")
        s3.abort_multipart_upload(Bucket="range-dst-bucket", Key="bad.bin",
                                  UploadId=mpu2["UploadId"])
    finally:
        server.should_exit = True
        thread.join(timeout=10)
