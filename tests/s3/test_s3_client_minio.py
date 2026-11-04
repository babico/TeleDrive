"""Real MinIO Python SDK (minio-py) compatibility over HTTP with Telegram-backed bytes.

Pinned SDK: ``minio==7.2.20``. The same pin is installed by CI in
``.github/workflows/quality-security.yml`` and listed in
``requirements-dev.txt`` for local runs. minio-py is deliberately NOT
botocore-based: it ships its own SigV4 signer (``minio.signer``), its own
urllib3 transport, and speaks path-style by default — a genuinely
independent wire implementation from boto3, the AWS CLI (botocore) and
rclone (Go), which is the gap in the client matrix this module closes.

Runs the SDK against Uvicorn in a background thread over the same service
fixture as the raw-HTTP and boto3 suites: real SQLite manifests, a fake
USER MTProto transport holding real bytes, every downloaded byte compared.

Local runs skip when the SDK is absent unless
TELEDRIVE_REQUIRE_CLI_CLIENTS=1 is set (the same fail-closed switch the
real AWS CLI / rclone tests use).
"""
from __future__ import annotations

import hashlib
import io
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import timedelta

import pytest
import uvicorn

import web.s3 as gateway
from tests.s3.test_s3_gateway import service

try:
    import minio
    from minio import Minio
    from minio.error import S3Error
except ImportError:  # pragma: no cover - only hit without the pinned SDK
    if os.getenv("TELEDRIVE_REQUIRE_CLI_CLIENTS") == "1":
        pytest.fail("Required real S3 client SDK is absent: minio",
                    allow_module_level=True)
    pytest.skip("Install minio==7.2.20 to run the real MinIO SDK tests",
                allow_module_level=True)

# The compatibility contract below is only proven for this exact pin;
# drift is a test failure, never a silent "probably still works".
PINNED_MINIO_VERSION = "7.2.20"


@pytest.fixture
def live_s3(service):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port, lifespan="off", log_level="error",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "S3 ASGI server did not start"
        yield f"http://127.0.0.1:{port}", service[1], service[2]
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "S3 ASGI server failed to stop"


def _sdk(live_s3, *, secret=None):
    endpoint, issued, _ = live_s3
    netloc = endpoint.rsplit("//", 1)[-1]
    return Minio(netloc,
                 access_key=issued.access_key,
                 secret_key=secret or issued.secret_key,
                 secure=False,
                 region="us-east-1")


def test_minio_sdk_bucket_object_multipart_round_trip(live_s3):
    """minio-py live flow: bucket create/exists/list, plain PUT, stat,
    full and ranged GET, ListObjectsV2, multipart PUT past the SDK's 5 MiB
    part cutoff, byte-identical readback, DELETE and NoSuchKey."""
    assert minio.__version__ == PINNED_MINIO_VERSION, (
        f"minio-py pin drifted: installed {minio.__version__}, "
        f"contract pinned to {PINNED_MINIO_VERSION}"
    )
    _, _, transport = live_s3
    client = _sdk(live_s3)

    # Bucket create, exists (HEAD), list.
    client.make_bucket("minio-py-flow")
    assert client.bucket_exists("minio-py-flow")
    assert not client.bucket_exists("minio-py-nope")
    assert "minio-py-flow" in [b.name for b in client.list_buckets()]

    # Plain PUT below the SDK's multipart threshold, with SDK metadata.
    small = os.urandom(257 * 1024 + 37)
    client.put_object("minio-py-flow", "small/object.bin",
                      io.BytesIO(small), len(small),
                      content_type="application/x-teledrive-test",
                      metadata={"X-Amz-Meta-Origin": "minio-py"})
    stat = client.stat_object("minio-py-flow", "small/object.bin")
    assert stat.size == len(small)
    assert stat.etag
    assert stat.content_type == "application/x-teledrive-test"
    assert stat.metadata.get("X-Amz-Meta-Origin") == "minio-py"

    # Full GET through the SDK transport, bytes compared.
    with client.get_object("minio-py-flow", "small/object.bin") as response:
        assert response.status == 200
        assert response.read() == small

    # Ranged GET via the SDK's offset/length API.
    with client.get_object("minio-py-flow", "small/object.bin",
                           offset=len(small) - 1024, length=512) as response:
        assert response.status == 206
        assert response.read() == small[-1024:-512]

    # ListObjectsV2 (encoding-type=url, empty delimiter/prefix, max-keys).
    listed = [obj.object_name
              for obj in client.list_objects("minio-py-flow", recursive=True)]
    assert "small/object.bin" in listed

    # Multipart: 12 MiB + 1234 bytes > the SDK's 5 MiB part cutoff, so
    # minio-py issues CreateMultipartUpload + 3 UploadPart + Complete.
    large = os.urandom(12 * 1024 * 1024 + 1234)
    uploads_before = transport.uploads
    result = client.put_object("minio-py-flow", "large/object.bin",
                               io.BytesIO(large), len(large))
    assert result.object_name == "large/object.bin"
    assert transport.uploads - uploads_before >= 3, (
        "SDK multipart path did not engage: every part must reach Telegram"
    )
    assert client.stat_object("minio-py-flow", "large/object.bin").size == len(large)
    with client.get_object("minio-py-flow", "large/object.bin") as response:
        body = response.read()
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(large).hexdigest()
    assert transport.downloads >= 2, "reads must come back through Telegram"

    # DELETE, then the modeled 404 surface the SDK raises.
    # Deleting the objects cannot make the bucket deletable: the gateway
    # deliberately retains buckets with object or multipart history until
    # a verified lifecycle GC pass (teledrive/storage/catalog_buckets.py
    # delete_bucket). The SDK surfaces that policy as BucketNotEmpty —
    # modeled here so the refusal is a documented, expected behavior
    # rather than an implied silent success.
    client.remove_object("minio-py-flow", "small/object.bin")
    client.remove_object("minio-py-flow", "large/object.bin")
    with pytest.raises(S3Error) as missing:
        client.stat_object("minio-py-flow", "small/object.bin")
    assert missing.value.code == "NoSuchKey"
    with pytest.raises(S3Error) as retained:
        client.remove_bucket("minio-py-flow")
    assert retained.value.code == "BucketNotEmpty"
    assert "safe GC required" in (retained.value.message or "")
    assert client.bucket_exists("minio-py-flow")


def test_minio_sdk_presigned_get_url(live_s3):
    """minio-py's own SigV4 presigned GET (query auth, no Authorization
    header) works against the gateway, including response-header overrides;
    a tampered signature is rejected with 403."""
    client = _sdk(live_s3)
    client.make_bucket("minio-py-presign")
    payload = os.urandom(4096 + 17)
    client.put_object("minio-py-presign", "share/payload.bin",
                      io.BytesIO(payload), len(payload))

    url = client.presigned_get_object("minio-py-presign", "share/payload.bin",
                                      expires=timedelta(minutes=10))
    assert url.startswith("http://")
    with urllib.request.urlopen(url, timeout=30) as response:  # anonymous
        assert response.status == 200
        assert response.read() == payload

    # Response-header overrides are signed query parameters.
    override = client.presigned_get_object(
        "minio-py-presign", "share/payload.bin",
        expires=timedelta(minutes=10),
        response_headers={"response-content-type": "text/x-custom"},
    )
    with urllib.request.urlopen(override, timeout=30) as response:
        assert response.status == 200
        assert response.headers.get_content_type() == "text/x-custom"
        assert response.read() == payload

    # Signature tampering must fail closed with the gateway's 403.
    marker = "X-Amz-Signature="
    head, _, signature = url.partition(marker)
    tampered = head + marker + ("0" * len(signature))
    assert tampered != url
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(tampered, timeout=30)
    assert refused.value.code == 403


def test_minio_sdk_wrong_credentials_surface_gateway_403(live_s3):
    """The SDK surfaces the gateway's real 403 SignatureDoesNotMatch, not a
    client-side invention: the negative path is modeled by the live flow."""
    client = _sdk(live_s3, secret="definitely-not-the-secret")
    with pytest.raises(S3Error) as denied:
        client.list_buckets()
    assert denied.value.code == "SignatureDoesNotMatch"
    assert denied.value.response.status == 403
