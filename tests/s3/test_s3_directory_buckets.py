"""S3 Express One Zone and Object Lambda: the honest closed-world answers.

TeleDrive implements neither directory buckets nor an Object Lambda runtime.
Those absences have different truthful wire answers:

* ``ListDirectoryBuckets`` is a real listing of the (empty) directory-bucket
  namespace: 200 with an empty ``ListDirectoryBucketsResult``. AWS's request
  URI is ``GET /`` with only ``continuation-token`` and
  ``max-directory-buckets`` (verified against the botocore model). Because a
  bare ``GET /`` is also ListBuckets, the directory listing is selected by
  the signed credential scope (``s3express``), ``max-directory-buckets`` or
  the SDK's ``x-id`` hint.
* ``CreateSession`` (``GET /{bucket}?session``) can only address a bucket
  that is not a directory bucket; the error distinguishes malformed names,
  existing general-purpose buckets and names that do not exist at all.
* ``WriteGetObjectResponse`` stays unsupported (501) but names the missing
  Object Lambda backing instead of returning a generic error.

All three are checked for side effects: no object, bucket or Telegram byte
changes.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def _empty_result(response) -> ET.Element:
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    assert root.tag == f"{NS}ListDirectoryBucketsResult"
    return root


@pytest.mark.parametrize("query", [
    "max-directory-buckets=1",
    "max-directory-buckets=1000",
    "max-directory-buckets=10&continuation-token=opaque",
    "x-id=ListDirectoryBuckets",
    "x-id=ListDirectoryBuckets&continuation-token=opaque",
])
def test_list_directory_buckets_is_a_real_always_empty_listing(service, query):
    assert signed(service, "PUT", "/some-bucket").status_code == 200
    root = _empty_result(signed(service, "GET", f"/?{query}"))
    # No directory bucket exists, so neither member is emitted.
    assert root.find(f"{NS}Buckets") is None
    assert root.find(f"{NS}ContinuationToken") is None
    assert list(root) == []


def test_bare_root_get_stays_list_buckets(service):
    # ListBuckets and ListDirectoryBuckets share GET /. Without the directory
    # selector the legacy operation must keep its meaning.
    assert signed(service, "PUT", "/general-purpose").status_code == 200
    response = signed(service, "GET", "/")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    assert root.tag == f"{NS}ListAllMyBucketsResult"
    assert b"general-purpose" in response.content


@pytest.mark.parametrize("query,fragment", [
    ("max-directory-buckets=0", b"max-directory-buckets"),
    ("max-directory-buckets=1001", b"max-directory-buckets"),
    ("max-directory-buckets=12345", b"max-directory-buckets"),
    ("max-directory-buckets=abc", b"max-directory-buckets"),
    ("max-directory-buckets=", b"max-directory-buckets"),
    ("max-directory-buckets=10&continuation-token=", b"continuation-token"),
    ("max-directory-buckets=10&continuation-token=" + "x" * 1025,
     b"continuation-token"),
    ("max-directory-buckets=10&unknown-parameter=1",
     b"Unknown ListDirectoryBuckets"),
    ("max-directory-buckets=10&prefix=x", b"Unknown ListDirectoryBuckets"),
])
def test_list_directory_buckets_rejects_malformed_input(service, query,
                                                         fragment):
    response = signed(service, "GET", f"/?{query}")
    assert response.status_code == 400, response.text
    assert fragment in response.content


def test_list_directory_buckets_has_its_own_permission(service):
    assert signed(service, "PUT", "/some-bucket").status_code == 200
    _, _, _, connect, master = service
    db = connect()
    try:
        store = S3CredentialStore(db, master)
        allowed = store.create("directory-reader", ["s3:ListDirectoryBuckets"])
        denied = store.create("bucket-list-only", ["s3:ListAllMyBuckets"])
    finally:
        db.close()
    ok = signed(service, "GET", "/?max-directory-buckets=1",
                access=allowed.access_key, secret=allowed.secret_key)
    assert ok.status_code == 200, ok.text
    refused = signed(service, "GET", "/?max-directory-buckets=1",
                     access=denied.access_key, secret=denied.secret_key)
    assert refused.status_code == 403, refused.text


def test_create_session_distinguishes_existing_general_purpose_bucket(service):
    assert signed(service, "PUT", "/session-bucket").status_code == 200
    assert signed(service, "PUT", "/session-bucket/asset.bin",
                  b"session-protected").status_code == 200
    telegram = service[2]
    before = telegram.uploads

    # An existing TeleDrive bucket is general-purpose: AWS Express sessions
    # cannot be created for it.
    present = signed(service, "GET", "/session-bucket?session")
    assert present.status_code == 400, present.text
    assert b"InvalidRequest" in present.content
    assert b"general-purpose bucket" in present.content

    # A well-formed name that is not a bucket here is NoSuchBucket, the only
    # error the botocore model declares for CreateSession.
    absent = signed(service, "GET", "/absent-bucket?session")
    assert absent.status_code == 404, absent.text
    assert b"NoSuchBucket" in absent.content
    assert b"directory bucket" in absent.content

    head = signed(service, "HEAD", "/session-bucket/asset.bin")
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"session-protected"))
    assert telegram.uploads == before
    assert telegram.downloads == 0


def test_create_session_rejects_malformed_bucket_name(service):
    response = signed(service, "GET", "/ab?session")
    assert response.status_code == 400, response.text
    assert b"InvalidBucketName" in response.content


@pytest.mark.parametrize("mode", ["Bogus", "", "readwrite"])
def test_create_session_rejects_malformed_session_mode(service, mode):
    assert signed(service, "PUT", "/session-bucket").status_code == 200
    response = signed(service, "GET", "/session-bucket?session",
                      extra_headers={"x-amz-create-session-mode": mode})
    assert response.status_code == 400, response.text
    assert b"InvalidArgument" in response.content


@pytest.mark.parametrize("mode", ["ReadWrite", "ReadOnly"])
def test_create_session_accepts_well_formed_session_modes(service, mode):
    assert signed(service, "PUT", "/session-bucket").status_code == 200
    response = signed(service, "GET", "/session-bucket?session",
                      extra_headers={"x-amz-create-session-mode": mode})
    # Still not a directory bucket, so no credentials can be issued.
    assert response.status_code == 400, response.text
    assert b"InvalidRequest" in response.content


def test_actual_boto3_directory_bucket_client(service):
    """A real SDK round-trip, including the ``s3express`` signing scope.

    botocore signs ListDirectoryBuckets and CreateSession with the
    ``s3express`` service and sends NO distinguishing query field for a
    default listing, so this test also proves the credential-scope
    discriminator works and that the XML parses into the SDK model.
    """
    import socket
    import threading
    import time
    import uvicorn
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    import web.s3 as gateway

    _, credential, _, _, _ = service
    assert signed(service, "PUT", "/general-purpose").status_code == 200
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port, log_level="error", lifespan="off",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        s3 = boto3.client("s3", endpoint_url=f"http://127.0.0.1:{port}",
                          region_name="us-east-1",
                          aws_access_key_id=credential.access_key,
                          aws_secret_access_key=credential.secret_key,
                          config=Config(signature_version="s3v4",
                                        s3={"addressing_style": "path"}))
        listing = s3.list_directory_buckets()
        assert listing["ResponseMetadata"]["HTTPStatusCode"] == 200
        # There is no directory bucket, so no bucket entry and no next page.
        assert listing.get("Buckets", []) == []
        assert "ContinuationToken" not in listing
        # The general-purpose list is untouched by the directory listing.
        assert [b["Name"] for b in s3.list_buckets()["Buckets"]] == [
            "general-purpose"]
        with pytest.raises(ClientError) as refused:
            s3.create_session(
                Bucket="demo-bucket--use1-az4--x-s3",
                SessionMode="ReadWrite",
            )
        assert refused.value.response["Error"]["Code"] == "NoSuchBucket"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_write_get_object_response_names_the_missing_runtime_and_mutates_nothing(
        service):
    assert signed(service, "PUT", "/lambda-bucket").status_code == 200
    assert signed(service, "PUT", "/lambda-bucket/asset.bin",
                  b"lambda-protected").status_code == 200
    telegram = service[2]
    before = telegram.uploads
    response = signed(
        service, "POST", "/WriteGetObjectResponse", b"",
        extra_headers={
            "x-amz-request-route": "route-token",
            "x-amz-request-token": "request-token",
        },
    )
    assert response.status_code == 501, response.text
    assert b"NotImplemented" in response.content
    assert b"Object Lambda" in response.content
    assert b"no backing here" in response.content
    head = signed(service, "HEAD", "/lambda-bucket/asset.bin")
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"lambda-protected"))
    assert telegram.uploads == before
    assert telegram.downloads == 0


def test_actual_boto3_directory_bucket_and_session_clients(service):
    """botocore's real wire shape: a bare GET / signed with s3express."""
    import socket
    import threading
    import time
    import uvicorn
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    import web.s3 as gateway

    _, credential, _, _, _ = service
    assert signed(service, "PUT", "/ordinary-bucket").status_code == 200
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port, log_level="error", lifespan="off",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        s3 = boto3.client("s3", endpoint_url=f"http://127.0.0.1:{port}",
                          region_name="us-east-1",
                          aws_access_key_id=credential.access_key,
                          aws_secret_access_key=credential.secret_key,
                          config=Config(signature_version="s3v4",
                                        s3={"addressing_style": "path"}))
        # list_directory_buckets() sends GET / with NO query field and an
        # s3express credential scope. The scope is what selects the empty
        # directory-bucket namespace instead of the real bucket list.
        result = s3.list_directory_buckets()
        assert result.get("Buckets", []) == []
        assert "ContinuationToken" not in result
        # The ordinary call keeps its meaning and sees the real bucket.
        assert {b["Name"] for b in s3.list_buckets()["Buckets"]} == {
            "ordinary-bucket"}
        # CreateSession is signed with the same s3express scope and is
        # answered with the truthful distinction between a general-purpose
        # bucket and a name that does not exist.
        try:
            s3.create_session(Bucket="ordinary-bucket")
            raise AssertionError("CreateSession must not succeed")
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "InvalidRequest"
            assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        try:
            s3.create_session(Bucket="absent--usw2-az1--x-s3")
            raise AssertionError("CreateSession must not succeed")
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "NoSuchBucket"
            assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404
    finally:
        server.should_exit = True
        thread.join(timeout=10)
