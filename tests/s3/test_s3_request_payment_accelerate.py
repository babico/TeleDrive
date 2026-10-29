"""Phase O6: RequestPayment and Accelerate manage the one real state.

Both configurations are writable-but-single-state: the accepted value is the
only state that exists, and the value that would require absent infrastructure
(requester billing / an edge network) is rejected with an explicit 501.

The GET renderers emit AWS's real wire members — ``Payer`` and ``Status``
(both verified against the botocore S3 model) — and are the exact documents
the PUT parsers accept, so PUT-then-GET round-trips byte-identically.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.bucket_flags import (
    accelerate_xml, parse_accelerate_xml, parse_request_payment_xml,
    request_payment_xml,
)
from teledrive.s3.credentials import S3CredentialStore

BUCKET_OWNER = (
    b"<RequestPaymentConfiguration>"
    b"<Payer>BucketOwner</Payer>"
    b"</RequestPaymentConfiguration>"
)
REQUESTER = (
    b"<RequestPaymentConfiguration>"
    b"<Payer>Requester</Payer>"
    b"</RequestPaymentConfiguration>"
)
SUSPENDED = (
    b"<AccelerateConfiguration>"
    b"<Status>Suspended</Status>"
    b"</AccelerateConfiguration>"
)
ENABLED = (
    b"<AccelerateConfiguration>"
    b"<Status>Enabled</Status>"
    b"</AccelerateConfiguration>"
)


def _root_values(response) -> dict[str, str]:
    return {node.tag.rsplit("}", 1)[-1]: node.text
            for node in ET.fromstring(response.content)}


def test_request_payment_accepts_bucket_owner_and_get_reports_it(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    read = signed(service, "GET", "/flags?requestPayment")
    assert read.status_code == 200
    assert _root_values(read) == {"Payer": "BucketOwner"}
    put = signed(service, "PUT", "/flags?requestPayment", BUCKET_OWNER)
    assert put.status_code == 200, put.text
    # Nothing is stored beyond the constant: GET still reports the one state.
    assert _root_values(signed(service, "GET", "/flags?requestPayment")) == {
        "Payer": "BucketOwner"}


def test_request_payment_rejects_requester_with_honest_501(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    refused = signed(service, "PUT", "/flags?requestPayment", REQUESTER)
    assert refused.status_code == 501, refused.text
    assert b"NotImplemented" in refused.content
    assert b"billing" in refused.content
    assert _root_values(signed(service, "GET", "/flags?requestPayment")) == {
        "Payer": "BucketOwner"}


def test_accelerate_accepts_suspended_and_get_reports_it(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    read = signed(service, "GET", "/flags?accelerate")
    assert read.status_code == 200
    assert _root_values(read) == {"Status": "Suspended"}
    put = signed(service, "PUT", "/flags?accelerate", SUSPENDED)
    assert put.status_code == 200, put.text
    assert _root_values(signed(service, "GET", "/flags?accelerate")) == {
        "Status": "Suspended"}


@pytest.mark.parametrize("selector,parse,render", [
    ("requestPayment", parse_request_payment_xml, request_payment_xml),
    ("accelerate", parse_accelerate_xml, accelerate_xml),
])
def test_put_then_get_round_trips_byte_identically(service, selector, parse,
                                                   render):
    """The GET body is exactly what the PUT parser accepts.

    Round-trip proof: read the canonical document, PUT those same bytes, and
    read it back byte-for-byte. The PUT parser and the GET renderer are the
    same wire shape, so a client that re-uploads a GET body cannot drift.
    """
    assert signed(service, "PUT", "/flags").status_code == 200
    first = signed(service, "GET", f"/flags?{selector}")
    assert first.status_code == 200, first.text
    # The canonical document parses back to the single real state.
    assert parse(first.content) in {"BucketOwner", "Suspended"}
    assert first.content == render()
    put = signed(service, "PUT", f"/flags?{selector}", first.content)
    assert put.status_code == 200, put.text
    second = signed(service, "GET", f"/flags?{selector}")
    assert second.status_code == 200, second.text
    assert second.content == first.content


def test_accelerate_rejects_enabled_with_honest_501(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    refused = signed(service, "PUT", "/flags?accelerate", ENABLED)
    assert refused.status_code == 501, refused.text
    assert b"NotImplemented" in refused.content
    assert b"edge network" in refused.content
    assert _root_values(signed(service, "GET", "/flags?accelerate")) == {
        "Status": "Suspended"}


@pytest.mark.parametrize("selector,body,status,fragment", [
    ("requestPayment", b"", 400, b"MalformedXML"),
    ("requestPayment", b"<RequestPaymentConfiguration/>", 400, b"MalformedXML"),
    ("requestPayment", b"<Wrong><Payer>BucketOwner</Payer></Wrong>", 400, b"MalformedXML"),
    ("requestPayment",
     b"<RequestPaymentConfiguration><Payer>BucketOwner</Payer>"
     b"<Extra>x</Extra></RequestPaymentConfiguration>", 400, b"MalformedXML"),
    ("requestPayment",
     b"<RequestPaymentConfiguration><Payer>Someone</Payer>"
     b"</RequestPaymentConfiguration>", 400, b"InvalidArgument"),
    ("requestPayment",
     b"<!DOCTYPE r [<!ENTITY x 'BucketOwner'>]>"
     b"<RequestPaymentConfiguration><Payer>&x;</Payer>"
     b"</RequestPaymentConfiguration>", 400, b"MalformedXML"),
    ("accelerate", b"", 400, b"MalformedXML"),
    ("accelerate", b"<AccelerateConfiguration/>", 400, b"MalformedXML"),
    ("accelerate", b"<AccelerateConfiguration><Status>Fast</Status>"
     b"</AccelerateConfiguration>", 400, b"InvalidArgument"),
    ("accelerate", b"<AccelerateConfiguration><Status>Enabled</Status>"
     b"</AccelerateConfiguration><Extra/>", 400, b"MalformedXML"),
])
def test_strict_xml_rejects_malformed_and_unknown_values(
    service, selector, body, status, fragment,
):
    assert signed(service, "PUT", "/flags").status_code == 200
    reply = signed(service, "PUT", f"/flags?{selector}", body)
    assert reply.status_code == status, reply.text
    assert fragment in reply.content


def test_bucket_control_payload_is_bounded_to_16_kib(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    huge = (b"<RequestPaymentConfiguration><Payer>BucketOwner</Payer>"
            + b" " * (16 * 1024) + b"</RequestPaymentConfiguration>")
    reply = signed(service, "PUT", "/flags?requestPayment", huge)
    assert reply.status_code == 400
    assert b"MalformedXML" in reply.content


def test_missing_bucket_and_signed_checksum(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    assert signed(service, "GET", "/missing-flags?requestPayment").status_code == 404
    assert signed(service, "PUT", "/missing-flags?requestPayment",
                  BUCKET_OWNER).status_code == 404
    bad = signed(service, "PUT", "/flags?requestPayment", BUCKET_OWNER,
                 extra_headers={"Content-MD5": "AAAA"})
    assert bad.status_code == 400
    assert b"BadDigest" in bad.content


def test_request_payment_and_accelerate_permission_separation(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    _, _, _, connect, master = service
    db = connect()
    try:
        store = S3CredentialStore(db, master)
        reader = store.create("flags-reader", [
            "s3:GetBucketRequestPayment", "s3:GetAccelerateConfiguration",
        ])
        writer = store.create("flags-writer", [
            "s3:PutBucketRequestPayment", "s3:PutBucketAccelerateConfiguration",
        ])
        unrelated = store.create("flags-none", ["s3:GetObject"])
    finally:
        db.close()
    for selector, body in (("requestPayment", BUCKET_OWNER),
                           ("accelerate", SUSPENDED)):
        path = f"/flags?{selector}"
        assert signed(service, "GET", path, access=reader.access_key,
                      secret=reader.secret_key).status_code == 200
        assert signed(service, "PUT", path, body, access=reader.access_key,
                      secret=reader.secret_key).status_code == 403
        assert signed(service, "GET", path, access=writer.access_key,
                      secret=writer.secret_key).status_code == 403
        assert signed(service, "PUT", path, body, access=writer.access_key,
                      secret=writer.secret_key).status_code == 200
        assert signed(service, "GET", path, access=unrelated.access_key,
                      secret=unrelated.secret_key).status_code == 403


def test_no_bucket_crud_or_object_route_fallback(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    assert signed(service, "PUT", "/flags/item", b"data").status_code == 200
    # Bucket-only controls must not degrade into object operations.
    assert signed(service, "PUT", "/flags/item?requestPayment",
                  BUCKET_OWNER).status_code == 501
    assert signed(service, "PUT", "/flags/item?accelerate",
                  SUSPENDED).status_code == 501
    assert signed(service, "GET", "/flags/item").content == b"data"


def test_actual_boto3_client_reads_accelerate_and_request_payment(service):
    """The regression a raw-XML test cannot catch.

    boto3 parses the response against the botocore S3 model. The old
    accelerate renderer emitted ``TransferAcceleratedStatus``, which the
    model does not know, so boto3 silently returned an empty dict. This test
    goes through a real client over an in-process uvicorn listener and would
    have failed before the shape fix.
    """
    import socket
    import threading
    import time
    import uvicorn
    import boto3
    from botocore.config import Config
    import web.s3 as gateway

    _, credential, _, _, _ = service
    assert signed(service, "PUT", "/flags-ci").status_code == 200
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
        accel = s3.get_bucket_accelerate_configuration(Bucket="flags-ci")
        assert accel["Status"] == "Suspended"
        payment = s3.get_bucket_request_payment(Bucket="flags-ci")
        assert payment["Payer"] == "BucketOwner"
        assert s3.put_bucket_accelerate_configuration(
            Bucket="flags-ci",
            AccelerateConfiguration={"Status": "Suspended"},
        )["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert s3.put_bucket_request_payment(
            Bucket="flags-ci", RequestPaymentConfiguration={"Payer": "BucketOwner"},
        )["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert s3.get_bucket_accelerate_configuration(
            Bucket="flags-ci")["Status"] == "Suspended"
        assert s3.get_bucket_request_payment(
            Bucket="flags-ci")["Payer"] == "BucketOwner"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
