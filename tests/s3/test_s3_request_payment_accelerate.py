"""Phase O6: RequestPayment and Accelerate manage the one real state.

Both configurations are writable-but-single-state: the accepted value is the
only state that exists, and the value that would require absent infrastructure
(requester billing / an edge network) is rejected with an explicit 501.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from tests.s3.test_s3_gateway import service, signed
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
    assert _root_values(read) == {"TransferAcceleratedStatus": "Suspended"}
    put = signed(service, "PUT", "/flags?accelerate", SUSPENDED)
    assert put.status_code == 200, put.text
    assert _root_values(signed(service, "GET", "/flags?accelerate")) == {
        "TransferAcceleratedStatus": "Suspended"}


def test_accelerate_rejects_enabled_with_honest_501(service):
    assert signed(service, "PUT", "/flags").status_code == 200
    refused = signed(service, "PUT", "/flags?accelerate", ENABLED)
    assert refused.status_code == 501, refused.text
    assert b"NotImplemented" in refused.content
    assert b"edge network" in refused.content
    assert _root_values(signed(service, "GET", "/flags?accelerate")) == {
        "TransferAcceleratedStatus": "Suspended"}


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
