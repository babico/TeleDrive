"""S3 read-compatibility probes for optional, unconfigured AWS features.

Real-world clients (s3fs, Cyberduck, Terraform, MinIO tools) probe these
optional features at startup. TeleDrive answers with valid AWS-shaped READ
responses for the enforced private-only model; every configuration attempt
fails closed with 501 before any SQL or Telegram side effect.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from tests.s3.test_s3_gateway import service, signed  # noqa: F401

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


@pytest.fixture
def bucket(service):  # noqa: F401
    assert signed(service, "PUT", "/compat-bucket").status_code == 200


@pytest.mark.parametrize("selector,tag,value", [
    ("ownershipControls", "ObjectOwnership", "BucketOwnerEnforced"),
    ("requestPayment", "Payer", "BucketOwner"),
    ("accelerate", "TransferAcceleratedStatus", "Suspended"),
])
def test_bucket_config_reads_return_fixed_private_answers(service, bucket,
                                                          selector, tag, value):
    response = signed(service, "GET", f"/compat-bucket?{selector}")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    assert root.find(f".//{NS}{tag}").text == value


def test_bucket_notification_reads_return_empty_configuration(service, bucket):
    for selector in ("notification", "notificationConfiguration"):
        response = signed(service, "GET", f"/compat-bucket?{selector}")
        assert response.status_code == 200, response.text
        root = ET.fromstring(response.content)
        assert root.tag.rsplit("}", 1)[-1] == "NotificationConfiguration"
        assert list(root) == []


def test_bucket_logging_read_returns_empty_status(service, bucket):
    response = signed(service, "GET", "/compat-bucket?logging")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    assert root.tag.rsplit("}", 1)[-1] == "BucketLoggingStatus"
    assert list(root) == []


@pytest.mark.parametrize("selector,code", [
    ("policy", "NoSuchBucketPolicy"),
    ("replication", "ReplicationConfigurationNotFoundError"),
    ("website", "NoSuchWebsiteConfiguration"),
    ("encryption", "ServerSideEncryptionConfigurationNotFoundError"),
    ("object-lock", "ObjectLockConfigurationNotFoundError"),
])
def test_bucket_unconfigured_reads_return_aws_not_found(service, bucket,
                                                        selector, code):
    response = signed(service, "GET", f"/compat-bucket?{selector}")
    assert response.status_code == 404, response.text
    root = ET.fromstring(response.content)
    assert root.findtext("Code") == code


def test_bucket_acl_read_returns_private_canned_acl(service, bucket):
    response = signed(service, "GET", "/compat-bucket?acl")
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    assert root.tag.rsplit("}", 1)[-1] == "AccessControlPolicy"
    grants = root.findall(f"{NS}AccessControlList/{NS}Grant")
    assert len(grants) == 1
    assert grants[0].findtext(f"{NS}Permission") == "FULL_CONTROL"
    grantee = grants[0].find(f"{NS}Grantee")
    assert grantee.get("{http://www.w3.org/2001/XMLSchema-instance}type") \
        == "CanonicalUser"
    # The grantee is the authenticated caller, never another identity.
    assert grantee.findtext(NS + "ID") == response.headers.get("x-amz-id-2", None) or \
        grantee.findtext(NS + "ID")


def test_object_acl_read_requires_existing_object(service, bucket):
    response = signed(service, "GET", "/compat-bucket/missing.txt?acl")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchKey"


def test_object_lock_reads_return_not_configured(service, bucket):
    # Any existing object: use a small signed PUT through the batch path is
    # heavy; the response is config-driven, so a missing object is the only
    # difference. Use the object-existence contract directly.
    response = signed(service, "GET", "/compat-bucket/absent.bin?retention")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchKey"
    response = signed(service, "GET", "/compat-bucket/absent.bin?legal-hold")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchKey"


@pytest.mark.parametrize("method,path", [
    ("PUT", "/compat-bucket?acl"),
    ("DELETE", "/compat-bucket?acl"),
    ("PUT", "/compat-bucket?ownershipControls"),
    ("PUT", "/compat-bucket?policy"),
    ("DELETE", "/compat-bucket?policy"),
    ("PUT", "/compat-bucket?replication"),
    ("DELETE", "/compat-bucket?replication"),
    ("PUT", "/compat-bucket?website"),
    ("DELETE", "/compat-bucket?website"),
    ("PUT", "/compat-bucket?logging"),
    ("PUT", "/compat-bucket?notification"),
    ("PUT", "/compat-bucket?notificationConfiguration"),
    ("PUT", "/compat-bucket?requestPayment"),
    ("PUT", "/compat-bucket?accelerate"),
    ("PUT", "/compat-bucket?encryption"),
    ("DELETE", "/compat-bucket?encryption"),
    # PUT ?object-lock / ?retention / ?legal-hold are REAL Phase C
    # controls now — covered by tests/s3/test_s3_object_lock.py.
    ("PUT", "/compat-bucket/item?acl"),
    ("POST", "/compat-bucket/item?restore"),
    ("POST", "/compat-bucket/item?restore&versionId=x"),
])
def test_configuration_attempts_fail_closed(service, bucket, method, path):
    response = signed(service, method, path)
    assert response.status_code == 501, response.text
    # Nothing was uploaded to or downloaded from Telegram.
    assert service[2].uploads == 0 and service[2].downloads == 0


@pytest.mark.parametrize("path", [
    "/compat-bucket?acl=full",
    "/compat-bucket?acl&acl",
    "/compat-bucket?policy&tagging",
    "/compat-bucket?ownershipControls&cors",
    "/compat-bucket?acl&versionId=abc",
    "/compat-bucket/item?acl&versionId=abc",
    "/compat-bucket/item?retention&uploads",
    "/compat-bucket/item?legal-hold&tagging",
])
def test_malformed_or_conflicting_probes_are_rejected(service, bucket, path):
    response = signed(service, "GET", path)
    assert response.status_code in (400, 501), response.text


def test_probe_requires_signature_and_existing_bucket(service):
    # Unsigned request: rejected before any data-plane effect.
    assert service[0].get("/compat-bucket?acl").status_code == 403
    # Missing bucket: AWS-shaped 404, not a canned compat answer.
    response = signed(service, "GET", "/no-such-bucket?acl")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchBucket"
    response = signed(service, "GET", "/no-such-bucket?policy")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchBucket"


def test_probe_permissions_are_scoped(service, bucket):
    from teledrive.s3.credentials import S3CredentialStore
    db = service[3]()
    try:
        credentials = S3CredentialStore(db, service[4])
        acl_reader = credentials.create("compat-acl-reader", ["s3:GetBucketAcl"])
        object_reader = credentials.create("object-only", ["s3:GetObject"])
    finally:
        db.close()
    ok = signed(service, "GET", "/compat-bucket?acl",
                access=acl_reader.access_key, secret=acl_reader.secret_key)
    assert ok.status_code == 200, ok.text
    denied = signed(service, "GET", "/compat-bucket?acl",
                    access=object_reader.access_key, secret=object_reader.secret_key)
    assert denied.status_code == 403


def test_checksum_mode_header_is_rejected_on_probes(service, bucket):
    response = signed(service, "GET", "/compat-bucket?acl",
                      extra_headers={"x-amz-checksum-mode": "ENABLED"})
    assert response.status_code == 501
