"""Phase O1: RestoreObject is strict, then truthfully InvalidObjectState.

No archive tier exists, so every object is already immediately readable. AWS
returns 403 InvalidObjectState for a restore of an object that is not archived;
that is the only honest answer here. Malformed request XML is still 400.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore

VALID = (b"<RestoreRequest><Days>3</Days>"
         b"<GlacierJobParameters><Tier>Standard</Tier></GlacierJobParameters>"
         b"<Description>restore please</Description></RestoreRequest>")


def _restore(service, path="/restore-bucket/archive.bin?restore", body=VALID,
             **kwargs):
    return signed(service, "POST", path, body, **kwargs)


def _seed(service):
    assert signed(service, "PUT", "/restore-bucket").status_code == 200
    assert signed(service, "PUT", "/restore-bucket/archive.bin",
                  b"already-readable").status_code == 200


def test_malformed_restore_xml_is_400(service):
    _seed(service)
    response = _restore(service, body=b"<RestoreRequest>")
    assert response.status_code == 400, response.text
    assert ET.fromstring(response.content).findtext("Code") == "MalformedXML"
    response = _restore(service, body=b"<RestoreRequest></RestoreRequest>")
    assert response.status_code == 400


def test_valid_restore_is_403_invalid_object_state(service):
    _seed(service)
    response = _restore(service)
    assert response.status_code == 403, response.text
    assert ET.fromstring(response.content).findtext("Code") == "InvalidObjectState"
    assert b"immediately readable" in response.content


def test_restore_missing_key_is_404(service):
    _seed(service)
    response = _restore(service, "/restore-bucket/missing.bin?restore")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchKey"


def test_malformed_fields_are_400(service):
    _seed(service)
    for body in (
        b"<RestoreRequest><Days>0</Days></RestoreRequest>",
        b"<RestoreRequest><Days>forever</Days></RestoreRequest>",
        b"<RestoreRequest><Days>1</Days><Unknown>x</Unknown></RestoreRequest>",
        b"<WrongRoot><Days>1</Days></WrongRoot>",
    ):
        response = _restore(service, body=body)
        assert response.status_code == 400, (body, response.text)


def test_restore_permission_separation(service):
    _seed(service)
    db = service[3]()
    try:
        store = S3CredentialStore(db, service[4])
        restorer = store.create("restorer", ["s3:RestoreObject"])
        reader = store.create("reader", ["s3:GetObject"])
    finally:
        db.close()
    allowed = _restore(
        service, access=restorer.access_key, secret=restorer.secret_key)
    assert allowed.status_code == 403
    assert ET.fromstring(allowed.content).findtext("Code") == "InvalidObjectState"
    denied = _restore(
        service, access=reader.access_key, secret=reader.secret_key)
    assert denied.status_code == 403
    assert ET.fromstring(denied.content).findtext("Code") == "AccessDenied"


def test_restore_route_guard(service):
    _seed(service)
    assert signed(service, "GET", "/restore-bucket/archive.bin?restore").status_code == 501
    assert signed(service, "DELETE", "/restore-bucket/archive.bin?restore").status_code == 501
    assert signed(
        service, "POST", "/restore-bucket/archive.bin?restore&tagging",
        VALID,
    ).status_code == 501
    # VersionId is supported by the selector, but an unpublished version is
    # a 404, not a fallback to the current object.
    response = _restore(
        service, "/restore-bucket/archive.bin?restore&versionId=missing")
    assert response.status_code == 404
    assert ET.fromstring(response.content).findtext("Code") == "NoSuchVersion"
