"""By-code gap closures: list Owner elements, CopyObject date
conditions and CompleteMultipartUpload composite checksums."""
from __future__ import annotations

import base64
import hashlib
import time
from email.utils import format_datetime
from datetime import datetime, timezone

import pytest

from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, part
from xml.etree import ElementTree as ET


def _contents_owner(xml_body: bytes, key: str) -> str | None:
    root = ET.fromstring(xml_body)
    for contents in root.findall("{*}Contents"):
        if contents.findtext("{*}Key") == key:
            owner = contents.find("{*}Owner")
            return owner.findtext("{*}ID") if owner is not None else None
    return None


def test_list_objects_v1_always_includes_owner(service):
    assert signed(service, "PUT", "/owner-bucket").status_code == 200
    assert signed(service, "PUT", "/owner-bucket/obj.bin", b"owner-payload"
                  ).status_code == 200
    listed = signed(service, "GET", "/owner-bucket")
    assert listed.status_code == 200
    owner = _contents_owner(listed.content, "obj.bin")
    assert owner  # V1 always carries Owner
    assert len(owner) >= 16


def test_list_objects_v2_fetch_owner_controls_the_element(service):
    assert signed(service, "PUT", "/owner-bucket").status_code == 200
    assert signed(service, "PUT", "/owner-bucket/v2.bin", b"v2"
                  ).status_code == 200
    # Default V2: no Owner element.
    plain = signed(service, "GET", "/owner-bucket?list-type=2")
    assert plain.status_code == 200
    assert _contents_owner(plain.content, "v2.bin") is None
    # fetch-owner=true adds it.
    fetched = signed(service, "GET", "/owner-bucket?list-type=2&fetch-owner=true")
    assert fetched.status_code == 200
    assert _contents_owner(fetched.content, "v2.bin")
    # Invalid values are rejected.
    bad = signed(service, "GET", "/owner-bucket?list-type=2&fetch-owner=yes")
    assert bad.status_code == 400
    assert b"InvalidArgument" in bad.content


def test_copy_object_date_conditions(service):
    assert signed(service, "PUT", "/date-bucket").status_code == 200
    assert signed(service, "PUT", "/date-bucket/src.bin", b"dated-payload"
                  ).status_code == 200
    old = format_datetime(
        datetime(2020, 1, 1, tzinfo=timezone.utc), usegmt=True)
    future = format_datetime(
        datetime(2038, 1, 1, tzinfo=timezone.utc), usegmt=True)

    # Source (modified now, 2026) WAS modified after 2020 -> passes.
    fresh = signed(service, "PUT", "/date-bucket/dst1.bin",
                   extra_headers={
                       "x-amz-copy-source": "/date-bucket/src.bin",
                       "x-amz-copy-source-if-modified-since": old})
    assert fresh.status_code == 200, fresh.text
    # Source was NOT modified after 2038 -> if-modified-since fails.
    stale = signed(service, "PUT", "/date-bucket/dst2.bin",
                   extra_headers={
                       "x-amz-copy-source": "/date-bucket/src.bin",
                       "x-amz-copy-source-if-modified-since": future})
    assert stale.status_code == 412, stale.text
    assert b"PreconditionFailed" in stale.content

    # Source WAS modified after 2020 -> if-unmodified-since fails.
    changed = signed(service, "PUT", "/date-bucket/dst3.bin",
                     extra_headers={
                         "x-amz-copy-source": "/date-bucket/src.bin",
                         "x-amz-copy-source-if-unmodified-since": old})
    assert changed.status_code == 412
    # Source was NOT modified after 2038 -> if-unmodified-since passes.
    ok_old = signed(service, "PUT", "/date-bucket/dst4.bin",
                    extra_headers={
                        "x-amz-copy-source": "/date-bucket/src.bin",
                        "x-amz-copy-source-if-unmodified-since": future})
    assert ok_old.status_code == 200, ok_old.text

    # AWS precedence: a passing ETag condition overrides the violated
    # unmodified-since date.
    etag = hashlib.sha256(b"dated-payload").hexdigest()
    precedence = signed(service, "PUT", "/date-bucket/dst5.bin",
                        extra_headers={
                            "x-amz-copy-source": "/date-bucket/src.bin",
                            "x-amz-copy-source-if-match": '"' + etag + '"',
                            "x-amz-copy-source-if-unmodified-since": old})
    assert precedence.status_code == 200, precedence.text

    # Malformed dates are rejected, never silently ignored.
    malformed = signed(service, "PUT", "/date-bucket/dst6.bin",
                       extra_headers={
                           "x-amz-copy-source": "/date-bucket/src.bin",
                           "x-amz-copy-source-if-modified-since": "not-a-date"})
    assert malformed.status_code == 400
    assert b"InvalidArgument" in malformed.content


def test_complete_multipart_composite_checksum_and_part_digests(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200

    def _complete(upload_id, selection, key, extra_headers=None):
        root = ET.Element("CompleteMultipartUpload")
        for number, etag, *checksum in selection:
            node = ET.SubElement(root, "Part")
            ET.SubElement(node, "PartNumber").text = str(number)
            ET.SubElement(node, "ETag").text = etag
            if checksum and checksum[0] is not None:
                ET.SubElement(node, "ChecksumSHA256").text = checksum[0]
        payload = ET.tostring(root)
        headers = {"x-amz-content-sha256":
                   hashlib.sha256(payload).hexdigest()}
        headers.update(extra_headers or {})
        return signed(service, "POST",
                      f"/backup-bucket/{key}?uploadId={upload_id}",
                      payload, extra_headers=headers)

    upload_id = begin(service, "comp.bin")
    etag_one = part(service, upload_id, 1, b"f" * (5 * 1024 * 1024),
                    key="comp.bin")
    etag_two = part(service, upload_id, 2, b"s" * 4096,
                    key="comp.bin")

    from sqlalchemy import select
    connection = service[3]()
    try:
        from teledrive.s3.multipart import parts
        from teledrive.storage.manifest import objects
        rows = connection.connection.execute(
            select(parts.c.number, objects.c.sha256)
            .select_from(parts.join(objects, objects.c.id == parts.c.object_id))
            .where(parts.c.upload_id == upload_id)
            .order_by(parts.c.number)).all()
    finally:
        pass
    composite = base64.b64encode(hashlib.sha256(b"".join(
        bytes.fromhex(sha) for _, sha in rows)).digest()).decode("ascii")
    part_one = base64.b64encode(bytes.fromhex(rows[0][1])).decode("ascii")

    # Correct composite checksum: 200 + the checksum echoed in the XML.
    good = _complete(upload_id, [(1, etag_one), (2, etag_two)], "comp.bin", {
        "x-amz-checksum-sha256": composite,
        "x-amz-checksum-type": "COMPOSITE"})
    assert good.status_code == 200, good.text
    assert composite.encode() in good.content

    # Wrong composite: rejected before publication.
    upload2 = begin(service, "comp2.bin")
    a2 = part(service, upload2, 1, b"f" * (5 * 1024 * 1024), key="comp2.bin")
    b2 = part(service, upload2, 2, b"s" * 4096, key="comp2.bin")
    wrong = _complete(upload2, [(1, a2), (2, b2)], "comp2.bin", {
        "x-amz-checksum-sha256": base64.b64encode(b"0" * 32).decode("ascii"),
        "x-amz-checksum-type": "COMPOSITE"})
    assert wrong.status_code == 400
    assert b"BadDigest" in wrong.content

    # Per-part ChecksumSHA256 in the XML body is verified too.
    upload3 = begin(service, "comp3.bin")
    a3 = part(service, upload3, 1, b"f" * (5 * 1024 * 1024), key="comp3.bin")
    bad_digest = base64.b64encode(b"X" * 32).decode("ascii")
    bad_part = _complete(upload3, [(1, a3, bad_digest)], "comp3.bin")
    assert bad_part.status_code == 400
    assert b"BadDigest" in bad_part.content

    # FULL_OBJECT cannot be verified without streaming: honest 501.
    upload4 = begin(service, "comp4.bin")
    a4 = part(service, upload4, 1, b"f" * (5 * 1024 * 1024), key="comp4.bin")
    unsupported = _complete(upload4, [(1, a4)], "comp4.bin", {
        "x-amz-checksum-sha256": composite,
        "x-amz-checksum-type": "FULL_OBJECT"})
    assert unsupported.status_code == 501
    assert b"NotImplemented" in unsupported.content

    # A correct part checksum completes normally.
    upload5 = begin(service, "comp5.bin")
    a5 = part(service, upload5, 1, b"f" * (5 * 1024 * 1024), key="comp5.bin")
    ok = _complete(upload5, [(1, a5, part_one)], "comp5.bin")
    assert ok.status_code == 200, ok.text
