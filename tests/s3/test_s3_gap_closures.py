"""By-code gap closures: list Owner elements, CopyObject date
conditions and CompleteMultipartUpload composite checksums."""
from __future__ import annotations

import base64
import hashlib
import hmac
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


def test_list_object_versions_delimiter_and_encoding(service):
    assert signed(service, "PUT", "/owner-bucket").status_code == 200
    assert signed(service, "PUT", "/owner-bucket/logs/app/1.bin", b"one"
                  ).status_code == 200
    assert signed(service, "PUT", "/owner-bucket/logs/app/2.bin", b"two"
                  ).status_code == 200
    assert signed(service, "PUT", "/owner-bucket/readme.txt", b"rm"
                  ).status_code == 200

    # No delimiter: raw version entries for every key.
    plain = signed(service, "GET", "/owner-bucket?versions")
    assert plain.status_code == 200
    body = plain.content
    assert b"<Version>" in body and b"readme.txt" in body
    assert b"CommonPrefixes" not in body

    # Delimiter groups the logs/ keys into one CommonPrefixes entry.
    grouped = signed(service, "GET", "/owner-bucket?versions&delimiter=%2F")
    assert grouped.status_code == 200, grouped.text
    gbody = grouped.content
    assert gbody.count(b"<CommonPrefixes>") == 1
    assert b"logs/" in gbody
    assert b"logs/app/1.bin" not in gbody  # collapsed into the prefix
    assert b"readme.txt" in gbody  # non-grouped keys stay as versions

    # The common prefix counts against max-keys: budget of 1 = the
    # prefix alone, truncated, with NextKeyMarker pointing at it.
    tight = signed(service, "GET", "/owner-bucket?versions&delimiter=%2F&max-keys=1")
    assert tight.status_code == 200
    tbody = tight.content
    assert b"IsTruncated>true<" in tbody
    assert b"logs/" in tbody and b"readme.txt" not in tbody

    # encoding-type=url percent-encodes keys and prefixes inside XML.
    encoded = signed(service,
                     "GET", "/owner-bucket?versions&delimiter=%2F&encoding-type=url")
    assert encoded.status_code == 200
    assert b"readme.txt" in encoded.content  # ASCII unchanged
    assert b"<EncodingType>url<" in encoded.content

    # Invalid encoding values fail closed.
    bad = signed(service, "GET", "/owner-bucket?versions&encoding-type=xml")
    assert bad.status_code == 400
    assert b"InvalidArgument" in bad.content


def test_presigned_copy_object_binds_the_source(service):
    from datetime import datetime, timezone
    from urllib.parse import quote as _q
    client, issued, _, _, _ = service
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    assert signed(service, "PUT", "/backup-bucket/presign-src.bin",
                  b"presigned-payload").status_code == 200

    def presign_copy(path, copy_source, *, expires=3600):
        now = datetime.now(timezone.utc)
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        date = now.strftime("%Y%m%d")
        region, host = "us-east-1", "localhost:9000"
        scope = f"{issued.access_key}/{date}/{region}/s3/aws4_request"
        headers = {
            "host": host,
            "x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
            "x-amz-copy-source": copy_source,
        }
        names = sorted(headers)
        query = "&".join(
            f"{_q(k, safe='-_.~')}={_q(v, safe='-_.~')}" for k, v in sorted({
                "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                "X-Amz-Credential": scope,
                "X-Amz-Date": stamp,
                "X-Amz-Expires": str(expires),
                "X-Amz-SignedHeaders": ";".join(names),
            }.items()))
        canonical = (
            f"PUT\n{path}\n{query}\n"
            + "".join(f"{n}:{headers[n]}\n" for n in names)
            + f"\n{';'.join(names)}\n{headers['x-amz-content-sha256']}")
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{stamp}\n{date}/{region}/s3/aws4_request\n"
            + hashlib.sha256(canonical.encode()).hexdigest())
        secret = issued.secret_key.encode()
        key = hmac.new(b"AWS4" + secret, date.encode(), hashlib.sha256).digest()
        for word in (region, "s3", "aws4_request"):
            key = hmac.new(key, word.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, string_to_sign.encode(),
                             hashlib.sha256).hexdigest()
        return (f"{path}?{query}&X-Amz-Signature={signature}",
                {k: v for k, v in headers.items() if k != "host"})

    # A correctly presigned copy works without any Authorization header.
    url, headers = presign_copy("/backup-bucket/presign-dst.bin",
                                "/backup-bucket/presign-src.bin")
    copied = client.put(url, headers=headers)
    assert copied.status_code == 200, copied.text
    assert signed(service, "GET", "/backup-bucket/presign-dst.bin"
                  ).content == b"presigned-payload"

    # Tampering with the signature is rejected.
    url_bad = url[:-2] + ("00" if not url.endswith("00") else "11")
    tampered = client.put(url_bad, headers=headers)
    assert tampered.status_code == 403
    assert b"SignatureDoesNotMatch" in tampered.content

    # An expired URL is refused.
    url_old, headers_old = presign_copy("/backup-bucket/presign-dst2.bin",
                                        "/backup-bucket/presign-src.bin",
                                        expires=1)
    import time as _time
    _time.sleep(2)
    expired = client.put(url_old, headers=headers_old)
    assert expired.status_code == 403
    assert b"expired" in expired.content.lower()

    # The URL cannot be replayed against a DIFFERENT source: the
    # signature binds x-amz-copy-source, and swapping the header
    # breaks it.
    swapped = client.put(url, headers={
        **headers, "x-amz-copy-source": "/backup-bucket/other-src.bin"})
    assert swapped.status_code == 403
    assert b"SignatureDoesNotMatch" in swapped.content
    # The other source never existed anyway — but the signature guard
    # fires before the catalog lookup either way.


def test_ranged_copy_object_stages_new_bytes(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    payload = bytes(range(256)) * 64  # 16 KiB deterministic payload
    assert signed(service, "PUT", "/backup-bucket/ranged-src.bin", payload
                  ).status_code == 200
    # Inclusive range 100..299 → bytes[100:300].
    result = signed(service, "PUT", "/backup-bucket/ranged-dst.bin", b"",
                    extra_headers={
                        "x-amz-copy-source": "/backup-bucket/ranged-src.bin",
                        "x-amz-copy-source-range": "bytes=100-299"})
    assert result.status_code == 200, result.text
    downloaded = signed(service, "GET", "/backup-bucket/ranged-dst.bin")
    assert downloaded.status_code == 200
    assert downloaded.content == payload[100:300]
    assert downloaded.headers["content-length"] == "200"

    # Out-of-range slices fail closed with 416 and never create the key.
    beyond = signed(service, "PUT", "/backup-bucket/ranged-bad.bin", b"",
                    extra_headers={
                        "x-amz-copy-source": "/backup-bucket/ranged-src.bin",
                        "x-amz-copy-source-range": "bytes=0-999999"})
    assert beyond.status_code == 416
    assert b"InvalidRange" in beyond.content
    assert signed(service, "HEAD", "/backup-bucket/ranged-bad.bin"
                  ).status_code == 404

    # Malformed ranges are InvalidArgument, never silently ignored.
    malformed = signed(service, "PUT", "/backup-bucket/ranged-bad2.bin", b"",
                       extra_headers={
                           "x-amz-copy-source": "/backup-bucket/ranged-src.bin",
                           "x-amz-copy-source-range": "bytes=5-"})
    assert malformed.status_code == 400
    assert b"InvalidArgument" in malformed.content

    # The source object is untouched by the ranged copy.
    source = signed(service, "GET", "/backup-bucket/ranged-src.bin")
    assert source.content == payload


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

    # FULL_OBJECT: one streaming pass verifies the assembled digest.
    upload4 = begin(service, "comp4.bin")
    a4 = part(service, upload4, 1, b"f" * (5 * 1024 * 1024), key="comp4.bin")
    full_payload = b"f" * (5 * 1024 * 1024)
    full_sha = base64.b64encode(
        hashlib.sha256(full_payload).digest()).decode("ascii")
    full_ok = _complete(upload4, [(1, a4)], "comp4.bin", {
        "x-amz-checksum-sha256": full_sha,
        "x-amz-checksum-type": "FULL_OBJECT"})
    assert full_ok.status_code == 200, full_ok.text
    assert full_sha.encode() in full_ok.content

    # FULL_OBJECT with a wrong digest is rejected before publication.
    upload6 = begin(service, "comp6.bin")
    a6 = part(service, upload6, 1, b"f" * (5 * 1024 * 1024), key="comp6.bin")
    full_bad = _complete(upload6, [(1, a6)], "comp6.bin", {
        "x-amz-checksum-sha256": base64.b64encode(b"0" * 32).decode("ascii"),
        "x-amz-checksum-type": "FULL_OBJECT"})
    assert full_bad.status_code == 400
    assert b"BadDigest" in full_bad.content

    # FULL_OBJECT works for non-SHA algorithms too (same streaming pass).
    import zlib as _zlib
    upload7 = begin(service, "comp7.bin")
    a7 = part(service, upload7, 1, b"f" * (5 * 1024 * 1024), key="comp7.bin")
    b7 = part(service, upload7, 2, b"s" * 4096, key="comp7.bin")
    full_crc32 = base64.b64encode((_zlib.crc32(
        b"f" * (5 * 1024 * 1024) + b"s" * 4096) & 0xffffffff)
        .to_bytes(4, "big")).decode("ascii")
    crc_ok = _complete(upload7, [(1, a7), (2, b7)], "comp7.bin", {
        "x-amz-checksum-crc32": full_crc32,
        "x-amz-checksum-type": "FULL_OBJECT"})
    assert crc_ok.status_code == 200, crc_ok.text

    # Non-SHA COMPOSITE: CRC32 over the concatenated little-endian
    # per-part CRC32s.
    upload8 = begin(service, "comp8.bin")
    a8 = part(service, upload8, 1, b"f" * (5 * 1024 * 1024), key="comp8.bin")
    b8 = part(service, upload8, 2, b"s" * 4096, key="comp8.bin")
    part_one_crc = _zlib.crc32(b"f" * (5 * 1024 * 1024)) & 0xffffffff
    part_two_crc = _zlib.crc32(b"s" * 4096) & 0xffffffff
    composite_crc = _zlib.crc32(
        part_one_crc.to_bytes(4, "little") + part_two_crc.to_bytes(4, "little")
    ) & 0xffffffff
    comp_crc = base64.b64encode(
        composite_crc.to_bytes(4, "big")).decode("ascii")
    crc_composite = _complete(upload8, [(1, a8), (2, b8)], "comp8.bin", {
        "x-amz-checksum-crc32": comp_crc,
        "x-amz-checksum-type": "COMPOSITE"})
    assert crc_composite.status_code == 200, crc_composite.text

    # Non-SHA without an explicit checksum-type fails closed.
    upload9 = begin(service, "comp9.bin")
    a9 = part(service, upload9, 1, b"f" * (5 * 1024 * 1024), key="comp9.bin")
    missing_type = _complete(upload9, [(1, a9)], "comp9.bin", {
        "x-amz-checksum-crc32": full_crc32})
    assert missing_type.status_code == 400
    assert b"InvalidArgument" in missing_type.content

    # A correct part checksum completes normally.
    upload5 = begin(service, "comp5.bin")
    a5 = part(service, upload5, 1, b"f" * (5 * 1024 * 1024), key="comp5.bin")
    ok = _complete(upload5, [(1, a5, part_one)], "comp5.bin")
    assert ok.status_code == 200, ok.text
