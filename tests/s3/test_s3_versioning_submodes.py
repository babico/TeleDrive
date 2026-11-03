"""S3 versioning submodes: exact AWS null-version slot semantics.

TeleDrive's version IDs are internal UUIDs, so the AWS wire-level literal
``versionId: null`` is represented by a single per-key NULL-version SLOT:
every write published while the bucket's versioning is Suspended (PUT,
CopyObject, CompleteMultipartUpload, or the delete marker of a DELETE
without a VersionId) occupies that one slot and permanently retires the
previous occupant. Versions published while versioning was Enabled are
immutable history and are never retired by a suspended write.

References (Amazon S3 User Guide):
* "Adding objects to versioning-suspended buckets"
* "Deleting objects from versioning-suspended buckets"
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from urllib.parse import quote

import pytest

from tests.s3.test_s3_gateway import service, signed

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
BUCKET = "submode-bucket"

SUSPEND = (b'<?xml version="1.0"?>\n'
           b'<VersioningConfiguration><Status>Suspended</Status>'
           b'</VersioningConfiguration>')
ENABLE = (b'<?xml version="1.0"?>\n'
          b'<VersioningConfiguration><Status>Enabled</Status>'
          b'</VersioningConfiguration>')


def _put(svc, key: str, body: bytes):
    reply = signed(svc, "PUT", f"/{BUCKET}/{quote(key, safe='/')}", body)
    assert reply.status_code == 200, reply.text
    return reply


def _get(svc, key: str, version_id: str | None = None):
    path = f"/{BUCKET}/{quote(key, safe='/')}"
    if version_id is not None:
        path += f"?versionId={version_id}"
    return signed(svc, "GET", path)


def _head(svc, key: str, version_id: str | None = None):
    path = f"/{BUCKET}/{quote(key, safe='/')}"
    if version_id is not None:
        path += f"?versionId={version_id}"
    return signed(svc, "HEAD", path)


def _delete(svc, key: str, version_id: str | None = None):
    path = f"/{BUCKET}/{quote(key, safe='/')}"
    if version_id is not None:
        path += f"?versionId={version_id}"
    return signed(svc, "DELETE", path)


def _set_versioning(svc, body: bytes):
    reply = signed(svc, "PUT", f"/{BUCKET}?versioning", body)
    assert reply.status_code == 200, reply.text


def _versions(svc, prefix: str = ""):
    """(versions, delete_markers) entries from ListObjectVersions."""
    reply = signed(svc, "GET",
                   f"/{BUCKET}?versions&prefix={quote(prefix, safe='')}")
    assert reply.status_code == 200, reply.text
    root = ET.fromstring(reply.content)
    return root.findall(NS + "Version"), root.findall(NS + "DeleteMarker")


def _begin_mpu(svc, key: str):
    reply = signed(svc, "POST",
                   f"/{BUCKET}/{quote(key, safe='/')}?uploads")
    assert reply.status_code == 200, reply.text
    return ET.fromstring(reply.content).findtext(NS + "UploadId")


def _put_part(svc, upload_id: str, number: int, payload: bytes, key: str):
    reply = signed(
        svc, "PUT",
        f"/{BUCKET}/{quote(key, safe='/')}"
        f"?partNumber={number}&uploadId={upload_id}",
        payload,
    )
    assert reply.status_code == 200, reply.text
    return reply.headers["etag"]


def _complete_mpu(svc, upload_id: str, selection, key: str):
    root = ET.Element("CompleteMultipartUpload")
    for number, etag in selection:
        node = ET.SubElement(root, "Part")
        ET.SubElement(node, "PartNumber").text = str(number)
        ET.SubElement(node, "ETag").text = etag
    reply = signed(svc, "POST",
                   f"/{BUCKET}/{quote(key, safe='/')}?uploadId={upload_id}",
                   ET.tostring(root))
    assert reply.status_code == 200, reply.text
    return reply


@pytest.fixture(autouse=True)
def _bucket(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200


def test_suspended_put_creates_and_replaces_the_null_version(service):
    """AWS: a suspended PUT overwrites an existing null version; a
    versioned (enabled-era) head is NOT overwritten."""
    _put(service, "slot.bin", b"v1")
    v2 = _put(service, "slot.bin", b"v2").headers["x-amz-version-id"]
    _set_versioning(service, SUSPEND)

    v3 = _put(service, "slot.bin", b"v3").headers["x-amz-version-id"]
    assert _get(service, "slot.bin").content == b"v3"
    versions, markers = _versions(service, "slot.bin")
    assert len(versions) == 3 and not markers  # v1 + v2 preserved + v3 (NULL)

    v4 = _put(service, "slot.bin", b"v4").headers["x-amz-version-id"]
    assert v4 != v3
    assert _get(service, "slot.bin").content == b"v4"
    versions, _ = _versions(service, "slot.bin")
    # v3 (the previous NULL occupant) was permanently retired; v1/v2 stay.
    ids = {v.findtext(NS + "VersionId") for v in versions}
    assert v3 not in ids and v4 in ids and v2 in ids
    assert len(versions) == 3  # v1, v2, v4
    # The retired null version is no longer addressable.
    assert _get(service, "slot.bin", v3).status_code == 404


def test_first_suspended_write_to_a_new_key_is_the_null_version(service):
    _set_versioning(service, SUSPEND)
    reply = _put(service, "fresh.bin", b"null-first")
    assert reply.headers.get("x-amz-version-id")
    assert _get(service, "fresh.bin").content == b"null-first"
    versions, markers = _versions(service, "fresh.bin")
    assert len(versions) == 1 and not markers
    # A suspended DELETE of a key with NO null version removes nothing and
    # just inserts a delete marker (AWS figure: "a delete marker insertion").
    _put(service, "empty-slot.bin", b"data")
    deleted = _delete(service, "empty-slot.bin")
    assert deleted.status_code == 204
    assert deleted.headers.get("x-amz-delete-marker") == "true"
    assert deleted.headers.get("x-amz-version-id")


def test_suspended_delete_inserts_a_null_marker_and_keeps_history(service):
    """AWS: DELETE without VersionId removes the null version and inserts
    a delete marker with the null version ID as the current version."""
    _put(service, "del.bin", b"enabled-v1")
    _put(service, "del.bin", b"enabled-v2")
    _set_versioning(service, SUSPEND)
    null_id = _put(service, "del.bin", b"null-data").headers["x-amz-version-id"]

    deleted = _delete(service, "del.bin")
    assert deleted.status_code == 204
    assert deleted.headers.get("x-amz-delete-marker") == "true"
    assert deleted.headers.get("x-amz-version-id")
    marker_id = deleted.headers["x-amz-version-id"]

    # The current GET reports the marker, not NoSuchKey-without-marker.
    missing = _get(service, "del.bin")
    assert missing.status_code == 404
    assert missing.headers.get("x-amz-delete-marker") == "true"
    assert missing.headers.get("x-amz-version-id") == marker_id

    versions, markers = _versions(service, "del.bin")
    assert len(versions) == 2  # both enabled-era versions survive
    assert len(markers) == 1
    assert markers[0].findtext(NS + "VersionId") == marker_id
    assert markers[0].findtext(NS + "IsLatest") == "true"
    # The null DATA version was permanently removed with the marker insert.
    assert _get(service, "del.bin", null_id).status_code == 404


def test_repeated_suspended_deletes_replace_the_null_marker(service):
    _set_versioning(service, SUSPEND)
    first = _delete(service, "chain.bin")
    assert first.status_code == 204
    second = _delete(service, "chain.bin")
    assert second.status_code == 204
    # Only ONE null version ever exists: the new marker replaced the old.
    _, markers = _versions(service, "chain.bin")
    assert len(markers) == 1
    assert markers[0].findtext(NS + "VersionId") == \
        second.headers["x-amz-version-id"]
    assert first.headers["x-amz-version-id"] != \
        second.headers["x-amz-version-id"]


def test_enabled_mode_contrasts_stack_distinct_markers(service):
    """While Enabled, every DELETE adds a NEW marker version (AWS
    contrast: suspended deletes replace one shared null marker)."""
    _put(service, "stack.bin", b"data")
    first = _delete(service, "stack.bin")
    second = _delete(service, "stack.bin")
    assert first.headers["x-amz-version-id"] != second.headers["x-amz-version-id"]
    _, markers = _versions(service, "stack.bin")
    assert len(markers) == 2
    latest = [m for m in markers if m.findtext(NS + "IsLatest") == "true"]
    assert len(latest) == 1
    assert latest[0].findtext(NS + "VersionId") == second.headers["x-amz-version-id"]


def test_delete_versionid_removes_the_null_version_and_marker(service):
    _put(service, "explicit.bin", b"enabled-v1")
    _set_versioning(service, SUSPEND)
    null_id = _put(service, "explicit.bin", b"null-data").headers["x-amz-version-id"]

    # DELETE ?versionId of the null DATA version removes it; the latest
    # remaining (enabled-era) version becomes current again.
    removed = _delete(service, "explicit.bin", null_id)
    assert removed.status_code == 204
    assert removed.headers.get("x-amz-version-id") == null_id
    assert "x-amz-delete-marker" not in removed.headers
    assert _get(service, "explicit.bin").content == b"enabled-v1"

    # DELETE ?versionId of a null MARKER also removes it.
    marker_id = _delete(service, "explicit.bin").headers["x-amz-version-id"]
    assert _delete(service, "explicit.bin", marker_id).status_code == 204
    assert _get(service, "explicit.bin").content == b"enabled-v1"
    _, markers = _versions(service, "explicit.bin")
    assert not markers


def test_versioned_get_and_head_of_the_null_version(service):
    _put(service, "read.bin", b"enabled-v1")
    _set_versioning(service, SUSPEND)
    null_id = _put(service, "read.bin", b"null-bytes").headers["x-amz-version-id"]

    got = _get(service, "read.bin", null_id)
    assert got.status_code == 200
    assert got.content == b"null-bytes"
    assert got.headers["x-amz-version-id"] == null_id
    head = _head(service, "read.bin", null_id)
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"null-bytes"))
    assert head.headers["x-amz-version-id"] == null_id

    # The null MARKER version answers 405 MethodNotAllowed with the
    # delete-marker headers, exactly like an enabled-bucket marker.
    marker_id = _delete(service, "read.bin").headers["x-amz-version-id"]
    marker_get = _get(service, "read.bin", marker_id)
    assert marker_get.status_code == 405
    assert marker_get.headers.get("x-amz-delete-marker") == "true"
    assert marker_get.headers.get("x-amz-version-id") == marker_id
    assert marker_get.headers.get("allow") == "DELETE"


def test_version_listing_reports_null_slot_states(service):
    _put(service, "list.bin", b"v1")
    _put(service, "list.bin", b"v2")
    _set_versioning(service, SUSPEND)
    null_id = _put(service, "list.bin", b"v3").headers["x-amz-version-id"]

    versions, markers = _versions(service, "list.bin")
    assert len(versions) == 3 and not markers
    latest = [v for v in versions if v.findtext(NS + "IsLatest") == "true"]
    assert [v.findtext(NS + "VersionId") for v in latest] == [null_id]

    _delete(service, "list.bin")
    versions, markers = _versions(service, "list.bin")
    assert len(versions) == 2
    assert all(v.findtext(NS + "IsLatest") == "false" for v in versions)
    assert len(markers) == 1
    assert markers[0].findtext(NS + "IsLatest") == "true"


def test_copy_into_suspended_bucket_occupies_the_null_slot(service):
    """Cross-surface parity: CopyObject behaves like PUT in a suspended
    destination bucket."""
    _put(service, "src.bin", b"source-bytes")
    _put(service, "dst.bin", b"enabled-v1")
    _set_versioning(service, SUSPEND)

    first = signed(service, "PUT", f"/{BUCKET}/dst.bin", extra_headers={
        "x-amz-copy-source": f"/{BUCKET}/src.bin"})
    assert first.status_code == 200, first.text
    assert _get(service, "dst.bin").content == b"source-bytes"
    versions, _ = _versions(service, "dst.bin")
    assert len(versions) == 2  # enabled-v1 preserved + copied NULL version

    second = signed(service, "PUT", f"/{BUCKET}/dst.bin", extra_headers={
        "x-amz-copy-source": f"/{BUCKET}/src.bin"})
    assert second.status_code == 200, second.text
    versions, _ = _versions(service, "dst.bin")
    # The previous copied null version was retired; still one enabled-era.
    assert len(versions) == 2
    ids = {v.findtext(NS + "VersionId") for v in versions}
    assert _get(service, "dst.bin").content == b"source-bytes"
    # A suspended DELETE now inserts the null marker over the copy.
    deleted = _delete(service, "dst.bin")
    assert deleted.headers.get("x-amz-delete-marker") == "true"
    versions, markers = _versions(service, "dst.bin")
    assert len(versions) == 1 and len(markers) == 1
    assert ids  # enabled-era id survived every suspended mutation above


def test_multipart_complete_into_suspended_bucket_occupies_the_null_slot(service):
    """Cross-surface parity: CompleteMultipartUpload behaves like PUT in
    a suspended destination bucket."""
    _put(service, "mpu.bin", b"enabled-v1")
    _set_versioning(service, SUSPEND)

    upload_id = _begin_mpu(service, "mpu.bin")
    etag = _put_part(service, upload_id, 1, os.urandom(5 * 1024 * 1024),
                     "mpu.bin")
    done = _complete_mpu(service, upload_id, [(1, etag)], "mpu.bin")
    mpu_id = done.headers["x-amz-version-id"]
    assert _get(service, "mpu.bin").status_code == 200
    versions, _ = _versions(service, "mpu.bin")
    assert len(versions) == 2  # enabled-v1 preserved + completed NULL version

    # A plain suspended PUT after the MPU retires the completed null
    # version: every suspended surface shares ONE slot.
    null_id = _put(service, "mpu.bin", b"after-mpu").headers["x-amz-version-id"]
    versions, _ = _versions(service, "mpu.bin")
    ids = {v.findtext(NS + "VersionId") for v in versions}
    assert mpu_id not in ids and null_id in ids
    assert len(versions) == 2


def test_buried_null_version_is_retired_after_reenable_cycle(service):
    """The NULL slot survives a re-enable: a later suspended write
    retires the OLD buried null version, not the enabled-era head."""
    _put(service, "cycle.bin", b"enabled-v1")
    _set_versioning(service, SUSPEND)
    buried = _put(service, "cycle.bin", b"null-era").headers["x-amz-version-id"]
    _set_versioning(service, ENABLE)
    enabled_id = _put(service, "cycle.bin", b"enabled-v2").headers["x-amz-version-id"]
    assert _get(service, "cycle.bin").content == b"enabled-v2"

    _set_versioning(service, SUSPEND)
    new_null = _put(service, "cycle.bin", b"null-era-2").headers["x-amz-version-id"]
    versions, _ = _versions(service, "cycle.bin")
    ids = {v.findtext(NS + "VersionId") for v in versions}
    # The buried null version was permanently retired; BOTH enabled-era
    # versions are preserved as history.
    assert buried not in ids
    assert enabled_id in ids and new_null in ids
    assert len(versions) == 3  # enabled-v1, enabled-v2, null-era-2


def test_suspended_delete_of_retained_head_still_refuses(service):
    """TeleDrive's stricter WORM stance is preserved: an ordinary DELETE
    on a suspended bucket whose current head is retained/held is 403 and
    the head stays readable."""
    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    import time as _time

    reply = _put(service, "worm.bin", b"immutable")
    object_id = reply.headers["x-amz-version-id"]
    db = service[3]()
    try:
        from sqlalchemy import text
        db.connection.execute(text(
            "UPDATE storage_objects SET retention_mode = 'GOVERNANCE', "
            "retention_until_ns = :u WHERE id = :o"),
            {"u": _time.time_ns() + 3600 * 10**9, "o": object_id})
        db.connection.commit()
    finally:
        db.close()
    _set_versioning(service, SUSPEND)

    denied = _delete(service, "worm.bin")
    assert denied.status_code == 403, denied.text
    still = _get(service, "worm.bin")
    assert still.status_code == 200 and still.content == b"immutable"
    # Nothing was retired or marked.
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        assert catalog.is_visible_version(BUCKET, "worm.bin", object_id)
        assert catalog._null_slot_version(BUCKET, "worm.bin") is None
    finally:
        db.close()


def test_conditional_delete_in_suspended_bucket_still_cas(service):
    """if-match conditional DELETE keeps its CAS semantics in a suspended
    bucket: a stale ETag is 412 and inserts no marker."""
    reply = _put(service, "cas.bin", b"data")
    etag = reply.headers["etag"]
    _set_versioning(service, SUSPEND)
    stale = _put(service, "cas.bin", b"newer").headers["etag"]

    refused = signed(service, "DELETE", f"/{BUCKET}/cas.bin",
                     extra_headers={"if-match": etag})
    assert refused.status_code == 412, refused.text
    _, markers = _versions(service, "cas.bin")
    assert not markers

    accepted = signed(service, "DELETE", f"/{BUCKET}/cas.bin",
                      extra_headers={"if-match": stale})
    assert accepted.status_code == 204
    assert accepted.headers.get("x-amz-delete-marker") == "true"
