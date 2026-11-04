"""Crash-restart column for the object- and service-level operations.

Companion of ``tests/s3/test_s3_evidence_restart_config.py``: the same
fresh-``Database``/store restart pattern, applied to the remaining open
crash-restart cells that are not single-transaction bucket config
writes:

* CreateBucket / DeleteBucket (the service lifecycle),
* UpdateObjectEncryption (an SSE-C key rotation),
* CreateMultipartUpload and UploadPartCopy (the multipart session
  creates the restart matrix deliberately skipped),
* PutObjectAcl, PutObjectAnnotation, DeleteObjectAnnotation,
* PutObjectRetention, PutObjectLegalHold (per-version lock rows),
* DeleteObjectTagging.

Every case performs the write through the signed gateway, then opens a
brand-new ``Database``/store pair — exactly what a restarted process
would do — and asserts the persisted state reads back exactly, and a
delete stays dead.
"""
from __future__ import annotations

import time
from xml.etree import ElementTree as ET

from sqlalchemy import func, select

from teledrive.s3.annotations import AnnotationStore
from teledrive.s3.cors import cors_config
from teledrive.s3.multipart import MultipartStore
from teledrive.s3.tagging import ObjectTagStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore, objects
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, part, setup, xml_text
from tests.s3.test_s3_sse_c import (
    COPY_PREFIX, KEY_A, KEY_B, make_bucket, ssec_headers,
)
from tests.s3.test_s3_tagging import create, tag_xml

NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _fresh(service):
    """A new Database + catalog, as a restarted process would open them."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _object_id(service, bucket, key):
    db, catalog = _fresh(service)
    try:
        return catalog.get(bucket, key).item.id
    finally:
        db.close()


def _acl_xml(owner: str, grants: list[tuple[str, str]]) -> bytes:
    grants_xml = "".join(
        f'<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:type="CanonicalUser"><ID>{grantee}</ID></Grantee>'
        f"<Permission>{permission}</Permission></Grant>"
        for grantee, permission in grants)
    return (f'<AccessControlPolicy xmlns="{NS}">'
            f"<Owner><ID>{owner}</ID></Owner>"
            f"<AccessControlList>{grants_xml}</AccessControlList>"
            f"</AccessControlPolicy>").encode()


# ---------------------------------------------------------------------------
# Service lifecycle
# ---------------------------------------------------------------------------

def test_create_bucket_survives_a_restart(service):
    assert signed(service, "PUT", "/restart-created").status_code == 200

    db, catalog = _fresh(service)
    try:
        assert "restart-created" in catalog.list_buckets(), (
            "a created bucket vanished after a restart")
        # A restart must not duplicate the row either.
        assert catalog.list_buckets().count("restart-created") == 1
    finally:
        db.close()
    assert signed(service, "HEAD", "/restart-created").status_code == 200


def test_delete_bucket_stays_dead_after_a_restart(service):
    assert signed(service, "PUT", "/restart-deleted").status_code == 200
    # Attach governance state a recreated bucket must never inherit.
    assert signed(service, "PUT", "/restart-deleted?cors",
                  _cors_xml()).status_code == 200
    assert signed(service, "DELETE", "/restart-deleted").status_code == 204

    db, catalog = _fresh(service)
    try:
        assert "restart-deleted" not in catalog.list_buckets(), (
            "a deleted bucket resurrected after a restart")
        assert db.connection.execute(select(
            func.count()).select_from(cors_config).where(
            cors_config.c.bucket == "restart-deleted")).scalar_one() == 0, (
            "the deleted bucket left its CORS configuration behind")
    finally:
        db.close()
    assert signed(service, "HEAD", "/restart-deleted").status_code == 404
    # The same name is creatable again, with none of the old state.
    assert signed(service, "PUT", "/restart-deleted").status_code == 200
    assert signed(service, "GET", "/restart-deleted?cors").status_code == 404


def _cors_xml() -> bytes:
    root = ET.Element("CORSConfiguration")
    rule = ET.SubElement(root, "CORSRule")
    ET.SubElement(rule, "AllowedOrigin").text = "https://app.example.com"
    ET.SubElement(rule, "AllowedMethod").text = "GET"
    return ET.tostring(root)


# ---------------------------------------------------------------------------
# UpdateObjectEncryption (SSE-C key rotation)
# ---------------------------------------------------------------------------

def test_update_object_encryption_survives_a_restart(service):
    make_bucket(service)
    payload = b"rotated-across-a-restart"
    assert signed(service, "PUT", "/sse-bucket/rotate.bin", payload,
                  extra_headers=ssec_headers(KEY_A)).status_code == 200
    rotation = signed(
        service, "PUT", "/sse-bucket/rotate.bin?encryption", b"",
        extra_headers={**ssec_headers(KEY_B),
                       **ssec_headers(KEY_A, prefix=COPY_PREFIX)})
    assert rotation.status_code == 200, rotation.text

    # Restart: only the NEW key can read the object, and the bytes are
    # exactly the original payload.
    db, _catalog = _fresh(service)
    try:
        row = db.connection.execute(select(
            objects.c.id).where(
            objects.c.bucket == "sse-bucket",
            objects.c.object_key == "rotate.bin")).scalars().all()
        assert row, "the rotated object vanished after a restart"
    finally:
        db.close()

    fresh = signed(service, "GET", "/sse-bucket/rotate.bin",
                   extra_headers=ssec_headers(KEY_B))
    assert fresh.status_code == 200, fresh.text
    assert fresh.content == payload
    stale = signed(service, "GET", "/sse-bucket/rotate.bin",
                   extra_headers=ssec_headers(KEY_A))
    assert stale.status_code == 400, (
        "the pre-rotation key still works after a restart")


# ---------------------------------------------------------------------------
# Multipart session creates
# ---------------------------------------------------------------------------

def test_create_multipart_upload_survives_a_restart(service):
    setup(service)
    uid = begin(service)

    db, mpu = _fresh_mpu(service)
    try:
        # The session is durable SQL state: a new process still sees it.
        row = mpu.require(uid, "backup-bucket", "asset.bin",
                          service[1].access_key)
        assert row["state"] == "active"
        assert [upload for upload in mpu.list_uploads(
            "backup-bucket", service[1].access_key)[0]
            if upload[0] == uid], "the upload is not listed after a restart"
    finally:
        db.close()

    # And it remains usable: a part staged after the restart completes.
    etag = part(service, uid, 1, b"begun-before-restart")
    done = complete(service, uid, [(1, etag)])
    assert done.status_code == 200, done.text
    assert signed(service, "GET",
                  "/backup-bucket/asset.bin").content == b"begun-before-restart"

    # Negative: an abort after the restart still kills the finished session
    # listing (the finished session cannot come back as active).
    db2, mpu2 = _fresh_mpu(service)
    try:
        assert [upload for upload in mpu2.list_uploads(
            "backup-bucket", service[1].access_key)[0]
            if upload[0] == uid] == []
    finally:
        db2.close()


def test_upload_part_copy_survives_a_restart(service):
    setup(service)
    source = b"c" * (5 * 1024 * 1024 + 11)
    assert signed(service, "PUT", "/backup-bucket/source.bin",
                  source).status_code == 200
    uid = begin(service, key="copied.bin")
    copied = signed(
        service, "PUT",
        f"/backup-bucket/copied.bin?partNumber=1&uploadId={uid}",
        extra_headers={"x-amz-copy-source": "/backup-bucket/source.bin"})
    assert copied.status_code == 200, copied.text
    etag = f'"{xml_text(copied, "ETag")}"'

    # Restart: the copied part is still staged for the session.
    db, mpu = _fresh_mpu(service)
    try:
        stored = mpu.list_parts_page(uid, "backup-bucket", "copied.bin",
                                      service[1].access_key)[0]
        assert [(row[0], row[2]) for row in stored] == [
            (1, etag.strip('"'))]
    finally:
        db.close()

    tail = part(service, uid, 2, b"copy-tail", key="copied.bin")
    done = complete(service, uid, [(1, etag), (2, tail)], key="copied.bin")
    assert done.status_code == 200, done.text
    body = signed(service, "GET", "/backup-bucket/copied.bin")
    assert body.status_code == 200
    assert body.content == source + b"copy-tail"


def _fresh_mpu(service):
    db, catalog = _fresh(service)
    return db, MultipartStore(catalog)


# ---------------------------------------------------------------------------
# Object ACL
# ---------------------------------------------------------------------------

def test_put_object_acl_survives_a_restart(service):
    assert signed(service, "PUT", "/restart-obj-acl").status_code == 200
    assert signed(service, "PUT", "/restart-obj-acl/data.bin",
                  b"acl-payload").status_code == 200
    from teledrive.s3.credentials import S3CredentialStore
    db = service[3]()
    try:
        other = S3CredentialStore(db, service[4]).create(
            "object-acl-grantee", ["s3:GetObject"])
    finally:
        db.close()
    owner = service[1].access_key
    grants = [(other.access_key, "READ")]
    assert signed(service, "PUT", "/restart-obj-acl/data.bin?acl",
                  _acl_xml(owner, grants)).status_code == 200

    db, catalog = _fresh(service)
    try:
        stored_owner, stored_grants = catalog.object_acl(
            "restart-obj-acl", "data.bin")
        assert stored_owner == owner
        assert sorted(stored_grants) == sorted(
            grants + [(owner, "FULL_CONTROL")])
    finally:
        db.close()
    read = signed(service, "GET", "/restart-obj-acl/data.bin?acl")
    assert read.status_code == 200
    assert other.access_key.encode() in read.content


# ---------------------------------------------------------------------------
# Object annotations
# ---------------------------------------------------------------------------

def _annotation(service, name, value, method="PUT"):
    from urllib.parse import quote
    path = (f"/annotations/doc.txt?annotation"
            f"&annotationName={quote(name, safe='')}")
    return signed(service, method, path, value)


def test_put_object_annotation_survives_a_restart(service):
    assert signed(service, "PUT", "/annotations").status_code == 200
    assert signed(service, "PUT", "/annotations/doc.txt",
                  b"annotated-payload").status_code == 200
    assert _annotation(service, "summary",
                       b"survives a restart").status_code == 200
    object_id = _object_id(service, "annotations", "doc.txt")

    db, catalog = _fresh(service)
    try:
        stored = AnnotationStore(catalog).get(object_id, "summary")
        assert stored is not None, "the annotation vanished after a restart"
        assert stored["value"] == "survives a restart"
        assert AnnotationStore(catalog).count(object_id) == 1
    finally:
        db.close()
    read = _annotation(service, "summary", b"", method="GET")
    assert read.status_code == 200
    assert read.content == b"survives a restart"


def test_delete_object_annotation_stays_dead_after_a_restart(service):
    assert signed(service, "PUT", "/annotations").status_code == 200
    assert signed(service, "PUT", "/annotations/doc.txt",
                  b"annotated-payload").status_code == 200
    assert _annotation(service, "summary", b"doomed").status_code == 200
    assert _annotation(service, "summary", b"", method="DELETE").status_code == 204
    object_id = _object_id(service, "annotations", "doc.txt")

    db, catalog = _fresh(service)
    try:
        store = AnnotationStore(catalog)
        assert store.get(object_id, "summary") is None, (
            "a deleted annotation resurrected after a restart")
        assert store.count(object_id) == 0
    finally:
        db.close()
    assert _annotation(service, "summary", b"", method="GET").status_code == 404


# ---------------------------------------------------------------------------
# Object lock rows (retention, legal hold)
# ---------------------------------------------------------------------------

def test_put_object_retention_survives_a_restart(service):
    assert signed(service, "PUT", "/restart-lock").status_code == 200
    put = signed(service, "PUT", "/restart-lock/worm.bin", b"retained")
    assert put.status_code == 200
    version = put.headers["x-amz-version-id"]
    until = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                          time.gmtime(time.time() + 3600))
    body = (f'<Retention xmlns="{NS}"><Mode>COMPLIANCE</Mode>'
            f"<RetainUntilDate>{until}</RetainUntilDate>"
            f"</Retention>").encode()
    assert signed(service, "PUT", "/restart-lock/worm.bin?retention",
                  body).status_code == 200

    db, catalog = _fresh(service)
    try:
        state = catalog.object_lock_state(version)
        assert state["mode"] == "COMPLIANCE", (
            "the retention mode vanished after a restart")
        assert state["retain_until_ns"] is not None
        assert state["retain_until_ns"] > time.time_ns(), (
            "the retention window did not survive the restart")
    finally:
        db.close()
    read = signed(service, "GET", "/restart-lock/worm.bin?retention")
    assert read.status_code == 200
    assert b"COMPLIANCE" in read.content
    # The WORM fence is enforced by a restarted process too.
    assert signed(service, "DELETE",
                  f"/restart-lock/worm.bin?versionId={version}"
                  ).status_code == 403


def test_put_object_legal_hold_survives_a_restart(service):
    assert signed(service, "PUT", "/restart-lock").status_code == 200
    put = signed(service, "PUT", "/restart-lock/hold.bin", b"held")
    assert put.status_code == 200
    version = put.headers["x-amz-version-id"]
    body = (f'<LegalHold xmlns="{NS}"><Status>ON</Status>'
            f"</LegalHold>").encode()
    assert signed(service, "PUT", "/restart-lock/hold.bin?legal-hold",
                  body).status_code == 200

    db, catalog = _fresh(service)
    try:
        assert catalog.object_lock_state(version)["legal_hold"] is True, (
            "the legal hold vanished after a restart")
    finally:
        db.close()
    read = signed(service, "GET", "/restart-lock/hold.bin?legal-hold")
    assert read.status_code == 200
    assert b"<Status>ON</Status>" in read.content
    assert signed(service, "DELETE",
                  f"/restart-lock/hold.bin?versionId={version}"
                  ).status_code == 403


# ---------------------------------------------------------------------------
# Object tagging (delete)
# ---------------------------------------------------------------------------

def test_delete_object_tagging_stays_dead_after_a_restart(service):
    create(service)
    assert signed(service, "PUT", "/backup-bucket/file.bin?tagging",
                  tag_xml([("layer", "object")])).status_code == 200
    assert signed(service, "DELETE",
                  "/backup-bucket/file.bin?tagging").status_code == 204
    object_id = _object_id(service, "backup-bucket", "file.bin")

    db, catalog = _fresh(service)
    try:
        assert ObjectTagStore(catalog).get(object_id) == [], (
            "a deleted object tag set resurrected after a restart")
    finally:
        db.close()
    cleared = signed(service, "GET", "/backup-bucket/file.bin?tagging")
    assert cleared.status_code == 200
    assert b"<Tag>" not in cleared.content
