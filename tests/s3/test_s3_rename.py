"""Phase O4: RenameObject is one SQL transaction, never a Telegram copy.

Wire shape: POST /{bucket}/{destination}?rename with the source in the signed
``x-amz-rename-source: bucket/source`` header (the AWS directory-bucket shape).
TeleDrive additionally supports standard buckets; that superset is documented
in web/s3.py::_handle_object_rename and teledrive/storage/catalog.py.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.tagging import (
    ObjectTagStore, journal_pending_tags_uncommitted,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def _catalog(service):
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _rename(service, bucket, destination, source, **kwargs):
    return signed(
        service, "POST", f"/{bucket}/{destination}?rename",
        extra_headers={"x-amz-rename-source": f"{bucket}/{source}"},
        **kwargs,
    )


def _seed(service, bucket="rename-bucket"):
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    response = signed(
        service, "PUT", f"/{bucket}/source.bin", b"rename-me",
        extra_headers={
            "Content-Type": "application/json",
            "x-amz-meta-color": "blue",
            "x-amz-tagging": "team=storage",
        },
    )
    assert response.status_code == 200, response.text


def test_rename_moves_head_and_chunks_without_touching_telegram(service):
    _seed(service)
    telegram = service[2]
    uploads = telegram.uploads
    db, catalog = _catalog(service)
    try:
        source = catalog.get("rename-bucket", "source.bin")
        parts_before = [(part.ordinal, part.message_id, part.sha256)
                        for part in catalog.manifests.parts(source.item.id)]
    finally:
        db.close()
    response = _rename(service, "rename-bucket", "destination.bin", "source.bin")
    assert response.status_code == 200, response.text
    assert telegram.uploads == uploads
    assert signed(service, "GET", "/rename-bucket/destination.bin").content == b"rename-me"
    assert signed(service, "GET", "/rename-bucket/source.bin").status_code == 404
    db, catalog = _catalog(service)
    try:
        moved = catalog.get("rename-bucket", "destination.bin")
        assert moved.item.id == source.item.id
        assert moved.item.key == "destination.bin"
        assert moved.generation == source.generation + 1
        assert [(part.ordinal, part.message_id, part.sha256)
                for part in catalog.manifests.parts(moved.item.id)] == parts_before
        assert catalog.is_visible_version(
            "rename-bucket", "destination.bin", moved.item.id)
    finally:
        db.close()


def test_rename_refuses_existing_destination(service):
    _seed(service)
    assert signed(service, "PUT", "/rename-bucket/occupied.bin", b"keep").status_code == 200
    response = _rename(service, "rename-bucket", "occupied.bin", "source.bin")
    assert response.status_code == 409, response.text
    assert ET.fromstring(response.content).findtext("Code") == "OperationAborted"
    assert signed(service, "GET", "/rename-bucket/occupied.bin").content == b"keep"
    assert signed(service, "GET", "/rename-bucket/source.bin").content == b"rename-me"


def test_rename_is_same_bucket_only(service):
    _seed(service)
    assert signed(service, "PUT", "/other-bucket").status_code == 200
    response = signed(
        service, "POST", "/rename-bucket/destination.bin?rename",
        extra_headers={"x-amz-rename-source": "other-bucket/source.bin"},
    )
    assert response.status_code == 400, response.text
    assert ET.fromstring(response.content).findtext("Code") == "InvalidRequest"
    assert signed(service, "GET", "/rename-bucket/source.bin").content == b"rename-me"


def test_object_lock_blocks_rename(service):
    _seed(service)
    db, catalog = _catalog(service)
    try:
        source = catalog.get("rename-bucket", "source.bin")
        catalog.set_retention(
            source.item.id, mode="GOVERNANCE",
            until_ns=__import__("time").time_ns() + 86_400 * 1_000_000_000,
        )
    finally:
        db.close()
    response = _rename(service, "rename-bucket", "destination.bin", "source.bin")
    assert response.status_code == 403, response.text
    assert ET.fromstring(response.content).findtext("Code") == "AccessDenied"
    assert signed(service, "GET", "/rename-bucket/source.bin").content == b"rename-me"


def test_rename_acl_enforced_on_source_and_destination(service):
    _seed(service)
    db = service[3]()
    try:
        store = S3CredentialStore(db, service[4])
        mover = store.create(
            "rename-mover",
            ["s3:RenameObject", "s3:GetObject", "s3:PutObject"],
        )
        catalog = BucketCatalog(ManifestStore(db))
        # Phase L5: object-ACL grants only apply under ObjectWriter (the
        # default BucketOwnerEnforced ignores them by design).
        catalog.set_object_ownership("rename-bucket", "ObjectWriter")
        # Source ACL restricts READ to the owning credential only.
        catalog.set_object_acl(
            "rename-bucket", "source.bin", service[1].access_key,
            [(service[1].access_key, "FULL_CONTROL")],
        )
    finally:
        db.close()
    denied = _rename(
        service, "rename-bucket", "destination.bin", "source.bin",
        access=mover.access_key, secret=mover.secret_key,
    )
    assert denied.status_code == 403, denied.text
    assert ET.fromstring(denied.content).findtext("Code") == "AccessDenied"
    assert signed(service, "GET", "/rename-bucket/source.bin").content == b"rename-me"

    # Allow source READ for the mover, but restrict destination WRITE.
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        catalog.set_object_acl(
            "rename-bucket", "source.bin", service[1].access_key,
            [(service[1].access_key, "FULL_CONTROL"), (mover.access_key, "READ")],
        )
        catalog.set_object_acl(
            "rename-bucket", "destination.bin", service[1].access_key,
            [(service[1].access_key, "FULL_CONTROL")],
        )
    finally:
        db.close()
    denied = _rename(
        service, "rename-bucket", "destination.bin", "source.bin",
        access=mover.access_key, secret=mover.secret_key,
    )
    assert denied.status_code == 403, denied.text
    assert signed(service, "GET", "/rename-bucket/destination.bin").status_code == 404


def test_tags_metadata_and_pending_journal_follow_the_object(service):
    _seed(service)
    db, catalog = _catalog(service)
    try:
        source = catalog.get("rename-bucket", "source.bin")
        source_id = source.item.id
        journal_pending_tags_uncommitted(
            db.connection, source_id, [("pending", "yes")], service[1].access_key)
        db.commit()
        pending_before = ObjectTagStore(catalog).get_pending(source_id)
    finally:
        db.close()
    assert pending_before == [("pending", "yes")]
    assert _rename(
        service, "rename-bucket", "destination.bin", "source.bin",
    ).status_code == 200
    tagging = signed(service, "GET", "/rename-bucket/destination.bin?tagging")
    assert tagging.status_code == 200
    assert tagging.content.count(b"<Key>team</Key>") == 1
    head = signed(service, "HEAD", "/rename-bucket/destination.bin")
    assert head.headers["content-type"] == "application/json"
    assert head.headers["x-amz-meta-color"] == "blue"
    db, catalog = _catalog(service)
    try:
        # The journal is keyed by object ID, so an atomic head move cannot
        # orphan it; it remains attached to the same version at the new key.
        assert ObjectTagStore(catalog).get_pending(source_id) == [("pending", "yes")]
        assert catalog.object_acl("rename-bucket", "destination.bin")[0] is None
    finally:
        db.close()


def test_rename_permission_and_route_guard(service):
    _seed(service)
    db = service[3]()
    try:
        store = S3CredentialStore(db, service[4])
        no_rename = store.create("swap-only", ["s3:GetObject", "s3:PutObject"])
    finally:
        db.close()
    denied = _rename(
        service, "rename-bucket", "destination.bin", "source.bin",
        access=no_rename.access_key, secret=no_rename.secret_key,
    )
    assert denied.status_code == 403
    assert ET.fromstring(denied.content).findtext("Code") == "AccessDenied"
    # Non-POST methods and a missing signed source fail closed.
    assert signed(service, "GET", "/rename-bucket/source.bin?rename").status_code == 501
    assert signed(service, "PUT", "/rename-bucket/source.bin?rename").status_code == 501
    missing = signed(service, "POST", "/rename-bucket/destination.bin?rename")
    assert missing.status_code == 400
    assert signed(service, "GET", "/rename-bucket/source.bin").content == b"rename-me"
