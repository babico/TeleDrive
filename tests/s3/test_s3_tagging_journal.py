"""Phase J: deferred object-tag journal for READY-but-unpublished versions.

A tagging write against a version that is not published yet must be
journaled, applied in the same SQL transaction as the publish head move,
and never exposed through GetObjectTagging before publication.
"""
from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from hashlib import sha256

import pytest
from sqlalchemy import delete, select

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.tagging import ObjectTagStore, TaggingError, pending_tags
from teledrive.storage.catalog import BucketCatalog, heads, published_versions
from teledrive.storage.manifest import ManifestStore, objects
from tests.s3.test_s3_gateway import service, signed

_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def tag_xml(entries):
    root = ET.Element("Tagging")
    tag_set = ET.SubElement(root, "TagSet")
    for key, value in entries:
        item = ET.SubElement(tag_set, "Tag")
        ET.SubElement(item, "Key").text = key
        ET.SubElement(item, "Value").text = value
    return ET.tostring(root, encoding="utf-8")


def extract_tags(response):
    assert response.status_code == 200, response.text
    root = ET.fromstring(response.content)
    return [(tag.findtext(_NS + "Key"), tag.findtext(_NS + "Value"))
            for tag in root.findall(_NS + "TagSet/" + _NS + "Tag")]


def stage_object(service, *, key="staged.bin", bucket="backup-bucket"):
    """Create a READY manifest that no head/published-version row references."""
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        now = int(time.time())
        identifier = catalog.manifests.begin(bucket, key, 0, now)
        catalog.manifests.finish(identifier, sha256(b"").hexdigest(), now)
        return identifier
    finally:
        db.close()


def pending_rows(service, identifier):
    db = service[3]()
    try:
        ObjectTagStore(BucketCatalog(ManifestStore(db)))
        return db.connection.execute(
            select(pending_tags.c.tags, pending_tags.c.actor).where(
                pending_tags.c.object_id == identifier)
        ).all()
    finally:
        db.close()


def catalog_for(service):
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


@pytest.fixture
def bucket(service):
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    return "backup-bucket"


def test_staged_tagging_journals_instead_of_failing_and_get_does_not_leak(
        service, bucket):
    staged = stage_object(service)
    url = f"/backup-bucket/staged.bin?tagging&versionId={staged}"

    written = signed(service, "PUT", url,
                     tag_xml([("env", "staging"), ("owner", "ci")]))
    assert written.status_code == 200, written.text
    assert written.headers["x-amz-version-id"] == staged

    rows = pending_rows(service, staged)
    assert len(rows) == 1
    assert json.loads(rows[0][0]) == [["env", "staging"], ["owner", "ci"]]
    assert rows[0][1] == service[1].access_key

    # No real version tag exists before publication.
    db, catalog = catalog_for(service)
    try:
        assert ObjectTagStore(catalog).get(staged) == []
        assert ObjectTagStore(catalog).get_pending(staged) == [
            ("env", "staging"), ("owner", "ci")]
    finally:
        db.close()

    # GET must not disclose the staged journal.
    leaked = signed(service, "GET", url)
    assert leaked.status_code == 404
    assert b"NoSuchVersion" in leaked.content
    assert b"staging" not in leaked.content


def test_publish_applies_journal_atomically_and_clears_it(service, bucket):
    staged = stage_object(service)
    url = f"/backup-bucket/staged.bin?tagging&versionId={staged}"
    assert signed(service, "PUT", url,
                  tag_xml([("phase", "J"), ("state", "pending")])).status_code == 200
    assert pending_rows(service, staged)

    db, catalog = catalog_for(service)
    try:
        head = catalog.publish(staged, now=int(time.time()))
        assert head.item.id == staged
        assert ObjectTagStore(catalog).get(staged) == [
            ("phase", "J"), ("state", "pending")]
        assert ObjectTagStore(catalog).get_pending(staged) is None
    finally:
        db.close()
    assert pending_rows(service, staged) == []

    assert extract_tags(signed(service, "GET", url)) == [
        ("phase", "J"), ("state", "pending")]
    assert extract_tags(signed(service, "GET", "/backup-bucket/staged.bin?tagging")) == [
        ("phase", "J"), ("state", "pending")]


def test_failed_publish_leaves_no_visible_tags_and_no_applied_state(
        service, bucket, monkeypatch):
    staged = stage_object(service)
    url = f"/backup-bucket/staged.bin?tagging&versionId={staged}"
    assert signed(service, "PUT", url,
                  tag_xml([("retry", "yes")])).status_code == 200

    db, catalog = catalog_for(service)
    try:
        with pytest.raises(ValueError):
            catalog.publish(staged, now=int(time.time()), expected_generation=7)
        assert ObjectTagStore(catalog).get(staged) == []
        assert ObjectTagStore(catalog).get_pending(staged) == [("retry", "yes")]
        with pytest.raises(FileNotFoundError):
            catalog.get(bucket, "staged.bin")
    finally:
        db.close()

    # A failure while applying the journal rolls the whole publish back.
    import teledrive.s3.tagging as tagging_mod
    original = tagging_mod.apply_pending_tags_uncommitted

    def failing_apply(connection, object_id):
        original(connection, object_id)
        raise RuntimeError("injected journal failure")

    monkeypatch.setattr(tagging_mod, "apply_pending_tags_uncommitted",
                        failing_apply)
    db, catalog = catalog_for(service)
    try:
        with pytest.raises(RuntimeError):
            catalog.publish(staged, now=int(time.time()))
        assert ObjectTagStore(catalog).get(staged) == []
        assert ObjectTagStore(catalog).get_pending(staged) == [("retry", "yes")]
        assert db.connection.execute(select(heads.c.object_id).where(
            heads.c.object_id == staged)).first() is None
        assert db.connection.execute(select(published_versions.c.object_id).where(
            published_versions.c.object_id == staged)).first() is None
    finally:
        db.close()
    assert signed(service, "GET", url).status_code == 404


def test_delete_tagging_on_staged_clears_the_journal(service, bucket):
    staged = stage_object(service)
    url = f"/backup-bucket/staged.bin?tagging&versionId={staged}"
    assert signed(service, "PUT", url,
                  tag_xml([("old", "tags")])).status_code == 200
    assert pending_rows(service, staged)

    removed = signed(service, "DELETE", url)
    assert removed.status_code == 204
    assert pending_rows(service, staged) == []

    db, catalog = catalog_for(service)
    try:
        catalog.publish(staged, now=int(time.time()))
        assert ObjectTagStore(catalog).get(staged) == []
    finally:
        db.close()
    assert extract_tags(signed(service, "GET", url)) == []


def test_published_version_tagging_is_unchanged(service, bucket):
    assert signed(service, "PUT", "/backup-bucket/published.bin",
                  b"published-body").status_code == 200
    db, catalog = catalog_for(service)
    try:
        identifier = catalog.get(bucket, "published.bin").item.id
    finally:
        db.close()
    url = f"/backup-bucket/published.bin?tagging&versionId={identifier}"
    assert signed(service, "PUT", url,
                  tag_xml([("real", "version")])).status_code == 200
    assert pending_rows(service, identifier) == []
    assert extract_tags(signed(service, "GET", url)) == [("real", "version")]
    assert signed(service, "DELETE", url).status_code == 204
    assert extract_tags(signed(service, "GET", url)) == []


def test_journal_cleanup_on_version_revocation(service, bucket):
    assert signed(service, "PUT", "/backup-bucket/revoked.bin",
                  b"revoked-body").status_code == 200
    db, catalog = catalog_for(service)
    try:
        identifier = catalog.get(bucket, "revoked.bin").item.id
        tagger = ObjectTagStore(catalog)
        # Simulate an orphan journal that survived a failed publication
        # attempt for an already-published version.
        from teledrive.s3.tagging import journal_pending_tags_uncommitted
        journal_pending_tags_uncommitted(
            db.connection, identifier, [("orphan", "row")], "ci")
        db.commit()
        assert tagger.get_pending(identifier) == [("orphan", "row")]
        assert catalog.delete_version(bucket, "revoked.bin", identifier)
        assert tagger.get_pending(identifier) is None
    finally:
        db.close()


def test_journal_cleanup_on_bucket_delete(service):
    assert signed(service, "PUT", "/journal-bucket").status_code == 200
    staged = stage_object(service, key="pending.bin", bucket="journal-bucket")
    url = f"/journal-bucket/pending.bin?tagging&versionId={staged}"
    assert signed(service, "PUT", url,
                  tag_xml([("bucket", "cleanup")])).status_code == 200
    assert pending_rows(service, staged)

    db, catalog = catalog_for(service)
    try:
        # Bucket deletion refuses real object history; simulate the
        # post-GC empty-bucket state that leaves only an unreclaimable
        # journal row behind.
        db.connection.execute(delete(objects).where(objects.c.id == staged))
        db.commit()
        catalog.delete_bucket("journal-bucket")
        assert db.connection.execute(select(pending_tags.c.object_id).where(
            pending_tags.c.object_id == staged)).first() is None
    finally:
        db.close()


def test_staged_tag_grammar_is_still_strictly_validated(service, bucket):
    staged = stage_object(service)
    url = f"/backup-bucket/staged.bin?tagging&versionId={staged}"
    invalid_sets = [
        [("duplicate", "a"), ("duplicate", "b")],
        [(f"k{n}", "v") for n in range(11)],
        [("aws:reserved", "no")],
        [("", "invalid")],
        [("k" * 129, "v")],
        [("k", "v" * 257)],
    ]
    for entries in invalid_sets:
        rejected = signed(service, "PUT", url, tag_xml(entries))
        assert rejected.status_code == 400, (entries, rejected.text)
        assert b"InvalidTag" in rejected.content
    assert pending_rows(service, staged) == []


def test_staged_tagging_requires_put_and_delete_permissions(service, bucket):
    staged = stage_object(service)
    db = service[3]()
    try:
        reader = S3CredentialStore(db, service[4]).create(
            "tag-reader-only", ["s3:GetObjectTagging"])
    finally:
        db.close()
    url = f"/backup-bucket/staged.bin?tagging&versionId={staged}"
    denied_put = signed(service, "PUT", url, tag_xml([("no", "write")]),
                        access=reader.access_key, secret=reader.secret_key)
    assert denied_put.status_code == 403
    assert pending_rows(service, staged) == []

    assert signed(service, "PUT", url,
                  tag_xml([("ok", "write")])).status_code == 200
    denied_delete = signed(service, "DELETE", url,
                           access=reader.access_key, secret=reader.secret_key)
    assert denied_delete.status_code == 403
    assert pending_rows(service, staged)


def test_pending_journal_is_not_visible_through_a_published_replacement(
        service, bucket):
    """A later published version of the same key never inherits staged tags."""
    assert signed(service, "PUT", "/backup-bucket/same-key.bin",
                  b"v1").status_code == 200
    staged = stage_object(service, key="same-key.bin")
    url = f"/backup-bucket/same-key.bin?tagging&versionId={staged}"
    assert signed(service, "PUT", url,
                  tag_xml([("staged", "secret")])).status_code == 200
    assert extract_tags(
        signed(service, "GET", "/backup-bucket/same-key.bin?tagging")) == []
    assert signed(service, "GET", url).status_code == 404
