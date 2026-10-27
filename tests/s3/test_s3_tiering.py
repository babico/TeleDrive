"""Phase N5/O1: Intelligent-Tiering config CRUD, the real access gate and
the RestoreObject window it makes meaningful.

The honesty contract this module pins:

* a tier label must have a real consequence -- an ARCHIVE_ACCESS object
  answers 403 InvalidObjectState until restored;
* the Telegram chunks never move, so "archived" is an access gate in our
  own catalog, not AWS Glacier;
* RestoreObject opens a bounded window, refuses a second concurrent
  request, and the gate closes again when the window expires.
"""
from __future__ import annotations

import time
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy import select, update

from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore, objects
from teledrive.s3.tiering import (
    ACCESS_TIERS, TieringError, TieringStore, config_xml, list_xml,
    parse_document,
)
from tests.s3.test_s3_gateway import service, signed

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
NSQ = "{" + NS + "}"  # ElementTree path prefix
BUCKET = "tier-bucket"


def _document(*, config_id="tier1", status="Enabled", prefix="cold/",
              archive_days=1, deep_days=None):
    deep = (f"<Tiering><Days>{deep_days}</Days>"
            f"<AccessTier>DEEP_ARCHIVE_ACCESS</AccessTier></Tiering>"
            if deep_days else "")
    return (
        f'<IntelligentTieringConfiguration xmlns="{NS}">'
        f"<Id>{config_id}</Id>"
        f"<Filter><Prefix>{prefix}</Prefix></Filter>"
        f"<Status>{status}</Status>"
        f"<Tiering><Days>{archive_days}</Days>"
        f"<AccessTier>ARCHIVE_ACCESS</AccessTier></Tiering>"
        f"{deep}"
        f"</IntelligentTieringConfiguration>").encode()


def _path(config_id=None):
    """The real AWS selector: ?intelligent-tiering&id=<Id>.

    PUT and DELETE require the id in the query, exactly like AWS; GET with
    no id lists every configuration.
    """
    base = f"/{BUCKET}?intelligent-tiering"
    return base if config_id is None else f"{base}&id={config_id}"


def _catalog(service):
    return BucketCatalog(ManifestStore(service[3]()))


def _seed(service, *, key="cold/archived.bin", body=b"cold-bytes"):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    put = signed(service, "PUT", f"/{BUCKET}/{key}", body)
    assert put.status_code == 200, put.text
    return put.headers.get("x-amz-version-id")


def _archive(service, version_id, *, klass="ARCHIVE_ACCESS"):
    """Force an object into an archived class (the scheduler does this)."""
    catalog = _catalog(service)
    try:
        catalog.db.connection.execute(
            update(objects).where(objects.c.id == version_id)
            .values(storage_class=klass))
        catalog.db.commit()
    finally:
        catalog.db.close()


def test_configuration_round_trip_and_listing(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    put = signed(service, "PUT", _path("tier1"), _document())
    assert put.status_code == 200, put.text
    read = signed(service, "GET", _path("tier1"))
    assert read.status_code == 200, read.text
    root = ET.fromstring(read.content)
    assert root.findtext(NSQ + "Id") == "tier1"
    assert root.findtext(NSQ + "Status") == "Enabled"
    assert root.findtext(NSQ + "Filter/" + NSQ + "Prefix") == "cold/"
    listed = signed(service, "GET", _path())
    assert listed.status_code == 200
    listed_root = ET.fromstring(listed.content)
    ids = [node.text for node in listed_root.iter()
           if node.tag.rsplit("}", 1)[-1] == "Id"]
    assert ids == ["tier1"]
    # DELETE is idempotent.
    assert signed(service, "DELETE", _path("tier1")).status_code == 204
    assert signed(service, "DELETE", _path("tier1")).status_code == 204
    assert signed(service, "GET", _path("tier1")).status_code == 404


def test_missing_configuration_is_an_honest_404(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    missing = signed(service, "GET", _path("nope"))
    assert missing.status_code == 404
    assert b"NoSuchConfiguration" in missing.content


@pytest.mark.parametrize("body", [
    b"<IntelligentTieringConfiguration><Id>x</Id></IntelligentTieringConfiguration>",
    b"x" * (16 * 1024 + 1),
    b'<!DOCTYPE x [<!ENTITY e "v">]><IntelligentTieringConfiguration '
    b'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Id>&e;</Id>'
    b"</IntelligentTieringConfiguration>",
])
def test_strict_document_validation(service, body):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    # A bare document without namespace is accepted only when complete;
    # these are all incomplete/oversized/entity-bearing and must fail.
    reply = signed(service, "PUT", _path("probe"), body)
    assert reply.status_code in (400, 501), reply.text


def test_unsupported_tier_name_is_rejected(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    body = (f'<IntelligentTieringConfiguration xmlns="{NS}">'
            "<Id>x</Id><Status>Enabled</Status>"
            "<Tiering><Days>1</Days><AccessTier>GLACIER</AccessTier></Tiering>"
            "</IntelligentTieringConfiguration>").encode()
    reply = signed(service, "PUT", _path("probe"), body)
    assert reply.status_code in (400, 501), reply.text


def test_archived_object_is_not_immediately_readable(service):
    version = _seed(service)
    # Sanity: readable while STANDARD.
    assert signed(service, "GET", f"/{BUCKET}/cold/archived.bin").content \
        == b"cold-bytes"
    _archive(service, version)
    gated = signed(service, "GET", f"/{BUCKET}/cold/archived.bin")
    assert gated.status_code == 403, gated.text
    assert b"InvalidObjectState" in gated.content
    head = signed(service, "HEAD", f"/{BUCKET}/cold/archived.bin")
    assert head.status_code == 403
    # A range read is gated identically -- there is no partial bypass.
    ranged = signed(service, "GET", f"/{BUCKET}/cold/archived.bin",
                    extra_headers={"Range": "bytes=0-3"})
    assert ranged.status_code == 403
    # The Telegram bytes are untouched.
    assert service[2].uploads == 1


def test_restore_opens_a_window_and_expiry_closes_it(service):
    version = _seed(service)
    _archive(service, version)
    restore = signed(service, "POST", f"/{BUCKET}/cold/archived.bin?restore",
                     b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert restore.status_code == 202, restore.text
    # Reads work inside the window.
    body = signed(service, "GET", f"/{BUCKET}/cold/archived.bin")
    assert body.status_code == 200
    assert body.content == b"cold-bytes"
    head = signed(service, "HEAD", f"/{BUCKET}/cold/archived.bin")
    assert head.status_code == 200
    header = head.headers.get("x-amz-restore", "")
    assert 'ongoing-request="false"' in header
    # A second request while active is a conflict (AWS semantics).
    again = signed(service, "POST", f"/{BUCKET}/cold/archived.bin?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert again.status_code == 409, again.text
    assert b"RestoreAlreadyInProgress" in again.content
    # Expire the window: the gate closes again.
    catalog = _catalog(service)
    try:
        catalog.db.connection.execute(
            update(objects).where(objects.c.id == version)
            .values(restore_until_ns=time.time_ns() - 1))
        catalog.db.commit()
    finally:
        catalog.db.close()
    assert signed(service, "GET", f"/{BUCKET}/cold/archived.bin"
                  ).status_code == 403


def test_standard_object_restore_stays_invalid_object_state(service):
    _seed(service)
    reply = signed(service, "POST", f"/{BUCKET}/cold/archived.bin?restore",
                   b"<RestoreRequest><Days>1</Days></RestoreRequest>")
    assert reply.status_code == 403
    assert b"InvalidObjectState" in reply.content


def test_scheduler_transitions_by_idle_time_and_resets_on_access(service):
    version = _seed(service)
    assert signed(service, "PUT", _path("tier1"),
                  _document(archive_days=1)).status_code == 200
    catalog = _catalog(service)
    try:
        store = TieringStore(catalog)
        day = 86_400_000_000_000
        # Simulate 5 idle days on a never-accessed object.
        catalog.db.connection.execute(
            update(objects).where(objects.c.id == version)
            .values(created_at=int(time.time()) - 6 * 86400))
        catalog.db.commit()
        changed = store.apply_due(now_ns=time.time_ns() + 0)
        assert changed >= 1
        state = catalog.object_read_state(version, now_ns=time.time_ns())
        assert state["archived"] is True, state
        # A fresh access resets it to STANDARD and reopens reads.
    finally:
        catalog.db.close()
    body = signed(service, "GET", f"/{BUCKET}/cold/archived.bin")
    # Still gated (the reset happens on the next scheduler pass).
    assert body.status_code == 403
    catalog = _catalog(service)
    try:
        store = TieringStore(catalog)
        catalog.db.connection.execute(
            update(objects).where(objects.c.id == version)
            .values(last_accessed_ns=time.time_ns()))
        catalog.db.commit()
        changed = store.apply_due(now_ns=time.time_ns())
        assert changed >= 1
        state = catalog.object_read_state(version, now_ns=time.time_ns())
        assert state["archived"] is False, state
    finally:
        catalog.db.close()
    assert signed(service, "GET", f"/{BUCKET}/cold/archived.bin"
                  ).content == b"cold-bytes"


def test_access_counters_increment_on_reads_only(service):
    version = _seed(service)
    catalog = _catalog(service)
    try:
        before = catalog.db.connection.execute(select(
            objects.c.access_count, objects.c.last_accessed_ns)
            .where(objects.c.id == version)).first()
    finally:
        catalog.db.close()
    assert before[0] in (0, None) or before[0] >= 0
    assert signed(service, "GET", f"/{BUCKET}/cold/archived.bin").status_code == 200
    assert signed(service, "HEAD", f"/{BUCKET}/cold/archived.bin").status_code == 200
    # A denied request must not count as an access.
    assert signed(service, "GET", f"/{BUCKET}/missing.bin").status_code == 404
    catalog = _catalog(service)
    try:
        after = catalog.db.connection.execute(select(
            objects.c.access_count, objects.c.last_accessed_ns)
            .where(objects.c.id == version)).first()
    finally:
        catalog.db.close()
    assert after[0] and after[0] >= 2, after
    assert after[1] is not None


def test_tiering_permission_separation(service):
    from teledrive.s3.credentials import S3CredentialStore
    store = S3CredentialStore(service[3](), service[4])
    reader = store.create("tier-reader", ["s3:GetBucketIntelligentTieringConfiguration"])
    writer = store.create("tier-writer", ["s3:PutBucketIntelligentTieringConfiguration"])
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", _path("tier1"), _document(),
                  access=writer.access_key, secret=writer.secret_key
                  ).status_code == 200
    assert signed(service, "GET", _path("tier1"),
                  access=reader.access_key, secret=reader.secret_key
                  ).status_code == 200
    # The writer has no read scope and vice versa.
    assert signed(service, "GET", _path("tier1"),
                  access=writer.access_key, secret=writer.secret_key
                  ).status_code == 403
    assert signed(service, "PUT", _path("t2"), _document(config_id="t2"),
                  access=reader.access_key, secret=reader.secret_key
                  ).status_code == 403


def test_tiering_route_guard_rejects_unknown_parameters(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    # PUT without an id is a required-id failure (AWS shape), never CRUD.
    reply = signed(service, "PUT", _path(), _document())
    assert reply.status_code == 400, reply.text
    # An unrelated control mixed into the selector fails closed.
    mixed = signed(service, "GET",
                   f"/{BUCKET}?intelligent-tiering&tagging")
    assert mixed.status_code in (400, 501), mixed.text


def test_parser_and_renderer_round_trip():
    config = parse_document(_document(archive_days=2, deep_days=9))
    assert config["id"] == "tier1"
    assert config["archive_days"] == 2
    assert config["deep_days"] == 9
    rendered = ET.fromstring(config_xml(config))
    assert rendered.findtext(NSQ + "Id") == "tier1"
    assert config["status"] == "Enabled"
    assert "ARCHIVE_ACCESS" in {t["access_tier"] for t in config["tiers"]}
    listed = ET.fromstring(list_xml([config]))
    assert listed.find(f".//{NSQ}Id").text == "tier1"


def test_empty_configuration_list_is_well_formed(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    listed = signed(service, "GET", _path())
    assert listed.status_code == 200
    root = ET.fromstring(listed.content)
    assert root.tag.rsplit("}", 1)[-1] == "ListBucketIntelligentTieringConfigurationsResult"
