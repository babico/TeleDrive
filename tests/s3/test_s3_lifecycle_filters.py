"""Lifecycle ``Filter`` Tag conjunctions and Date-based expiration.

The handoff-08 rule grammar parsed only ``Filter/Prefix``. AWS's
lifecycle filter model is wider, and this module pins the two families
that were explicitly left out of scope then:

* ``Filter`` blocks containing ``Tag`` (key/value) conditions, directly
  or under an ``And`` together with a ``Prefix`` — matched against the
  VERSION's immutable tag set, all conditions conjunctive;
* ``Expiration`` and ``NoncurrentVersionExpiration`` accepting a
  ``Date`` (ISO-8601) alongside ``Days`` — a Date rule fires for every
  matching version once ``now >= date``.

Fail-closed taxonomy follows the existing parser: unknown filter
contents (``ObjectSize*``, foreign namespaces, duplicate structural
elements) answer 501, known-but-invalid combinations (Days and Date
together, a Filter with two condition kinds, an ``And`` without a Tag)
answer 400 InvalidArgument, and the legacy rule-level ``<Prefix>``
element next to a ``Filter`` stays rejected.
"""
from __future__ import annotations

import time
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy import select, update

from tests.s3.test_s3_gateway import service, signed  # noqa: F401 — fixture
from teledrive.s3.lifecycle import (
    BucketLifecycleStore, LifecycleError, parse_lifecycle_xml,
)
from teledrive.storage.cold_store import ColdBlobStore
from teledrive.storage.manifest import ManifestStore, objects
from teledrive.storage.catalog import BucketCatalog

BUCKET = "lifecycle-filters"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


@pytest.fixture
def cold(service, monkeypatch, tmp_path):
    root = tmp_path / "cold-archive"
    monkeypatch.setenv("TELEDRIVE_COLD_ARCHIVE_DIR", str(root))
    return root


def _open(service):
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _bucket(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200


def _seed(service, key, body):
    put = signed(service, "PUT", f"/{BUCKET}/{key}", body)
    assert put.status_code == 200, put.text
    return put.headers["x-amz-version-id"]


def _tag(service, key, tags, version_id=None):
    root = ET.Element("Tagging")
    set_el = ET.SubElement(root, "TagSet")
    for name, value in tags:
        item = ET.SubElement(set_el, "Tag")
        ET.SubElement(item, "Key").text = name
        ET.SubElement(item, "Value").text = value
    target = f"/{BUCKET}/{key}?tagging"
    if version_id:
        target += f"&versionId={version_id}"
    reply = signed(service, "PUT", target, ET.tostring(root))
    assert reply.status_code == 200, reply.text


def _rules(service, *rule_bodies):
    _bucket(service)
    body = (b"<LifecycleConfiguration>" + b"".join(rule_bodies)
            + b"</LifecycleConfiguration>")
    reply = signed(service, "PUT", f"/{BUCKET}?lifecycle", body)
    assert reply.status_code == 200, reply.text
    return reply


def _apply(service, **kwargs):
    db, catalog = _open(service)
    try:
        return BucketLifecycleStore(catalog).apply_due(**kwargs)
    finally:
        db.close()


def _age(service, *version_ids, days=10):
    db = service[3]()
    try:
        db.connection.execute(update(objects).where(
            objects.c.id.in_(list(version_ids))
        ).values(updated_at=int(time.time()) - days * 86400))
        db.commit()
    finally:
        db.close()


def _tag_rule(tag, action="expiration", prefix=None, ident="tagged"):
    """A rule whose filter is a single Tag (optionally under And with a
    prefix) and whose action element is chosen by ``action``."""
    if action == "expiration":
        action_xml = "<Expiration><Days>1</Days></Expiration>"
    elif action == "noncurrent-expiration":
        action_xml = ("<NoncurrentVersionExpiration>"
                      "<NoncurrentDays>1</NoncurrentDays>"
                      "</NoncurrentVersionExpiration>")
    else:
        action_xml = ("<Transition><Days>1</Days>"
                      "<StorageClass>ARCHIVE_ACCESS</StorageClass>"
                      "</Transition>")
    key, value = tag
    tag_xml = (f"<Tag><Key>{key}</Key><Value>{value}</Value></Tag>")
    if prefix is None:
        filter_xml = f"<Filter>{tag_xml}</Filter>"
    else:
        filter_xml = (f"<Filter><And><Prefix>{prefix}</Prefix>"
                      f"{tag_xml}</And></Filter>")
    return (f"<Rule><ID>{ident}</ID><Status>Enabled</Status>"
            f"{filter_xml}{action_xml}</Rule>").encode()


def _and_tags_rule(tags, ident="and"):
    tags_xml = "".join(
        f"<Tag><Key>{key}</Key><Value>{value}</Value></Tag>"
        for key, value in tags)
    return (f"<Rule><ID>{ident}</ID><Status>Enabled</Status>"
            f"<Filter><And>{tags_xml}</And></Filter>"
            f"<Expiration><Days>1</Days></Expiration></Rule>").encode()


def _expiration_rule(days=None, date=None, ident="dated"):
    schedule = (f"<Days>{days}</Days>" if days is not None
                else f"<Date>{date}</Date>")
    return (f"<Rule><ID>{ident}</ID><Status>Enabled</Status>"
            f"<Filter><Prefix>docs/</Prefix></Filter>"
            f"<Expiration>{schedule}</Expiration></Rule>").encode()


def _noncurrent_expiration_rule(days=None, date=None, ident="nve"):
    schedule = (f"<NoncurrentDays>{days}</NoncurrentDays>" if days is not None
                else f"<Date>{date}</Date>")
    return (f"<Rule><ID>{ident}</ID><Status>Enabled</Status>"
            f"<Filter><Prefix>docs/</Prefix></Filter>"
            f"<NoncurrentVersionExpiration>{schedule}"
            f"</NoncurrentVersionExpiration></Rule>").encode()


def _head_status(service, key):
    return signed(service, "HEAD", f"/{BUCKET}/{key}").status_code


# ---------------------------------------------------------------------------
# Tag filters
# ---------------------------------------------------------------------------

def test_tag_filter_expires_only_tagged_heads(service, cold):
    _bucket(service)
    tagged = _seed(service, "docs/tagged.bin", b"tagged")
    _seed(service, "docs/plain.bin", b"plain")
    _tag(service, "docs/tagged.bin", [("stage", "expired")])
    _age(service, tagged, days=10)
    _rules(service, _tag_rule(("stage", "expired")))
    assert _apply(service, now=int(time.time())) == 1
    # The tagged head was logically expired; the untagged head survives.
    assert _head_status(service, "docs/tagged.bin") == 404
    assert _head_status(service, "docs/plain.bin") == 200


def test_tag_value_must_match_exactly(service, cold):
    _bucket(service)
    other = _seed(service, "docs/other-value.bin", b"other")
    _tag(service, "docs/other-value.bin", [("stage", "keep")])
    _age(service, other, days=10)
    _rules(service, _tag_rule(("stage", "expired")))
    assert _apply(service, now=int(time.time())) == 0
    assert _head_status(service, "docs/other-value.bin") == 200


def test_and_prefix_and_tag_requires_both(service, cold):
    _bucket(service)
    both = _seed(service, "docs/both.bin", b"both")
    _seed(service, "other/tagged.bin", b"wrong prefix")
    _seed(service, "docs/plain.bin", b"no tag")
    _tag(service, "docs/both.bin", [("stage", "expired")])
    _tag(service, "other/tagged.bin", [("stage", "expired")])
    _age(service, both, days=10)
    _rules(service, _tag_rule(("stage", "expired"), prefix="docs/"))
    assert _apply(service, now=int(time.time())) == 1
    assert _head_status(service, "docs/both.bin") == 404
    assert _head_status(service, "other/tagged.bin") == 200
    assert _head_status(service, "docs/plain.bin") == 200


def test_and_two_tags_requires_the_conjunction(service, cold):
    _bucket(service)
    both = _seed(service, "docs/both.bin", b"both")
    one = _seed(service, "docs/one.bin", b"one")
    _tag(service, "docs/both.bin", [("stage", "expired"), ("team", "red")])
    _tag(service, "docs/one.bin", [("stage", "expired")])
    _age(service, both, one, days=10)
    _rules(service, _and_tags_rule([("stage", "expired"), ("team", "red")]))
    assert _apply(service, now=int(time.time())) == 1
    assert _head_status(service, "docs/both.bin") == 404
    assert _head_status(service, "docs/one.bin") == 200


def test_tag_filter_gates_noncurrent_expiration(service, cold):
    _bucket(service)
    tagged = _seed(service, "docs/file.bin", b"v1")
    _seed(service, "docs/file.bin", b"v2")  # makes v1 noncurrent
    _tag(service, "docs/file.bin", [("stage", "gone")], version_id=tagged)
    _age(service, tagged, days=10)
    _rules(service, _tag_rule(("stage", "gone"),
                              action="noncurrent-expiration"))
    assert _apply(service, now=int(time.time())) == 1
    db, catalog = _open(service)
    try:
        from teledrive.storage.catalog import removed_versions
        revoked = db.connection.execute(select(
            removed_versions.c.object_id).where(
            removed_versions.c.object_id == tagged)).first()
    finally:
        db.close()
    assert revoked is not None


def test_tag_filter_gates_transitions(service, cold):
    _bucket(service)
    tagged = _seed(service, "docs/tagged.bin", b"tagged")
    plain = _seed(service, "docs/plain.bin", b"plain")
    _tag(service, "docs/tagged.bin", [("stage", "archive")])
    _age(service, tagged, plain, days=10)
    _rules(service, _tag_rule(("stage", "archive"), action="transition"))
    assert _apply(service, now=int(time.time())) == 1
    db = service[3]()
    try:
        classes = dict(db.connection.execute(select(
            objects.c.id, objects.c.storage_class).where(
            objects.c.id.in_([tagged, plain]))).all())
    finally:
        db.close()
    assert classes[tagged] == "ARCHIVE_ACCESS"
    assert classes[plain] != "ARCHIVE_ACCESS"


# ---------------------------------------------------------------------------
# Date-based expiration
# ---------------------------------------------------------------------------

def test_past_date_expiration_fires_now(service, cold):
    """A Date already in the past expires every matching head now — no
    age cutoff applies."""
    _bucket(service)
    fresh = _seed(service, "docs/fresh.bin", b"fresh")  # not aged at all
    _rules(service, _expiration_rule(date="2020-01-01T00:00:00Z"))
    assert _apply(service, now=int(time.time())) == 1
    assert _head_status(service, "docs/fresh.bin") == 404
    assert fresh


def test_future_date_expiration_not_yet_firing(service, cold):
    _bucket(service)
    _seed(service, "docs/fresh.bin", b"fresh")
    _age_days = 30
    _age(service, _version_of(service, "docs/fresh.bin"), days=_age_days)
    _rules(service, _expiration_rule(date="2035-06-01T00:00:00Z"))
    assert _apply(service, now=int(time.time())) == 0
    assert _head_status(service, "docs/fresh.bin") == 200
    # Once the schedule's instant is reached, the rule fires.
    assert _apply(service, now=int(
        time.mktime(time.strptime("2035-06-02", "%Y-%m-%d")))) == 1
    assert _head_status(service, "docs/fresh.bin") == 404


def test_date_based_noncurrent_expiration(service, cold):
    _bucket(service)
    old = _seed(service, "docs/file.bin", b"v1")
    _seed(service, "docs/file.bin", b"v2")
    _age(service, old, days=1)
    _rules(service, _noncurrent_expiration_rule(date="2020-01-01"))
    assert _apply(service, now=int(time.time())) == 1
    db = service[3]()
    try:
        from teledrive.storage.catalog import removed_versions
        revoked = db.connection.execute(select(
            removed_versions.c.object_id).where(
            removed_versions.c.object_id == old)).first()
    finally:
        db.close()
    assert revoked is not None
    # A future Date revokes nothing yet.
    _rules(service, _noncurrent_expiration_rule(date="2035-06-01"))
    assert _apply(service, now=int(time.time())) == 0


def _version_of(service, key):
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        return catalog.get(BUCKET, key).item.id
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Round trip through the S3 API
# ---------------------------------------------------------------------------

def test_tag_and_date_rules_round_trip_through_the_api(service, cold):
    _bucket(service)
    _rules(
        service,
        _tag_rule(("stage", "expired"), prefix="docs/"),
        _expiration_rule(date="2030-01-01T00:00:00Z", ident="dated"),
        _and_tags_rule([("a", "1"), ("b", "2")], ident="multi"),
    )
    body = signed(service, "GET", f"/{BUCKET}?lifecycle").content
    root = ET.fromstring(body)
    rules = root.findall(NS + "Rule")
    assert len(rules) == 3
    by_id = {rule.findtext(NS + "ID"): rule for rule in rules}
    # Prefix + Tag under And round trips.
    fil = by_id["tagged"].find(NS + "Filter")
    assert fil.findtext(NS + "And/" + NS + "Prefix") == "docs/"
    tag = fil.find(NS + "And/" + NS + "Tag")
    assert (tag.findtext(NS + "Key"), tag.findtext(NS + "Value")) == (
        "stage", "expired")
    # A Date schedule serializes as <Date>, not <Days>.
    dated = by_id["dated"].find(NS + "Expiration")
    assert dated.findtext(NS + "Date") == "2030-01-01T00:00:00Z"
    assert dated.find(NS + "Days") is None
    # A two-tag And round trips both conditions.
    multi = by_id["multi"].find(NS + "Filter/" + NS + "And")
    pairs = [(tag.findtext(NS + "Key"), tag.findtext(NS + "Value"))
             for tag in multi.findall(NS + "Tag")]
    assert pairs == [("a", "1"), ("b", "2")]
    # The stored document re-parses to the same model.
    parsed = parse_lifecycle_xml(body)
    assert parsed[0]["tags"] == [{"key": "stage", "value": "expired"}]
    assert parsed[1]["expiration"]["date"] is not None
    assert parsed[1]["expiration"]["days"] is None
    assert parsed[2]["tags"] == [
        {"key": "a", "value": "1"}, {"key": "b", "value": "2"}]


# ---------------------------------------------------------------------------
# Fail-closed taxonomy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad,expected", [
    # Unknown filter contents still 501.
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan></Filter>"
     b"<Expiration><Days>1</Days></Expiration></Rule>", 501),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><And><ObjectSizeLessThan>1</ObjectSizeLessThan></And></Filter>"
     b"<Expiration><Days>1</Days></Expiration></Rule>", 501),
    # The legacy rule-level Prefix next to a Filter stays rejected.
    (b"<Rule><ID>x</ID><Status>Enabled</Status><Prefix>p/</Prefix>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<Expiration><Days>1</Days></Expiration></Rule>", 501),
    # Known-but-invalid combinations are InvalidArgument.
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix><Tag><Key>a</Key><Value>1</Value></Tag>"
     b"</Filter><Expiration><Days>1</Days></Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><And><Prefix>p/</Prefix></And></Filter>"
     b"<Expiration><Days>1</Days></Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Tag><Key>a</Key></Tag></Filter>"
     b"<Expiration><Days>1</Days></Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><And><Tag><Key>a</Key><Value>1</Value></Tag>"
     b"<Tag><Key>a</Key><Value>2</Value></Tag></And></Filter>"
     b"<Expiration><Days>1</Days></Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><And>" + b"<Tag><Key>a</Key><Value>1</Value></Tag>" * 11
     + b"</And></Filter><Expiration><Days>1</Days></Expiration></Rule>", 400),
    # Date schedules: exactly one of Days or Date, ISO-8601 only.
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<Expiration><Days>1</Days><Date>2020-01-01T00:00:00Z</Date>"
     b"</Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<Expiration></Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<Expiration><Date>not-a-date</Date></Expiration></Rule>", 400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<Expiration><Date>2020-13-01T00:00:00Z</Date></Expiration></Rule>",
     400),
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>"
     b"<Date>2020-01-01T00:00:00Z</Date></NoncurrentVersionExpiration>"
     b"</Rule>", 400),
    # A delete marker carries no tags: the combination is rejected.
    (b"<Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Tag><Key>a</Key><Value>1</Value></Tag></Filter>"
     b"<Expiration><Days>1</Days>"
     b"<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>"
     b"</Expiration></Rule>", 400),
])
def test_invalid_filter_and_date_documents_fail_closed(service, cold, bad,
                                                        expected):
    _rules(service, _tag_rule(("stage", "expired")))
    # The rule body must sit inside the root document, exactly as a client
    # sends it; a bare <Rule> is a different (empty) document and would
    # fail for the wrong reason.
    body = (b"<LifecycleConfiguration>" + bad
            + b"</LifecycleConfiguration>")
    reply = signed(service, "PUT", f"/{BUCKET}?lifecycle", body)
    assert reply.status_code == expected, reply.text
    # The stored configuration was never mutated.
    assert b"<Value>expired</Value>" in signed(
        service, "GET", f"/{BUCKET}?lifecycle").content


def test_parser_rejects_direct_multi_tag_without_and():
    """Two Tags directly under Filter (no And) is not a valid filter."""
    with pytest.raises(LifecycleError) as error:
        parse_lifecycle_xml(
            b"<LifecycleConfiguration><Rule><ID>x</ID>"
            b"<Status>Enabled</Status>"
            b"<Filter><Tag><Key>a</Key><Value>1</Value></Tag>"
            b"<Tag><Key>b</Key><Value>2</Value></Tag></Filter>"
            b"<Expiration><Days>1</Days></Expiration></Rule>"
            b"</LifecycleConfiguration>")
    assert error.value.code == "InvalidArgument"
