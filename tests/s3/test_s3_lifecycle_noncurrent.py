"""Handoff 08, phase D: lifecycle transitions and noncurrent-version rules.

The rule matrix this module pins:

* ``Transition`` - due CURRENT heads move to ARCHIVE_ACCESS /
  DEEP_ARCHIVE_ACCESS and are queued for a verified cold copy (an
  additional copy; nothing moves or is deleted); GLACIER and every other
  AWS class fail closed 501;
* ``NoncurrentVersionTransitions`` - noncurrent versions transition after
  ``NoncurrentDays``, with ``NewerNoncurrentVersions`` retaining the
  newest per key;
* ``NoncurrentVersionExpiration`` - due noncurrent versions are revoked
  from version history while their media stays retained (logical expiry
  while GC is off), with Object Lock / legal-hold and dedup-alias fences;
* ``ExpiredObjectDeleteMarker`` - an orphan delete marker is removed, a
  marker with remaining versions is kept;
* bucket/version races stay atomic: concurrent evaluators never
  double-revoke or expire a version that became current again.
"""
from __future__ import annotations

import threading
import time
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy import select, update

from tests.s3.test_s3_gateway import backend_service, service, signed
from teledrive.db import connect_database
from teledrive.s3.lifecycle import (
    BucketLifecycleStore, LifecycleError, lifecycle_xml,
    parse_lifecycle_xml,
)
from teledrive.storage.catalog import (
    BucketCatalog, published_versions, removed_versions)
from teledrive.storage.manifest import ManifestStore, chunks, objects
from teledrive.storage.cold_store import ArchiveStore, ColdBlobStore

BUCKET = "lifecycle-noncurrent"
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


def _seed(service, key="docs/file.bin", body=b"lifecycle-payload"):
    _bucket(service)
    put = signed(service, "PUT", f"/{BUCKET}/{key}", body)
    assert put.status_code == 200, put.text
    return put.headers["x-amz-version-id"]


def _put_rules(service, *rule_bodies):
    _bucket(service)
    body = (b"<LifecycleConfiguration>" + b"".join(rule_bodies)
            + b"</LifecycleConfiguration>")
    reply = signed(service, "PUT", f"/{BUCKET}?lifecycle", body)
    assert reply.status_code == 200, reply.text
    return reply


def _transition_rule(days=1, storage_class="ARCHIVE_ACCESS", prefix="docs/",
                     ident="t"):
    return (f"<Rule><ID>{ident}</ID><Status>Enabled</Status>"
            f"<Filter><Prefix>{prefix}</Prefix></Filter>"
            f"<Transition><Days>{days}</Days>"
            f"<StorageClass>{storage_class}</StorageClass></Transition>"
            f"</Rule>").encode()


def _noncurrent_transition_rule(days=1, storage_class="ARCHIVE_ACCESS",
                                newer=None, prefix="docs/"):
    newer_xml = (f"<NewerNoncurrentVersions>{newer}</NewerNoncurrentVersions>"
                 if newer is not None else "")
    return (f"<Rule><ID>nvt</ID><Status>Enabled</Status>"
            f"<Filter><Prefix>{prefix}</Prefix></Filter>"
            f"<NoncurrentVersionTransitions>"
            f"<NoncurrentDays>{days}</NoncurrentDays>"
            f"<StorageClass>{storage_class}</StorageClass>{newer_xml}"
            f"</NoncurrentVersionTransitions></Rule>").encode()


def _noncurrent_expiration_rule(days=1, newer=None, prefix="docs/"):
    newer_xml = (f"<NewerNoncurrentVersions>{newer}</NewerNoncurrentVersions>"
                 if newer is not None else "")
    return (f"<Rule><ID>nve</ID><Status>Enabled</Status>"
            f"<Filter><Prefix>{prefix}</Prefix></Filter>"
            f"<NoncurrentVersionExpiration>"
            f"<NoncurrentDays>{days}</NoncurrentDays>{newer_xml}"
            f"</NoncurrentVersionExpiration></Rule>").encode()


def _expiration_rule(days=1, marker=False, prefix="docs/"):
    marker_xml = (f"<ExpiredObjectDeleteMarker>{'true' if marker else 'false'}"
                  f"</ExpiredObjectDeleteMarker>")
    return (f"<Rule><ID>exp</ID><Status>Enabled</Status>"
            f"<Filter><Prefix>{prefix}</Prefix></Filter>"
            f"<Expiration><Days>{days}</Days>{marker_xml}</Expiration>"
            f"</Rule>").encode()


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


def _classes(service, *version_ids):
    db = service[3]()
    try:
        rows = db.connection.execute(select(
            objects.c.id, objects.c.storage_class).where(
            objects.c.id.in_(list(version_ids)))).all()
        return {row[0]: row[1] for row in rows}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Transition (current versions)
# ---------------------------------------------------------------------------

def test_transition_moves_due_heads_and_queues_a_verified_archive(
        service, cold):
    version = _seed(service)
    _put_rules(service, _transition_rule(days=1))
    _age(service, version, days=10)
    assert _apply(service, now=int(time.time())) == 1
    assert _classes(service, version)[version] == "ARCHIVE_ACCESS"
    # The physical archive was queued (HOT) and the worker seals it.
    import asyncio
    db, catalog = _open(service)
    try:
        store = ArchiveStore(catalog, ColdBlobStore(cold))
        report = asyncio.run(store.run_archive_pass(
            service[2], scratch_directory=None))
    finally:
        db.close()
    assert report["archived"] == [version], report
    # The transitioned object is a real archived object: gated, then
    # restorable from the cold copy.
    path = f"/{BUCKET}/docs/file.bin"
    assert signed(service, "GET", path).status_code == 403
    assert signed(service, "POST", f"{path}?restore",
                  b"<RestoreRequest><Days>1</Days></RestoreRequest>"
                  ).status_code == 202
    db, catalog = _open(service)
    try:
        ArchiveStore(catalog, ColdBlobStore(cold)).run_restore_pass()
    finally:
        db.close()
    assert signed(service, "GET", path).content == b"lifecycle-payload"
    # Nothing was moved or deleted on Telegram.
    assert service[2].uploads == 1


def test_transition_keeps_fresh_heads_and_other_prefixes(service, cold):
    due = _seed(service, key="docs/due.bin")
    fresh = _seed(service, key="docs/fresh.bin")
    other = _seed(service, key="other/prefix.bin")
    _put_rules(service, _transition_rule(days=30))
    _age(service, due, days=40)
    _age(service, other, days=40)
    assert _apply(service, now=int(time.time())) == 1
    classes = _classes(service, due, fresh, other)
    assert classes[due] == "ARCHIVE_ACCESS"
    assert classes[fresh] == "STANDARD"
    assert classes[other] == "STANDARD"


def test_deep_archive_ladder_transitions_compose(service, cold):
    version = _seed(service)
    _put_rules(service,
               _transition_rule(days=1, storage_class="ARCHIVE_ACCESS",
                                ident="to-archive"),
               _transition_rule(days=30, storage_class="DEEP_ARCHIVE_ACCESS",
                                ident="to-deep"))
    _age(service, version, days=40)
    assert _apply(service, now=int(time.time())) == 2
    assert _classes(service, version)[version] == "DEEP_ARCHIVE_ACCESS"


def test_unsupported_transition_classes_fail_closed(service, cold):
    _put_rules(service, _transition_rule())
    for storage_class in ("GLACIER", "STANDARD_IA", "GLACIER_IR",
                          "INTELLIGENT_TIERING"):
        reply = signed(
            service, "PUT", f"/{BUCKET}?lifecycle",
            b"<LifecycleConfiguration>" +
            _transition_rule(storage_class=storage_class) +
            b"</LifecycleConfiguration>")
        assert reply.status_code == 501, (storage_class, reply.text)
        assert b"NotImplemented" in reply.content
    # Unknown elements inside a known action also fail closed, and the
    # previously stored configuration is untouched.
    bad = (b"<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status>"
           b"<Filter><Prefix>docs/</Prefix></Filter>"
           b"<Transition><Days>1</Days><StorageClass>ARCHIVE_ACCESS"
           b"</StorageClass><Foo>1</Foo></Transition></Rule>"
           b"</LifecycleConfiguration>")
    assert signed(service, "PUT", f"/{BUCKET}?lifecycle", bad).status_code == 501
    stored = signed(service, "GET", f"/{BUCKET}?lifecycle")
    assert stored.status_code == 200
    assert b"<StorageClass>ARCHIVE_ACCESS</StorageClass>" in stored.content


def test_transition_rule_round_trips_through_the_api(service, cold):
    _put_rules(service, _transition_rule(days=7))
    body = signed(service, "GET", f"/{BUCKET}?lifecycle").content
    root = ET.fromstring(body)
    assert root.findtext(f".//{NS}Transition/{NS}Days") == "7"
    assert root.findtext(
        f".//{NS}Transition/{NS}StorageClass") == "ARCHIVE_ACCESS"
    # Parse -> serialize is stable.
    rules = parse_lifecycle_xml(body)
    assert lifecycle_xml(rules) == body


# ---------------------------------------------------------------------------
# NoncurrentVersionTransitions
# ---------------------------------------------------------------------------

def test_noncurrent_transitions_move_old_versions_only(service, cold):
    first = _seed(service, body=b"first")
    second = _seed(service, body=b"second")  # first becomes noncurrent
    _put_rules(service, _noncurrent_transition_rule(days=1))
    _age(service, first, days=10)
    assert _apply(service, now=int(time.time())) == 1
    classes = _classes(service, first, second)
    assert classes[first] == "ARCHIVE_ACCESS"
    assert classes[second] == "STANDARD"


def test_newer_noncurrent_versions_are_retained(service, cold):
    first = _seed(service, body=b"first")
    second = _seed(service, body=b"second")
    third = _seed(service, body=b"third")  # first and second noncurrent
    _put_rules(service, _noncurrent_transition_rule(days=1, newer=1))
    _age(service, first, second, days=10)
    assert _apply(service, now=int(time.time())) == 1
    classes = _classes(service, first, second, third)
    # The NEWEST noncurrent version (second) is retained; the older one
    # transitions.
    assert classes[first] == "ARCHIVE_ACCESS"
    assert classes[second] == "STANDARD"
    assert classes[third] == "STANDARD"


# ---------------------------------------------------------------------------
# NoncurrentVersionExpiration
# ---------------------------------------------------------------------------

def test_noncurrent_expiration_revokes_history_and_retains_media(
        service, cold):
    first = _seed(service, body=b"first")
    second = _seed(service, body=b"second")
    third = _seed(service, body=b"third")
    _put_rules(service, _noncurrent_expiration_rule(days=1))
    _age(service, first, second, days=10)
    assert _apply(service, now=int(time.time())) == 2
    db = service[3]()
    try:
        revoked = {row[0] for row in db.connection.execute(select(
            removed_versions.c.object_id)).all()}
        assert {first, second} <= revoked
        assert third not in revoked
        # Logical expiry: the media is fully retained (GC is off).
        for version in (first, second, third):
            assert db.connection.execute(select(
                chunks.c.ordinal).where(
                chunks.c.object_id == version)).first() is not None
        from teledrive.storage.gc_collect import gc_queue
        assert db.connection.execute(select(
            gc_queue.c.object_id)).first() is None
    finally:
        db.close()
    assert service[2].uploads == 3
    # The current version still reads.
    assert signed(service, "GET", f"/{BUCKET}/docs/file.bin"
                  ).content == b"third"
    # The revoked versions answer 404 through the versioned read.
    assert signed(service, "GET",
                  f"/{BUCKET}/docs/file.bin?versionId={first}"
                  ).status_code == 404


def test_noncurrent_expiration_fences_locked_and_aliased_versions(
        service, cold):
    locked = _seed(service, body=b"locked")
    aliased = _seed(service, body=b"aliased-source")
    head = _seed(service, body=b"head")
    # A copy that aliases the NONCURRENT version's content: its media is
    # referenced and must never be expired out from under the alias.
    copy = signed(service, "PUT", f"/{BUCKET}/docs/copy.bin", b"",
                  extra_headers={
                      "x-amz-copy-source":
                          f"/{BUCKET}/docs/file.bin?versionId={aliased}"})
    assert copy.status_code == 200, copy.text
    db, catalog = _open(service)
    try:
        catalog.set_retention(locked, mode="GOVERNANCE",
                              until_ns=time.time_ns() + 86_400_000_000_000)
    finally:
        db.close()
    _put_rules(service, _noncurrent_expiration_rule(days=1))
    _age(service, locked, aliased, days=10)
    assert _apply(service, now=int(time.time())) == 0
    db = service[3]()
    try:
        revoked = {row[0] for row in db.connection.execute(select(
            removed_versions.c.object_id)).all()}
        assert revoked == set()
    finally:
        db.close()


def test_noncurrent_expiration_prefix_filter(service, cold):
    first = _seed(service, key="docs/inside.bin", body=b"v1")
    inside = _seed(service, key="docs/inside.bin", body=b"v2")
    _seed(service, key="logs/outside.bin")
    _put_rules(service, _noncurrent_expiration_rule(days=1, prefix="docs/"))
    _age(service, first, days=10)
    assert _apply(service, now=int(time.time())) == 1
    db = service[3]()
    try:
        revoked = {row[0] for row in db.connection.execute(select(
            removed_versions.c.object_id)).all()}
        assert revoked == {first}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ExpiredObjectDeleteMarker
# ---------------------------------------------------------------------------

def test_expired_object_delete_marker_removes_orphan_markers(service, cold):
    version = _seed(service)
    marker = signed(service, "DELETE", f"/{BUCKET}/docs/file.bin")
    assert marker.status_code == 204
    # Remove the underlying version too: the marker is now orphaned.
    assert signed(service, "DELETE",
                  f"/{BUCKET}/docs/file.bin?versionId={version}"
                  ).status_code == 204
    _put_rules(service, _expiration_rule(days=1, marker=True))
    assert _apply(service, now=int(time.time())) == 1
    db = service[3]()
    try:
        assert db.connection.execute(select(
            removed_versions.c.object_id).where(
            removed_versions.c.object_id != version)).first() is not None
    finally:
        db.close()
    # The key is fully gone (no marker head, no versions).
    assert signed(service, "GET", f"/{BUCKET}/docs/file.bin"
                  ).status_code == 404


def test_marker_with_remaining_versions_is_kept(service, cold):
    _seed(service, body=b"v1")
    marker = signed(service, "DELETE", f"/{BUCKET}/docs/file.bin")
    assert marker.status_code == 204
    _put_rules(service, _expiration_rule(days=1, marker=True))
    assert _apply(service, now=int(time.time())) == 0
    # The marker survives: v1 is still a (noncurrent) version of the key.
    result = signed(service, "GET", f"/{BUCKET}/docs/file.bin")
    assert result.status_code == 404
    assert result.headers.get("x-amz-delete-marker") == "true"


# ---------------------------------------------------------------------------
# Rule combinations and validation
# ---------------------------------------------------------------------------

def test_combined_rule_with_all_action_families(service, cold):
    version = _seed(service)
    # Only the current-version transition is due at 10 days; the other
    # families sit at ages that keep them inert for this object.
    body = (b"<LifecycleConfiguration><Rule><ID>all</ID>"
            b"<Status>Enabled</Status>"
            b"<Filter><Prefix>docs/</Prefix></Filter>"
            b"<Transition><Days>1</Days><StorageClass>ARCHIVE_ACCESS"
            b"</StorageClass></Transition>"
            b"<NoncurrentVersionTransitions><NoncurrentDays>3650"
            b"</NoncurrentDays><StorageClass>DEEP_ARCHIVE_ACCESS"
            b"</StorageClass><NewerNoncurrentVersions>1"
            b"</NewerNoncurrentVersions></NoncurrentVersionTransitions>"
            b"<NoncurrentVersionExpiration><NoncurrentDays>3650"
            b"</NoncurrentDays></NoncurrentVersionExpiration>"
            b"<Expiration><Days>3650</Days>"
            b"<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>"
            b"</Expiration>"
            b"<AbortIncompleteMultipartUpload>"
            b"<DaysAfterInitiation>5</DaysAfterInitiation>"
            b"</AbortIncompleteMultipartUpload>"
            b"</Rule></LifecycleConfiguration>")
    reply = signed(service, "PUT", f"/{BUCKET}?lifecycle", body)
    assert reply.status_code == 200, reply.text
    stored = signed(service, "GET", f"/{BUCKET}?lifecycle").content
    for needle in (b"<Transition>", b"<NoncurrentVersionTransitions>",
                   b"<NoncurrentVersionExpiration>",
                   b"<ExpiredObjectDeleteMarker>true",
                   b"<DaysAfterInitiation>5"):
        assert needle in stored
    # The combined rule still applies its due transition to the head.
    _age(service, version, days=10)
    assert _apply(service, now=int(time.time())) == 1
    assert _classes(service, version)[version] == "ARCHIVE_ACCESS"


@pytest.mark.parametrize("bad,expected", [
    (b"<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter></Rule></LifecycleConfiguration>", 400),
    (b"<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<Transition><Days>0</Days><StorageClass>ARCHIVE_ACCESS"
     b"</StorageClass></Transition></Rule></LifecycleConfiguration>", 400),
    (b"<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<NoncurrentVersionExpiration><NoncurrentDays>0</NoncurrentDays>"
     b"</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>", 400),
    (b"<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status>"
     b"<Filter><Prefix>p/</Prefix></Filter>"
     b"<NoncurrentVersionTransitions><NoncurrentDays>1</NoncurrentDays>"
     b"</NoncurrentVersionTransitions></Rule></LifecycleConfiguration>", 400),
    (b'<!DOCTYPE x [<!ENTITY a "7">]><LifecycleConfiguration>&a;'
     b"</LifecycleConfiguration>", 400),
])
def test_invalid_new_rule_documents_fail_closed(service, cold, bad, expected):
    _put_rules(service, _transition_rule())
    reply = signed(service, "PUT", f"/{BUCKET}?lifecycle", bad)
    assert reply.status_code == expected, reply.text
    # The stored configuration was never mutated.
    assert b"<StorageClass>ARCHIVE_ACCESS</StorageClass>" in signed(
        service, "GET", f"/{BUCKET}?lifecycle").content


def test_legacy_stored_rules_still_apply(service, cold):
    """Rules stored by pre-handoff-08 releases keep working unchanged."""
    version = _seed(service)
    db, catalog = _open(service)
    try:
        legacy = [{"id": "old-abort", "status": "Enabled",
                   "prefix": "upload/", "days": 1, "action": "abort"},
                  {"id": "old-expire", "status": "Enabled",
                   "prefix": "docs/", "days": 1, "action": "expire",
                   "expired_marker": False}]
        BucketLifecycleStore(catalog).replace(BUCKET, legacy)
    finally:
        db.close()
    _age(service, version, days=10)
    assert _apply(service, now=int(time.time())) == 1
    # The legacy expire rule created a delete marker for the due head.
    result = signed(service, "GET", f"/{BUCKET}/docs/file.bin")
    assert result.status_code == 404
    assert result.headers.get("x-amz-delete-marker") == "true"


# ---------------------------------------------------------------------------
# Races
# ---------------------------------------------------------------------------

def test_concurrent_evaluators_never_double_revoke(backend_service,
                                                   monkeypatch, tmp_path):
    """Two apply_due passes over the same due noncurrent version: exactly
    one revocation, no exception, and the second pass is a no-op.

    Runs on SQLite plus every configured real backend (the matrix
    pattern), because row-lock and snapshot semantics are the point.
    """
    service = backend_service
    monkeypatch.setenv("TELEDRIVE_COLD_ARCHIVE_DIR",
                       str(tmp_path / "cold-archive"))
    first = _seed(service, body=b"contended-first")
    _seed(service, body=b"contended-second")
    _put_rules(service, _noncurrent_expiration_rule(days=1))
    _age(service, first, days=10)
    totals: list[int] = []
    errors: list[BaseException] = []

    def evaluator():
        db = None
        try:
            db, catalog = _open(service)
            totals.append(BucketLifecycleStore(catalog).apply_due(
                now=int(time.time())))
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)
        finally:
            if db is not None:
                db.close()

    threads = [threading.Thread(target=evaluator) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors
    # Exactly one evaluator revoked the version; the other saw nothing
    # due (or lost the atomic delete_version race and skipped).
    assert sum(totals) == 1, totals
    db = service[3]()
    try:
        assert db.connection.execute(select(
            removed_versions.c.object_id)).scalars().all() == [first]
    finally:
        db.close()
    # A re-run is a clean no-op.
    assert _apply(service, now=int(time.time())) == 0
