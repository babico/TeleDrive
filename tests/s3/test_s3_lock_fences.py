"""Handoff 09, Object Lock row: per-version immutable enforcement and
the AWS retention-transition rules.

AWS semantics verified against the S3 User Guide ("Locking objects with
Object Lock"):

* COMPLIANCE: "a protected object version can't be overwritten or
  deleted by any user, including the root user"; "its retention mode
  can't be changed, and its retention period can't be shortened" —
  extend-only, mode-immutable, not clearable;
* GOVERNANCE: altering or removing the retention requires the
  ``s3:BypassGovernanceRetention`` permission AND the explicit
  ``x-amz-bypass-governance-retention:true`` header (the dedicated
  scope exists — tests/s3/test_s3_governance_bypass.py owns its full
  matrix). Without both, shortening or clearing GOVERNANCE answers
  403, and the header itself stays rejected 501 on every route except
  the retention write;
* a permanent DELETE (``?versionId``) of a protected version answers
  403; a simple DELETE answers 200 with a delete marker (the marker
  never removes the protected version);
* legal holds are freely placeable/removable with
  ``s3:PutObjectLegalHold`` and fence deletes exactly like retention.

The lock-fence audit table (path -> fence -> proof) lives in the module
docstring of the handoff report; every catalog-level fence below is
exercised through the real S3 gateway.
"""
from __future__ import annotations

import time

import pytest

from tests.s3.test_s3_gateway import service, signed  # noqa: F401

ACL_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _iso(seconds_from_now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() + seconds_from_now))


def _put_lock_config(service, bucket, mode="COMPLIANCE", days=None):
    days_xml = f"<Days>{days}</Days>" if days else ""
    body = (f'<ObjectLockConfiguration xmlns="{ACL_XMLNS}">'
            f"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
            f"<Rule><DefaultRetention><Mode>{mode}</Mode>{days_xml}"
            f"</DefaultRetention></Rule>"
            f"</ObjectLockConfiguration>").encode()
    return signed(service, "PUT", f"/{bucket}?object-lock", body)


def _put_retention(service, path, mode, until_iso):
    body = (f'<Retention xmlns="{ACL_XMLNS}">'
            f"<Mode>{mode}</Mode>"
            f"<RetainUntilDate>{until_iso}</RetainUntilDate>"
            f"</Retention>").encode()
    return signed(service, "PUT", f"{path}?retention", body)


def _clear_retention(service, path):
    body = f'<Retention xmlns="{ACL_XMLNS}"/>'.encode()
    return signed(service, "PUT", f"{path}?retention", body)


def _put_legal_hold(service, path, status):
    body = (f'<LegalHold xmlns="{ACL_XMLNS}">'
            f"<Status>{status}</Status></LegalHold>").encode()
    return signed(service, "PUT", f"{path}?legal-hold", body)


def _version_of(service, path):
    return signed(service, "GET", path).headers.get("x-amz-version-id")


def _age_retention(service, object_id):
    """Push a version's retention window into the past via SQL."""
    connection = service[3]()
    try:
        from sqlalchemy import text
        connection.connection.execute(text(
            "UPDATE storage_objects SET retention_until_ns = 1 "
            "WHERE id = :id"), {"id": object_id})
        connection.commit()
    finally:
        connection.close()


def _object_id(service, bucket, key):
    connection = service[3]()
    try:
        from sqlalchemy import text
        row = connection.connection.execute(text(
            "SELECT o.id FROM storage_object_heads h "
            "JOIN storage_objects o ON o.id = h.object_id "
            "WHERE h.bucket = :b AND o.object_key = :k"),
            {"b": bucket, "k": key}).first()
        return row[0] if row else None
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# COMPLIANCE: extend-only, mode-immutable, not clearable — even for the
# owner (AWS: "including the root user in your AWS account").
# ---------------------------------------------------------------------------

def test_compliance_retention_is_immutable_for_everyone(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/worm.bin",
                  b"worm").status_code == 200
    path = "/fence-bucket/worm.bin"
    applied = _put_retention(service, path, "COMPLIANCE", _iso(3600))
    assert applied.status_code == 200, applied.text

    # Extend: allowed for any user with PutObjectRetention.
    extended = _put_retention(service, path, "COMPLIANCE", _iso(7200))
    assert extended.status_code == 200, extended.text

    # Shorten: 403, owner or not.
    shortened = _put_retention(service, path, "COMPLIANCE", _iso(60))
    assert shortened.status_code == 403, shortened.text
    assert b"retention" in shortened.content.lower()

    # Mode change to GOVERNANCE: 403 even with a later date.
    switched = _put_retention(service, path, "GOVERNANCE", _iso(10800))
    assert switched.status_code == 403, switched.text

    # Clearing: 403.
    cleared = _clear_retention(service, path)
    assert cleared.status_code == 403, cleared.text

    # The protected version answers 403 on a permanent delete and
    # stays fully readable.
    version = _version_of(service, path)
    denied = signed(service, "DELETE",
                    f"{path}?versionId={version}")
    assert denied.status_code == 403, denied.text
    assert signed(service, "GET", path).content == b"worm"


def test_expired_retention_frees_the_version(service):
    """Once the window has passed, the version is no longer protected:
    modes can change and the retention can be removed (AWS: after the
    retention period expires, the version can be overwritten or
    deleted)."""
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/expired.bin",
                  b"old").status_code == 200
    path = "/fence-bucket/expired.bin"
    assert _put_retention(service, path, "COMPLIANCE",
                          _iso(3600)).status_code == 200
    object_id = _object_id(service, "fence-bucket", "expired.bin")
    assert object_id
    _age_retention(service, object_id)

    # An expired COMPLIANCE window no longer fences anything: the
    # retention can be cleared outright...
    cleared = _clear_retention(service, path)
    assert cleared.status_code == 200, cleared.text
    # ...and a fresh GOVERNANCE window can take its place.
    switched = _put_retention(service, path, "GOVERNANCE", _iso(3600))
    assert switched.status_code == 200, switched.text
    # The new window is active again: age it, then the version delete
    # that was fenced while retained goes through.
    _age_retention(service, object_id)
    version = _version_of(service, path)
    assert signed(service, "DELETE",
                  f"{path}?versionId={version}").status_code == 204


# ---------------------------------------------------------------------------
# GOVERNANCE: the fence holds for every principal that cannot prove the
# dedicated bypass scope AND the explicit header (the full bypass matrix
# lives in tests/s3/test_s3_governance_bypass.py).
# ---------------------------------------------------------------------------

def test_governance_retention_transitions(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/gov.bin",
                  b"gov").status_code == 200
    path = "/fence-bucket/gov.bin"
    assert _put_retention(service, path, "GOVERNANCE",
                          _iso(3600)).status_code == 200

    # Extending is a normal write.
    extended = _put_retention(service, path, "GOVERNANCE", _iso(7200))
    assert extended.status_code == 200, extended.text

    # Shortening is a governance bypass: 403 without the (nonexistent)
    # permission + header proof.
    shortened = _put_retention(service, path, "GOVERNANCE", _iso(60))
    assert shortened.status_code == 403, shortened.text
    assert b"governance" in shortened.content.lower()

    # Strengthening to COMPLIANCE with a later date is allowed (it
    # only extends protection)...
    strengthened = _put_retention(service, path, "COMPLIANCE", _iso(10800))
    assert strengthened.status_code == 200, strengthened.text
    # ...and from then on the version is COMPLIANCE-immutable.
    relaxed = _put_retention(service, path, "GOVERNANCE", _iso(10800))
    assert relaxed.status_code == 403, relaxed.text


def test_governance_shortening_via_compliance_with_earlier_date(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/gov2.bin",
                  b"gov2").status_code == 200
    path = "/fence-bucket/gov2.bin"
    assert _put_retention(service, path, "GOVERNANCE",
                          _iso(7200)).status_code == 200
    # Switching the mode while ALSO shortening the window is a bypass.
    refused = _put_retention(service, path, "COMPLIANCE", _iso(60))
    assert refused.status_code == 403, refused.text


def test_governance_retention_cannot_be_cleared_without_bypass(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/gov3.bin",
                  b"gov3").status_code == 200
    path = "/fence-bucket/gov3.bin"
    assert _put_retention(service, path, "GOVERNANCE",
                          _iso(3600)).status_code == 200
    cleared = _clear_retention(service, path)
    assert cleared.status_code == 403, cleared.text
    assert b"governance" in cleared.content.lower()
    # Still protected: a permanent delete is fenced.
    version = _version_of(service, path)
    assert signed(service, "DELETE",
                  f"{path}?versionId={version}").status_code == 403


def test_governance_bypass_with_scope_and_header_shortens(service):
    """The bypass now has backing: s3:BypassGovernanceRetention exists,
    and the fixture credential (minted with the full default permission
    set) holds it. With the explicit header the GOVERNANCE fence opens
    for that principal — deliberately, exactly like AWS — while the
    header without the scope stays 403 (pinned in
    tests/s3/test_s3_governance_bypass.py)."""
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/bypass.bin",
                  b"x").status_code == 200
    path = "/fence-bucket/bypass.bin"
    original = _iso(3600)
    assert _put_retention(service, path, "GOVERNANCE",
                          original).status_code == 200
    shortened_at = _iso(60)
    body = (f'<Retention xmlns="{ACL_XMLNS}"><Mode>GOVERNANCE</Mode>'
            f"<RetainUntilDate>{shortened_at}</RetainUntilDate>"
            f"</Retention>").encode()
    shortened = signed(service, "PUT", f"{path}?retention", body,
                       extra_headers={
                           "x-amz-bypass-governance-retention": "true"})
    assert shortened.status_code == 200, shortened.text
    state = signed(service, "GET", f"{path}?retention")
    assert b"<Mode>GOVERNANCE</Mode>" in state.content
    assert ("T" + shortened_at[11:16] + ":").encode() in state.content
    assert ("T" + original[11:16] + ":").encode() not in state.content
    # The bypassed version stays otherwise fenced: it is still readable
    # and a permanent delete of it keeps answering 403 while retained.
    version = _version_of(service, path)
    assert signed(service, "DELETE",
                  f"{path}?versionId={version}").status_code == 403


# ---------------------------------------------------------------------------
# Deletion-path fences
# ---------------------------------------------------------------------------

def _batch_delete(service, bucket, entries):
    import base64
    import hashlib
    objects_xml = "".join(
        f"<Object><Key>{key}</Key>"
        + (f"<VersionId>{version}</VersionId>" if version else "")
        + "</Object>"
        for key, version in entries)
    body = (f'<Delete xmlns="{ACL_XMLNS}">{objects_xml}</Delete>').encode()
    digest = base64.b64encode(
        hashlib.md5(body, usedforsecurity=False).digest()).decode()
    return signed(service, "POST", f"/{bucket}?delete", body,
                  extra_headers={"content-md5": digest})


def test_batch_delete_fences_retained_and_held_versions(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    for name in ("bd-retained.bin", "bd-held.bin", "bd-free.bin"):
        assert signed(service, "PUT", f"/fence-bucket/{name}",
                      name.encode()).status_code == 200
    retained = _version_of(service, "/fence-bucket/bd-retained.bin")
    held = _version_of(service, "/fence-bucket/bd-held.bin")
    assert _put_retention(service, "/fence-bucket/bd-retained.bin",
                          "COMPLIANCE", _iso(3600)).status_code == 200
    assert _put_legal_hold(service, "/fence-bucket/bd-held.bin",
                           "ON").status_code == 200

    reply = _batch_delete(service, "fence-bucket", [
        ("bd-retained.bin", retained),
        ("bd-held.bin", held),
        ("bd-free.bin", None),
    ])
    assert reply.status_code == 200, reply.text
    assert reply.content.count(b"<Code>AccessDenied</Code>") == 2
    # Protected versions survive...
    assert signed(service, "GET",
                  f"/fence-bucket/bd-retained.bin?versionId={retained}"
                  ).status_code == 200
    assert signed(service, "GET",
                  f"/fence-bucket/bd-held.bin?versionId={held}"
                  ).status_code == 200
    # ...the simple delete of the free object went through (marker).
    assert signed(service, "GET", "/fence-bucket/bd-free.bin"
                  ).status_code == 404


def test_suspended_bucket_cannot_overwrite_or_hide_a_retained_version(
        service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    versioning = (f'<VersioningConfiguration xmlns="{ACL_XMLNS}">'
                  f"<Status>Suspended</Status>"
                  f"</VersioningConfiguration>").encode()
    assert signed(service, "PUT", "/fence-bucket?versioning",
                  versioning).status_code == 200
    assert signed(service, "PUT", "/fence-bucket/suspended.bin",
                  b"first-null").status_code == 200
    path = "/fence-bucket/suspended.bin"
    assert _put_retention(service, path, "GOVERNANCE",
                          _iso(3600)).status_code == 200

    # Overwriting the NULL slot would destroy the retained version.
    overwrite = signed(service, "PUT", path, b"second-null")
    assert overwrite.status_code == 403, overwrite.text
    # A simple DELETE creates a marker that would replace the null
    # slot: also fenced (stricter than AWS, which cannot reach this
    # state — versioning cannot be suspended on a lock-enabled bucket).
    delete = signed(service, "DELETE", path)
    assert delete.status_code == 403, delete.text
    assert signed(service, "GET", path).content == b"first-null"


def test_copy_overwrite_of_a_retained_suspended_null_version(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    versioning = (f'<VersioningConfiguration xmlns="{ACL_XMLNS}">'
                  f"<Status>Suspended</Status>"
                  f"</VersioningConfiguration>").encode()
    assert signed(service, "PUT", "/fence-bucket?versioning",
                  versioning).status_code == 200
    assert signed(service, "PUT", "/fence-bucket/nullsource.bin",
                  b"source").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/copynull.bin",
                  b"null").status_code == 200
    assert _put_retention(service, "/fence-bucket/copynull.bin",
                          "COMPLIANCE", _iso(3600)).status_code == 200
    copy = signed(service, "PUT", "/fence-bucket/copynull.bin",
                  extra_headers={
                      "x-amz-copy-source": "/fence-bucket/nullsource.bin"})
    assert copy.status_code == 403, copy.text
    assert signed(service, "GET", "/fence-bucket/copynull.bin"
                  ).content == b"null"


def test_rename_of_a_retained_version_is_refused(service):
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/rename-me.bin",
                  b"locked").status_code == 200
    assert _put_retention(service, "/fence-bucket/rename-me.bin",
                          "COMPLIANCE", _iso(3600)).status_code == 200
    refused = signed(service, "PUT", "/fence-bucket/renamed.bin?rename",
                     extra_headers={
                         "x-amz-rename-source":
                             "/fence-bucket/rename-me.bin"})
    assert refused.status_code == 403, refused.text
    assert signed(service, "GET", "/fence-bucket/rename-me.bin"
                  ).content == b"locked"


def test_gc_never_collects_retained_or_held_media(service):
    """Read-only audit proof: the GC collector's queue scope filters
    protected versions out of the candidate set entirely."""
    from teledrive.storage.gc_collect import RetainedMediaGC

    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    for name in ("gc-retained.bin", "gc-held.bin", "gc-free.bin"):
        assert signed(service, "PUT", f"/fence-bucket/{name}",
                      name.encode()).status_code == 200
    retained = _object_id(service, "fence-bucket", "gc-retained.bin")
    held = _object_id(service, "fence-bucket", "gc-held.bin")
    free = _object_id(service, "fence-bucket", "gc-free.bin")
    assert _put_retention(service, "/fence-bucket/gc-retained.bin",
                          "GOVERNANCE", _iso(3600)).status_code == 200
    assert _put_legal_hold(service, "/fence-bucket/gc-held.bin",
                           "ON").status_code == 200
    # Revoke every version so they become collection candidates.
    for name in ("gc-retained.bin", "gc-held.bin", "gc-free.bin"):
        version = _version_of(service, f"/fence-bucket/{name}")
        assert signed(service, "DELETE",
                      f"/fence-bucket/{name}?versionId={version}"
                      ).status_code in (204, 403)

    connection = service[3]()
    try:
        gcx = RetainedMediaGC(connection)
        gcx.set_enabled(True, by="test")
        # Enqueue directly: even a hostile/buggy enqueuer cannot make
        # the collector touch protected media.
        gcx.enqueue([retained, held, free], "fence-audit")
        from sqlalchemy import text
        connection.connection.execute(text(
            "UPDATE storage_gc_queue SET enqueued_ns = "
            "enqueued_ns - 7200000000000"))
        connection.commit()
        candidates = gcx.candidates(scope="queued")
        ids = [c["object_id"] for c in candidates]
        assert retained not in ids
        assert held not in ids
    finally:
        connection.close()


def test_locked_object_stays_readable(service):
    """Reads are never fenced by Object Lock (AWS: WORM is
    write-once-READ-MANY); this also covers public-share reads, which
    are reads of the same bytes through another router."""
    assert signed(service, "PUT", "/fence-bucket").status_code == 200
    assert signed(service, "PUT", "/fence-bucket/readable.bin",
                  b"readme").status_code == 200
    path = "/fence-bucket/readable.bin"
    assert _put_retention(service, path, "COMPLIANCE",
                          _iso(3600)).status_code == 200
    assert _put_legal_hold(service, path, "ON").status_code == 200
    assert signed(service, "GET", path).content == b"readme"
    assert signed(service, "HEAD", path).status_code == 200
