"""Per-operation evidence for the storage-report configuration family.

Fills four columns of the evidence matrix in
``docs/reference/s3-evidence.md`` for the twelve analytics / inventory /
metrics configuration operations (Get/Put/Delete/List for each kind):

* **auth-failure** — a validly signed credential WITHOUT the operation's
  own permission is refused 403 ``AccessDenied``, the read / write /
  delete scopes are independently grantable, and a scope for one report
  kind never unlocks another;
* **retry** — replaying a PUT keeps exactly one SQL row (last write
  wins), and replaying a DELETE stays 204 with no resurrected row;
* **crash-restart** — a stored configuration is read back through a NEW
  ``Database``/store pair, exactly as a restarted process would open it;
* **race** — two concurrent replacements of the same configuration id
  leave exactly one stored document, never two rows and never a torn
  write.

Normal / malformed / over-limit for this family are proven in
``tests/s3/test_s3_report_configs.py``; the global unsigned sweep covers
the missing-credential column for every operation. The bodies are the
same strict documents that module uses, so the fixtures cannot drift.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import func, select

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.report_configs import ReportConfigStore, report_configs
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_report_configs import analytics, inventory, metrics

BUCKET = "report-source"
DESTINATION = "report-dest"

# kind -> document builder for configuration id "evidence-1".
BODIES = {
    "analytics": lambda prefix: analytics("evidence-1", prefix=prefix),
    "inventory": lambda prefix: inventory("evidence-1", prefix=prefix),
    "metrics": lambda prefix: metrics("evidence-1", prefix=prefix),
}

# kind -> the capitalized AWS family used in the permission names.
KIND_LABEL = {"analytics": "Analytics", "inventory": "Inventory",
              "metrics": "Metrics"}


def _scoped(service, name, permissions):
    db = service[3]()
    try:
        return S3CredentialStore(db, service[4]).create(name, permissions)
    finally:
        db.close()


def _as(service, credential):
    return dict(access=credential.access_key,
                secret=credential.secret_key)


def _put(service, kind, body, credential=None):
    kwargs = _as(service, credential) if credential else {}
    return signed(service, "PUT", f"/{BUCKET}?{kind}&id=evidence-1",
                  body, **kwargs)


def _rows(connection, bucket, kind, config_id="evidence-1"):
    db = connection()
    try:
        return db.connection.execute(select(
            report_configs.c.document).where(
            report_configs.c.bucket == bucket,
            report_configs.c.kind == kind,
            report_configs.c.config_id == config_id)).all()
    finally:
        db.close()


@pytest.mark.parametrize("kind", sorted(BODIES))
def test_each_operation_denies_a_credential_without_its_permission(
        service, kind):
    """Get / Put / Delete / List each refuse their own missing scope."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{DESTINATION}").status_code == 200
    label = KIND_LABEL[kind]
    reader = _scoped(service, f"{kind}-reader",
                     [f"s3:GetBucket{label}Configuration"])
    writer = _scoped(service, f"{kind}-writer",
                     [f"s3:PutBucket{label}Configuration"])
    deleter = _scoped(service, f"{kind}-deleter",
                      [f"s3:DeleteBucket{label}Configuration"])
    outsider = _scoped(service, f"{kind}-outsider", ["s3:GetObject"])
    body = BODIES[kind]("data/")

    # ListBucket*Configurations: the id-less GET is the list operation.
    listed = signed(service, "GET", f"/{BUCKET}?{kind}",
                    **_as(service, outsider))
    assert listed.status_code == 403, listed.text
    assert b"AccessDenied" in listed.content
    assert signed(service, "GET", f"/{BUCKET}?{kind}",
                  **_as(service, reader)).status_code == 200

    # GetBucket*Configuration: refused without the read scope, and a
    # refused write must not have stored anything to read.
    denied_get = signed(service, "GET", f"/{BUCKET}?{kind}&id=evidence-1",
                        **_as(service, outsider))
    assert denied_get.status_code == 403
    assert b"AccessDenied" in denied_get.content

    # PutBucket*Configuration: a reader cannot write.
    denied_put = _put(service, kind, body, reader)
    assert denied_put.status_code == 403, denied_put.text
    assert b"AccessDenied" in denied_put.content
    assert not _rows(service[3], BUCKET, kind), "a denied PUT stored a row"

    assert _put(service, kind, body, writer).status_code == 200

    # DeleteBucket*Configuration: a reader cannot delete either.
    denied_delete = signed(service, "DELETE",
                           f"/{BUCKET}?{kind}&id=evidence-1",
                           **_as(service, reader))
    assert denied_delete.status_code == 403
    assert b"AccessDenied" in denied_delete.content
    assert signed(service, "GET",
                  f"/{BUCKET}?{kind}&id=evidence-1",
                  **_as(service, reader)).status_code == 200

    assert signed(service, "DELETE", f"/{BUCKET}?{kind}&id=evidence-1",
                  **_as(service, deleter)).status_code == 204


@pytest.mark.parametrize("kind", sorted(BODIES))
def test_a_scope_for_one_report_kind_never_unlocks_another(service, kind):
    """An analytics reader gets 403 on inventory and metrics routes."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    other = next(name for name in sorted(BODIES) if name != kind)
    label = KIND_LABEL[kind]
    reader = _scoped(service, f"{kind}-only",
                     [f"s3:GetBucket{label}Configuration"])
    denied = signed(service, "GET", f"/{BUCKET}?{other}",
                    **_as(service, reader))
    assert denied.status_code == 403, denied.text
    assert b"AccessDenied" in denied.content


@pytest.mark.parametrize("kind", sorted(BODIES))
def test_replayed_put_keeps_one_row_and_replayed_delete_stays_dead(
        service, kind):
    """Retry column: a replay is one row, last write wins, no resurrection."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{DESTINATION}").status_code == 200
    first = BODIES[kind]("alpha/")
    second = BODIES[kind]("beta/")

    assert _put(service, kind, first).status_code == 200
    assert _put(service, kind, first).status_code == 200  # client retry
    rows = _rows(service[3], BUCKET, kind)
    assert len(rows) == 1, f"a replayed PUT left {len(rows)} rows"

    assert _put(service, kind, second).status_code == 200  # conflicting doc
    rows = _rows(service[3], BUCKET, kind)
    assert len(rows) == 1, f"a replacing PUT left {len(rows)} rows"
    stored = signed(service, "GET", f"/{BUCKET}?{kind}&id=evidence-1")
    assert stored.status_code == 200
    assert b"beta/" in stored.content

    path = f"/{BUCKET}?{kind}&id=evidence-1"
    assert signed(service, "DELETE", path).status_code == 204
    # The second delete is not an error and cannot resurrect the row.
    assert signed(service, "DELETE", path).status_code == 204
    assert not _rows(service[3], BUCKET, kind)
    missing = signed(service, "GET", path)
    assert missing.status_code == 404
    assert b"NoSuchConfiguration" in missing.content


@pytest.mark.parametrize("kind", sorted(BODIES))
def test_a_stored_configuration_survives_a_restart(service, kind):
    """Crash-restart column: a fresh Database/store still reads the row."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{DESTINATION}").status_code == 200
    assert _put(service, kind, BODIES[kind]("durable/")).status_code == 200

    connection = service[3]
    db = connection()
    try:
        store = ReportConfigStore(BucketCatalog(ManifestStore(db)))
        stored = store.get(BUCKET, kind, "evidence-1")
        assert stored is not None, "the configuration vanished after a restart"
        assert stored["id"] == "evidence-1"
        listed = store.list(BUCKET, kind)
        assert [item["id"] for item in listed] == ["evidence-1"]
    finally:
        db.close()

    # The gateway opens a new connection per request; the read-back is the
    # same document, not a stale cache.
    reply = signed(service, "GET", f"/{BUCKET}?{kind}&id=evidence-1")
    assert reply.status_code == 200
    assert b"durable/" in reply.content


@pytest.mark.parametrize("kind", sorted(BODIES))
def test_concurrent_replacements_leave_exactly_one_document(service, kind):
    """Race column: two writers, one id — one stored document, never two."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{DESTINATION}").status_code == 200
    assert _put(service, kind, BODIES[kind]("seed/")).status_code == 200

    connection = service[3]
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    prefixes = ("writer-a/", "writer-b/")

    def writer(prefix: str) -> None:
        db = connection()
        try:
            store = ReportConfigStore(BucketCatalog(ManifestStore(db)))
            document = store.get(BUCKET, kind, "evidence-1")
            barrier.wait(timeout=10)
            store.put(BUCKET, kind, "evidence-1",
                      {**document, "filter": {"prefix": prefix, "tags": []}})
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(prefix,))
               for prefix in prefixes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert not failures, failures

    rows = _rows(service[3], BUCKET, kind)
    assert len(rows) == 1, (
        f"concurrent PUTs left {len(rows)} rows for one configuration id")
    stored = signed(service, "GET", f"/{BUCKET}?{kind}&id=evidence-1")
    assert stored.status_code == 200
    assert (b"writer-a/" in stored.content) != (
        b"writer-b/" in stored.content), (
        "the stored document is neither writer's, or both leaked in")
    listed = signed(service, "GET", f"/{BUCKET}?{kind}")
    assert listed.content.count(b">evidence-1<") == 1
