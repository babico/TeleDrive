"""Store-layer contracts for share links, pins and sessions.

These run on SQLite; the same functions are exercised on PostgreSQL/MySQL by
``tests/e2e/test_database_live.py`` when those URLs are configured.
"""
from __future__ import annotations

import pytest

from teledrive.db import connect_database
from teledrive.storage import quota
from teledrive.stores import pins, sessions, shares


@pytest.fixture
def db(tmp_path):
    conn = connect_database(str(tmp_path / "stores.sqlite"))
    try:
        yield conn
    finally:
        conn.close()


def _create(db, token="t" * 24, **overrides):
    values = dict(
        token=token, bucket="b1", object_key="dir/obj.bin", object_id="oid-1",
        created_by="admin", created_at=100, expires_at=None, max_downloads=None,
        password_salt=None, password_hash=None,
    )
    values.update(overrides)
    return shares.create(db, **values)


def test_share_create_resolve_and_object_binding(db):
    _create(db, token="a" * 24)
    row = shares.resolve_token(db, "a" * 24, now=200)
    assert row is not None
    assert row["object_id"] == "oid-1"
    assert row["bucket"] == "b1" and row["object_key"] == "dir/obj.bin"


def test_share_resolve_refuses_expired_revoked_and_exhausted(db):
    _create(db, token="b" * 24, expires_at=150)
    assert shares.resolve_token(db, "b" * 24, now=151) is None

    _create(db, token="c" * 24, max_downloads=1)
    assert shares.resolve_token(db, "c" * 24, now=200) is not None
    assert shares.claim_download(db, "c" * 24, now=200) is True
    assert shares.resolve_token(db, "c" * 24, now=200) is None
    # A second claim cannot exceed the cap.
    assert shares.claim_download(db, "c" * 24, now=200) is False

    _create(db, token="d" * 24)
    assert shares.revoke(db, "d" * 24) is True
    assert shares.resolve_token(db, "d" * 24, now=200) is None
    assert shares.revoke(db, "d" * 24) is False


def test_share_list_and_delete_for_bucket(db):
    _create(db, token="e" * 24, password_salt="salt", password_hash="hash")
    _create(db, token="f" * 24, bucket="b2")
    rows = shares.list(db)
    assert {row["token"] for row in rows} == {"e" * 24, "f" * 24}
    assert next(r for r in rows if r["token"] == "e" * 24)["has_password"] is True

    assert shares.delete_for_bucket(db, "b1") == 1
    assert [row["token"] for row in shares.list(db)] == ["f" * 24]


def test_pin_set_get_update_and_delete(db):
    assert pins.get(db, "b1") is None
    pins.set(db, "b1", "account-a", now=10)
    assert pins.get(db, "b1") == "account-a"
    # Updating an existing pin must not insert a second row.
    pins.set(db, "b1", "account-b", now=20)
    assert pins.get(db, "b1") == "account-b"
    assert pins.delete(db, "b1") == 1
    assert pins.get(db, "b1") is None
    assert pins.delete(db, "b1") == 0


def test_bucket_quota_set_update_and_list(db):
    assert quota.bucket_quota(db, "b1") == (None, None)
    quota.set_bucket_quota(db, "b1", 100, 2, now=10)
    quota.set_bucket_quota(db, "b2", 200, None, now=11)
    assert quota.bucket_quota(db, "b1") == (100, 2)
    # Updating an existing quota keeps a single row and clears fields.
    quota.set_bucket_quota(db, "b1", None, 3, now=20)
    assert quota.bucket_quota(db, "b1") == (None, 3)
    assert quota.all_bucket_quotas(db) == [
        ("b1", None, 3), ("b2", 200, None)]


def _add_user(db, username="alice", role="admin", enabled=1):
    from sqlalchemy import insert

    from teledrive.db import users

    db.connection.execute(insert(users).values(
        username=username, password_hash="x", role=role, enabled=enabled,
        created_at=1, updated_at=1,
    ))
    db.commit()
    from sqlalchemy import select

    return int(db.connection.execute(
        select(users.c.id).where(users.c.username == username)).scalar_one())


def _session(db, token, user_id, created_at=10, expires_at=1000):
    sessions.create(db, token=token, user_id=user_id,
                    created_at=created_at, expires_at=expires_at)


def test_session_create_resolve_username_and_list(db):
    uid = _add_user(db)
    _session(db, "tok-a", uid, created_at=10)
    _session(db, "tok-b", uid, created_at=20)

    assert sessions.username_for_token(db, "tok-a") == "alice"
    assert sessions.username_for_token(db, "missing") is None
    assert sessions.resolve(db, "tok-a", now=100) == {
        "id": uid, "username": "alice", "role": "admin"}
    assert [s["token"] for s in sessions.list_for_user(db, uid)] == [
        "tok-b", "tok-a"]


def test_session_resolve_deletes_expired_token(db):
    uid = _add_user(db)
    _session(db, "tok-exp", uid, expires_at=100)
    assert sessions.resolve(db, "tok-exp", now=101) is None
    assert sessions.username_for_token(db, "tok-exp") is None


def test_session_resolve_treats_disabled_user_as_unauthenticated(db):
    uid = _add_user(db, enabled=0)
    _session(db, "tok-disabled", uid)
    assert sessions.resolve(db, "tok-disabled", now=100) is None
    # All of that user's sessions are gone, not just the one presented.
    assert sessions.list_for_user(db, uid) == []


def test_session_delete_scopes(db):
    uid = _add_user(db)
    other = _add_user(db, username="bob")
    _session(db, "tok-1", uid)
    _session(db, "tok-2", uid)
    _session(db, "tok-3", other, expires_at=50)
    _session(db, "tok-4", other, expires_at=5000)

    assert sessions.delete_token(db, "tok-1") == 1
    assert sessions.delete_token(db, "tok-1") == 0
    assert sessions.delete_for_user(db, uid) == 1
    assert sessions.list_for_user(db, uid) == []
    # bob's expired token is purged; his live token survives.
    assert sessions.purge_expired(db, now=100) == 1
    assert [s["token"] for s in sessions.list_for_user(db, other)] == ["tok-4"]
    assert sessions.delete_all(db) == 1
    assert sessions.list_for_user(db, other) == []