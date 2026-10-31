"""Store-layer contracts for share links, pins and sessions.

These run on SQLite; the same functions are exercised on PostgreSQL/MySQL by
``tests/e2e/test_database_live.py`` when those URLs are configured.
"""
from __future__ import annotations

import pytest

from teledrive.db import connect_database
from teledrive.storage import quota
from teledrive.stores import (
    content_index as content_store, pins, sessions, shares, telegram_pending,
    users)


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


def _new_user(db, username="alice", role="admin", enabled=True):
    return users.create(db, username=username, password_hash="hash-1",
                        role=role, now=10, enabled=enabled)["id"]


def test_user_create_lookup_and_list(db):
    uid = _new_user(db)
    _new_user(db, username="bob", role="viewer", enabled=False)

    created = users.get_by_id(db, uid)
    assert created is not None
    assert created["username"] == "alice" and created["role"] == "admin"
    assert created["enabled"] is True
    assert "password_hash" not in created

    # Login needs the hash; lookup is by the UNIQUE username.
    auth = users.get_by_username(db, "alice")
    assert auth is not None and auth["password_hash"] == "hash-1"
    assert users.get_by_username(db, "nobody") is None
    assert users.get_by_id(db, 9999) is None

    assert [(u["username"], u["enabled"]) for u in users.list(db)] == [
        ("alice", True), ("bob", False)]


def test_user_duplicate_username_raises(db):
    from sqlalchemy.exc import IntegrityError

    _new_user(db, username="alice")
    with pytest.raises(IntegrityError):
        _new_user(db, username="alice", role="viewer")


def test_user_mutations(db):
    uid = _new_user(db)
    assert users.set_password(db, uid, "hash-2", now=20) == 1
    assert users.set_role(db, uid, "viewer", now=21) == 1
    assert users.set_enabled(db, uid, False, now=22) == 1
    assert users.set_last_login(db, uid, now=23) == 1

    record = users.get_by_id(db, uid)
    assert record is not None
    assert record["role"] == "viewer" and record["enabled"] is False
    assert record["last_login"] == 23
    assert record["updated_at"] == 22
    assert users.get_by_username(db, "alice")["password_hash"] == "hash-2"

    assert users.rename(db, uid, "alice-2", now=24) == 1
    assert users.get_by_id(db, uid)["username"] == "alice-2"
    # Renaming a missing row is a no-op, not an error.
    assert users.rename(db, 9999, "ghost", now=24) == 0


def test_user_delete_and_enabled_admin_count(db):
    admin = _new_user(db, username="admin", role="admin")
    second = _new_user(db, username="second", role="admin")
    _new_user(db, username="disabled-admin", role="admin", enabled=False)
    _new_user(db, username="viewer", role="viewer")

    assert users.count_enabled_admins(db) == 2
    assert users.delete(db, second) == 1
    assert users.count_enabled_admins(db) == 1
    assert users.delete(db, second) == 0

    # commit=False leaves the delete for the caller's transaction.
    assert users.delete(db, admin, commit=False) == 1
    db.commit()
    assert users.get_by_id(db, admin) is None


def _pending(db, token="pending-a", created_at=100):
    return telegram_pending.create(
        db, token=token, api_id=1, api_hash="hash", phone="+15550001111",
        phone_code_hash="pch", session_string="sess", channel="chan",
        strategy="round_robin", created_at=created_at)


def test_pending_create_get_and_consume(db):
    _pending(db)
    record = telegram_pending.get(db, "pending-a")
    assert record is not None
    assert record["phone"] == "+15550001111" and record["attempts"] == 0
    assert record["session_string"] == "sess"
    assert telegram_pending.get(db, "missing") is None

    assert telegram_pending.consume(db, "pending-a") == 1
    assert telegram_pending.get(db, "pending-a") is None
    assert telegram_pending.consume(db, "pending-a") == 0


def test_pending_attempts_bump_and_purge(db):
    _pending(db, token="old", created_at=100)
    _pending(db, token="new", created_at=1000)
    for expected in (1, 2):
        assert telegram_pending.bump_attempts(db, "old") == 1
        assert telegram_pending.get(db, "old")["attempts"] == expected
    assert telegram_pending.bump_attempts(db, "missing") == 0

    # Strictly older than the cutoff; the new request survives.
    assert telegram_pending.purge_older_than(db, 500) == 1
    assert telegram_pending.get(db, "old") is None
    assert telegram_pending.get(db, "new") is not None

    # commit=False leaves the purge for the caller's transaction.
    assert telegram_pending.purge_older_than(db, 5000, commit=False) == 1
    db.commit()
    assert telegram_pending.get(db, "new") is None


def _indexed_object(db, key="notes.txt"):
    from teledrive.storage.manifest import ManifestStore

    store = ManifestStore(db)
    object_id = store.begin("b1", key, 0, 1)
    store.finish(object_id, "a" * 64, 1)
    return object_id


def _index_row(db, object_id):
    from sqlalchemy import select

    from teledrive.storage.manifest import content_index

    row = db.connection.execute(
        select(content_index.c.text, content_index.c.indexed_at)
        .where(content_index.c.object_id == object_id)
    ).first()
    return dict(row._mapping) if row else None


def test_content_index_ensure_and_delete(db):
    object_id = _indexed_object(db)

    assert _index_row(db, object_id) is None
    assert content_store.ensure_row(db, object_id, indexed_at=100) is True
    row = _index_row(db, object_id)
    assert row["text"] == "" and row["indexed_at"] == 100

    # Idempotent: an existing row is neither duplicated nor overwritten.
    assert content_store.ensure_row(db, object_id, indexed_at=200) is False
    assert _index_row(db, object_id)["indexed_at"] == 100

    assert content_store.delete_for_object(db, object_id) == 1
    assert _index_row(db, object_id) is None
    assert content_store.delete_for_object(db, object_id) == 0


def test_content_index_search_delegates_and_delete_clears_fts(db, tmp_path):
    from teledrive.storage.content_index import index_object_content

    object_id = _indexed_object(db, key="doc.txt")
    path = tmp_path / "doc.txt"
    path.write_text("searchable body", encoding="utf-8")
    assert index_object_content(db, object_id, path, "doc.txt")

    assert [hit[0] for hit in content_store.search(db, "searchable")] == [
        object_id]
    content_store.delete_for_object(db, object_id)
    assert content_store.search(db, "searchable") == []


def test_telegram_account_and_channel_id_are_unique(db):
    """upsert_session/upsert_channel rely on the database to reject a
    duplicate INSERT, so the columns must actually be unique."""
    from sqlalchemy import insert, select
    from sqlalchemy.exc import IntegrityError

    from teledrive.db import telegram_channels, telegram_sessions
    from teledrive.stores import telegram_accounts

    telegram_accounts.upsert_session(
        db, api_id=1, api_hash="h", session_string="s", account="unique-acct",
        now=10)
    with pytest.raises(IntegrityError):
        db.connection.execute(insert(telegram_sessions).values(
            api_id=1, api_hash="h", session_string="dup", account="unique-acct",
            created_at=10, updated_at=10))
    db.connection.rollback()

    telegram_accounts.upsert_channel_by_channel_id(
        db, name="one", channel_id="unique-chan", strategy="round_robin",
        scratch_dir="/tmp", now=10)
    with pytest.raises(IntegrityError):
        db.connection.execute(insert(telegram_channels).values(
            name="dup", channel_id="unique-chan", strategy="round_robin",
            scratch_dir="/tmp", is_active=0, created_at=10, updated_at=10))
    db.connection.rollback()

    assert db.connection.execute(
        select(telegram_sessions.c.id)
        .where(telegram_sessions.c.account == "unique-acct")).all()
    assert len(db.connection.execute(
        select(telegram_channels.c.id)
        .where(telegram_channels.c.channel_id == "unique-chan")).all()) == 1


def test_upsert_session_recovers_from_a_lost_insert_race(tmp_path):
    """Deterministically exercise the IntegrityError recovery branch.

    A concurrent creator commits between our UPDATE (rowcount 0) and our
    INSERT, so the INSERT hits the unique account constraint. The store must
    roll back, re-apply the UPDATE, and leave exactly one row -- not raise.
    """
    from types import SimpleNamespace

    from sqlalchemy import insert, select
    from sqlalchemy.sql.dml import Update

    from teledrive.db import telegram_sessions
    from teledrive.stores import telegram_accounts

    url = str(tmp_path / "lost-race.sqlite")
    real = connect_database(url)
    rival = connect_database(url)

    class RacingConnection:
        def __init__(self):
            self.raced = False

        def execute(self, statement, *args, **kwargs):
            if (not self.raced and isinstance(statement, Update)
                    and statement.table.name == "telegram_sessions"):
                self.raced = True
                rival.connection.execute(insert(telegram_sessions).values(
                    api_id=1, api_hash="h", session_string="rival",
                    account="lost-race", created_at=1, updated_at=1))
                rival.connection.commit()
                return SimpleNamespace(rowcount=0)
            return real.connection.execute(statement, *args, **kwargs)

        def rollback(self):
            real.connection.rollback()

        def commit(self):
            real.connection.commit()

    class RacingDatabase:
        def __init__(self):
            self.connection = RacingConnection()

        def commit(self):
            self.connection.commit()

    racing = RacingDatabase()
    try:
        telegram_accounts.upsert_session(
            racing, api_id=1, api_hash="h", session_string="winner",
            account="lost-race", now=10)
        assert racing.connection.raced
        rows = real.connection.execute(
            select(telegram_sessions.c.session_string)
            .where(telegram_sessions.c.account == "lost-race")).scalars().all()
        assert rows == ["winner"]
    finally:
        real.close()
        rival.close()


def test_concurrent_upsert_session_and_channel_leave_one_row(tmp_path):
    """Two racing creators of one account/channel must converge on one row."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from sqlalchemy import select

    from teledrive.db import telegram_channels, telegram_sessions
    from teledrive.stores import telegram_accounts

    url = str(tmp_path / "upsert-race.sqlite")
    observer = connect_database(url)
    gate = Barrier(2)

    def worker(index):
        conn = connect_database(url)
        try:
            gate.wait(timeout=20)
            telegram_accounts.upsert_session(
                conn, api_id=1, api_hash="h",
                session_string=f"session-{index}", account="race-acct", now=100)
            telegram_accounts.upsert_channel_by_channel_id(
                conn, name=f"chan-{index}", channel_id="race-chan",
                strategy="round_robin", scratch_dir="/tmp", now=100)
        finally:
            conn.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(worker, range(2)))
        assert len(observer.connection.execute(
            select(telegram_sessions.c.id)
            .where(telegram_sessions.c.account == "race-acct")).all()) == 1
        assert len(observer.connection.execute(
            select(telegram_channels.c.id)
            .where(telegram_channels.c.channel_id == "race-chan")).all()) == 1
    finally:
        observer.close()


def test_schema_migration_dedupes_legacy_telegram_rows(tmp_path):
    """Step 27 keeps the newest row per account/channel before indexing.

    Simulates a pre-27 database: the tables exist without the unique
    constraint and already contain duplicates, which the old race could
    create.
    """
    from sqlalchemy import create_engine, select
    from sqlalchemy.exc import IntegrityError

    from teledrive.db import telegram_channels, telegram_sessions
    from teledrive.storage import schema as schema_module

    path = tmp_path / "legacy-telegram.sqlite"
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE telegram_sessions ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " api_id BIGINT NOT NULL, api_hash VARCHAR(128) NOT NULL,"
            " phone VARCHAR(64), session_string TEXT NOT NULL,"
            " account VARCHAR(128) NOT NULL DEFAULT 'mtproto-user',"
            " channel VARCHAR(255), strategy VARCHAR(32),"
            " created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)")
        connection.exec_driver_sql(
            "INSERT INTO telegram_sessions"
            " (api_id, api_hash, session_string, account, created_at, updated_at)"
            " VALUES (1, 'h', 'old', 'dup', 1, 10),"
            "        (1, 'h', 'newest-a', 'dup', 1, 20),"
            "        (1, 'h', 'newest-b', 'dup', 1, 20)")
        connection.exec_driver_sql(
            "CREATE TABLE telegram_channels ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " name VARCHAR(128) NOT NULL, channel_id VARCHAR(255) NOT NULL,"
            " strategy VARCHAR(32) NOT NULL DEFAULT 'round_robin',"
            " scratch_dir VARCHAR(512), is_active INTEGER NOT NULL DEFAULT 0,"
            " created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)")
        connection.exec_driver_sql(
            "INSERT INTO telegram_channels"
            " (name, channel_id, strategy, scratch_dir, is_active,"
            "  created_at, updated_at)"
            " VALUES ('old', 'chan', 'round_robin', '/tmp', 0, 1, 10),"
            "        ('newest-a', 'chan', 'round_robin', '/tmp', 0, 1, 20),"
            "        ('newest-b', 'chan', 'round_robin', '/tmp', 0, 1, 20)")
    engine.dispose()

    schema_module.reset_process_cache()
    db = connect_database(str(path))
    try:
        sessions = db.connection.execute(
            select(telegram_sessions.c.session_string)
            .where(telegram_sessions.c.account == "dup")).scalars().all()
        channels = db.connection.execute(
            select(telegram_channels.c.name)
            .where(telegram_channels.c.channel_id == "chan")).scalars().all()
        # Latest updated_at wins; the id tie-break keeps the lower id.
        assert sessions == ["newest-a"]
        assert channels == ["newest-a"]
        with pytest.raises(IntegrityError):
            db.connection.execute(telegram_sessions.insert().values(
                api_id=1, api_hash="h", session_string="again", account="dup",
                created_at=1, updated_at=1))
        db.connection.rollback()
    finally:
        db.close()


