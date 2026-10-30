"""The Telegram account/channel store: portable SQL, secrets never listed."""
from __future__ import annotations

import pytest
from sqlalchemy import text

from teledrive.db import connect_database
from teledrive.stores import telegram_accounts as store


@pytest.fixture()
def db(tmp_path):
    database = connect_database(str(tmp_path / "telegram.sqlite"))
    try:
        yield database
    finally:
        database.close()


def test_a_session_is_upserted_and_its_secret_is_never_listed(db):
    store.upsert_session(db, api_id=123, api_hash="h" * 32,
                         session_string="1BVtsSESSION-SECRET", account="acct-a",
                         phone="+15550001111", now=10)
    # Second call replaces the credential in place (portable upsert).
    store.upsert_session(db, api_id=123, api_hash="h" * 32,
                         session_string="1BVtsNEW-SECRET", account="acct-a",
                         now=20)

    rows = store.list_sessions(db)
    assert len(rows) == 1, "the upsert must not have created a second row"
    assert "session_string" not in rows[0], "a listing must not carry the secret"
    assert "1BVts" not in str(rows)

    raw = store.get_session(db, "acct-a")
    assert raw["session_string"] == "1BVtsNEW-SECRET"
    assert store.has_session(db, "acct-a") is True
    assert store.has_session(db, "nobody") is False


def test_authorized_is_tri_state(db):
    store.upsert_session(db, api_id=1, api_hash="h", session_string="s",
                         account="acct-b", now=1)
    assert store.list_sessions(db)[0]["authorized"] is None, (
        "never-checked must stay NULL, not become 0")
    store.record_health(db, "acct-b", True, now=5)
    assert store.list_sessions(db)[0]["authorized"] == 1
    store.record_health(db, "acct-b", False, now=6)
    assert store.list_sessions(db)[0]["authorized"] == 0


def test_soft_quota_round_trips_and_clears(db):
    store.upsert_session(db, api_id=1, api_hash="h", session_string="s",
                         account="acct-c", now=1)
    assert store.set_soft_quota(db, "acct-c", 4096) is True
    assert store.list_sessions(db)[0]["soft_quota_bytes"] == 4096
    store.set_soft_quota(db, "acct-c", None)
    assert store.list_sessions(db)[0]["soft_quota_bytes"] is None
    assert store.set_soft_quota(db, "missing", 1) is False


def test_delete_reports_what_it_did(db):
    store.upsert_session(db, api_id=1, api_hash="h", session_string="s",
                         account="acct-d", now=1)
    assert store.delete_session(db, "acct-d") is True
    assert store.delete_session(db, "acct-d") is False


def test_exactly_one_channel_is_active(db):
    first = store.create_channel(db, name="one", channel_id="chan-1",
                                 strategy="single", scratch_dir="/tmp", now=1)
    second = store.create_channel(db, name="two", channel_id="chan-2",
                                  strategy="single", scratch_dir="/tmp", now=2)
    assert first != second
    # New channels start inactive, so nothing is live until chosen.
    assert store.list_channels(db, active_only=True) == []

    store.activate_channel(db, first, now=3)
    active = store.list_channels(db, active_only=True)
    assert [c["id"] for c in active] == [first]

    store.activate_channel(db, second, now=4)
    active = store.list_channels(db, active_only=True)
    assert [c["id"] for c in active] == [second], (
        "activating one channel must deactivate the other")

    store.deactivate_all_channels(db, now=5)
    assert store.list_channels(db, active_only=True) == []
    assert len(store.list_channels(db)) == 2, "rows are kept, not deleted"

    assert store.get_channel(db, first)["name"] == "one"
    assert store.delete_channel(db, first) is True
    assert store.get_channel(db, first) is None
