"""Typed access to the Telegram account, channel and flood-wait tables.

These are the last raw-SQL tables in `web/app.py`. Each function takes the
`Database` wrapper, commits once, and keeps the SQL portable: UPDATE-then-
INSERT instead of `ON CONFLICT`, SELECT-then-INSERT instead of `INSERT OR
IGNORE`, no `RETURNING`, and every multi-row filter with `LIMIT 1` plus a
deterministic `ORDER BY`.

Design notes that are easy to lose in a rewrite:

* **A Telegram session string is a credential.** Nothing here logs it, and no
  function returns it to a caller that did not ask for the raw value -- the
  listing helpers project an explicit column set instead of `SELECT *`.
* **`authorized` is tri-state** (NULL never checked, 1 authorized, 0 expired).
  A helper that coerces NULL to 0 would make a healthy account look dead.
* **Channels are deactivated, not deleted,** by the login flow, so a listing
  must be able to ask for all of them.
"""
from __future__ import annotations

import time

from sqlalchemy import delete, insert, select, update

from teledrive.db import flood_waits, telegram_channels, telegram_sessions

# api_id is metadata (the numeric app id), not a credential: only api_hash
# and session_string are secrets, and those are what the listing excludes.
_SESSION_LIST_COLUMNS = (
    telegram_sessions.c.id, telegram_sessions.c.account,
    telegram_sessions.c.api_id,
    telegram_sessions.c.phone, telegram_sessions.c.channel,
    telegram_sessions.c.strategy, telegram_sessions.c.created_at,
    telegram_sessions.c.updated_at, telegram_sessions.c.authorized,
    telegram_sessions.c.health_checked_at, telegram_sessions.c.soft_quota_bytes,
)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def list_sessions(db) -> list[dict]:
    """Metadata only: the session string is a credential and never listed."""
    rows = db.connection.execute(
        select(*_SESSION_LIST_COLUMNS).order_by(
            telegram_sessions.c.created_at, telegram_sessions.c.id)
    ).mappings().all()
    return [dict(row) for row in rows]


def get_session(db, account: str) -> dict | None:
    """One account INCLUDING its session string, for the transport only."""
    row = db.connection.execute(
        select(*_SESSION_LIST_COLUMNS, telegram_sessions.c.session_string,
               telegram_sessions.c.api_id, telegram_sessions.c.api_hash)
        .where(telegram_sessions.c.account == account)
        .order_by(telegram_sessions.c.updated_at.desc(),
                  telegram_sessions.c.id.desc())
        .limit(1)
    ).mappings().first()
    return dict(row) if row is not None else None


def has_session(db, account: str) -> bool:
    return db.connection.execute(
        select(telegram_sessions.c.id)
        .where(telegram_sessions.c.account == account)
        .limit(1)
    ).first() is not None


def upsert_session(db, *, api_id: int, api_hash: str, session_string: str,
                   account: str, phone: str | None = None,
                   channel: str | None = None,
                   strategy: str | None = None, now: int | None = None) -> None:
    """Create the account's session, or replace its credential in place.

    Portable by construction: UPDATE first, INSERT only when the row is
    missing, and let the unique account constraint catch a concurrent
    creator (the caller retries the update).
    """
    now = int(time.time()) if now is None else now
    values = {
        "api_id": int(api_id), "api_hash": api_hash,
        "session_string": session_string, "updated_at": now,
        "authorized": None, "health_checked_at": None,
    }
    if phone is not None:
        values["phone"] = phone
    if channel is not None:
        values["channel"] = channel
    if strategy is not None:
        values["strategy"] = strategy
    changed = db.connection.execute(
        update(telegram_sessions)
        .where(telegram_sessions.c.account == account)
        .values(**values)
    )
    if changed.rowcount == 0:
        try:
            db.connection.execute(insert(telegram_sessions).values(
                account=account, created_at=now, **values))
        except Exception:
            # Lost a race: the row exists now, so apply the update.
            db.connection.rollback()
            db.connection.execute(
                update(telegram_sessions)
                .where(telegram_sessions.c.account == account)
                .values(**values))
    db.commit()


def delete_session(db, account: str) -> bool:
    changed = db.connection.execute(
        delete(telegram_sessions).where(
            telegram_sessions.c.account == account))
    db.commit()
    return bool(changed.rowcount)


def record_health(db, account: str, authorized: bool,
                  now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    db.connection.execute(
        update(telegram_sessions)
        .where(telegram_sessions.c.account == account)
        .values(authorized=1 if authorized else 0, health_checked_at=now)
    )
    db.commit()


def set_soft_quota(db, account: str, max_bytes: int | None) -> bool:
    changed = db.connection.execute(
        update(telegram_sessions)
        .where(telegram_sessions.c.account == account)
        .values(soft_quota_bytes=max_bytes)
    )
    db.commit()
    return bool(changed.rowcount)


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------

def list_channels(db, *, active_only: bool = False) -> list[dict]:
    statement = select(
        telegram_channels.c.id, telegram_channels.c.name,
        telegram_channels.c.channel_id, telegram_channels.c.strategy,
        telegram_channels.c.scratch_dir, telegram_channels.c.is_active,
        telegram_channels.c.created_at, telegram_channels.c.updated_at,
    )
    if active_only:
        statement = statement.where(telegram_channels.c.is_active == 1)
    statement = statement.order_by(
        telegram_channels.c.created_at, telegram_channels.c.id)
    return [dict(row) for row in db.connection.execute(statement).mappings()]


def get_channel(db, channel_id: int) -> dict | None:
    row = db.connection.execute(
        select(telegram_channels.c.id, telegram_channels.c.name,
               telegram_channels.c.channel_id, telegram_channels.c.strategy,
               telegram_channels.c.scratch_dir,
               telegram_channels.c.is_active, telegram_channels.c.created_at,
               telegram_channels.c.updated_at)
        .where(telegram_channels.c.id == channel_id)
        .limit(1)
    ).mappings().first()
    return dict(row) if row is not None else None


def create_channel(db, *, name: str, channel_id: str, strategy: str,
                   scratch_dir: str, now: int | None = None) -> int:
    now = int(time.time()) if now is None else now
    db.connection.execute(insert(telegram_channels).values(
        name=name, channel_id=str(channel_id), strategy=strategy,
        scratch_dir=scratch_dir, is_active=0,
        created_at=now, updated_at=now,
    ))
    # `inserted_primary_key` is not portable across backends here, so read it
    # back deterministically instead.
    identifier = db.connection.execute(
        select(telegram_channels.c.id)
        .where(telegram_channels.c.channel_id == str(channel_id))
        .order_by(telegram_channels.c.id.desc())
        .limit(1)
    ).scalar_one()
    db.commit()
    return int(identifier)


def activate_channel(db, channel_id: int, now: int | None = None) -> None:
    """Exactly one channel is active; the others are deactivated together."""
    now = int(time.time()) if now is None else now
    db.connection.execute(update(telegram_channels).values(
        is_active=0, updated_at=now))
    db.connection.execute(
        update(telegram_channels)
        .where(telegram_channels.c.id == channel_id)
        .values(is_active=1, updated_at=now))
    db.commit()


def deactivate_all_channels(db, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    db.connection.execute(update(telegram_channels).values(
        is_active=0, updated_at=now))
    db.commit()


def delete_channel(db, channel_id: int) -> bool:
    changed = db.connection.execute(
        delete(telegram_channels).where(
            telegram_channels.c.id == channel_id))
    db.commit()
    return bool(changed.rowcount)


# ---------------------------------------------------------------------------
# Flood waits
# ---------------------------------------------------------------------------

def record_flood_wait(db, *, scope: str, wait_seconds: int, detail,
                      now: int | None = None) -> dict:
    """Append a FloodWait observation and return the reported window."""
    now = int(time.time()) if now is None else now
    seconds = int(wait_seconds)
    db.connection.execute(insert(flood_waits).values(
        scope=scope, started_at=now, wait_seconds=seconds,
        expires_at=now + seconds, detail=detail))
    db.commit()
    return {"active": True, "remaining_seconds": seconds,
            "expires_at": now + seconds}


def last_flood_wait(db) -> dict | None:
    """The most recent observation, newest first, deterministic."""
    row = db.connection.execute(
        select(flood_waits.c.scope, flood_waits.c.started_at,
               flood_waits.c.wait_seconds, flood_waits.c.expires_at,
               flood_waits.c.detail)
        .order_by(flood_waits.c.started_at.desc(), flood_waits.c.id.desc())
        .limit(1)
    ).mappings().first()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------
# Whole-table reads the runtime needs (credentials included, never listed)
# ---------------------------------------------------------------------------

def all_session_credentials(db) -> list[dict]:
    """Every account's api credentials and session string, for the runtime.

    Deliberately NOT named "list": this returns secrets, so a caller has to
    ask for credentials by name. Nothing logs or returns these to a request.
    """
    rows = db.connection.execute(
        select(telegram_sessions.c.account, telegram_sessions.c.api_id,
               telegram_sessions.c.api_hash,
               telegram_sessions.c.session_string,
               telegram_sessions.c.authorized)
        .order_by(telegram_sessions.c.account)
    ).mappings().all()
    return [dict(row) for row in rows]


def latest_session(db) -> dict | None:
    """The most recently inserted session, for the single-account status view."""
    row = db.connection.execute(
        select(telegram_sessions.c.id, telegram_sessions.c.api_id,
               telegram_sessions.c.phone, telegram_sessions.c.account,
               telegram_sessions.c.channel, telegram_sessions.c.strategy,
               telegram_sessions.c.created_at, telegram_sessions.c.updated_at)
        .order_by(telegram_sessions.c.id.desc())
        .limit(1)
    ).mappings().first()
    return dict(row) if row is not None else None


def upsert_channel_by_channel_id(db, *, name: str, channel_id: str,
                                 strategy: str, scratch_dir: str,
                                 active: bool = False,
                                 now: int | None = None) -> int:
    """Create the channel, or update the row that already has this channel_id.

    Portable: no `RETURNING` (MySQL has none), so the id is read back after
    the write.
    """
    now = int(time.time()) if now is None else now
    existing = db.connection.execute(
        select(telegram_channels.c.id)
        .where(telegram_channels.c.channel_id == str(channel_id))
        .order_by(telegram_channels.c.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        db.connection.execute(
            update(telegram_channels)
            .where(telegram_channels.c.id == existing)
            .values(name=name, strategy=strategy, scratch_dir=scratch_dir,
                    is_active=1 if active else 0, updated_at=now))
        db.commit()
        return int(existing)
    identifier = create_channel(db, name=name, channel_id=channel_id,
                                strategy=strategy, scratch_dir=scratch_dir,
                                now=now)
    if active:
        activate_channel(db, identifier, now=now)
    return identifier
