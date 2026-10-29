"""Pending Telegram login-code requests.

A code request persists ``phone_code_hash`` together with the *unauthorized*
Telethon session that requested it, because verify-code must sign in with
that exact auth key. ``attempts`` bounds wrong-code retries: a five-digit
code with unlimited retries is a brute force against the account, so the
handler destroys the row once the counter reaches the cap.

Rows are single-use: :func:`consume` deletes on success, expiry and after a
burned code hash.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import insert, select, update

from teledrive.db import Database, telegram_session_pending

_COLUMNS = (
    telegram_session_pending.c.token,
    telegram_session_pending.c.api_id,
    telegram_session_pending.c.api_hash,
    telegram_session_pending.c.phone,
    telegram_session_pending.c.phone_code_hash,
    telegram_session_pending.c.session_string,
    telegram_session_pending.c.channel,
    telegram_session_pending.c.strategy,
    telegram_session_pending.c.created_at,
    telegram_session_pending.c.attempts,
)


def create(db: Database, *, token: str, api_id: int, api_hash: str,
           phone: str, phone_code_hash: str | None,
           session_string: str | None, channel: str | None,
           strategy: str | None, created_at: int) -> dict[str, Any]:
    """Insert one pending request and commit; ``attempts`` starts at 0."""
    db.connection.execute(insert(telegram_session_pending).values(
        token=token, api_id=api_id, api_hash=api_hash, phone=phone,
        phone_code_hash=phone_code_hash, session_string=session_string,
        channel=channel, strategy=strategy, created_at=created_at,
        attempts=0,
    ))
    db.commit()
    return {
        "token": token, "api_id": api_id, "api_hash": api_hash,
        "phone": phone, "phone_code_hash": phone_code_hash,
        "session_string": session_string, "channel": channel,
        "strategy": strategy, "created_at": created_at, "attempts": 0,
    }


def get(db: Database, token: str) -> dict[str, Any] | None:
    """Every stored field for one pending request, or None.

    ``token`` is the primary key, so no ORDER BY/LIMIT is needed.
    """
    row = db.connection.execute(
        select(*_COLUMNS)
        .where(telegram_session_pending.c.token == token)
    ).first()
    return dict(row._mapping) if row else None


def bump_attempts(db: Database, token: str) -> int:
    """Increment the wrong-code counter; returns rows changed (0 or 1)."""
    result = db.connection.execute(
        update(telegram_session_pending)
        .where(telegram_session_pending.c.token == token)
        .values(attempts=telegram_session_pending.c.attempts + 1)
    )
    db.commit()
    return int(result.rowcount or 0)


def consume(db: Database, token: str) -> int:
    """Delete one pending request (success, expiry, burned hash)."""
    result = db.connection.execute(
        sa_delete(telegram_session_pending)
        .where(telegram_session_pending.c.token == token)
    )
    db.commit()
    return int(result.rowcount or 0)


def purge_older_than(db: Database, cutoff: int, *,
                     commit: bool = True) -> int:
    """Delete requests created before ``cutoff``; returns rows removed.

    ``request-code`` passes ``commit=False`` so the purge and the new request
    commit in one transaction, exactly like the original two-statement block.
    """
    result = db.connection.execute(
        sa_delete(telegram_session_pending)
        .where(telegram_session_pending.c.created_at < cutoff)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)
