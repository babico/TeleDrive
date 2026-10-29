"""WebUI session tokens.

Rows store the SHA-256 digest of the bearer/cookie token, never the token
itself. ``resolve`` treats a disabled user as unauthenticated and clears that
user's sessions; an expired token is removed on sight.

``user_sessions`` has no foreign key and SQLite reuses integer row ids, so a
session must be deleted in the SAME transaction as the user. Callers that
delete both pass ``commit=False`` to :func:`delete_for_user` and commit after
the user row is gone.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import insert, select

from teledrive.db import Database, user_sessions, users


def create(db: Database, *, token: str, user_id: int, created_at: int,
           expires_at: int) -> None:
    """Insert one session row and commit.

    ``token`` is already a digest; this store never sees the raw token.
    """
    db.connection.execute(insert(user_sessions).values(
        token=token, user_id=user_id, created_at=created_at,
        expires_at=expires_at,
    ))
    db.commit()


def username_for_token(db: Database, token: str) -> str | None:
    """Best-effort username for a session token, regardless of expiry.

    Used by audit extraction, which must not clean up or gate on the user
    being enabled. ``token`` is a unique primary key, so no ORDER BY is
    needed.
    """
    row = db.connection.execute(
        select(users.c.username)
        .select_from(user_sessions.join(
            users, users.c.id == user_sessions.c.user_id))
        .where(user_sessions.c.token == token)
    ).first()
    return str(row[0]) if row else None


def resolve(db: Database, token: str, now: int) -> dict[str, Any] | None:
    """Return ``{id, username, role}`` for a live session, else None.

    A disabled user is unauthenticated: every session for that user is
    deleted. An expired token is deleted. Successful resolution writes
    nothing.
    """
    row = db.connection.execute(
        select(users.c.id, users.c.username, users.c.role,
               user_sessions.c.expires_at, users.c.enabled)
        .select_from(user_sessions.join(
            users, users.c.id == user_sessions.c.user_id))
        .where(user_sessions.c.token == token)
    ).first()
    if row is None:
        return None
    data = dict(row._mapping)
    if not data["enabled"]:
        delete_for_user(db, data["id"])
        return None
    if int(now) > int(data["expires_at"]):
        delete_token(db, token)
        return None
    return {"id": data["id"], "username": data["username"],
            "role": data["role"]}


def list_for_user(db: Database, user_id: int) -> list[dict[str, Any]]:
    """A user's sessions, newest first."""
    rows = db.connection.execute(
        select(user_sessions.c.token, user_sessions.c.created_at,
               user_sessions.c.expires_at)
        .where(user_sessions.c.user_id == user_id)
        .order_by(user_sessions.c.created_at.desc(), user_sessions.c.token.asc())
    ).all()
    return [dict(row._mapping) for row in rows]


def delete_token(db: Database, token: str) -> int:
    """Revoke one session by digest; returns rows removed (0 or 1)."""
    result = db.connection.execute(
        sa_delete(user_sessions).where(user_sessions.c.token == token)
    )
    db.commit()
    return int(result.rowcount or 0)


def delete_for_user(db: Database, user_id: int, *, commit: bool = True) -> int:
    """Revoke every session for a user.

    Pass ``commit=False`` when the caller is deleting the user row in the
    same transaction, so the two deletes cannot be split.
    """
    result = db.connection.execute(
        sa_delete(user_sessions).where(user_sessions.c.user_id == user_id)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def delete_all(db: Database) -> int:
    """Revoke every session (logout-all/emergency); returns rows removed."""
    result = db.connection.execute(sa_delete(user_sessions))
    db.commit()
    return int(result.rowcount or 0)


def purge_expired(db: Database, now: int) -> int:
    """Delete sessions whose expiry is strictly in the past."""
    result = db.connection.execute(
        sa_delete(user_sessions).where(user_sessions.c.expires_at < now)
    )
    db.commit()
    return int(result.rowcount or 0)
