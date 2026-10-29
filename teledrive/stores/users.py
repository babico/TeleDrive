"""WebUI accounts: lookup, creation, credential/role/state changes, deletion.

Username *policy* (the 1-64 character ASCII rule and the reserved ``admin``
case-variant) deliberately stays in ``web.app._validate_username``: it is a
request-shape check that returns HTTP errors, and one validator is easier to
audit than two. This store only persists already-validated values.

The bootstrap row is never written by :func:`create`; the caller checks
:func:`get_by_username` first and leaves an existing ``admin`` untouched.
The last-enabled-admin guard is a read (:func:`count_enabled_admins`) applied
by the handlers before a role change, disable or delete.

``user_sessions`` has no foreign key and SQLite reuses integer row ids, so
:func:`delete` accepts ``commit=False``: the handler deletes the sessions and
the user in the SAME transaction and commits once.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, insert, select, update

from teledrive.db import Database, users

_PROFILE = (
    users.c.id,
    users.c.username,
    users.c.role,
    users.c.enabled,
    users.c.created_at,
    users.c.updated_at,
    users.c.last_login,
)


def _profile(row: Any) -> dict[str, Any]:
    data = dict(row._mapping)
    data["enabled"] = bool(data["enabled"])
    return data


def get_by_id(db: Database, user_id: int) -> dict[str, Any] | None:
    """Public profile for one user (no password hash), or None.

    ``id`` is the primary key, so no ORDER BY/LIMIT is needed.
    """
    row = db.connection.execute(
        select(*_PROFILE).where(users.c.id == user_id)
    ).first()
    return _profile(row) if row else None


def get_by_username(db: Database, username: str) -> dict[str, Any] | None:
    """Authentication record for a username, or None.

    Includes ``password_hash`` because login needs it. ``username`` is
    UNIQUE, so no ORDER BY/LIMIT is needed.
    """
    row = db.connection.execute(
        select(*_PROFILE, users.c.password_hash)
        .where(users.c.username == username)
    ).first()
    return _profile(row) if row else None


def list(db: Database) -> list[dict[str, Any]]:  # noqa: A001 - store API name
    """Every user profile, oldest first (the listing's historical order)."""
    rows = db.connection.execute(
        select(*_PROFILE).order_by(users.c.id.asc())
    ).all()
    return [_profile(row) for row in rows]


def create(db: Database, *, username: str, password_hash: str, role: str,
           now: int, enabled: bool = True) -> dict[str, Any]:
    """Insert one account and commit.

    A duplicate username raises ``IntegrityError``; the handler maps it to
    409. The id is read back by username because ``RETURNING`` is not
    portable.
    """
    db.connection.execute(insert(users).values(
        username=username, password_hash=password_hash, role=role,
        enabled=1 if enabled else 0, created_at=now, updated_at=now,
    ))
    db.commit()
    row = db.connection.execute(
        select(*_PROFILE).where(users.c.username == username)
    ).first()
    if row is None:  # pragma: no cover - the insert above just committed
        raise RuntimeError("created user row disappeared")
    return _profile(row)


def set_password(db: Database, user_id: int, password_hash: str, now: int,
                 *, commit: bool = True) -> int:
    """Replace one user's password hash; returns rows changed (0 or 1)."""
    result = db.connection.execute(
        update(users)
        .where(users.c.id == user_id)
        .values(password_hash=password_hash, updated_at=now)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def set_role(db: Database, user_id: int, role: str, now: int,
             *, commit: bool = True) -> int:
    """Replace one user's role; returns rows changed (0 or 1)."""
    result = db.connection.execute(
        update(users)
        .where(users.c.id == user_id)
        .values(role=role, updated_at=now)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def set_enabled(db: Database, user_id: int, enabled: bool, now: int,
                *, commit: bool = True) -> int:
    """Enable or disable one account; returns rows changed (0 or 1)."""
    result = db.connection.execute(
        update(users)
        .where(users.c.id == user_id)
        .values(enabled=1 if enabled else 0, updated_at=now)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def set_last_login(db: Database, user_id: int, now: int,
                   *, commit: bool = True) -> int:
    """Record a successful login; returns rows changed (0 or 1).

    Login passes ``commit=False`` so the last_login write and the new session
    row commit in one transaction.
    """
    result = db.connection.execute(
        update(users).where(users.c.id == user_id).values(last_login=now)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def rename(db: Database, user_id: int, username: str, now: int,
           *, commit: bool = True) -> int:
    """Change one username; returns rows changed (0 or 1).

    A duplicate username raises ``IntegrityError``; the handler maps it to
    409. The caller enforces that the bootstrap ``admin`` row cannot be
    renamed.
    """
    result = db.connection.execute(
        update(users)
        .where(users.c.id == user_id)
        .values(username=username, updated_at=now)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def delete(db: Database, user_id: int, *, commit: bool = True) -> int:
    """Delete one account; returns rows removed (0 or 1).

    Pass ``commit=False`` when the caller deletes the user's sessions in the
    same transaction (the handler that owns the transaction commits).
    """
    result = db.connection.execute(
        sa_delete(users).where(users.c.id == user_id)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0)


def count_enabled_admins(db: Database) -> int:
    """Number of enabled accounts with role ``admin``.

    Used by the last-enabled-admin guard; read-only, never commits.
    """
    return int(db.connection.execute(
        select(func.count())
        .select_from(users)
        .where(users.c.role == "admin", users.c.enabled == 1)
    ).scalar_one() or 0)
