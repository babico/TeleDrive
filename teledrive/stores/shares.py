"""Signed public share links: create, list, resolve, claim, revoke.

A share URL is bound to the exact object VERSION it was issued for. The
handler resolves the object BEFORE calling :func:`claim_download`, so a
request that cannot be served never consumes a download slot.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import delete, insert, select, update

from teledrive.db import Database, share_links

_COLUMNS = (
    share_links.c.token,
    share_links.c.bucket,
    share_links.c.object_key,
    share_links.c.created_by,
    share_links.c.created_at,
    share_links.c.expires_at,
    share_links.c.max_downloads,
    share_links.c.download_count,
    share_links.c.revoked,
)


def _as_dict(row: Any) -> dict[str, Any]:
    return dict(row._mapping)


def _public(row: dict[str, Any]) -> dict[str, Any]:
    """Project a stored row into the shape the admin listing exposes."""
    return {
        "token": row["token"],
        "bucket": row["bucket"],
        "object_key": row["object_key"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "max_downloads": row["max_downloads"],
        "download_count": row["download_count"],
        "has_password": row.get("password_salt") is not None,
        "revoked": bool(row["revoked"]),
    }


def create(db: Database, *, token: str, bucket: str, object_key: str,
           object_id: str | None, created_by: str, created_at: int,
           expires_at: int | None, max_downloads: int | None,
           password_salt: str | None, password_hash: str | None) -> dict[str, Any]:
    """Insert one share row and commit."""
    db.connection.execute(insert(share_links).values(
        token=token, bucket=bucket, object_key=object_key,
        object_id=object_id, created_by=created_by, created_at=created_at,
        expires_at=expires_at, max_downloads=max_downloads, download_count=0,
        password_salt=password_salt, password_hash=password_hash, revoked=0,
    ))
    db.commit()
    return {
        "token": token, "bucket": bucket, "object_key": object_key,
        "object_id": object_id, "created_by": created_by,
        "created_at": created_at, "expires_at": expires_at,
        "max_downloads": max_downloads, "download_count": 0,
        "has_password": password_salt is not None, "revoked": False,
    }


def list(db: Database) -> list[dict[str, Any]]:  # noqa: A001 - store API name
    """Every share row, newest first, as plain dicts."""
    rows = db.connection.execute(
        select(*_COLUMNS, share_links.c.password_salt)
        .order_by(share_links.c.created_at.desc(), share_links.c.token.asc())
    ).all()
    return [_public(_as_dict(row)) for row in rows]


def resolve_token(db: Database, token: str, now: int) -> dict[str, Any] | None:
    """Return an active (unrevoked, unexpired, not exhausted) share row.

    ``token`` is the primary key, so no ORDER BY/LIMIT is needed.
    """
    row = db.connection.execute(
        select(share_links.c.token, share_links.c.bucket,
               share_links.c.object_key, share_links.c.password_salt,
               share_links.c.password_hash, share_links.c.object_id)
        .where(
            share_links.c.token == token,
            share_links.c.revoked == 0,
            share_links.c.expires_at.is_(None) | (share_links.c.expires_at > now),
            share_links.c.max_downloads.is_(None)
            | (share_links.c.download_count < share_links.c.max_downloads),
        )
    ).first()
    return _as_dict(row) if row else None


def claim_download(db: Database, token: str, now: int) -> bool:
    """Consume one download slot and commit; False when the link is no longer active.

    The caller MUST resolve the object first. This is the last check, so a
    concurrent request that exhausted the link is refused here instead of
    being served a slot that does not exist.
    """
    result = db.connection.execute(
        update(share_links)
        .where(
            share_links.c.token == token,
            share_links.c.revoked == 0,
            share_links.c.expires_at.is_(None) | (share_links.c.expires_at > now),
            share_links.c.max_downloads.is_(None)
            | (share_links.c.download_count < share_links.c.max_downloads),
        )
        .values(download_count=share_links.c.download_count + 1)
    )
    db.commit()
    return result.rowcount == 1


def revoke(db: Database, token: str) -> bool:
    """Delete one share row; True when it existed."""
    result = db.connection.execute(
        delete(share_links).where(share_links.c.token == token)
    )
    db.commit()
    return bool(result.rowcount)


def delete_for_bucket(db: Database, bucket: str) -> int:
    """Delete every share row for a bucket (bucket-delete purge)."""
    result = db.connection.execute(
        delete(share_links).where(share_links.c.bucket == bucket)
    )
    db.commit()
    return int(result.rowcount or 0)
