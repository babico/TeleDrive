"""Operator-managed bucket → Telegram-account pins.

A pin wins over the strategy rotation on upload, so it is a tiny table but a
load-bearing one. The upsert is UPDATE-then-INSERT (portable to MySQL); a lost
insert race is resolved by re-applying the UPDATE.
"""
from __future__ import annotations

from sqlalchemy import delete as sa_delete
from sqlalchemy import insert, select, update

from teledrive.db import Database, bucket_account_pins


def set(db: Database, bucket: str, account: str, now: int) -> None:
    """Pin ``bucket`` to ``account``, creating the row when missing."""
    values = {"account": account, "updated_at": now}
    changed = db.connection.execute(
        update(bucket_account_pins)
        .where(bucket_account_pins.c.bucket == bucket)
        .values(**values)
    )
    if changed.rowcount == 0:
        try:
            db.connection.execute(insert(bucket_account_pins).values(
                bucket=bucket, **values,
            ))
        except Exception:
            # Lost the race: the row now exists, so apply the update.
            db.connection.rollback()
            db.connection.execute(
                update(bucket_account_pins)
                .where(bucket_account_pins.c.bucket == bucket)
                .values(**values)
            )
    db.commit()


def get(db: Database, bucket: str) -> str | None:
    """The pinned account for ``bucket``, or None. ``bucket`` is the PK."""
    row = db.connection.execute(
        select(bucket_account_pins.c.account)
        .where(bucket_account_pins.c.bucket == bucket)
    ).first()
    return str(row[0]) if row else None


def delete(db: Database, bucket: str) -> int:
    """Remove the pin; returns the number of rows removed (0 or 1)."""
    result = db.connection.execute(
        sa_delete(bucket_account_pins)
        .where(bucket_account_pins.c.bucket == bucket)
    )
    db.commit()
    return int(result.rowcount or 0)
