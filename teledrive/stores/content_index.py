"""The per-object content index (``object_content_index``).

Only the plain table lives here. The dialect-specific full-text structures
(SQLite FTS5, PostgreSQL tsvector) and the snippet query stay in
``teledrive.storage.content_index``; :func:`search` delegates to them so
there is exactly one search implementation.

:func:`ensure_row` is the portable idempotent insert the reindex handler
needs: SELECT first, then INSERT, because ``INSERT OR IGNORE`` is SQLite-only.
A lost concurrent insert is rolled back; the existing row is what the caller
wanted anyway.
"""
from __future__ import annotations

from sqlalchemy import delete as sa_delete
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from teledrive.db import Database
from teledrive.storage.content_index import search_content
from teledrive.storage.manifest import content_index


def ensure_row(db: Database, object_id: str, indexed_at: int, *,
               commit: bool = True) -> bool:
    """Insert an empty index row when missing; True when one was inserted.

    Used to mark a non-text object as examined so it is not re-downloaded
    forever. Commits by default, matching the old handler's unconditional
    commit after the SELECT/INSERT pair.
    """
    exists = db.connection.execute(
        select(content_index.c.object_id)
        .where(content_index.c.object_id == object_id)
    ).first()
    if exists is not None:
        if commit:
            db.commit()
        return False
    try:
        db.connection.execute(insert(content_index).values(
            object_id=object_id, text="", indexed_at=indexed_at,
        ))
    except IntegrityError:
        # Lost the insert race: the row exists, which is all the caller
        # needs. The rollback discards the failed statement. Only the
        # unique-constraint race may take this path -- any other failure
        # must propagate instead of quietly marking the object examined.
        db.connection.rollback()
        return False
    if commit:
        db.commit()
    return True


def search(db: Database, q: str, limit: int = 100) -> list[tuple[str, str]]:
    """``[(object_id, snippet)]`` content matches; empty on any error.

    Delegates to the FTS5/tsvector implementation; read-only, never commits.
    """
    return search_content(db, q, limit)


def delete_for_object(db: Database, object_id: str, *,
                      commit: bool = True) -> int:
    """Delete one object's index row and (on SQLite) its FTS mirror row.

    Deliberately unwired: no deletion path calls this yet, because the
    content index is retained as metadata after an object unlink/GC. It
    exists so a future retention job can drop both the row and its FTS
    mirror atomically; wiring it into object deletion without that policy
    would silently lose search history.
    """
    result = db.connection.execute(
        sa_delete(content_index)
        .where(content_index.c.object_id == object_id)
    )
    if db.engine.url.get_backend_name() == "sqlite":
        # The FTS5 table is manually synced; a stale mirror row would keep
        # returning a hit for an object whose index row is gone.
        db.connection.exec_driver_sql(
            "DELETE FROM object_content_fts WHERE object_id = ?", (object_id,))
    if commit:
        db.commit()
    return int(result.rowcount or 0)
