"""Content search: full-text index over text-extractable object bytes.

Key search only matches object names; this module makes the CONTENT of
stored text files searchable. Text is extracted at upload time from the
staged source (before any Telegram round-trip), capped and
extension-gated, and stored in a per-dialect full-text structure:

- SQLite: an FTS5 virtual table (object_content_fts), manually synced
- PostgreSQL: a generated tsvector column (language 'simple' — no
  stemming, so multilingual content matches literally) with a GIN index

Both answer (object_id, snippet) pairs. Searches join the CURRENT
object heads, so unlinked objects never appear even though their index
rows (like their catalog rows) are retained for recovery.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

_logger = logging.getLogger(__name__)

# Extension-gated extraction: the same text family the UI previews.
TEXT_EXTENSIONS = frozenset({
    "txt", "json", "csv", "md", "log", "xml", "yaml", "yml", "ini",
    "conf", "cfg", "py", "js", "html", "css", "sh", "sql", "toml",
    "env", "rst", "tex", "ts", "java", "c", "h", "cpp", "go", "rs",
    "rb", "php", "properties", "service", "po", "srt", "vtt",
})

# Cap extracted text: snippets stay meaningful and rows stay small.
MAX_INDEX_BYTES = 512 * 1024


def extract_text(path: Path, key: str) -> str | None:
    """Best-effort plain-text extraction; None means 'not indexable'."""
    try:
        if "." not in key:
            return None
        extension = key.rsplit(".", 1)[-1].lower()
        if extension not in TEXT_EXTENSIONS:
            return None
        with open(path, "rb") as handle:
            data = handle.read(MAX_INDEX_BYTES + 1)
        if not data:
            return ""
        # A NUL byte in the head of the file means binary content.
        if b"\x00" in data[:4096]:
            return None
        text = data[:MAX_INDEX_BYTES].decode("utf-8", "replace")
        return text
    except Exception:
        return None


def ensure_content_search(database) -> None:
    """Create the dialect-specific FTS structures (idempotent)."""
    engine = database.engine
    backend = engine.url.get_backend_name()
    if backend not in ("sqlite", "postgresql"):
        # MySQL and other backends have no tsvector/GIN; content search
        # stays a PostgreSQL/SQLite accelerator rather than an error.
        return
    try:
        if backend == "sqlite":
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS object_content_fts "
                    "USING fts5(content, object_id UNINDEXED)")
        else:
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER TABLE object_content_index "
                    "ADD COLUMN IF NOT EXISTS tsv tsvector "
                    "GENERATED ALWAYS AS (to_tsvector('simple', text)) STORED")
                connection.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_object_content_tsv "
                    "ON object_content_index USING GIN(tsv)")
    except Exception:
        # Search is an accelerator: a database without the FTS structures
        # simply returns no content matches.
        _logger.warning("content search structures unavailable",
                        exc_info=True)


def index_object_content(database, object_id: str, path: Path,
                         key: str) -> bool:
    """Index one object's text; False when the object is not text.

    Best effort by design: indexing failures never fail an upload.
    """
    try:
        text = extract_text(path, key)
        if text is None:
            return False
        now = int(time.time())
        connection = database.connection
        connection.execute(_text_sql(
            "DELETE FROM object_content_index WHERE object_id = :i"),
            {"i": object_id})
        connection.execute(_text_sql(
            "INSERT INTO object_content_index (object_id, text, indexed_at) "
            "VALUES (:i, :t, :n)"), {"i": object_id, "t": text, "n": now})
        if database.engine.url.get_backend_name() == "sqlite":
            connection.exec_driver_sql(
                "DELETE FROM object_content_fts WHERE object_id = ?",
                (object_id,))
            connection.exec_driver_sql(
                "INSERT INTO object_content_fts (content, object_id) "
                "VALUES (?, ?)", (text, object_id))
        database.commit()
        return True
    except Exception:
        try:
            database.connection.rollback()
        except Exception:
            pass
        _logger.warning("content indexing failed for %s", object_id,
                        exc_info=True)
        return False


def _fts_match_query(q: str) -> str:
    """Quote every token so user input is always a literal FTS5 phrase."""
    tokens = [t for t in q.split() if t]
    if not tokens:
        return '""'
    return " ".join('"' + t.replace('"', '""') + '"' for t in tokens)


def _text_sql(sql: str):
    from sqlalchemy import text
    return text(sql)


def search_content(database, q: str, limit: int = 100
                   ) -> list[tuple[str, str]]:
    """[(object_id, snippet)] for content matches; empty on any error."""
    try:
        if database.engine.url.get_backend_name() == "sqlite":
            rows = database.connection.exec_driver_sql(
                "SELECT object_id, snippet(object_content_fts, 0, "
                "'[', ']', '…', 12) FROM object_content_fts "
                "WHERE object_content_fts MATCH ? LIMIT ?",
                (_fts_match_query(q), limit)).fetchall()
        else:
            rows = database.connection.execute(_text_sql(
                "SELECT object_id, ts_headline('simple', text, "
                "plainto_tsquery('simple', :q), "
                "'StartSel=[, StopSel=], MaxFragments=2') "
                "FROM object_content_index "
                "WHERE tsv @@ plainto_tsquery('simple', :q) "
                "LIMIT :n"), {"q": q, "n": limit}).fetchall()
        return [(str(r[0]), str(r[1])) for r in rows]
    except Exception:
        _logger.warning("content search failed", exc_info=True)
        return []
