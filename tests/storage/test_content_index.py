"""Content search: extraction rules and dialect-aware FTS round-trips."""
import os
import tempfile
from pathlib import Path

from teledrive.db import connect_database
from teledrive.storage.content_index import (
    ensure_content_search, extract_text, index_object_content, search_content)
from teledrive.storage.manifest import ManifestStore


def _store(tmp_path):
    conn = connect_database(str(tmp_path / "state.db"))
    return conn, ManifestStore(conn)


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_extract_text_is_extension_gated_and_binary_safe(tmp_path):
    text = _write(tmp_path, "notes.txt", b"hello searchable world")
    assert extract_text(text, "notes.txt") == "hello searchable world"
    # Unknown extensions are skipped entirely.
    assert extract_text(_write(tmp_path, "a.bin", b"hello"), "a.bin") is None
    assert extract_text(_write(tmp_path, "noext", b"hello"), "noext") is None
    # NUL bytes in the head mean binary: never indexed.
    binary = _write(tmp_path, "fake.txt", b"ab\x00cd more text")
    assert extract_text(binary, "fake.txt") is None
    # The extraction cap is honored.
    big = _write(tmp_path, "big.log", b"x" * (600 * 1024))
    assert len(extract_text(big, "big.log")) == 512 * 1024


def test_index_and_search_round_trip_sqlite(tmp_path):
    conn, store = _store(tmp_path)
    a = store.begin("b1", "notes.txt", 0, 1)
    store.finish(a, "a" * 64, 1)
    b = store.begin("b1", "data.bin", 0, 1)
    store.finish(b, "b" * 64, 1)

    assert index_object_content(
        conn, a, _write(tmp_path, "notes.txt",
                        b"the quick brown fox jumps"), "notes.txt")
    # Binary content is not indexed at all.
    assert not index_object_content(
        conn, b, _write(tmp_path, "data.bin", b"\x00\x01"), "data.bin")

    hits = search_content(conn, "quick fox")
    assert len(hits) == 1 and hits[0][0] == a
    assert "fox" in hits[0][1]
    assert search_content(conn, "zebra") == []

    # Re-indexing is an upsert: no duplicates, updated text wins.
    assert index_object_content(
        conn, a, _write(tmp_path, "notes.txt", b"updated content"),
        "notes.txt")
    assert len(search_content(conn, "updated")) == 1
    assert search_content(conn, "quick fox") == []


def test_fts5_query_tokens_are_always_literal(tmp_path):
    conn, store = _store(tmp_path)
    a = store.begin("b1", "q.txt", 0, 1)
    store.finish(a, "c" * 64, 1)
    index_object_content(
        conn, a, _write(tmp_path, "q.txt", b"literal OR AND NOT tokens"),
        "q.txt")
    # SQL/FTS operators in user input must match literally, not parse.
    assert len(search_content(conn, "OR")) == 1
    assert len(search_content(conn, '"quoted"')) == 0  # no such literal
    assert len(search_content(conn, "AND NOT")) == 1


def test_upload_path_indexes_automatically(tmp_path):
    """The engine indexes text uploads without an explicit call."""
    import asyncio
    import sys
    sys.path.insert(0, str(tmp_path))
    from tests.storage.test_storage_engine import MemoryTelegram
    from teledrive.storage.engine import TelegramObjectStorage
    conn, store = _store(tmp_path)
    engine = TelegramObjectStorage(store, MemoryTelegram(), chunk_size=4096)
    source = _write(tmp_path, "upload.md", b"# Heading\nsearchable body")
    item = asyncio.run(engine.put_file("backup", "doc.md", source))
    assert search_content(conn, "searchable body")
    hits = search_content(conn, "Heading")
    assert hits and hits[0][0] == item.id
