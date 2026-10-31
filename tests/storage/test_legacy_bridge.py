"""Legacy folder -> durable object queue is explicit, idempotent and safe."""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.jobs import StorageUploadJobs
from teledrive.storage.legacy_bridge import enqueue_legacy_folder
from teledrive.storage.manifest import ManifestStore
from tests.storage.test_storage_engine import MemoryTelegram


@pytest.fixture
def bridge(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    db_path = tmp_path / "legacy-bridge.db"
    conn = connect_database(str(db_path))
    cat = BucketCatalog(ManifestStore(conn))
    cat.create_bucket("bridge-ci", int(time.time()))
    config = SimpleNamespace(
        source_dir=str(root), db_path=str(db_path),
        allowed_extensions=[".txt"], max_file_size_mb=1,
    )
    try:
        yield root, db_path, StorageUploadJobs(cat), config
    finally:
        conn.close()


def test_legacy_folder_bridge_idempotent_across_restart_and_preserves_paths(bridge):
    root, db_path, queue, cfg = bridge
    nested = root / "documents"
    nested.mkdir()
    (root / "one.txt").write_bytes(b"one")
    (nested / "two.txt").write_bytes(b"two")
    (root / "not-included.dat").write_bytes(b"exclude")
    (root / "external.txt").symlink_to(root / "one.txt")

    first = enqueue_legacy_folder(cfg, queue, bucket="bridge-ci", prefix="backup")
    assert first.queued == 2
    assert first.already_queued == 0
    assert first.excluded == 1
    assert len(first.job_ids) == 2
    records = queue.list_jobs()
    assert {r["object_key"] for r in records} == {
        "backup/one.txt", "backup/documents/two.txt",
    }
    assert all(r["state"] == "queued" for r in records)
    # No remote bytes are uploaded by a folder scan, even after restart.
    conn = connect_database(str(db_path))
    try:
        recreated = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        again = enqueue_legacy_folder(cfg, recreated, bucket="bridge-ci", prefix="backup")
        assert again.queued == 0 and again.already_queued == 2
        assert {r["id"] for r in recreated.list_jobs()} == set(first.job_ids)
        source = root / "one.txt"
        source.write_bytes(b"modified")
        changed = enqueue_legacy_folder(cfg, recreated, bucket="bridge-ci", prefix="backup")
        assert changed.queued == 1 and changed.already_queued == 1
        assert len(recreated.list_jobs()) == 3
    finally:
        conn.close()


def test_legacy_bridge_rejects_traversal_and_unknown_destination(bridge):
    root, _, queue, cfg = bridge
    (root / "normal.txt").write_bytes(b"no-send")
    for prefix in ("/absolute", "../escape", "foo/../bar", "foo//bar",
                   "bad\\windows", "bad/"):
        with pytest.raises(ValueError):
            enqueue_legacy_folder(cfg, queue, bucket="bridge-ci", prefix=prefix)
    for limit in (0, 1001):
        with pytest.raises(ValueError):
            enqueue_legacy_folder(cfg, queue, bucket="bridge-ci", max_files=limit)
    with pytest.raises(FileNotFoundError):
        enqueue_legacy_folder(cfg, queue, bucket="does-not-exist")
    assert queue.list_jobs() == []


def test_legacy_bridge_only_queues_with_explicit_worker(bridge):
    root, _, queue, cfg = bridge
    (root / "chunked.txt").write_bytes(bytes(range(30)))
    report = enqueue_legacy_folder(cfg, queue, bucket="bridge-ci", max_files=1)
    assert report.queued == 1
    remote = MemoryTelegram()
    assert remote.uploads == 0
    completed = asyncio.run(queue.run_next(
        remote, allowed_root=root, scratch_directory=root, chunk_size=7,
    ))
    assert completed["state"] == "done"
    assert remote.uploads == 5
    assert queue.catalog.get("bridge-ci", "chunked.txt").item.size == 30
    again = enqueue_legacy_folder(cfg, queue, bucket="bridge-ci")
    assert again.queued == 0 and again.already_queued == 1
    assert queue.list_jobs()[0]["state"] == "done"


