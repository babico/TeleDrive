"""Several OS processes must build the same fresh schema without racing.

Every store constructor used to run its own ``create_all`` / ``ALTER TABLE``
outside any cross-process lock.  With several workers starting together that
is concurrent DDL: a duplicate-table error, a lost ``ALTER``, or a process
that dies during startup.  ``teledrive.storage.schema`` is now the single
serialized path; this test proves it with real processes, not threads.

SQLite always runs (a fresh file per test).  PostgreSQL and MySQL run when
``DB_TEST_POSTGRES_URL`` / ``DB_TEST_MYSQL_URL`` are set, following the
``tests/e2e/test_database_live.py`` convention.  The live database is made
fresh by dropping only TeleDrive-owned tables, never unrelated ones.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

WORKER = r'''
import sys
import time
from pathlib import Path

from cryptography.fernet import Fernet

url, ready_path, go_path, worker_id = sys.argv[1:5]

from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.jobs import StorageUploadJobs
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.mtproto_rate_guard import MtprotoRateGuard
from teledrive.storage.schema import SCHEMA_VERSION
from teledrive.storage.user_mode import UserSendJournal
from teledrive.api_keys import ApiKeyStore
from teledrive.settings_store import SettingsStore
from teledrive.s3.annotations import AnnotationStore
from teledrive.s3.bucket_encryption import BucketEncryptionStore
from teledrive.s3.cors import BucketCORSStore
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.lifecycle import BucketLifecycleStore
from teledrive.s3.metadata_journal import (
    MetadataConfigurationStore, MetadataJournalStore)
from teledrive.s3.multipart import MultipartStore
from teledrive.s3.notifications import NotificationStore
from teledrive.s3.object_metadata import ObjectMetadataStore
from teledrive.s3.policy import BucketAbacStore, BucketPolicyStore
from teledrive.s3.report_configs import ReportConfigStore
from teledrive.s3.replication import BucketReplicationStore
from teledrive.s3.tagging import ObjectTagStore
from teledrive.s3.tiering import TieringStore
from teledrive.s3.website import WebsiteConfigStore

# Announce readiness, then wait for the shared go signal so every process
# enters connect_database() at the same moment: the actual race.
Path(ready_path).write_text("ready", encoding="ascii")
while not Path(go_path).exists():
    time.sleep(0.005)

started = time.monotonic()
conn = connect_database(url)
try:
    manifests = ManifestStore(conn)
    catalog = BucketCatalog(manifests)
    # Every constructor that used to run its own create_all/ALTER, all
    # through the one coordinator.
    _stores = [
        ObjectTagStore(catalog),
        StorageUploadJobs(catalog),
        MultipartStore(catalog),
        ObjectMetadataStore(catalog),
        AnnotationStore(catalog),
        TieringStore(catalog),
        MetadataJournalStore(catalog),
        MetadataConfigurationStore(catalog),
        ReportConfigStore(catalog),
        BucketPolicyStore(catalog),
        BucketAbacStore(catalog),
        BucketCORSStore(catalog),
        BucketLifecycleStore(catalog),
        WebsiteConfigStore(catalog),
        BucketReplicationStore(catalog),
        BucketEncryptionStore(conn),
        NotificationStore(catalog),
    ]
    _schema_stores = [
        RetainedMediaGC(conn),
        MtprotoRateGuard(conn),
        UserSendJournal(conn),
        ApiKeyStore(conn),
        SettingsStore(conn, None),
        S3CredentialStore(conn, Fernet.generate_key()),
    ]
    # A real write after startup proves the schema is usable, not just present.
    bucket = "schema-race-" + worker_id
    catalog.create_bucket(bucket, int(time.time()))
    assert bucket in catalog.list_buckets()

    versions = [int(row[0]) for row in conn.connection.exec_driver_sql(
        "SELECT version FROM schema_migrations").fetchall()]
    assert sorted(versions) == list(range(1, SCHEMA_VERSION + 1)), versions

    # Columns that legacy migrations used to add outside the lock.
    backend = conn.engine.url.get_backend_name()
    if backend == "sqlite":
        def columns(table):
            from sqlalchemy import text
            return {row[1] for row in conn.connection.execute(
                text("PRAGMA table_info(" + table + ")"))}
    else:
        from sqlalchemy import text
        schema = "DATABASE()" if backend == "mysql" else "current_schema()"
        def columns(table):
            return {row[0] for row in conn.connection.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :t AND table_schema = " + schema),
                {"t": table})}
    expected = {
        "files": {"claim_token", "tg_account", "claim_ts"},
        "storage_buckets": {"versioning_state", "public_read",
                            "object_lock_enabled"},
        "storage_objects": {"storage_class", "legal_hold", "access_count"},
        "storage_chunks": {"encryption"},
        "storage_multipart_uploads": {"encryption"},
        "storage_gc_state": {"grace_seconds"},
        "storage_s3_credentials": {"tags"},
        "users": {"enabled"},
    }
    for table, required in expected.items():
        missing = required - columns(table)
        assert not missing, (table, missing)
finally:
    conn.close()

print(f"{worker_id} {time.monotonic() - started:.3f}")
'''

WORKER_COUNT = 5


def _sqlite_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'schema-race.db').as_posix()}"


def _telemetry():
    """Every MetaData that owns a TeleDrive table.

    The s3 modules are imported for their side effects: several attach their
    tables to ``catalog_metadata`` / ``manifest.metadata`` at import time.
    """
    from teledrive import api_keys, db, settings_store
    from teledrive.s3 import (annotations, bucket_encryption, cors, credentials,
                              lifecycle, metadata_journal, multipart,
                              notifications, object_metadata, policy,
                              replication, report_configs, tagging, tiering,
                              website)
    from teledrive.storage import catalog, gc_collect, jobs, manifest
    from teledrive.storage import mtproto_rate_guard, user_mode

    _ = (annotations, bucket_encryption, cors, lifecycle, object_metadata,
         policy, replication, tagging, website, gc_collect)
    return [
        db.metadata, manifest.metadata, catalog.catalog_metadata,
        notifications.outbox_metadata,
        metadata_journal.metadata_journal_metadata, tiering.tiering_metadata,
        report_configs.report_metadata, multipart._meta, credentials._meta,
        jobs._meta, mtproto_rate_guard._meta, user_mode._meta,
        api_keys._metadata, settings_store._metadata,
    ]


def _fresh_live_database(url: str) -> None:
    """Drop only TeleDrive-owned tables in a dedicated test database."""
    from sqlalchemy import create_engine

    from teledrive.db import normalize_database_url

    engine = create_engine(normalize_database_url(url))
    names: set[str] = {"schema_migrations", "object_content_fts"}
    for metadata in _telemetry():
        names.update(metadata.tables)
    try:
        with engine.begin() as connection:
            if engine.dialect.name == "mysql":
                connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=0")
            preparer = engine.dialect.identifier_preparer
            for name in sorted(names):
                quoted = preparer.quote(name)
                suffix = " CASCADE" if engine.dialect.name == "postgresql" else ""
                connection.exec_driver_sql(
                    f"DROP TABLE IF EXISTS {quoted}{suffix}")
            if engine.dialect.name == "mysql":
                connection.exec_driver_sql("SET FOREIGN_KEY_CHECKS=1")
    finally:
        engine.dispose()


def _run_race(url: str, tmp_path: Path) -> list[str]:
    go = tmp_path / "schema-race-go"
    processes = []
    outputs: list[str] = []
    try:
        for index in range(WORKER_COUNT):
            ready = tmp_path / f"schema-race-{index}.ready"
            process = subprocess.Popen(
                [sys.executable, "-c", WORKER, url, str(ready), str(go),
                 str(index)],
                cwd=Path(__file__).resolve().parents[2],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            processes.append((process, ready))
        # Generous: under xdist several workers each spawn five interpreters
        # that import the whole storage/S3 module tree before the gate.
        deadline = time.monotonic() + 240
        while not all(ready.exists() for _, ready in processes):
            assert time.monotonic() < deadline, "workers did not reach the gate"
            for process, _ in processes:
                if process.poll() is not None:
                    _, err = process.communicate()
                    pytest.fail(
                        "worker exited before the start gate: "
                        + err.decode(errors="replace")[-3000:])
            time.sleep(0.02)
        go.write_text("go", encoding="ascii")
        for process, _ in processes:
            out, err = process.communicate(timeout=300)
            assert process.returncode == 0, (
                f"worker exit {process.returncode}: "
                + err.decode(errors="replace")[-4000:])
            outputs.append(out.decode(errors="replace").strip())
    finally:
        for process, _ in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
    return outputs


def _assert_one_coherent_schema(url: str) -> None:
    from teledrive.db import connect_database
    from teledrive.storage.schema import SCHEMA_VERSION

    connection = connect_database(url)
    try:
        rows = connection.connection.exec_driver_sql(
            "SELECT version, COUNT(*) FROM schema_migrations "
            "GROUP BY version ORDER BY version").fetchall()
        assert [int(row[0]) for row in rows] == list(
            range(1, SCHEMA_VERSION + 1))
        assert all(int(row[1]) == 1 for row in rows)
        # The application's own view must still be usable after the race.
        from teledrive.storage.catalog import BucketCatalog
        from teledrive.storage.manifest import ManifestStore
        catalog = BucketCatalog(ManifestStore(connection))
        buckets = catalog.list_buckets()
        assert len([b for b in buckets if b.startswith("schema-race-")]) >= 1
    finally:
        connection.close()


def test_simultaneous_processes_create_sqlite_schema_once(tmp_path):
    url = _sqlite_url(tmp_path)
    _run_race(url, tmp_path)
    _assert_one_coherent_schema(url)


@pytest.mark.skipif(not os.getenv("DB_TEST_POSTGRES_URL"),
                    reason="DB_TEST_POSTGRES_URL not configured")
def test_simultaneous_processes_create_postgres_schema_once(tmp_path):
    url = os.environ["DB_TEST_POSTGRES_URL"]
    _fresh_live_database(url)
    _run_race(url, tmp_path)
    _assert_one_coherent_schema(url)


@pytest.mark.skipif(not os.getenv("DB_TEST_MYSQL_URL"),
                    reason="DB_TEST_MYSQL_URL not configured")
def test_simultaneous_processes_create_mysql_schema_once(tmp_path):
    url = os.environ["DB_TEST_MYSQL_URL"]
    _fresh_live_database(url)
    _run_race(url, tmp_path)
    _assert_one_coherent_schema(url)


def test_warm_schema_check_is_a_no_op(tmp_path):
    """Once a process has migrated an engine, constructors do no DDL."""
    from teledrive.db import connect_database
    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    from teledrive.storage.schema import ensure_schema

    connection = connect_database(_sqlite_url(tmp_path))
    try:
        manifests = ManifestStore(connection)
        assert ensure_schema(connection.engine) is False
        started = time.perf_counter()
        for _ in range(200):
            BucketCatalog(manifests)
        elapsed = time.perf_counter() - started
        # 200 warm constructors are an in-memory set lookup; even a slow CI
        # box must not pay a database round-trip per call.
        assert elapsed < 1.0, f"warm constructor too slow: {elapsed:.3f}s"

        # Stronger claim: the warm path emits no SQL at all.
        from sqlalchemy import event

        statements: list[str] = []

        def record(conn, cursor, statement, parameters, context, many):
            statements.append(statement)

        event.listen(connection.engine, "before_cursor_execute", record)
        try:
            ManifestStore(connection)
            BucketCatalog(manifests)
        finally:
            event.remove(connection.engine, "before_cursor_execute", record)
        assert statements == [], statements
    finally:
        connection.close()
