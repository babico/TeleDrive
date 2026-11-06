"""Schema step ``bucket_fk_cascade``: every bucket-keyed table cascades.

``BucketAdminMixin.delete_bucket`` used to sweep ~19 bucket-name-keyed
configuration tables before deleting the bucket row.  A configuration write
whose existence check ran in an earlier transaction could commit after the
sweep and leave an orphan, which a same-name re-create then silently revived.

Schema step 31 gives each of those tables a real foreign key to
``storage_buckets.name`` with ``ON DELETE CASCADE``.  SQLite cannot alter a
foreign key, so the step rebuilds each table; PostgreSQL and MySQL replace
the constraint.  These tests cover:

* the step is idempotent (a second run changes nothing),
* every listed table reports a cascading FK (SQLite always; PostgreSQL and
  MySQL when ``DB_TEST_POSTGRES_URL`` / ``DB_TEST_MYSQL_URL`` are set),
* deleting the bucket row directly removes its configuration rows,
* existing rows survive the rebuild/migration.

The live-backend tests follow the ``tests/e2e/test_database_live.py``
convention: skip cleanly when the URL is not configured, let the CI database
job run them.
"""
from __future__ import annotations

import os
from hashlib import sha256

import pytest
from sqlalchemy import (
    BigInteger, Boolean, Integer, MetaData, Numeric, String, Table, Text,
    create_engine, inspect, text,
)
from sqlalchemy.exc import IntegrityError

from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.schema import (
    SchemaContext, _BUCKET_FK_TABLES, _STEPS, _enable_sqlite_foreign_keys,
    _ensure_bookkeeping_table, _record, _step_bucket_fk_cascade,
)

STEP_NAME = "bucket_fk_cascade"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sqlite_url(tmp_path) -> str:
    return str(tmp_path / "cascade.sqlite")


def _pre_migration_engine(path):
    """An SQLite engine migrated only through the step BEFORE the cascade.

    This is the real upgrade path: an already-deployed database where the
    configuration tables exist without a cascading bucket foreign key.
    """
    engine = create_engine(f"sqlite:///{path}")
    _enable_sqlite_foreign_keys(engine)
    _ensure_bookkeeping_table(engine)
    context = SchemaContext(engine)
    for version, (name, step) in enumerate(_STEPS, start=1):
        if name == STEP_NAME:
            break
        step(context)
        _record(engine, version, name)
    return engine


def _placeholder(column):
    """A harmless non-NULL value for a required, non-key column."""
    if isinstance(column.type, Boolean):
        return True
    if isinstance(column.type, (Integer, BigInteger, Numeric)):
        return 1
    if isinstance(column.type, (String, Text)):
        return "probe"
    return "probe"


def seed_bucket_rows(connection, bucket: str) -> dict[str, int]:
    """Insert one row for ``bucket`` into every listed table that exists.

    Columns are discovered from the live table so this keeps working when a
    table grows a column; required columns get a type-appropriate value.
    Returns the expected row count per table.
    """
    metadata = MetaData()
    inspector = inspect(connection.engine)
    seeded: dict[str, int] = {}
    for table, column in _BUCKET_FK_TABLES:
        if not inspector.has_table(table):
            continue
        reflected = Table(table, metadata, autoload_with=connection.engine)
        values = {}
        for reflected_column in reflected.columns:
            if reflected_column.name == column:
                values[reflected_column.name] = bucket
                continue
            if reflected_column.nullable:
                continue
            # Single-column integer primary keys are auto-assigned.
            if (reflected_column.primary_key
                    and isinstance(reflected_column.type, Integer)
                    and reflected_column.autoincrement in (True, "auto")):
                continue
            values[reflected_column.name] = _placeholder(reflected_column)
        connection.execute(reflected.insert().values(**values))
        seeded[table] = 1
    connection.commit()
    return seeded


def _count_bucket_rows(connection, table: str, bucket: str) -> int:
    return connection.execute(
        text(f"SELECT COUNT(*) FROM {table} WHERE bucket = :bucket"),  # nosec B608
        {"bucket": bucket},
    ).scalar_one()


def _cascade_tables_present(connection) -> list[tuple[str, str]]:
    inspector = inspect(connection.engine)
    return [(table, column) for table, column in _BUCKET_FK_TABLES
            if inspector.has_table(table)]


def _assert_all_cascade_sqlite(connection) -> None:
    present = _cascade_tables_present(connection)
    assert present, "no bucket-keyed tables were created"
    missing = []
    for table, column in present:
        rows = connection.exec_driver_sql(
            f"PRAGMA foreign_key_list({connection.dialect.identifier_preparer.quote(table)})"  # nosec B608
        ).fetchall()
        if not any(row[2] == "storage_buckets" and row[3] == column
                   and (row[6] or "").upper() == "CASCADE" for row in rows):
            missing.append(f"{table}.{column}")
    assert missing == [], f"missing ON DELETE CASCADE: {missing}"


def _assert_all_cascade_information_schema(connection) -> None:
    backend = connection.engine.url.get_backend_name()
    schema = "DATABASE()" if backend == "mysql" else "current_schema()"
    present = _cascade_tables_present(connection)
    assert present, "no bucket-keyed tables were created"
    missing = []
    for table, column in present:
        rows = connection.execute(text(
            "SELECT kcu.column_name, rc.delete_rule "
            "FROM information_schema.key_column_usage AS kcu "
            "JOIN information_schema.referential_constraints AS rc "
            "  ON rc.constraint_schema = kcu.constraint_schema "
            " AND rc.constraint_name = kcu.constraint_name "
            f"WHERE kcu.table_schema = {schema} "  # nosec B608 - fixed literal
            "  AND kcu.table_name = :table "
            "  AND kcu.referenced_table_name = 'storage_buckets'"
        ), {"table": table}).fetchall()
        rules = {row[0]: (row[1] or "").upper() for row in rows}
        if rules.get(column) != "CASCADE":
            missing.append(f"{table}.{column} (rules={rules})")
    assert missing == [], f"missing ON DELETE CASCADE: {missing}"


# ---------------------------------------------------------------------------
# SQLite: migration, idempotency and data preservation
# ---------------------------------------------------------------------------

def test_step_is_idempotent_and_preserves_seeded_rows(tmp_path):
    """Run the rebuild twice; the second run skips and no row is lost."""
    bucket = "cascade-bucket"
    engine = _pre_migration_engine(_sqlite_url(tmp_path))
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO storage_buckets (name, created_at) "
                     "VALUES (:name, 1)"), {"name": bucket})
        with engine.connect() as connection:
            seeded = seed_bucket_rows(connection, bucket)
        assert seeded, "nothing was seeded"

        # Before the step: required tables exist without a cascading FK.
        with engine.connect() as connection:
            assert _count_bucket_rows(connection, "storage_bucket_tags", bucket) == 1

        first = SchemaContext(engine)
        _step_bucket_fk_cascade(first)
        with engine.connect() as connection:
            after_first = {
                table: _count_bucket_rows(connection, table, bucket)
                for table in seeded
            }
            _assert_all_cascade_sqlite(connection)
        assert after_first == seeded, "the migration lost rows"

        # Second run: every table is already CASCADE, so it is a no-op.
        _step_bucket_fk_cascade(SchemaContext(engine))
        with engine.connect() as connection:
            after_second = {
                table: _count_bucket_rows(connection, table, bucket)
                for table in seeded
            }
            _assert_all_cascade_sqlite(connection)
        assert after_second == seeded, "a repeated run lost rows"
    finally:
        engine.dispose()


def test_deleting_the_bucket_row_cascades_every_config_table(tmp_path):
    """A bare DELETE on storage_buckets removes configuration; no sweep."""
    bucket = "cascade-delete"
    db = connect_database(_sqlite_url(tmp_path))
    try:
        catalog = BucketCatalog(ManifestStore(db))
        catalog.create_bucket(bucket, 1)
        with db.engine.begin() as connection:
            seeded = seed_bucket_rows(connection, bucket)
        assert seeded

        # Deliberately bypass delete_bucket: the FK itself must do the work.
        with db.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM storage_buckets WHERE name = :name"),
                {"name": bucket})
            for table in seeded:
                assert _count_bucket_rows(connection, table, bucket) == 0, table
    finally:
        db.close()


def test_insert_after_delete_fails_like_a_real_foreign_key(tmp_path):
    """The orphan window: a late config write now fails instead of orphaning."""
    bucket = "cascade-window"
    db = connect_database(_sqlite_url(tmp_path))
    try:
        catalog = BucketCatalog(ManifestStore(db))
        catalog.create_bucket(bucket, 1)
        # A write that passed an existence check before the delete lands
        # after the bucket commit.  Every table must reject it.
        catalog.delete_bucket(bucket)
        metadata = MetaData()
        for table, _column in _BUCKET_FK_TABLES:
            if not inspect(db.engine).has_table(table):
                continue
            reflected = Table(table, metadata, autoload_with=db.engine)
            values = {}
            for reflected_column in reflected.columns:
                if reflected_column.name == "bucket":
                    values[reflected_column.name] = bucket
                elif reflected_column.nullable:
                    continue
                elif (reflected_column.primary_key
                      and isinstance(reflected_column.type, Integer)
                      and reflected_column.autoincrement in (True, "auto")):
                    continue
                else:
                    values[reflected_column.name] = _placeholder(reflected_column)
            with pytest.raises(IntegrityError), db.engine.begin() as connection:
                connection.execute(reflected.insert().values(**values))
            metadata = MetaData()  # fresh reflection per table
    finally:
        db.close()


def test_fresh_schema_declares_every_cascade(tmp_path):
    """A brand-new database (all steps run) has the cascades everywhere."""
    db = connect_database(_sqlite_url(tmp_path))
    try:
        _assert_all_cascade_sqlite(db.connection)
        # The rebuilt tables keep their indexes.
        heads_indexes = {
            index["name"]
            for index in inspect(db.engine).get_indexes("storage_object_heads")
        }
        assert "ix_storage_object_heads_object" in heads_indexes
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Live PostgreSQL / MySQL
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.getenv("DB_TEST_POSTGRES_URL"),
                    reason="DB_TEST_POSTGRES_URL not configured")
def test_postgres_bucket_fks_cascade():
    url = os.environ["DB_TEST_POSTGRES_URL"]
    connection = connect_database(url)
    try:
        _assert_all_cascade_information_schema(connection.connection)
    finally:
        connection.close()


@pytest.mark.skipif(not os.getenv("DB_TEST_MYSQL_URL"),
                    reason="DB_TEST_MYSQL_URL not configured")
def test_mysql_bucket_fks_cascade():
    url = os.environ["DB_TEST_MYSQL_URL"]
    connection = connect_database(url)
    try:
        _assert_all_cascade_information_schema(connection.connection)
    finally:
        connection.close()


@pytest.mark.parametrize("env_name", ["DB_TEST_POSTGRES_URL",
                                      "DB_TEST_MYSQL_URL"])
def test_live_delete_bucket_cascades_configuration(env_name):
    """The cascade works on the live backend, including delete_bucket."""
    url = os.getenv(env_name)
    if not url:
        pytest.skip(f"{env_name} not configured")
    bucket = "cascade-live-" + sha256(
        f"{env_name}".encode("ascii")).hexdigest()[:16]
    db = connect_database(url)
    try:
        catalog = BucketCatalog(ManifestStore(db))
        if bucket in catalog.list_buckets():
            catalog.delete_bucket(bucket)
        catalog.create_bucket(bucket, 1)
        with db.engine.begin() as connection:
            seed_bucket_rows(connection, bucket)
        catalog.delete_bucket(bucket)
        with db.engine.begin() as connection:
            for table, _column in _BUCKET_FK_TABLES:
                if inspect(db.engine).has_table(table):
                    assert _count_bucket_rows(connection, table, bucket) == 0, table
    finally:
        db.close()
