"""One serialized schema-migration path for every TeleDrive backend.

Historically every store constructor ran its own ``create_all`` /
``ALTER TABLE`` on its own connection, outside the advisory lock that only
guarded ``teledrive.db._setup_schema``.  Several workers starting at once
could therefore race on ``CREATE TABLE`` (duplicate-table error) or lose an
ALTER.  This module is the single place that decides whether the schema is
current and the single place that issues DDL.

Design
------
* A process-local :class:`weakref.WeakSet` remembers engines whose schema
  this process already verified.  Every constructor call after the first is
  a pure in-memory lookup: no connection, no query, no DDL.
* The first call per engine per process reads the highest
  ``schema_migrations.version``.  When it matches :data:`SCHEMA_VERSION` the
  process stops there — one cheap SELECT for a warm database.
* Only when the version is stale does the coordinator take a real
  cross-process lock, re-check the version (another worker may have just
  finished), and run every idempotent DDL step in a fixed order:
    - SQLite: ``flock`` on a sidecar ``<db>.schema-lock`` file, non-blocking
      attempts retried until a bounded timeout.  ``:memory:`` databases are
      process-local and skip the file lock.
    - PostgreSQL: ``pg_advisory_xact_lock`` on a dedicated connection, held
      until the migration transaction commits.
    - MySQL: ``GET_LOCK`` / ``RELEASE_LOCK`` on a dedicated connection with a
      bounded timeout (session-level lock, safe across the implicit commits
      DDL causes).
* After the steps succeed a row ``(version, name, applied_at)`` is written.
  A worker that starts later sees the version and does no DDL at all.  An
  interrupted migration is safe to re-run because every step is idempotent
  (``CREATE TABLE IF NOT EXISTS`` semantics via ``checkfirst`` and
  column-existence probes before every ``ALTER``).
* Steps are append-only.  :data:`SCHEMA_VERSION` is the length of the step
  list, so adding a step bumps the version.  When several were added the
  whole (idempotent) list is re-run once on the next start — correctness
  over cleverness.

No table's columns or semantics are defined here except the defensive ALTERs
that older databases already received; this module only decides *when* and
*by whom* that idempotent DDL runs.
"""
from __future__ import annotations

import logging
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator

from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

_LOGGER = logging.getLogger("teledrive.schema")

# Arbitrary stable key for the PostgreSQL schema-setup advisory lock.
_PG_LOCK_KEY = 715273001
# MySQL GET_LOCK is scoped to the server, so it needs a name, not a number.
_MYSQL_LOCK_NAME = "teledrive.schema.migrations"
# How long a worker waits for another worker's migration before giving up.
LOCK_TIMEOUT_SECONDS = 30.0

# Engines whose schema this process already verified.  WeakSet (not
# id(engine)) because id() values are reused after garbage collection and a
# brand-new engine must never inherit a stale "already migrated" verdict.
_verified_engines: "weakref.WeakSet[Engine]" = weakref.WeakSet()
_verify_lock = threading.RLock()

# SQLite engines whose connections already enable foreign-key enforcement.
_fk_enabled_engines: "weakref.WeakSet[Engine]" = weakref.WeakSet()


@dataclass(frozen=True)
class SchemaContext:
    """What a migration step may use."""

    engine: Engine


Step = Callable[[SchemaContext], None]


# ---------------------------------------------------------------------------
# Small dialect-aware DDL helpers
# ---------------------------------------------------------------------------

def _column_names(engine: Engine, table: str) -> set[str]:
    """Existing column names for ``table`` in THIS schema/database.

    Both information_schema probes are filtered by ``current_schema()`` /
    ``DATABASE()``: an unfiltered lookup sees same-named tables in other
    databases on the server and can silently skip a needed ALTER.
    """
    dialect = engine.dialect.name
    preparer = engine.dialect.identifier_preparer
    with engine.connect() as connection:
        if dialect == "sqlite":
            rows = connection.exec_driver_sql(
                # nosec B608 - `table` is a hardcoded internal identifier.
                f"PRAGMA table_info({preparer.quote(table)})").fetchall()
            return {row[1] for row in rows}
        if dialect == "mysql":
            # Fixed dialect literal; the table name is a bound parameter.
            query = ("SELECT column_name FROM information_schema.columns "
                     "WHERE table_name = :table AND table_schema = DATABASE()")
        else:
            # Filter by the CURRENT schema: an unfiltered lookup would see
            # same-named tables in other databases and skip a needed ALTER.
            query = ("SELECT column_name FROM information_schema.columns "
                     "WHERE table_name = :table "
                     "AND table_schema = current_schema()")
        rows = connection.execute(text(query), {"table": table}).fetchall()
        return {row[0] for row in rows}


def _add_columns(engine: Engine, table: str,
                 additions: list[tuple[str, str]]) -> None:
    """Add any missing columns; each ALTER is its own committed step.

    ``additions`` is ``(column, portable SQL type)``.  The table and column
    names are hardcoded internal identifiers, never request input.
    """
    existing = _column_names(engine, table)
    if not existing:
        # The table does not exist (yet); create_all owns its definition.
        return
    preparer = engine.dialect.identifier_preparer
    quoted_table = preparer.quote(table)
    with engine.begin() as connection:
        for name, sql_type in additions:
            if name in existing:
                continue
            connection.exec_driver_sql(
                # nosec B608 - internal identifiers and fixed SQL types.
                f"ALTER TABLE {quoted_table} ADD COLUMN "
                f"{preparer.quote(name)} {sql_type}")
            _LOGGER.info("schema: added %s.%s", table, name)


# ---------------------------------------------------------------------------
# Idempotent migration steps, in dependency order
# ---------------------------------------------------------------------------

def _step_core(ctx: SchemaContext) -> None:
    """Core worker tables plus their historical defensive columns."""
    from teledrive import db as core

    core.metadata.create_all(ctx.engine)
    _add_columns(ctx.engine, "files", [
        ("tg_account", "VARCHAR(255)"),
        ("claim_token", "VARCHAR(255)"),
        ("claim_ts", "BIGINT"),
    ])
    _add_columns(ctx.engine, "telegram_sessions", [
        ("authorized", "INTEGER"),
        ("health_checked_at", "BIGINT"),
        ("soft_quota_bytes", "BIGINT"),
    ])
    _add_columns(ctx.engine, "telegram_session_pending", [
        ("session_string", "TEXT"),
    ])
    # Older web databases predate the RBAC `enabled` flag (O5: the two
    # duplicated inline ALTERs in web/app.py now live here).
    _add_columns(ctx.engine, "users", [
        ("enabled", "INTEGER NOT NULL DEFAULT 1"),
    ])


def _step_manifest(ctx: SchemaContext) -> None:
    from teledrive.storage import manifest

    manifest.metadata.create_all(ctx.engine)


def _step_catalog(ctx: SchemaContext) -> None:
    from teledrive.storage import catalog

    catalog.catalog_metadata.create_all(ctx.engine)


def _step_tagging(ctx: SchemaContext) -> None:
    from teledrive.s3 import tagging

    tagging._meta.create_all(ctx.engine)
    tagging.catalog_metadata.create_all(
        ctx.engine, tables=[tagging.bucket_tags])


def _step_metadata_journal(ctx: SchemaContext) -> None:
    from teledrive.s3 import metadata_journal

    metadata_journal.metadata_journal_metadata.create_all(ctx.engine)


def _step_notifications(ctx: SchemaContext) -> None:
    from teledrive.s3 import notifications

    notifications.catalog_metadata.create_all(
        ctx.engine, tables=notifications._CONFIG_TABLES)
    notifications.outbox_metadata.create_all(
        ctx.engine, tables=[notifications.event_outbox])


def _step_annotations_and_metadata(ctx: SchemaContext) -> None:
    from teledrive.s3 import annotations, object_metadata

    annotations.annotation_metadata.create_all(
        ctx.engine, tables=[annotations.annotations])
    object_metadata.manifest_metadata.create_all(
        ctx.engine,
        tables=[object_metadata.object_http_metadata,
                object_metadata.upload_http_metadata])


def _step_tiering(ctx: SchemaContext) -> None:
    from teledrive.s3 import tiering

    tiering.tiering_metadata.create_all(
        ctx.engine, tables=[tiering.tiering_configs])


def _step_reports(ctx: SchemaContext) -> None:
    from teledrive.s3 import report_configs

    report_configs.report_metadata.create_all(
        ctx.engine, tables=[report_configs.report_configs])


def _step_api_keys(ctx: SchemaContext) -> None:
    from teledrive import api_keys

    api_keys._metadata.create_all(ctx.engine)


def _step_settings(ctx: SchemaContext) -> None:
    from teledrive import settings_store

    settings_store._metadata.create_all(
        ctx.engine, tables=[settings_store.settings_document])


def _step_multipart(ctx: SchemaContext) -> None:
    from teledrive.s3 import multipart

    multipart._meta.create_all(ctx.engine)


def _step_upload_jobs(ctx: SchemaContext) -> None:
    from teledrive.storage import jobs

    jobs._meta.create_all(ctx.engine)


def _step_mtproto(ctx: SchemaContext) -> None:
    from teledrive.storage import mtproto_rate_guard, user_mode

    mtproto_rate_guard._meta.create_all(ctx.engine)
    user_mode._meta.create_all(ctx.engine)


def _step_gc(ctx: SchemaContext) -> None:
    from teledrive.storage import gc_collect

    gc_collect.metadata.create_all(ctx.engine)
    _add_columns(ctx.engine, "storage_gc_state", [
        ("grace_seconds", "INTEGER"),
    ])


def _step_credentials(ctx: SchemaContext) -> None:
    from teledrive.s3 import credentials

    credentials._meta.create_all(ctx.engine)
    _add_columns(ctx.engine, "storage_s3_credentials", [
        ("tags", "TEXT"),
    ])


def _step_s3_config(ctx: SchemaContext) -> None:
    """Bucket-scoped S3 configuration tables (all in ``catalog_metadata``)."""
    from teledrive.s3 import (bucket_encryption, cors, lifecycle, policy,
                              replication, website)

    # Those imports register their tables in catalog_metadata as a side
    # effect; the create_all below then covers all of them at once.
    _ = (bucket_encryption, cors, lifecycle, policy, replication, website)
    from teledrive.storage.catalog import catalog_metadata
    from teledrive.storage.manifest import metadata as manifest_metadata

    # One create_all over the fully populated metadata creates every table
    # the imports above registered, including any added by future modules.
    catalog_metadata.create_all(ctx.engine)
    manifest_metadata.create_all(ctx.engine)


def _step_envelope_encryption(ctx: SchemaContext) -> None:
    """Envelope (SSE-S3) columns on the object encryption marker."""
    _add_columns(ctx.engine, "storage_object_encryption", [
        ("wrapped_key", "TEXT"),
        ("key_wrap", "VARCHAR(16) DEFAULT 'none'"),
        ("envelope_aad", "VARCHAR(64)"),
    ])


def _step_security_audit(ctx: SchemaContext) -> None:
    """Durable security-event trail (append-only migration).

    The in-memory log buffer is bounded and lost on restart, so no
    investigation could answer "who revealed this credential last week".
    """
    from teledrive.storage import audit
    audit.audit_events.create(ctx.engine, checkfirst=True)


def _step_share_object_id(ctx: SchemaContext) -> None:
    """Bind a share link to the object version it was issued for.

    A key-bound link silently re-targeted replaced content and revived after
    an unlink + re-upload, so an unauthenticated capability served bytes it
    was never issued for. Nullable: legacy rows stay key-bound.
    """
    _add_columns(ctx.engine, "share_links", [
        ("object_id", "VARCHAR(36)"),
    ])


def _step_gc_indexes(ctx: SchemaContext) -> None:
    """Indexes for the physical-GC candidate query (append-only migration).

    The GC "is this a head anywhere?" probe filters storage_object_heads by
    object_id, which is not part of that table's primary key, and the queued
    scope filters storage_gc_queue by enqueued_ns.
    """
    from teledrive.storage import gc_collect
    from teledrive.storage.catalog import heads
    gc_collect.gc_queue.create(ctx.engine, checkfirst=True)
    for index in gc_collect.gc_queue.indexes:
        index.create(ctx.engine, checkfirst=True)
    heads.create(ctx.engine, checkfirst=True)
    for index in heads.indexes:
        index.create(ctx.engine, checkfirst=True)


def _step_hot_indexes(ctx: SchemaContext) -> None:
    """Indexes for columns the hot paths filter on (append-only migration).

    ``storage_object_aliases.source_object_id`` is read for every GC
    candidate and for every dedup lookup; it had no index, so both were full
    scans.
    """
    from teledrive.storage.manifest import object_aliases
    # Defensive: a database created before the alias table existed gets it
    # here too, so the index never references a missing table.
    object_aliases.create(ctx.engine, checkfirst=True)
    for index in object_aliases.indexes:
        index.create(ctx.engine, checkfirst=True)


def _step_gc_leases(ctx: SchemaContext) -> None:
    """Durable physical-GC leases (append-only migration).

    Added after the gc step shipped: editing that step would never run on an
    already-migrated database, so the new table gets its own version.
    """
    from teledrive.storage import gc_collect
    gc_collect.gc_leases.create(ctx.engine, checkfirst=True)


def _step_verification_attempts(ctx: SchemaContext) -> None:
    """Login-verification attempt counter (append-only migration).

    Added as its own step rather than folded into an existing one: the
    coordinator records the step count as the schema version, so editing a
    shipped step would never run on an already-migrated database.
    """
    _add_columns(ctx.engine, "telegram_session_pending", [
        # A 5-digit login code with unlimited retries is a brute force
        # against the Telegram account; the pending row dies after a cap.
        ("attempts", "INTEGER NOT NULL DEFAULT 0"),
    ])


def _step_legacy_columns(ctx: SchemaContext) -> None:
    """Defensive ALTERs for databases created by older releases.

    Lessons kept from the original inline migrations:
    * booleans use ``DEFAULT false`` so PostgreSQL accepts them;
    * a column with a server default is VARCHAR, never TEXT (MySQL rejects
      defaults on TEXT/BLOB);
    * column probes filter information_schema by the current schema.
    """
    _add_columns(ctx.engine, "storage_buckets", [
        ("versioning_state", "VARCHAR(16) NOT NULL DEFAULT 'Enabled'"),
        ("object_lock_enabled", "BOOLEAN NOT NULL DEFAULT false"),
        ("object_lock_default_mode", "VARCHAR(16)"),
        ("object_lock_default_days", "INTEGER"),
        # VARCHAR, not TEXT: MySQL cannot DEFAULT a TEXT column.
        ("public_access_block",
         "VARCHAR(512) NOT NULL DEFAULT "
         "'{\"BlockPublicAcls\": true, \"IgnorePublicAcls\": true, "
         "\"BlockPublicPolicy\": true, \"RestrictPublicBuckets\": true}'"),
        ("object_ownership",
         "VARCHAR(32) NOT NULL DEFAULT 'BucketOwnerEnforced'"),
        ("public_read", "BOOLEAN NOT NULL DEFAULT false"),
    ])
    _add_columns(ctx.engine, "storage_objects", [
        ("retention_until_ns", "BIGINT"),
        ("legal_hold", "BOOLEAN NOT NULL DEFAULT false"),
        ("retention_mode", "VARCHAR(16)"),
        ("access_count", "BIGINT NOT NULL DEFAULT 0"),
        ("last_accessed_ns", "BIGINT"),
        # VARCHAR, not TEXT: MySQL rejects a server default on TEXT.
        ("storage_class", "VARCHAR(32) NOT NULL DEFAULT 'STANDARD'"),
        ("restore_until_ns", "BIGINT"),
    ])
    # SSE-C per-chunk metadata.  MySQL rejects a DEFAULT on TEXT, so this is
    # nullable with no server default; NULL means plaintext.
    _add_columns(ctx.engine, "storage_chunks", [
        ("encryption", "TEXT"),
    ])
    _add_columns(ctx.engine, "storage_multipart_uploads", [
        ("encryption", "TEXT"),
    ])


def _step_content_search(ctx: SchemaContext) -> None:
    from teledrive.storage.content_index import (
        _create_content_search_structures)

    _create_content_search_structures(ctx.engine)


def _dedupe_for_unique(engine: Engine, table: str, key_column: str) -> None:
    """Keep one row per ``key_column`` so a unique index can be created.

    Deterministic winner: the row with the latest ``updated_at``, ties broken
    by the lowest ``id``. The keep-set is materialised in a TEMPORARY table
    first: a correlated ``DELETE`` that reads its own table is rejected by
    MySQL (error 1093), and a plain NOT IN list would exceed the parameter
    limits of SQLite/PostgreSQL on a prod-sized table. Temporary tables are
    session-scoped on all three supported dialects and are dropped again at
    the end, so the statements remain idempotent if the step is re-run.
    """
    preparer = engine.dialect.identifier_preparer
    quoted_table = preparer.quote(table)
    quoted_key = preparer.quote(key_column)
    quoted_id = preparer.quote("id")
    keep_table = preparer.quote(f"_teledrive_keep_{table}")
    with engine.begin() as connection:
        connection.exec_driver_sql(f"DROP TABLE IF EXISTS {keep_table}")
        connection.exec_driver_sql(
            f"CREATE TEMPORARY TABLE {keep_table} AS "  # nosec B608 - internal, quoted
            f"SELECT s.{quoted_id} AS {quoted_id} FROM {quoted_table} AS s "
            f"WHERE NOT EXISTS ("
            f"SELECT 1 FROM {quoted_table} AS n "
            f"WHERE n.{quoted_key} = s.{quoted_key} AND ("
            f"n.updated_at > s.updated_at OR "
            f"(n.updated_at = s.updated_at AND n.{quoted_id} < s.{quoted_id})"
            f"))"
        )
        connection.exec_driver_sql(
            f"DELETE FROM {quoted_table} "  # nosec B608 - internal, quoted
            f"WHERE {quoted_id} NOT IN (SELECT {quoted_id} FROM {keep_table})"
        )
        connection.exec_driver_sql(f"DROP TABLE {keep_table}")


def _ensure_unique_index(engine: Engine, table: str, column: str,
                         name: str) -> None:
    """Create the named unique index unless an equivalent one already exists.

    A brand-new database already gets the constraint from ``create_all``
    (the column is ``unique=True`` in the table definition), so the probe
    avoids a duplicate index there; an older database gets the index here.
    """
    inspector = inspect(engine)
    for constraint in inspector.get_unique_constraints(table):
        if constraint.get("column_names") == [column]:
            return
    for index in inspector.get_indexes(table):
        if index.get("unique") and index.get("column_names") == [column]:
            return
    preparer = engine.dialect.identifier_preparer
    with engine.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE UNIQUE INDEX {preparer.quote(name)} ON "
            f"{preparer.quote(table)} ({preparer.quote(column)})")


def _step_unique_telegram_identities(ctx: SchemaContext) -> None:
    """One row per Telegram account and per channel_id (schema step 27).

    Both upserts are UPDATE-then-INSERT and their race recovery assumes the
    database rejects a duplicate INSERT. Without the constraint two
    concurrent logins created duplicate rows: phantom sessions in listings,
    duplicate account labels in Prometheus scrapes, and a credential probed
    twice. Existing duplicates are resolved first, then the index is added.
    """
    _dedupe_for_unique(ctx.engine, "telegram_sessions", "account")
    _ensure_unique_index(ctx.engine, "telegram_sessions", "account",
                         "uq_telegram_sessions_account")
    _dedupe_for_unique(ctx.engine, "telegram_channels", "channel_id")
    _ensure_unique_index(ctx.engine, "telegram_channels", "channel_id",
                         "uq_telegram_channels_channel_id")


def _step_directory_bucket_type(ctx: SchemaContext) -> None:
    """The bucket class column (append-only migration, handoff 07).

    ``storage_buckets.bucket_type`` is ``general`` (every historical row)
    or ``directory`` (an S3 Express-shaped ``base--zone-id--x-s3`` name).
    The directory namespace shares the table so object heads, manifests
    and GC keep working unchanged; only listings and routing read the
    type. VARCHAR with a server default: MySQL rejects defaults on TEXT,
    and pre-existing rows must read as ``general``.
    """
    _add_columns(ctx.engine, "storage_buckets", [
        ("bucket_type", "VARCHAR(16) NOT NULL DEFAULT 'general'"),
    ])


def _step_s3_express_sessions(ctx: SchemaContext) -> None:
    """S3 Express CreateSession credentials (append-only migration).

    ``storage_s3_sessions`` holds the short-lived zonal sessions: a unique
    access key, the SHA-256 hash of the session token (the token itself is
    never stored), the Fernet-encrypted secret, and the binding to one
    directory bucket, mode, signer and logical zone. Revocation is a row
    flag, so it is durable and immediately visible to every worker.
    """
    from teledrive.s3 import directory_buckets

    directory_buckets.sessions_metadata.create_all(ctx.engine)


def _step_archive_manifests(ctx: SchemaContext) -> None:
    """Cold-archive state machine (append-only migration, handoff 08).

    ``storage_archive_versions`` is one row per archived immutable object
    version: the resumable HOT -> ARCHIVING -> ARCHIVED -> RESTORING ->
    RESTORED_TEMP state machine, the idempotency key, the generation
    fence, the durable worker lease columns and the sealed-manifest
    mirror (whole SHA-256, stored bytes, target URI, manifest JSON,
    timestamps, last error). The physical blobs and sealed manifests
    live in the cold store on disk; this table is their catalog side.
    """
    from teledrive.storage import cold_store

    cold_store.cold_metadata.create_all(ctx.engine)
    for index in cold_store.archive_versions.indexes:
        index.create(ctx.engine, checkfirst=True)


# ---------------------------------------------------------------------------
# Step 31: bucket-name-keyed configuration cascades from storage_buckets
# ---------------------------------------------------------------------------
#
# ``BucketAdminMixin.delete_bucket`` used to sweep these tables explicitly
# before deleting the bucket row.  A configuration write whose existence
# check ran in an earlier transaction could still commit after the sweep,
# leaving a row for a bucket that no longer existed (and silently reviving
# on a same-name re-create).  An ON DELETE CASCADE foreign key makes the
# bucket DELETE itself remove every configuration row atomically, and makes
# a later insert fail instead of orphaning.
#
# Each entry is ``(table, column)``.  The list is deliberately explicit:
# a future bucket-scoped table must be added here (and gets a new step,
# because this one has already shipped on migrated databases).

_BUCKET_FK_TABLES: tuple[tuple[str, str], ...] = (
    # Swallowed by the old sweep loop in catalog_buckets.delete_bucket.
    ("storage_bucket_tags", "bucket"),
    ("storage_bucket_lifecycle", "bucket"),
    ("storage_bucket_cors", "bucket"),
    ("storage_website_configs", "bucket"),
    ("storage_metadata_journal", "bucket"),
    ("storage_metadata_configs", "bucket"),
    ("storage_bucket_acl_grants", "bucket"),
    ("storage_bucket_policy", "bucket"),
    ("storage_bucket_abac", "bucket"),
    ("storage_bucket_encryption", "bucket"),
    ("storage_replication_configs", "bucket"),
    ("storage_tiering_configs", "bucket"),
    ("storage_report_configs", "bucket"),
    ("storage_notification_configs", "bucket"),
    ("storage_logging_configs", "bucket"),
    ("bucket_quotas", "bucket"),
    ("bucket_account_pins", "bucket"),
    ("share_links", "bucket"),
    ("storage_object_acl_grants", "bucket"),
    # Not swept by the old code (bucket deletion refuses object history),
    # but bucket-name-keyed all the same: the cascade keeps a stray head
    # from outliving its bucket.
    ("storage_object_heads", "bucket"),
)

_BUCKET_TABLE = "storage_buckets"
_BUCKET_KEY = "name"


def _bucket_fk_is_cascade(engine: Engine, table: str, column: str) -> bool:
    """True when ``table.column`` already references the bucket with CASCADE."""
    dialect = engine.dialect.name
    inspector = inspect(engine)
    for fk in inspector.get_foreign_keys(table):
        if fk.get("referred_table") != _BUCKET_TABLE:
            continue
        if column not in (fk.get("constrained_columns") or []):
            continue
        if (fk.get("options") or {}).get("ondelete", "").upper() == "CASCADE":
            return True
    if dialect == "sqlite":
        # Some SQLite drivers omit FK options from the inspector; the
        # PRAGMA is authoritative for the on_delete rule.
        preparer = engine.dialect.identifier_preparer
        with engine.connect() as connection:
            rows = connection.exec_driver_sql(
                f"PRAGMA foreign_key_list({preparer.quote(table)})"  # nosec B608
            ).fetchall()
        return any(
            row[2] == _BUCKET_TABLE and row[3] == column
            and (row[6] or "").upper() == "CASCADE"
            for row in rows)
    if dialect in ("postgresql", "mysql"):
        # The inspector normally reports options, but not every reflected
        # constraint shape carries them; the catalog is authoritative and
        # keeps a re-run a true no-op.
        schema = "DATABASE()" if dialect == "mysql" else "current_schema()"
        with engine.connect() as connection:
            rows = connection.execute(text(
                "SELECT rc.delete_rule "
                "FROM information_schema.key_column_usage AS kcu "
                "JOIN information_schema.referential_constraints AS rc "
                "  ON rc.constraint_schema = kcu.constraint_schema "
                " AND rc.constraint_name = kcu.constraint_name "
                f"WHERE kcu.table_schema = {schema} "  # nosec B608 - fixed literal
                "  AND kcu.table_name = :table "
                "  AND kcu.column_name = :column "
                "  AND kcu.referenced_table_name = 'storage_buckets'"
            ), {"table": table, "column": column}).fetchall()
        return any((row[0] or "").upper() == "CASCADE" for row in rows)
    return False


def _delete_orphan_config_rows(engine: Engine, table: str, column: str) -> None:
    """Drop rows whose bucket is already gone (a pre-migration orphan).

    These are exactly the rows the old sweep raced with; they cannot be
    referenced by any live bucket, and an FK add would fail on them.  The
    delete is bounded to one table and runs in its own transaction.
    """
    preparer = engine.dialect.identifier_preparer
    with engine.begin() as connection:
        connection.exec_driver_sql(
            f"DELETE FROM {preparer.quote(table)} "  # nosec B608
            f"WHERE {preparer.quote(column)} NOT IN "
            f"(SELECT {preparer.quote(_BUCKET_KEY)} FROM "
            f"{preparer.quote(_BUCKET_TABLE)})"
        )


def _sqlite_rebuild_bucket_fk(engine: Engine, table: str, column: str) -> None:
    """SQLite cannot ALTER a foreign key: rebuild the table in one transaction.

    Standard SQLite table rebuild, wrapped in an explicit transaction so an
    interrupted migration rolls back to the old table (SQLite DDL is
    transactional).  ``PRAGMA foreign_keys=OFF`` is required for the
    create/copy/drop/rename sequence and is restored afterwards.  Columns,
    primary key, server defaults, non-bucket foreign keys, unique
    constraints and indexes are reproduced from live reflection, so no row
    or index is lost.  The step is idempotent: it only runs when the live
    FK is not already CASCADE.
    """
    from sqlalchemy import (Column, ForeignKeyConstraint, MetaData, String,
                            Table, UniqueConstraint)
    from sqlalchemy.schema import CreateTable

    inspector = inspect(engine)
    columns = inspector.get_columns(table)
    primary_key = set(
        inspector.get_pk_constraint(table).get("constrained_columns") or [])
    foreign_keys = inspector.get_foreign_keys(table)
    indexes = inspector.get_indexes(table)
    uniques = inspector.get_unique_constraints(table)

    temp_table = f"_teledrive_fk_{table}"
    metadata = MetaData()
    # Referenced table declared in the same MetaData so the FK can be
    # compiled; it is not part of the CREATE TABLE issued below.
    Table(_BUCKET_TABLE, metadata,
          Column(_BUCKET_KEY, String(63), primary_key=True))
    rebuilt_columns = []
    for reflected in columns:
        default = reflected.get("default")
        rebuilt_columns.append(Column(
            reflected["name"],
            reflected["type"],
            primary_key=reflected["name"] in primary_key,
            nullable=reflected.get("nullable", True),
            server_default=default if default is not None else None,
        ))
    rebuilt = Table(temp_table, metadata, *rebuilt_columns)
    for fk in foreign_keys:
        constrained = fk.get("constrained_columns") or []
        referred = fk.get("referred_table")
        if referred == _BUCKET_TABLE and constrained == [column]:
            continue  # replaced by the cascade constraint below
        rebuilt.append_constraint(ForeignKeyConstraint(
            constrained,
            [f"{referred}.{name}"
             for name in (fk.get("referred_columns") or [])],
            name=fk.get("name"),
        ))
    rebuilt.append_constraint(ForeignKeyConstraint(
        [column], [f"{_BUCKET_TABLE}.{_BUCKET_KEY}"],
        name=f"fk_{table}_{column}_cascade", ondelete="CASCADE"))
    for unique in uniques:
        constrained = unique.get("column_names") or []
        if unique.get("name") and constrained:
            rebuilt.append_constraint(UniqueConstraint(
                *constrained, name=unique["name"]))

    preparer = engine.dialect.identifier_preparer
    quote = preparer.quote
    quoted_table = quote(table)
    quoted_temp = quote(temp_table)
    column_list = ", ".join(quote(c["name"]) for c in columns)

    raw = engine.raw_connection()
    dbapi = getattr(raw, "driver_connection", raw)
    previous_isolation = dbapi.isolation_level
    try:
        dbapi.isolation_level = None  # explicit BEGIN below
        cursor = dbapi.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("BEGIN IMMEDIATE")
        try:
            cursor.execute(f"DROP TABLE IF EXISTS {quoted_temp}")
            cursor.execute(str(CreateTable(rebuilt).compile(dialect=engine.dialect)))
            # Remove pre-migration orphans before the rows change table.
            cursor.execute(
                f"DELETE FROM {quoted_table} "  # nosec B608
                f"WHERE {quote(column)} NOT IN "
                f"(SELECT {quote(_BUCKET_KEY)} FROM {quote(_BUCKET_TABLE)})")
            cursor.execute(
                f"INSERT INTO {quoted_temp} ({column_list}) "  # nosec B608
                f"SELECT {column_list} FROM {quoted_table}")
            cursor.execute(f"DROP TABLE {quoted_table}")
            cursor.execute(
                f"ALTER TABLE {quoted_temp} RENAME TO {quoted_table}")
            for index in indexes:
                names = index.get("column_names") or []
                if not names or any(name is None for name in names):
                    # Expression indexes are not used by these tables; a
                    # silent skip would lose an index, so make it loud.
                    _LOGGER.warning(
                        "schema: not rebuilding unused SQLite expression "
                        "index %s on %s", index.get("name"), table)
                    continue
                unique_sql = "UNIQUE " if index.get("unique") else ""
                cursor.execute(
                    f"CREATE {unique_sql}INDEX {quote(index['name'])} "  # nosec B608
                    f"ON {quoted_table} "
                    f"({', '.join(quote(name) for name in names)})")
            cursor.execute("COMMIT")
        except BaseException:
            cursor.execute("ROLLBACK")
            raise
        finally:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    finally:
        dbapi.isolation_level = previous_isolation
        raw.close()


def _add_bucket_fk_constraint(engine: Engine, table: str, column: str) -> None:
    """PostgreSQL/MySQL: replace the bucket FK with one that cascades.

    Adding a constraint is idempotent (a live CASCADE FK short-circuits in
    the caller) and atomic per statement; a crash between DROP and ADD
    leaves the table without a bucket FK, which the next start repairs.
    MySQL requires the child column to have an index and matching string
    length, so both are repaired first.
    """
    preparer = engine.dialect.identifier_preparer
    quote = preparer.quote
    inspector = inspect(engine)
    columns = {c["name"]: c for c in inspector.get_columns(table)}
    dialect = engine.dialect.name

    if dialect == "mysql":
        reflected = columns.get(column)
        length = getattr(reflected["type"], "length", None) if reflected else None
        if length is not None and length != 63:
            # bucket names are validated to 63 characters; MySQL needs the
            # child and parent string types to match exactly for an FK.
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"ALTER TABLE {quote(table)} MODIFY "  # nosec B608
                    f"{quote(column)} VARCHAR(63) NOT NULL")
        inspector = inspect(engine)
        indexed = (
            (inspector.get_pk_constraint(table).get("constrained_columns") or [None])[0]
            == column
            or any(
                (index.get("column_names") or [None])[0] == column
                for index in inspector.get_indexes(table)))
        if not indexed:
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    f"CREATE INDEX {quote(f'ix_{table}_{column}')} "  # nosec B608
                    f"ON {quote(table)} ({quote(column)})")

    _delete_orphan_config_rows(engine, table, column)

    inspector = inspect(engine)
    for fk in inspector.get_foreign_keys(table):
        if fk.get("referred_table") != _BUCKET_TABLE:
            continue
        if column not in (fk.get("constrained_columns") or []):
            continue
        name = fk.get("name")
        if not name:  # pragma: no cover - every real backend names its FKs
            continue
        with engine.begin() as connection:
            if dialect == "mysql":
                connection.exec_driver_sql(
                    f"ALTER TABLE {quote(table)} DROP FOREIGN KEY {quote(name)}")
            else:
                connection.exec_driver_sql(
                    f"ALTER TABLE {quote(table)} DROP CONSTRAINT {quote(name)}")

    constraint = f"fk_{table}_{column}_cascade"
    with engine.begin() as connection:
        connection.exec_driver_sql(
            f"ALTER TABLE {quote(table)} ADD CONSTRAINT {quote(constraint)} "  # nosec B608
            f"FOREIGN KEY ({quote(column)}) REFERENCES "
            f"{quote(_BUCKET_TABLE)} ({quote(_BUCKET_KEY)}) ON DELETE CASCADE")


def _step_bucket_fk_cascade(ctx: SchemaContext) -> None:
    """Give every bucket-name-keyed configuration table a cascading FK.

    The step is idempotent and skips tables that do not exist on older
    deployments.  SQLite rebuilds each table (it cannot alter a foreign
    key); PostgreSQL and MySQL drop any existing non-cascading bucket FK
    and add a named ``ON DELETE CASCADE`` one.  Existing rows and indexes
    are preserved; orphan rows (for already-deleted buckets) are removed
    first because a live FK cannot be validated over them.
    """
    engine = ctx.engine
    for table, column in _BUCKET_FK_TABLES:
        if not inspect(engine).has_table(table):
            _LOGGER.info("schema: %s absent, skipping bucket FK cascade", table)
            continue
        if _bucket_fk_is_cascade(engine, table, column):
            continue
        if engine.dialect.name == "sqlite":
            _sqlite_rebuild_bucket_fk(engine, table, column)
        else:
            _add_bucket_fk_constraint(engine, table, column)
        _LOGGER.info("schema: %s.%s now cascades from %s",
                     table, column, _BUCKET_TABLE)


_STEPS: list[tuple[str, Step]] = [
    ("core", _step_core),
    ("verification_attempts", _step_verification_attempts),
    ("gc_leases", _step_gc_leases),
    ("manifest", _step_manifest),
    ("catalog", _step_catalog),
    ("tagging", _step_tagging),
    ("metadata_journal", _step_metadata_journal),
    ("notifications", _step_notifications),
    ("annotations_and_metadata", _step_annotations_and_metadata),
    ("tiering", _step_tiering),
    ("reports", _step_reports),
    ("api_keys", _step_api_keys),
    ("settings", _step_settings),
    ("multipart", _step_multipart),
    ("upload_jobs", _step_upload_jobs),
    ("mtproto", _step_mtproto),
    ("gc", _step_gc),
    ("credentials", _step_credentials),
    ("s3_config", _step_s3_config),
    ("legacy_columns", _step_legacy_columns),
    ("content_search", _step_content_search),
    ("hot_indexes", _step_hot_indexes),
    ("gc_indexes", _step_gc_indexes),
    ("share_object_id", _step_share_object_id),
    ("security_audit", _step_security_audit),
    ("envelope_encryption", _step_envelope_encryption),
    ("unique_telegram_identities", _step_unique_telegram_identities),
    ("directory_bucket_type", _step_directory_bucket_type),
    ("s3_express_sessions", _step_s3_express_sessions),
    ("archive_manifests", _step_archive_manifests),
    ("bucket_fk_cascade", _step_bucket_fk_cascade),
]

# Bump by appending a step; never reorder or remove one.
SCHEMA_VERSION = len(_STEPS)


# ---------------------------------------------------------------------------
# Bookkeeping table
# ---------------------------------------------------------------------------

_BOOKKEEPING_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    " version INTEGER NOT NULL PRIMARY KEY,"
    " name VARCHAR(128) NOT NULL,"
    " applied_at BIGINT NOT NULL)")
_BOOKKEEPING_TABLE = "schema_migrations"


def _ensure_bookkeeping_table(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql(_BOOKKEEPING_DDL)


def _current_version(engine: Engine) -> int:
    """Highest applied version, or -1 when the bookkeeping table is absent."""
    try:
        with engine.connect() as connection:
            value = connection.exec_driver_sql(
                f"SELECT MAX(version) FROM {_BOOKKEEPING_TABLE}"  # nosec B608
            ).scalar()
        return int(value) if value is not None else 0
    except SQLAlchemyError:
        # Fresh database (or a worker is mid-DDL on SQLite): treat as empty.
        return -1


def _record(engine: Engine, version: int, name: str) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM schema_migrations WHERE version = :version"),
            {"version": version})
        connection.execute(
            text("INSERT INTO schema_migrations (version, name, applied_at) "
                 "VALUES (:version, :name, :applied_at)"),
            {"version": version, "name": name,
             "applied_at": int(time.time())})


# ---------------------------------------------------------------------------
# Cross-process locks
# ---------------------------------------------------------------------------

@contextmanager
def _sqlite_file_lock(engine: Engine) -> Iterator[None]:
    """Serialize migrations between OS processes with a sidecar flock.

    flock lives on an open file description and is independent of SQLite's
    own POSIX byte-range locks, so using a sidecar file avoids surprising
    the database engine.  ``:memory:`` databases cannot be shared between
    processes, so they need no file lock.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX platforms
        yield
        return

    database = engine.url.database
    if not database or database == ":memory:" or database.startswith("file:"):
        yield
        return

    lock_path = f"{database}.schema-lock"
    handle = open(lock_path, "a+b")
    try:
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "timed out waiting for the schema migration lock "
                        f"({lock_path})") from None
                time.sleep(0.02)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


@contextmanager
def _postgres_lock(engine: Engine) -> Iterator[None]:
    """pg_advisory_xact_lock held for the whole migration transaction."""
    with engine.connect() as guard:
        # Opening a transaction here makes the xact lock release on commit,
        # even if a step raises (the context manager rolls back).
        guard.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                      {"key": _PG_LOCK_KEY})
        try:
            yield
        finally:
            guard.commit()


@contextmanager
def _mysql_lock(engine: Engine) -> Iterator[None]:
    """GET_LOCK / RELEASE_LOCK on a dedicated connection."""
    with engine.connect() as guard:
        acquired = guard.execute(
            text("SELECT GET_LOCK(:name, :timeout)"),
            {"name": _MYSQL_LOCK_NAME,
             "timeout": int(LOCK_TIMEOUT_SECONDS)}).scalar()
        # GET_LOCK is session-level; MySQL can implicitly commit DDL on other
        # connections without dropping it, so holding this connection is
        # enough to serialize the whole migration.
        if acquired != 1:
            raise TimeoutError(
                "timed out waiting for the MySQL schema migration lock")
        try:
            yield
        finally:
            guard.execute(text("SELECT RELEASE_LOCK(:name)"),
                          {"name": _MYSQL_LOCK_NAME})
            guard.commit()


def _lock_for(engine: Engine):
    dialect = engine.dialect.name
    if dialect == "sqlite":
        return _sqlite_file_lock(engine)
    if dialect == "postgresql":
        return _postgres_lock(engine)
    if dialect == "mysql":
        return _mysql_lock(engine)
    return _null_lock()


@contextmanager
def _null_lock() -> Iterator[None]:
    """Other dialects: in-process serialization only (documented limit)."""
    yield


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _enable_sqlite_foreign_keys(engine: Engine) -> None:
    """Enable SQLite foreign-key enforcement on every connection.

    SQLite defaults to ``PRAGMA foreign_keys=OFF``, which makes a declared
    ``ON DELETE CASCADE`` inert.  The listener is installed before the
    engine hands out its first connection (``_build_engine`` calls
    ``ensure_schema`` immediately after ``create_engine``) and only once
    per engine.  Other dialects enforce foreign keys natively.
    """
    if engine.dialect.name != "sqlite":
        return
    with _verify_lock:
        if engine in _fk_enabled_engines:
            return

        def _turn_on(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

        event.listen(engine, "connect", _turn_on)
        _fk_enabled_engines.add(engine)


def ensure_schema(engine: Engine) -> bool:
    """Apply every pending idempotent migration, at most once per engine.

    Returns True when this call actually ran the DDL steps.  Costs one
    in-memory lookup on every call after the first for an engine.
    """
    _enable_sqlite_foreign_keys(engine)
    with _verify_lock:
        if engine in _verified_engines:
            return False
        ran = _migrate(engine)
        _verified_engines.add(engine)
        return ran


def _migrate(engine: Engine) -> bool:
    if _current_version(engine) >= SCHEMA_VERSION:
        return False

    with _lock_for(engine):
        # Another worker may have finished between the unlocked probe and
        # acquiring the lock; the re-check makes that a cheap no-op.
        if _current_version(engine) >= SCHEMA_VERSION:
            return False
        _ensure_bookkeeping_table(engine)
        if _current_version(engine) >= SCHEMA_VERSION:
            return False

        context = SchemaContext(engine)
        for version, (name, step) in enumerate(_STEPS, start=1):
            step(context)
            _record(engine, version, name)
        _LOGGER.info("schema: migrated %s to version %s",
                     engine.url.render_as_string(hide_password=True),
                     SCHEMA_VERSION)
        return True


def reset_process_cache() -> None:
    """Forget which engines this process verified (tests only)."""
    with _verify_lock:
        _verified_engines.clear()
