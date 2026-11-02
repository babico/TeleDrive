from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import (
    BigInteger, Column, Integer, MetaData, String, Table, Text,
    create_engine, delete, insert, select, update,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import IntegrityError, NoSuchModuleError

metadata = MetaData()

leases = Table(
    "leases", metadata,
    Column("name", String(128), primary_key=True),
    Column("holder", String(255), nullable=False),
    Column("lease_until", BigInteger, nullable=False),
    Column("last_update_ts", BigInteger, nullable=False),
)

telegram_sessions = Table(
    "telegram_sessions", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("api_id", BigInteger, nullable=False),
    Column("api_hash", String(128), nullable=False),
    Column("phone", String(64)),
    Column("session_string", Text, nullable=False),
    # One row per account: upsert_session's UPDATE-then-INSERT recovery
    # relies on this constraint to reject a concurrent creator.
    Column("account", String(128), nullable=False, unique=True,
           server_default="mtproto-user"),
    Column("channel", String(255)),
    Column("strategy", String(32), server_default="round_robin"),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
    # Health probe results: NULL = never checked, 1 = authorized,
    # 0 = expired/revoked/unusable.
    Column("authorized", Integer),
    Column("health_checked_at", BigInteger),
    # Soft quota: routing PREFERs accounts under this (user_mode switches
    # to an under-quota peer); it never rejects an upload. NULL =
    # unlimited. Monitored in UI/metrics.
    Column("soft_quota_bytes", BigInteger),
)

telegram_channels = Table(
    "telegram_channels", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(128), nullable=False),
    # Unique so a concurrent verify/login cannot create phantom channels;
    # upsert_channel_by_channel_id recovers from the losing INSERT.
    Column("channel_id", String(255), nullable=False, unique=True),
    Column("strategy", String(32), nullable=False, server_default="round_robin"),
    Column("scratch_dir", String(512), server_default="/data/tmp"),
    Column("is_active", Integer, nullable=False, server_default="0"),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)

telegram_session_pending = Table(
    "telegram_session_pending", metadata,
    Column("token", String(64), primary_key=True),
    Column("api_id", BigInteger, nullable=False),
    Column("api_hash", String(128), nullable=False),
    Column("phone", String(64), nullable=False),
    Column("phone_code_hash", String(255)),
    # Serialized (unauthorized) Telethon session of the code REQUEST
    # client: MTProto binds phone_code_hash to that session's auth key,
    # so verify-code must reuse it or Telegram rejects the hash as
    # expired no matter how fresh it is.
    Column("session_string", Text),
    Column("channel", String(255)),
    Column("strategy", String(32), server_default="round_robin"),
    Column("created_at", BigInteger, nullable=False),
    # Failed verification attempts. A login code is 5 digits, so an
    # uncapped retry loop is a brute force against a Telegram account: the
    # pending row is destroyed after a bounded number of wrong codes.
    Column("attempts", Integer, nullable=False, server_default="0"),
)

# Operator-managed placement: uploads to a pinned bucket prefer the
# pinned Telegram account. Explicit operator intent wins over the
# soft-quota routing preference.
bucket_account_pins = Table(
    "bucket_account_pins", metadata,
    Column("bucket", String(63), primary_key=True),
    Column("account", String(255), nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)

bucket_quotas = Table(
    "bucket_quotas", metadata,
    Column("bucket", String(255), primary_key=True),
    Column("max_size_bytes", BigInteger),
    Column("max_objects", BigInteger),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)

# Signed public share links: an unauthenticated URL that streams one
# object, bounded by expiry, download count and an optional password.
share_links = Table(
    "share_links", metadata,
    Column("token", String(64), primary_key=True),
    Column("bucket", String(63), nullable=False),
    Column("object_key", String(1024), nullable=False),
    # The exact object VERSION this link was issued for. A link bound only to
    # a key re-targeted whatever the key pointed at later, so a share URL
    # silently served replaced bytes, and kept working after an unlink plus a
    # re-upload. NULL for rows created before this column existed; those
    # links stay key-bound but are still bounded by expiry/revocation.
    Column("object_id", String(36)),
    Column("created_by", String(255), nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("expires_at", BigInteger),
    Column("max_downloads", Integer),
    Column("download_count", Integer, nullable=False, default=0),
    # PBKDF2-HMAC-SHA256; both NULL means the link needs no password.
    Column("password_salt", String(64)),
    Column("password_hash", String(128)),
    Column("revoked", Integer, nullable=False, default=0),
)

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(128), nullable=False, unique=True),
    Column("password_hash", String(255), nullable=False),
    Column("role", String(32), nullable=False, server_default="viewer"),
    Column("enabled", Integer, nullable=False, server_default="1"),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
    Column("last_login", BigInteger),
)

flood_waits = Table(
    "flood_waits", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scope", String(64), nullable=False),
    Column("started_at", BigInteger, nullable=False),
    Column("wait_seconds", Integer, nullable=False),
    Column("expires_at", BigInteger, nullable=False),
    Column("detail", Text),
)

user_sessions = Table(
    "user_sessions", metadata,
    Column("token", String(128), primary_key=True),
    Column("user_id", Integer, nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("expires_at", BigInteger, nullable=False),
)


def normalize_database_url(value: str, *, config_dir: Path | None = None) -> str:
    """Accept any synchronous SQLAlchemy URL; local paths become SQLite URLs."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Database URL/path must not be empty")

    if "://" not in raw:
        path = Path(raw).expanduser()
        if not path.is_absolute() and config_dir is not None:
            path = config_dir / path
        return f"sqlite:///{path.resolve().as_posix()}"

    # Convenience aliases only. Explicit dialect+driver URLs pass through unchanged.
    if raw.startswith("postgres://"):
        raw = "postgresql+psycopg://" + raw[len("postgres://"):]
    elif raw.startswith("postgresql://"):
        raw = "postgresql+psycopg://" + raw[len("postgresql://"):]
    elif raw.startswith("mysql://"):
        raw = "mysql+pymysql://" + raw[len("mysql://"):]

    if raw.startswith("sqlite:///") and not raw.startswith("sqlite:////") and raw != "sqlite:///:memory:" and config_dir:
        rel = raw[len("sqlite:///"):]
        return f"sqlite:///{(config_dir / rel).expanduser().resolve().as_posix()}"
    return raw


def sqlite_database_path(url: str) -> str | None:
    """Return the filesystem path for a SQLite URL, otherwise None."""
    try:
        parsed = make_url(normalize_database_url(url))
    except Exception:
        return None
    if parsed.get_backend_name() != "sqlite":
        return None
    database = parsed.database
    if not database or database == ":memory:":
        return None
    return str(Path(database).expanduser().resolve())


def redact_database_url(url: str) -> str:
    """Render a URL without userinfo passwords or sensitive query values."""
    try:
        rendered = make_url(normalize_database_url(url)).render_as_string(hide_password=True)
        parts = urlsplit(rendered)
        sensitive = {"password", "passwd", "pwd", "token", "access_token", "secret", "api_key", "apikey"}
        query = [
            (key, "***" if key.lower() in sensitive else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    except Exception:
        return "<invalid database URL>"


def _checkpoint_wal_best_effort(engine: "Engine") -> None:
    """Flush a shared SQLite WAL without ever stalling a caller.

    Uses a raw pooled connection so SQLAlchemy's automatic transaction
    does not wrap the PRAGMA (a checkpoint inside a transaction fails or
    blocks), and caps the busy timeout so a concurrent reader costs
    milliseconds, not seconds.
    """
    try:
        raw = engine.raw_connection()
    except Exception:
        return
    try:
        cursor = raw.cursor()
        try:
            cursor.execute("PRAGMA busy_timeout=200")
            cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            cursor.close()
    except Exception:
        pass
    finally:
        try:
            raw.close()
        except Exception:
            pass


@dataclass
class Database:
    url: str
    engine: Engine
    connection: Connection
    owns_engine: bool = True

    def close(self) -> None:
        """Release this connection; checkpoint a shared SQLite WAL if cheap.

        Shared (cached) engines keep pooled connections alive, so disposal
        never checkpoints the WAL. Flushing it keeps the file
        self-contained for readers that open it directly (DR rebuild
        publication), but the checkpoint MUST NOT run on this connection:
        an open transaction still holds table locks, and SQLite then
        blocks for the full busy_timeout (30s) before giving up. That cost
        was paid by every test teardown.

        The checkpoint therefore runs on a separate pooled connection
        with a tiny busy timeout, so it either succeeds immediately or
        gives up in milliseconds -- it is best-effort by contract.
        """
        connection, engine, owns_engine = (
            self.connection, self.engine, self.owns_engine)
        try:
            connection.close()
        finally:
            if not owns_engine and engine.url.get_backend_name() == "sqlite":
                _checkpoint_wal_best_effort(engine)
            if owns_engine:
                engine.dispose()

    def release_setup_snapshot(self) -> None:
        """End a transaction opened by schema probing during construction.

        Under MySQL's default REPEATABLE READ the FIRST statement on a
        connection freezes its snapshot, so a row committed by another
        worker afterwards stays invisible -- cross-connection reads then
        silently miss it. Schema creation and column probing are not part
        of any caller transaction, so they must not pin the snapshot.
        """
        if self.engine.url.get_backend_name() == "sqlite":
            return
        try:
            self.connection.commit()
        except Exception:  # noqa: BLE001 - best effort, never blocks setup
            try:
                self.connection.rollback()
            except Exception:
                pass

    def commit(self) -> None:
        self.connection.commit()

    def acquire_lease(self, name: str, holder: str, now: int, ttl_seconds: int) -> bool:
        lease_until = now + ttl_seconds
        result = self.connection.execute(
            update(leases)
            .where(
                leases.c.name == name,
                (leases.c.holder == holder) | (leases.c.lease_until < now),
            )
            .values(holder=holder, lease_until=lease_until, last_update_ts=now)
        )
        if result.rowcount:
            self.connection.commit()
            row = self.connection.execute(
                select(leases.c.holder, leases.c.lease_until).where(leases.c.name == name)
            ).first()
            owned = bool(row and row[0] == holder and int(row[1]) >= now)
            # Close read snapshot before another SQL connection writes jobs.
            self.connection.commit()
            return owned
        try:
            self.connection.execute(insert(leases).values(
                name=name, holder=holder, lease_until=lease_until, last_update_ts=now,
            ))
            self.connection.commit()
            return True
        except IntegrityError:
            self.connection.rollback()
            return False

    def renew_lease(self, name: str, holder: str, now: int, ttl_seconds: int) -> bool:
        result = self.connection.execute(
            update(leases)
            .where(leases.c.name == name, leases.c.holder == holder, leases.c.lease_until >= now)
            .values(lease_until=now + ttl_seconds, last_update_ts=now)
        )
        self.connection.commit()
        if not result.rowcount:
            self.connection.rollback()
            return False
        row = self.connection.execute(
            select(leases.c.holder, leases.c.lease_until).where(leases.c.name == name)
        ).first()
        owned = bool(row and row[0] == holder and int(row[1]) >= now)
        self.connection.commit()
        return owned

    def release_lease(self, name: str, holder: str) -> None:
        self.connection.execute(
            delete(leases).where(leases.c.name == name, leases.c.holder == holder)
        )
        self.connection.commit()

# Arbitrary stable key for the PostgreSQL schema-setup advisory lock.
# (Kept here for backwards compatibility; the migration coordinator in
# teledrive.storage.schema owns cross-process locking now.)
_SCHEMA_LOCK_KEY = 715273001


def _setup_schema(engine: Engine) -> None:
    """Apply every pending schema migration through the coordinator.

    Kept as a thin compatibility wrapper: a single serialized path lives in
    ``teledrive.storage.schema`` so no caller can issue DDL outside the
    cross-process lock.
    """
    from teledrive.storage.schema import ensure_schema

    ensure_schema(engine)


def _build_engine(url: str) -> Engine:
    """Create a new engine and ensure the schema is current."""
    connect_args: dict[str, Any] = {}

    if url.startswith("sqlite:"):
        connect_args["timeout"] = 30
        if url != "sqlite:///:memory:":
            db_path = url[len("sqlite:///"):]
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    try:
        engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
    except (NoSuchModuleError, ModuleNotFoundError) as exc:
        raise RuntimeError(
            "Database dialect/driver is not installed. Install the SQLAlchemy dialect/DBAPI "
            "required for the configured database_url."
        ) from exc

    # Every worker that opens the same database runs the same one serialized
    # migration: a process-local fast path first, then one version probe, and
    # real cross-process locks only when the schema is actually stale.
    _setup_schema(engine)
    return engine



# Bounded LRU cache of shared engines. Production uses exactly one database
# URL; the bound keeps long test runs from accumulating file handles.
# sqlite:///:memory: is never cached: every connection there is a separate
# throwaway database by design.
_ENGINE_CACHE_MAX = 8
_engine_cache: "OrderedDict[str, Engine]" = OrderedDict()
# Threadpool requests share this cache, and every read/write below is a
# multi-step OrderedDict operation (lookup + move_to_end, insert + evict).
# Without the lock two threads can build the same engine twice or corrupt
# the LRU ordering.
_engine_cache_lock = threading.Lock()


def _shared_engine(url: str) -> Engine:
    """Return a cached engine for this URL, building it on first use.

    Sharing the engine (instead of rebuilding it per request) skips the
    per-request YAML config parse, `create_all` and dialect migrations.
    Connections are still per-call; `pool_pre_ping` recovers stale ones.
    """
    with _engine_cache_lock:
        engine = _engine_cache.get(url)
        if engine is not None:
            _engine_cache.move_to_end(url)
            return engine
        engine = _build_engine(url)
        _engine_cache[url] = engine
        while len(_engine_cache) > _ENGINE_CACHE_MAX:
            _engine_cache.popitem(last=False)
        return engine


def connect_database(url_or_path: str, *, config_dir: Path | None = None) -> Database:
    url = normalize_database_url(url_or_path, config_dir=config_dir)

    if url == "sqlite:///:memory:":
        # Uncached: each call is an isolated in-memory database.
        engine = _build_engine(url)
        owns_engine = True
    else:
        engine = _shared_engine(url)
        owns_engine = False

    connection = engine.connect()
    if engine.url.get_backend_name() == "sqlite":
        connection.exec_driver_sql("PRAGMA busy_timeout=30000")
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
    return Database(url=url, engine=engine, connection=connection,
                    owns_engine=owns_engine)
