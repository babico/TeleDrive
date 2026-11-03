"""Service-settings machinery, extracted from ``web.app``.

Everything about reading, merging, redacting and persisting the service
configuration lives here: the bootstrap YAML file, the authoritative SQL
settings document, the secret scrub/restore helpers and the reload that
mirrors the parsed settings onto module attributes.

The mutable state these functions operate on -- ``CONFIG_PATH``,
``AUTH_DIR``, ``STORAGE_SCRATCH_DIR``, the mirrored attribute settings
and ``_CONFIG_CACHE`` -- deliberately stays on the ``web.app`` module
object, and every read/write goes through :func:`_app`. That is the
compatibility contract of the split: the routers resolve app-owned state
through their late-bound ``_webapp()`` lookups and the regression suite
steers it with ``monkeypatch.setattr(web.app, ...)``; both keep working
unchanged because the true read sites still resolve through ``web.app``
at call time.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from teledrive import uploader
from teledrive.db import redact_database_url


def _app():
    """The ``web.app`` module: the owner of the mutable service state.

    Resolved at call time, never at import time, because ``web.app``
    imports this module (a module-level import would be circular) and
    because tests rebind these attributes through
    ``monkeypatch.setattr(web.app, ...)``.
    """
    import web.app as module
    return module


def settings_bind_address() -> str:
    from teledrive.settings import load_settings
    try:
        return load_settings(uploader.load_config(str(_app().CONFIG_PATH)),
                             str(_app().CONFIG_PATH)).bind_address
    except Exception:
        return "0.0.0.0"  # nosec B104 — in-container bind, host mapping loopback


def settings_web_port() -> int:
    from teledrive.settings import load_settings
    try:
        return load_settings(uploader.load_config(str(_app().CONFIG_PATH)),
                             str(_app().CONFIG_PATH)).web_port
    except Exception:
        return 8080


def settings_s3_port() -> int:
    from teledrive.settings import load_settings
    try:
        return load_settings(uploader.load_config(str(_app().CONFIG_PATH)),
                             str(_app().CONFIG_PATH)).s3_port
    except Exception:
        return 9000


def _reload_service_settings() -> None:
    """Read service settings from the deployment config into module attrs."""
    app = _app()

    from teledrive.settings import load_settings
    cfg = uploader.load_config(str(app.CONFIG_PATH))
    settings = load_settings(cfg, str(app.CONFIG_PATH))
    app.MAX_REQUEST_BYTES = settings.max_request_bytes
    app.ALLOWED_HOSTS = list(settings.allowed_hosts)
    app.AUTH_DIR = Path(settings.auth_dir)
    app.STORAGE_SCRATCH_DIR = settings.storage_scratch_dir
    app.REST_MAX_UPLOAD_BYTES = settings.rest_max_upload_bytes
    app.JOB_SOURCE_ROOT = settings.job_source_root
    app.JOB_AUTO_RUN = settings.job_auto_run
    app.ALLOWED_SQLITE_ROOTS = settings.allowed_sqlite_roots
    app.AUTH_FAILURE_WINDOW_SECONDS = settings.auth_failure_window_seconds
    app.AUTH_FAILURE_LIMIT = settings.auth_failure_limit
    app.WATCH_ENABLED = settings.job_watch
    app.WATCH_INTERVAL = settings.job_watch_interval_seconds
    app.WATCH_BUCKET = settings.job_watch_bucket
    app.SSL_CERTFILE = settings.ssl_certfile
    app.SSL_KEYFILE = settings.ssl_keyfile
    app.S3_SSL_CERTFILE = settings.s3_ssl_certfile
    app.S3_SSL_KEYFILE = settings.s3_ssl_keyfile
    app.TRUSTED_PROXY = settings.trusted_proxy
    app.DB_EXTRA_PACKAGES = settings.db_extra_packages
    # Envelope encryption is a gateway property, so the flag lives on the
    # gateway module and is read at request time.
    import web.s3 as _s3_gateway
    _s3_gateway.ENVELOPE_ENABLED = (settings.encryption_mode == "envelope")
    # Legacy uploader path allowlists read os.environ internally; seed them
    # from the config so the operator never configures them via env.
    os.environ["TELEDRIVE_ALLOWED_SOURCE_ROOTS"] = settings.allowed_source_roots
    os.environ["TELEDRIVE_ALLOWED_SESSION_ROOTS"] = settings.allowed_session_roots
    os.environ["TELEDRIVE_ALLOWED_LOG_ROOTS"] = settings.allowed_log_roots
    os.environ["TELEDRIVE_ALLOWED_SQLITE_ROOTS"] = ",".join(
        settings.allowed_sqlite_roots)
    os.environ["TELEDRIVE_SPLIT_DIR"] = settings.split_dir
    os.environ["TELEDRIVE_SPLIT_MIN_FREE_BYTES"] = str(
        settings.split_min_free_bytes)
    os.environ["TELEDRIVE_LOCK_DIR"] = settings.lock_dir
    os.environ["TELEDRIVE_S3_MASTER_KEY_FILE"] = settings.s3_master_key_file


def _secure_mkdir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing to use symlinked security-sensitive directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
    except OSError:
        # Permission hardening may be unavailable on some non-POSIX hosts.
        pass


def _secure_write(path: Path, content: str) -> None:
    _app()._secure_mkdir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _create_default_admin() -> None:
    """Create the hardcoded first-boot admin if no ``admin`` row exists.

    The account is always ``admin``/``admin`` (role ``admin``, enabled).
    It is deliberately NOT configurable: no config key and no environment
    variable can change the username or password. If a row named ``admin``
    already exists it is left completely untouched — password hash, role
    and enabled flag included — so an operator who changes the password
    does not get it reset on the next start. Deleting the row re-creates
    the bootstrap account, which is the documented lockout recovery.
    """
    app = _app()
    conn = app.db_connect()
    try:
        from teledrive.stores import users as _user_store
        if _user_store.get_by_username(conn, "admin") is None:
            import time
            now = int(time.time())
            _user_store.create(
                conn, username="admin",
                password_hash=app._hash_password("admin"),
                role="admin", now=now)
            # The bootstrap gate and the /auth/me nudge key on this
            # account's stored hash; drop any cached probe result so the
            # fresh admin/admin row is seen immediately (the hash-keyed
            # cache would self-heal, this makes the intent explicit).
            app._invalidate_default_admin_cache()
            app._log("bootstrap admin account 'admin' created with the default "
                     "password — change it immediately", "startup")
    except Exception as exc:
        app._log(f"default admin creation failed: {type(exc).__name__}",
                 "startup")
    finally:
        conn.close()


def default_config() -> dict[str, Any]:
    """The first-boot template; every root derives from the data dir."""
    data_dir = _app().DATA_DIR
    return {
        "web": {
            "allowed_hosts": "localhost,127.0.0.1,[::1]",
            "bind_address": "0.0.0.0",  # nosec B104
            "port": 8080,
            "s3_port": 9000,
            "rest_max_upload_bytes": 2147483648,
            "auth_failure_limit": 5,
            "auth_failure_window_seconds": 300,
            "ssl_certfile": "",
            "ssl_keyfile": "",
        },
        "storage": {
            "channel": "",
            "strategy": "round_robin",
            "scratch_dir": os.path.join(data_dir, "tmp"),
            "apis": [],
        },
        "jobs": {
            "source_root": "/uploads",
            "auto_run": True,
            "watch": False,
            "watch_interval_seconds": 30,
            "watch_bucket": "",
        },
        "upload": {
            "source_dir": "/uploads",
            "allowed_extensions": [],
            "max_file_size_mb": 0,
            "sleep_min_seconds": 60,
            "sleep_max_seconds": 90,
            "max_files_per_run": 12,
            "max_files_per_day": 100,
            "retry_attempts": 5,
            "backoff_base_seconds": 10,
            "floodwait_buffer_seconds": 5,
            "caption_template": "{name}",
            "send_mode": "document",
        },
        "state": {"database_url": f"sqlite:///{os.path.join(data_dir, 'state.db')}"},
        "logging": {"log_path": os.path.join(data_dir, "uploader.log"),
                    "level": "INFO"},
    }


def _default_job_source_root() -> str:
    """The uploads root used when the config names none.

    ``jobs.source_root`` is the operator-facing setting; the environment
    variable is read only as the pre-config fallback so a non-Docker
    deployment can point the uploader at a writable directory.
    """
    return os.environ.get("TELEDRIVE_JOB_SOURCE_ROOT", "/uploads")


def ensure_config() -> None:
    app = _app()
    app._secure_mkdir(app.CONFIG_PATH.parent)
    if app.CONFIG_PATH.is_symlink():
        raise RuntimeError("Refusing to use a symlinked TeleDrive config file")
    app._secure_mkdir(app.AUTH_DIR)
    app._secure_mkdir(app.AUTH_DIR.parent / "sessions")
    # Scratch and source roots follow the settings (env/config), not
    # hardcoded /data and /uploads — non-Docker deployments broke here.
    app._secure_mkdir(Path(app.STORAGE_SCRATCH_DIR))
    # Inline YAML parse: read_raw_config()/effective_config() both call
    # ensure_config() and would recurse.
    try:
        raw = yaml.safe_load(app.CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except OSError:
        raw = {}
    source_dir = str(((raw.get("upload") or {}).get("source_dir"))
                     or _default_job_source_root())
    Path(source_dir).mkdir(parents=True, exist_ok=True)
    if not app.CONFIG_PATH.exists():
        app._secure_write(app.CONFIG_PATH,
                          yaml.safe_dump(default_config(), sort_keys=False))
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(app.CONFIG_PATH), flags)
            try:
                try:
                    os.fchmod(fd, 0o600)
                except PermissionError:
                    # A mounted config may be owned by another uid; accept it
                    # only when it is already private.
                    if os.fstat(fd).st_mode & 0o077:
                        raise
            finally:
                os.close(fd)
        except OSError as exc:
            raise RuntimeError("Unable to safely open TeleDrive config file") from exc


def _read_config_file() -> dict[str, Any]:
    """The bootstrap file, parsed. Never consults the database."""
    app = _app()
    ensure_config()
    return yaml.safe_load(app.CONFIG_PATH.read_text(encoding="utf-8")) or {}


# Authentication is no longer configured: the first-boot admin is
# hardcoded and sessions/API keys are the only mechanisms. These keys are
# stripped from config.yaml (and from the SQL settings document) so an
# upgraded deployment does not keep a credential-looking field that does
# nothing. The next settings save persists the stripped document.
_RETIRED_AUTH_KEYS = ("user", "password", "password_file", "allow_insecure")


def _drop_retired_auth_settings(document: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    web_cfg = result.get("web")
    if isinstance(web_cfg, dict):
        for key in _RETIRED_AUTH_KEYS:
            web_cfg.pop(key, None)
    return result


def _settings_store() -> "SettingsStore | None":
    """A store bound to the database named by the BOOTSTRAP FILE.

    The database URL itself lives in the settings, so resolving settings
    through the normal db_connect() would recurse. The file is therefore
    the bootstrap anchor: it names the database, and the database then
    carries the authoritative settings document.
    """
    from teledrive.settings_store import SettingsStore
    raw = _read_config_file()
    state = raw.get("state") or {}
    url = state.get("database_url") or state.get("db_path")
    if not url:
        return None
    try:
        connection = uploader.connect_db(str(url))
    except Exception:
        return None
    try:
        return SettingsStore(connection, _app().load_master_key())
    except Exception:
        connection.close()
        return None


def read_raw_config() -> dict[str, Any]:
    """Authoritative settings: SQL document, else the bootstrap file.

    The SQL document is written on every save (and seeded from the file
    on first boot), so every process sharing the database agrees. If the
    row is missing or undecryptable (master-key rotation), the file is
    used and the next save re-seeds the database.
    """
    app = _app()
    from teledrive.settings_store import SettingsStoreError
    file_document = _drop_retired_auth_settings(_read_config_file())
    store = app._settings_store()
    if store is None:
        return file_document
    try:
        stored = store.load()
    except SettingsStoreError as exc:
        app._log(f"settings: {exc}; falling back to config.yaml", "config")
        stored = None
    finally:
        store.db.close()
    if stored is None:
        # First boot (or an unusable row): seed SQL from the file so the
        # database becomes authoritative from now on.
        _seed_settings_document(file_document)
        return file_document
    document = _drop_retired_auth_settings(stored.document)
    return copy.deepcopy(document)


def _seed_settings_document(document: dict[str, Any]) -> None:
    app = _app()
    store = app._settings_store()
    if store is None:
        return
    try:
        store.save(document, by="bootstrap:config.yaml")
        app._log("settings: seeded the SQL document from config.yaml", "config")
    except Exception as exc:  # noqa: BLE001 - never block startup
        app._log(f"settings: seed failed: {type(exc).__name__}", "config")
    finally:
        store.db.close()


# Field names whose VALUE is a credential, matched at any depth across the
# whole document. A two-key denylist (api_hash) leaked the live Telethon
# StringSession -- full control of the storage account -- to a viewer.
_SECRET_FIELD_NAMES = frozenset({
    "api_hash", "api_id", "session_string", "session", "session_file",
    "password", "secret", "secret_key", "token", "access_key",
    "private_key", "master_key", "webhook_secret", "client_secret",
})


def _redact_tree(node):
    """Redact every credential-looking field, at any depth."""
    if isinstance(node, dict):
        for key, value in list(node.items()):
            normalised = str(key).lower().replace("-", "_")
            if normalised in _SECRET_FIELD_NAMES and value:
                node[key] = _app().REDACTED
            else:
                _redact_tree(value)
    elif isinstance(node, list):
        for item in node:
            _redact_tree(item)
    return node


def _redacted_config(raw: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(raw)
    # One recursive pass instead of an enumerated denylist: the previous
    # version only knew about telegram.api_hash, so storage.apis[*]
    # .session_string and account api_hash went out verbatim.
    _redact_tree(result)
    state_cfg = result.get("state", {})
    db_url = state_cfg.get("database_url") or state_cfg.get("db_path")
    if db_url:
        state_cfg["database_url"] = redact_database_url(str(db_url))
        state_cfg.pop("db_path", None)
    return result


def _restore_tree(node, previous):
    """Put back any REDACTED value the client echoed from the GET.

    Symmetric with _redact_tree, and positional in the same way: a list is
    matched by index and a dict by key, so an entry the client added has no
    previous value and keeps whatever it sent.
    """
    if isinstance(node, dict) and isinstance(previous, dict):
        for key, value in list(node.items()):
            if value == _app().REDACTED and key in previous:
                node[key] = previous[key]
            else:
                _restore_tree(value, previous.get(key))
    elif isinstance(node, list) and isinstance(previous, list):
        for index, item in enumerate(node):
            if index < len(previous):
                _restore_tree(item, previous[index])
    return node


def _restore_secrets(candidate: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    result = _drop_retired_auth_settings(candidate)
    _restore_tree(result, current)
    new_state = result.setdefault("state", {})
    old_state = current.get("state", {})
    old_url = old_state.get("database_url") or old_state.get("db_path")
    submitted = new_state.get("database_url")
    if old_url and submitted == redact_database_url(str(old_url)):
        new_state["database_url"] = old_url
    return result


def effective_config():
    """The parsed configuration the runtime uses.

    The SQL settings document is authoritative; the YAML file is a
    materialized mirror (and the bootstrap when SQL is empty). On a cache
    miss the authoritative document is compared with the file and the
    file is re-written only when they differ, so a mounted stale file is
    self-healing without a write on every request. The cache key stays
    the file mtime: every save rewrites the file, which invalidates the
    cache in every process sharing the volume.
    """
    app = _app()
    try:
        mtime = app.CONFIG_PATH.stat().st_mtime_ns
    except OSError:
        mtime = None
    if app._CONFIG_CACHE["config"] is not None and app._CONFIG_CACHE["mtime"] == mtime:
        return app._CONFIG_CACHE["config"]
    ensure_config()
    document = read_raw_config()
    try:
        on_disk = yaml.safe_load(app.CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except OSError:
        on_disk = {}
    if document != on_disk:
        app._secure_write(app.CONFIG_PATH,
                          yaml.safe_dump(document, sort_keys=False))
        try:
            mtime = app.CONFIG_PATH.stat().st_mtime_ns
        except OSError:
            mtime = None
    app._CONFIG_CACHE["config"] = uploader.load_config(str(app.CONFIG_PATH))
    app._CONFIG_CACHE["mtime"] = mtime
    return app._CONFIG_CACHE["config"]


def _persist_settings_document(document: dict[str, Any], *, by: str) -> None:
    """Write the SQL settings document; never fail the save on this."""
    app = _app()
    store = app._settings_store()
    if store is None:
        app._log("settings: no database reachable; file-only save", "config")
        return
    try:
        store.save(document, by=by)
    except Exception as exc:  # noqa: BLE001 - the file write already succeeded
        app._log(f"settings: SQL persist failed: {type(exc).__name__}", "config")
    finally:
        store.db.close()


def validate_and_write_config(raw: dict[str, Any], *,
                             by: str = "system") -> None:
    app = _app()
    current = read_raw_config()
    merged = _restore_secrets(raw, current)
    tmp = app.CONFIG_PATH.with_suffix(app.CONFIG_PATH.suffix + ".tmp")
    app._secure_write(tmp, yaml.safe_dump(merged, sort_keys=False))
    try:
        cfg = uploader.load_config(str(tmp))
        uploader.validate_config(cfg)
        conn = uploader.connect_db(cfg.db_path)
        conn.close()
    except ValueError:
        tmp.unlink(missing_ok=True)
        raise
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise RuntimeError("Database connection/initialization failed") from exc
    os.replace(tmp, app.CONFIG_PATH)
    # Persist the authoritative copy in SQL as well. The file stays the
    # bootstrap/recovery source and its mtime invalidates every process's
    # settings cache; the database is what a rebuild reads back.
    _persist_settings_document(merged, by=by)
    app._CONFIG_CACHE["config"] = None
    app._CONFIG_CACHE["mtime"] = None
    _reload_service_settings()
    # The administrator bootstrap belongs to startup only. Running it here
    # meant that a save pointing at a fresh database would silently create
    # admin/admin in it; the save path can no longer change the database, but
    # startup-only is the correct place for it regardless.
    # Core schema (including users.enabled) is brought current by the one
    # schema coordinator when the database engine is first built; there is
    # deliberately no DDL here any more.
