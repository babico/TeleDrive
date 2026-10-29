"""TeleDrive web application.

There is exactly one authentication mechanism for people: ``POST
/api/v1/auth/login`` verifies a row in the local ``users`` table and sets
an httpOnly session cookie. The user's role is mapped to endpoint
permissions by ``web.permissions``. HTTP Basic is not implemented at all;
a ``Basic`` header is treated like no credential.

The first boot creates a hardcoded ``admin``/``admin`` account if (and
only if) no user named ``admin`` exists. It is never configurable and an
existing admin row is never overwritten, so changing that password
survives restarts. Programmatic clients use API keys, which keep their
existing per-route scope semantics unchanged. See ``docs/UPGRADING.md``.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import copy
import html as _html
import secrets
import tempfile
import os
import gzip
import shutil
import logging
import threading
from logging.handlers import RotatingFileHandler
import re
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
import urllib.parse
from urllib.parse import quote as _url_quote, urlsplit
from typing import Any

import yaml
from fastapi import (Body, Depends, FastAPI, HTTPException, Query, Request,
                     WebSocket, WebSocketDisconnect, status)
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse, Response
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from pydantic import BaseModel, Field
from typing import Literal
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles

from teledrive import uploader
from teledrive.db import redact_database_url
from teledrive.api_keys import ApiKeyStore
from teledrive.s3.credentials import S3CredentialStore, load_master_key, DEFAULT_PERMISSIONS
from teledrive.s3.multipart import MultipartStore
from teledrive.s3.object_metadata import ObjectMetadataStore
from teledrive.s3.website import (
    WebsiteConfigStore, WebsiteError, validate_document_name,
)
from teledrive.storage.gc import StorageGCInventory
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.manifest import ManifestStore, objects
from sqlalchemy import select as _sa_select
from teledrive.storage.jobs import StorageUploadJobs, UploadJobError, jobs as storage_job_rows
from teledrive.storage.catalog import BucketCatalog
from teledrive.stores import pins as _pin_store
from teledrive.stores import sessions as _session_store
from teledrive.stores import shares as _share_store
from teledrive.stores import telegram_pending as _pending_store
from teledrive.stores import users as _user_store
from teledrive.storage.copy import copy_object, CopyConflict
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from teledrive.storage.user_mode import (
    UserSessionRuntime, UserSendJournal, UnifiedUserTransport, transport_mode,
)
from teledrive.storage.history_inventory import inventory_channel
from teledrive.storage.mtproto_rate_guard import MtprotoRateGuard
from web.permissions import READ_METHODS, is_admin_only
mtproto_storage_runtime = UserSessionRuntime()

CONFIG_PATH = Path(os.environ.get("TELEDRIVE_CONFIG", "config/config.yaml"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
REDACTED = "__REDACTED__"

# Service settings come ONLY from config/config.yaml (owner policy); the
# TELEDRIVE_CONFIG env var just points at the file. Tests override the
# module attributes below directly.
MAX_REQUEST_BYTES = 32 * 1024 * 1024
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]
AUTH_DIR = Path("/data/auth")
STORAGE_SCRATCH_DIR = "/data/tmp"
REST_MAX_UPLOAD_BYTES = 2 * 1024**3
JOB_SOURCE_ROOT = "/uploads"
JOB_AUTO_RUN = True
ALLOWED_SQLITE_ROOTS = ("/data",)
AUTH_FAILURE_WINDOW_SECONDS = 300
AUTH_FAILURE_LIMIT = 5
WATCH_ENABLED = False
WATCH_INTERVAL = 30
WATCH_BUCKET = ""
SSL_CERTFILE = ""
SSL_KEYFILE = ""
S3_SSL_CERTFILE = ""
S3_SSL_KEYFILE = ""
TRUSTED_PROXY = False
DB_EXTRA_PACKAGES: tuple[str, ...] = ()


def settings_bind_address() -> str:
    from teledrive.settings import load_settings
    try:
        return load_settings(uploader.load_config(str(CONFIG_PATH)),
                             str(CONFIG_PATH)).bind_address
    except Exception:
        return "0.0.0.0"  # nosec B104 — in-container bind, host mapping loopback


def settings_web_port() -> int:
    from teledrive.settings import load_settings
    try:
        return load_settings(uploader.load_config(str(CONFIG_PATH)),
                             str(CONFIG_PATH)).web_port
    except Exception:
        return 8080


def settings_s3_port() -> int:
    from teledrive.settings import load_settings
    try:
        return load_settings(uploader.load_config(str(CONFIG_PATH)),
                             str(CONFIG_PATH)).s3_port
    except Exception:
        return 9000


def _reload_service_settings() -> None:
    """Read service settings from the deployment config into module attrs."""
    global MAX_REQUEST_BYTES, ALLOWED_HOSTS, AUTH_DIR, STORAGE_SCRATCH_DIR
    global REST_MAX_UPLOAD_BYTES, JOB_SOURCE_ROOT, JOB_AUTO_RUN
    global ALLOWED_SQLITE_ROOTS, AUTH_FAILURE_WINDOW_SECONDS, AUTH_FAILURE_LIMIT
    global WATCH_ENABLED, WATCH_INTERVAL, WATCH_BUCKET
    global SSL_CERTFILE, SSL_KEYFILE, DB_EXTRA_PACKAGES
    global S3_SSL_CERTFILE, S3_SSL_KEYFILE, TRUSTED_PROXY

    from teledrive.settings import load_settings
    cfg = uploader.load_config(str(CONFIG_PATH))
    settings = load_settings(cfg, str(CONFIG_PATH))
    MAX_REQUEST_BYTES = settings.max_request_bytes
    ALLOWED_HOSTS = list(settings.allowed_hosts)
    AUTH_DIR = Path(settings.auth_dir)
    STORAGE_SCRATCH_DIR = settings.storage_scratch_dir
    REST_MAX_UPLOAD_BYTES = settings.rest_max_upload_bytes
    JOB_SOURCE_ROOT = settings.job_source_root
    JOB_AUTO_RUN = settings.job_auto_run
    ALLOWED_SQLITE_ROOTS = settings.allowed_sqlite_roots
    AUTH_FAILURE_WINDOW_SECONDS = settings.auth_failure_window_seconds
    AUTH_FAILURE_LIMIT = settings.auth_failure_limit
    WATCH_ENABLED = settings.job_watch
    WATCH_INTERVAL = settings.job_watch_interval_seconds
    WATCH_BUCKET = settings.job_watch_bucket
    SSL_CERTFILE = settings.ssl_certfile
    SSL_KEYFILE = settings.ssl_keyfile
    S3_SSL_CERTFILE = settings.s3_ssl_certfile
    S3_SSL_KEYFILE = settings.s3_ssl_keyfile
    TRUSTED_PROXY = settings.trusted_proxy
    DB_EXTRA_PACKAGES = settings.db_extra_packages
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
LOG_BUFFER: deque[str] = deque(maxlen=1500)
# Live log subscribers: asyncio queues fed by _log (thread-safe handoff).
_LOG_WAITERS: set = set()


class RotatingCompressedFileHandler(RotatingFileHandler):
    """RotatingFileHandler that gzip-compresses rotated files."""

    def rotation_filename(self, default_name: str) -> str:
        return default_name + ".gz"

    def rotate(self, source: str, dest: str) -> None:
        with open(source, "rb") as f_in:
            with gzip.open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(source)


def _extract_user(request: Request) -> str:
    """Extract the authenticated user identity from the request (best-effort)."""
    auth = request.headers.get("authorization", "")
    # Session token (cookie or Bearer) — resolve to the WebUI username.
    token = None
    if auth.lower().startswith("bearer ") and auth[7:].strip().startswith("td_sess_"):
        token = auth[7:].strip()
    elif request.cookies.get("teledrive_session"):
        token = request.cookies.get("teledrive_session")
    if token:
        try:
            conn = db_connect()
            try:
                username = _session_store.username_for_token(
                    conn, _session_token_digest(token))
                if username:
                    return username
            finally:
                conn.close()
        except Exception:
            pass
    # Bearer token (API key) — resolve to the key name if possible.
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        try:
            conn = db_connect()
            try:
                store = ApiKeyStore(conn)
                scopes = store.scopes_for_token(token)
                name = store.name_for_token(token) if scopes is not None else None
                if name:
                    return name
            finally:
                conn.close()
        except Exception:
            pass
        return "api-key"
    return "anonymous"


# A log LINE must not be able to contain a line break: several log call
# sites interpolate names, keys and exception text, and a newline let a
# caller forge a second record ("[2026-01-01] [system] [users] ...") that
# /api/logs serves as genuine. Control characters are stripped at the single
# place every record is built, so no call site has to remember.
_LOG_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _log_safe(value) -> str:
    text_value = str(value)
    text_value = text_value.replace("\r\n", " ").replace("\r", " ")
    text_value = text_value.replace("\n", " ")
    return _LOG_CONTROL_RE.sub("", text_value)


def _audit(request: Request | None, action: str, *, target: str | None = None,
           outcome: str = "ok", detail: dict | None = None) -> None:
    """Append a durable security event; never raises, never blocks the action."""
    try:
        from teledrive.storage import audit as _audit_store
        actor = (getattr(getattr(request, "state", None), "user", None) or {}).get(
            "username") or "system"
        client_ip = None
        client = getattr(request, "client", None) if request is not None else None
        if client is not None:
            client_ip = getattr(client, "host", None)
        conn = db_connect()
        try:
            _audit_store.record(conn, action=action, actor=actor,
                                outcome=outcome, target=target,
                                detail=detail, client_ip=client_ip)
        finally:
            conn.close()
    except Exception:
        pass


def _log(msg: str, source: str = "web", user: str = "system") -> None:
    """Append a timestamped, user-tagged, source-tagged entry to LOG_BUFFER."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    # Sanitise ONCE and use the same values everywhere: the in-memory buffer
    # and the durable rotating file must not disagree about what a log line
    # is, or a newline could forge a record in one and not the other.
    safe_user, safe_source, safe_msg = (_log_safe(user), _log_safe(source),
                                        _log_safe(msg))
    entry = f"[{ts}] [{safe_user}] [{safe_source}] {safe_msg}"
    LOG_BUFFER.append(entry)
    # Push to live WebSocket subscribers. _log can run in worker threads,
    # so the handoff to the main event loop must be thread-safe.
    if _LOG_WAITERS and _main_event_loop is not None and not _main_event_loop.is_closed():
        try:
            for waiter in list(_LOG_WAITERS):
                _main_event_loop.call_soon_threadsafe(waiter.put_nowait, entry)
        except RuntimeError:
            pass
    try:
        import logging as _logging
        record = _logging.LogRecord(
            name="teledrive", level=_logging.INFO, pathname="", lineno=0,
            msg=safe_msg, args=(), exc_info=None
        )
        record.source = safe_source
        record.user = safe_user
        record.created = time.time()
        if _FILE_LOG_HANDLER is not None:
            _FILE_LOG_HANDLER.emit(record)
    except Exception:
        pass
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:password|passwd|pwd|token|access_token|secret|api_key|apikey)=)[^&#\s]+"
)

bearer_auth = HTTPBearer(auto_error=False)
AUTH_FAILURES: dict[str, deque[float]] = {}
_FILE_LOG_HANDLER = None


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
    _secure_mkdir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _scrub_text(value: str) -> str:
    value = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:)[^@\s]+(@)", r"\1***\2", value)
    return _QUERY_SECRET_RE.sub(r"\1***", value)


def _same_origin(request: Request) -> None:
    if request.headers.get("x-teledrive-csrf") != "1":
        raise HTTPException(403, "Missing CSRF protection header")
    origin = request.headers.get("origin")
    if not origin:
        return
    host = request.headers.get("host", "").lower()
    try:
        origin_host = urlsplit(origin).netloc.lower()
    except Exception:
        raise HTTPException(403, "Invalid Origin header")
    if not host or origin_host != host:
        raise HTTPException(403, "Cross-origin state change rejected")


_PBKDF2_ITERATIONS = 260_000
# Pre-computed hash for timing-safe login checks when the user does not exist.
_DUMMY_PASSWORD_HASH = None


def _hash_password(password: str) -> str:
    """Salted PBKDF2-HMAC-SHA256 password hash (format: pbkdf2_sha256$iter$salt$digest)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Verify PBKDF2 hashes; legacy salt:sha256 hashes still verify (migrated on login)."""
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, iterations, salt, hexdigest = stored.split("$", 3)
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), int(iterations))
            return hmac.compare_digest(digest.hex(), hexdigest)
        if ":" in stored:  # legacy format
            salt, digest = stored.split(":", 1)
            return hmac.compare_digest(
                digest, hashlib.sha256((salt + password).encode()).hexdigest())
    except Exception:
        return False
    return False


def _dummy_password_hash() -> str:
    global _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        _DUMMY_PASSWORD_HASH = _hash_password("teledrive-invalid-password")
    return _DUMMY_PASSWORD_HASH


def _session_token_digest(token: str) -> str:
    """Session tokens are stored hashed in the DB (like API keys)."""
    return hashlib.sha256(token.encode()).hexdigest()


_DEFAULT_ADMIN_PW_CACHE: dict[str, bool] = {}


def _default_admin_password_in_use(username: str = "admin") -> bool:
    """True while the seeded account still uses the shipped 'admin' password.

    The PBKDF2 comparison is cached per username; every password change
    invalidates the cache via _invalidate_default_admin_cache().
    """
    cached = _DEFAULT_ADMIN_PW_CACHE.get(username)
    if cached is None:
        try:
            conn = db_connect()
            try:
                record = _user_store.get_by_username(conn, username)
            finally:
                conn.close()
            cached = bool(
                record is not None
                and _verify_password("admin", record["password_hash"]))
        except Exception:
            cached = False
        _DEFAULT_ADMIN_PW_CACHE[username] = cached
    return cached


def _invalidate_default_admin_cache() -> None:
    _DEFAULT_ADMIN_PW_CACHE.clear()


def _auth_throttle_blocked(key: str) -> bool:
    """True while a client has exhausted its authentication failures."""
    now = time.time()
    window = max(1, int(AUTH_FAILURE_WINDOW_SECONDS))
    limit = max(1, int(AUTH_FAILURE_LIMIT))
    failures = AUTH_FAILURES.get(key)
    if not failures:
        return False
    while failures and failures[0] <= now - window:
        failures.popleft()
    return len(failures) >= limit


def _auth_throttle_check(key: str) -> None:
    """Reject authentication attempts after repeated failures (brute-force guard)."""
    if _auth_throttle_blocked(key):
        raise HTTPException(429, "Too many failed attempts; try again later")


def _auth_failure_record(key: str) -> None:
    AUTH_FAILURES.setdefault(key, deque()).append(time.time())


def _migrate_users_enabled_column() -> None:
    """Add ``users.enabled`` to a pre-``enabled`` database (idempotent)."""
    try:
        conn = db_connect()
        try:
            from sqlalchemy import text as _text, inspect as _inspect
            cols = {c['name'] for c in _inspect(conn.engine).get_columns('users')}
            if 'enabled' not in cols:
                conn.connection.execute(_text(
                    "ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL "
                    "DEFAULT 1"))
                conn.connection.commit()
        finally:
            conn.close()
    except Exception:
        pass


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
    conn = db_connect()
    try:
        if _user_store.get_by_username(conn, "admin") is None:
            now = int(time.time())
            _user_store.create(
                conn, username="admin", password_hash=_hash_password("admin"),
                role="admin", now=now)
            _log("bootstrap admin account 'admin' created with the default "
                 "password — change it immediately", "startup")
    except Exception as exc:
        _log(f"default admin creation failed: {type(exc).__name__}", "startup")
    finally:
        conn.close()


def _get_current_user(request: Request) -> dict | None:
    """Resolve the authenticated user from a Bearer token or session cookie."""
    auth = request.headers.get("authorization", "")
    token = None
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    else:
        token = request.cookies.get("teledrive_session")
    if not token:
        return None
    digest = _session_token_digest(token)
    conn = db_connect()
    try:
        return _session_store.resolve(conn, digest, int(time.time()))
    except Exception:
        return None
    finally:
        conn.close()


_ROLE_ADMIN = frozenset({"admin"})
_ROLE_WRITE = frozenset({"admin", "operator"})
_ROLE_READ = frozenset({"admin", "operator", "viewer"})


def _required_roles(method: str, path: str) -> frozenset[str]:
    """Outer role gate for the API, before the permission map is applied.

    - admin-only surfaces (users, keys, credentials, physical GC, bucket
      quota, website publishing, config writes) require admin for every
      method. These are checked first: a GET is never a bypass.
    - other reads require a known role; the per-route permission map is
      the inner gate that decides whether a viewer/operator actually has
      that permission.
    - other writes require operator or admin; the map narrows further.

    ``web.permissions.is_admin_only`` is the single classification used
    both here and by the role->permission map, so the two cannot drift.
    """
    if is_admin_only(method, path):
        return _ROLE_ADMIN
    if str(method).upper() in READ_METHODS:
        return _ROLE_READ
    return _ROLE_WRITE


def _enforce_role_policy(request: Request, user: dict) -> None:
    roles = _required_roles(request.method, request.url.path)
    if user.get("role") not in roles:
        _log(f"denied: user={user.get('username')} role={user.get('role')} "
             f"{request.method} {request.url.path}", "auth")
        raise HTTPException(403, "Insufficient permissions for this action")


def _enforce_user_permission(request: Request, user: dict) -> None:
    """Inner gate: the route's permission must be granted by the role.

    HTML pages and public routes have no permission and pass through.
    API keys are handled earlier in require_auth with their own scope
    semantics and never reach this function.
    """
    registry = permission_registry()
    permission = registry.permission_for(request.method, request.url.path)
    if permission is None:
        return
    if not registry.role_allows(user.get("role"), permission):
        _log(f"denied: user={user.get('username')} role={user.get('role')} "
             f"permission={permission} {request.method} {request.url.path}",
             "auth")
        raise HTTPException(403, "Insufficient permissions for this action")


_permission_registry_cache: "PermissionRegistry | None" = None
_route_provider_installed = False


def permission_registry() -> "PermissionRegistry":
    """The per-endpoint permission catalog, built from the live route
    table (lazily: routes are declared while this module loads)."""
    global _permission_registry_cache, _route_provider_installed
    if _permission_registry_cache is None:
        from web.permissions import PermissionRegistry
        _permission_registry_cache = PermissionRegistry(app.routes)
        if not _route_provider_installed:
            # The API-key store lives in the teledrive package and cannot
            # import this module, so ``admin:*`` learns the live route table
            # through this one hook. Without it the wildcard only covered the
            # nine curated REST names, so an admin:* key was rejected on every
            # admin route -- a dead "full access" preset.
            from teledrive.api_keys import set_route_permissions_provider
            set_route_permissions_provider(
                lambda: [entry["name"]
                         for entry in permission_registry().catalog()])
            _route_provider_installed = True
    return _permission_registry_cache


def require_auth(request: Request) -> None:
    # Bearer API keys: every route is individually permissionable.
    # A key granted exactly this endpoint's permission passes; anything
    # else is 403. Keys are not users — no role policy applies.
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer td_live_"):
        token = auth[7:].strip()
        permission = permission_registry().permission_for(
            request.method, request.url.path)
        conn = db_connect()
        try:
            store = ApiKeyStore(conn)
            name = store.name_for_token(token)
            authorized = (permission is not None
                          and store.authorize(token, permission))
            # Delegation limit: a key may only mint/rotate/revoke within
            # its OWN effective permission set. Recorded here because the
            # management handlers must compare scopes, not just this route.
            scopes = store.scopes_for_token(token) if authorized else None
            expires_at = (store.expiry_for_token(token) if authorized
                          else None)
        finally:
            conn.close()
        if authorized:
            request.state.user = {
                "id": -1,
                "username": f"api-key:{name or 'unknown'}",
                "role": "api-key",
            }
            request.state.api_key_scopes = scopes or frozenset()
            # Delegation also covers LIFETIME: a key must not be able to
            # plant a descendant that outlives it, which would otherwise
            # make revocation of the parent meaningless.
            request.state.api_key_expires_at = expires_at
            return
        _log(f"denied: api-key {request.method} {request.url.path}",
             "auth")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key is invalid or lacks this endpoint's permission",
        )

    # Session token (httpOnly cookie) is the primary mechanism.
    user = _get_current_user(request)
    if user is not None:
        request.state.user = user
        _enforce_role_policy(request, user)
        _enforce_user_permission(request, user)
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="TeleDrive"'},
    )


def default_config() -> dict[str, Any]:
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
            "scratch_dir": "/data/tmp",
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
        "state": {"database_url": "sqlite:////data/state.db"},
        "logging": {"log_path": "/data/uploader.log", "level": "INFO"},
        "app": {"auto_run": False, "run_interval_minutes": 60},
    }


def ensure_config() -> None:
    _secure_mkdir(CONFIG_PATH.parent)
    if CONFIG_PATH.is_symlink():
        raise RuntimeError("Refusing to use a symlinked TeleDrive config file")
    _secure_mkdir(AUTH_DIR)
    _secure_mkdir(AUTH_DIR.parent / "sessions")
    # Scratch and source roots follow the settings (env/config), not
    # hardcoded /data and /uploads — non-Docker deployments broke here.
    _secure_mkdir(Path(STORAGE_SCRATCH_DIR))
    # Inline YAML parse: read_raw_config()/effective_config() both call
    # ensure_config() and would recurse.
    try:
        raw = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except OSError:
        raw = {}
    source_dir = str(((raw.get("upload") or {}).get("source_dir"))
                     or "/uploads")
    Path(source_dir).mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        _secure_write(CONFIG_PATH, yaml.safe_dump(default_config(), sort_keys=False))
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(CONFIG_PATH), flags)
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
    ensure_config()
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


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
        return SettingsStore(connection, load_master_key())
    except Exception:
        connection.close()
        return None


_SETTINGS_CACHE: dict[str, Any] = {"document": None, "generation": 0}


def read_raw_config() -> dict[str, Any]:
    """Authoritative settings: SQL document, else the bootstrap file.

    The SQL document is written on every save (and seeded from the file
    on first boot), so every process sharing the database agrees. If the
    row is missing or undecryptable (master-key rotation), the file is
    used and the next save re-seeds the database.
    """
    from teledrive.settings_store import SettingsStoreError
    file_document = _drop_retired_auth_settings(_read_config_file())
    store = _settings_store()
    if store is None:
        return file_document
    try:
        stored = store.load()
    except SettingsStoreError as exc:
        _log(f"settings: {exc}; falling back to config.yaml", "config")
        stored = None
    finally:
        store.db.close()
    if stored is None:
        # First boot (or an unusable row): seed SQL from the file so the
        # database becomes authoritative from now on.
        _seed_settings_document(file_document)
        return file_document
    document = _drop_retired_auth_settings(stored.document)
    _SETTINGS_CACHE["document"] = document
    _SETTINGS_CACHE["generation"] += 1
    return copy.deepcopy(document)


def _seed_settings_document(document: dict[str, Any]) -> None:
    store = _settings_store()
    if store is None:
        return
    try:
        store.save(document, by="bootstrap:config.yaml")
        _log("settings: seeded the SQL document from config.yaml", "config")
    except Exception as exc:  # noqa: BLE001 - never block startup
        _log(f"settings: seed failed: {type(exc).__name__}", "config")
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
                node[key] = REDACTED
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
            if value == REDACTED and key in previous:
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
    try:
        mtime = CONFIG_PATH.stat().st_mtime_ns
    except OSError:
        mtime = None
    if _CONFIG_CACHE["config"] is not None and _CONFIG_CACHE["mtime"] == mtime:
        return _CONFIG_CACHE["config"]
    ensure_config()
    document = read_raw_config()
    try:
        on_disk = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except OSError:
        on_disk = {}
    if document != on_disk:
        _secure_write(CONFIG_PATH,
                      yaml.safe_dump(document, sort_keys=False))
        try:
            mtime = CONFIG_PATH.stat().st_mtime_ns
        except OSError:
            mtime = None
    _CONFIG_CACHE["config"] = uploader.load_config(str(CONFIG_PATH))
    _CONFIG_CACHE["mtime"] = mtime
    return _CONFIG_CACHE["config"]


_CONFIG_CACHE: dict = {"mtime": None, "config": None}


def _persist_settings_document(document: dict[str, Any], *, by: str) -> None:
    """Write the SQL settings document; never fail the save on this."""
    store = _settings_store()
    if store is None:
        _log("settings: no database reachable; file-only save", "config")
        return
    try:
        store.save(document, by=by)
    except Exception as exc:  # noqa: BLE001 - the file write already succeeded
        _log(f"settings: SQL persist failed: {type(exc).__name__}", "config")
    finally:
        store.db.close()


def validate_and_write_config(raw: dict[str, Any], *,
                             by: str = "system") -> None:
    current = read_raw_config()
    merged = _restore_secrets(raw, current)
    tmp = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    _secure_write(tmp, yaml.safe_dump(merged, sort_keys=False))
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
    os.replace(tmp, CONFIG_PATH)
    # Persist the authoritative copy in SQL as well. The file stays the
    # bootstrap/recovery source and its mtime invalidates every process's
    # settings cache; the database is what a rebuild reads back.
    _persist_settings_document(merged, by=by)
    _CONFIG_CACHE["config"] = None
    _CONFIG_CACHE["mtime"] = None
    _reload_service_settings()
    # The administrator bootstrap belongs to startup only. Running it here
    # meant that a save pointing at a fresh database would silently create
    # admin/admin in it; the save path can no longer change the database, but
    # startup-only is the correct place for it regardless.
    # Core schema (including users.enabled) is brought current by the one
    # schema coordinator when the database engine is first built; there is
    # deliberately no DDL here any more.


def db_connect():
    cfg = effective_config()
    uploader.validate_storage_paths(cfg)
    return uploader.connect_db(cfg.db_path)


_SCHEDULER_IDLE_NOTICE: dict = {"message": None}


async def upload_job_scheduler_loop() -> None:
    """Opt-in durable job worker; SQL leases prevent duplicate claims.

    Disabled unless jobs.auto_run is enabled in config. Every cycle gets its
    own connection; failures retain job metadata for explicit operator retry.
    """
    while True:
        conn = None
        try:
            if not JOB_AUTO_RUN:
                await asyncio.sleep(10)
                continue
            root = _storage_job_root()
            conn = db_connect()
            queue = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
            scratch = Path(STORAGE_SCRATCH_DIR)
            _secure_mkdir(scratch)
            result = await queue.run_next(
                storage_transport(conn), allowed_root=root,
                scratch_directory=scratch, chunk_size=RECOMMENDED_CHUNK_SIZE,
            )
            _SCHEDULER_IDLE_NOTICE["message"] = None
            await asyncio.sleep(2 if result else 10)
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            # Expected while no Telegram session or source root is configured;
            # log the state change once instead of spamming every cycle.
            message = f"scheduler idle: {exc.detail}"
            if _SCHEDULER_IDLE_NOTICE["message"] != message:
                _log(message, "scheduler")
                _SCHEDULER_IDLE_NOTICE["message"] = message
            await asyncio.sleep(60)
        except Exception as exc:
            # Do not log source paths, credentials or Telegram tokens.
            _log("durable upload job scheduler: " + type(exc).__name__, "scheduler")
            await asyncio.sleep(20)
        finally:
            if conn is not None:
                conn.close()


async def lifecycle_scheduler_loop() -> None:
    """Apply bounded SQL-only lifecycle rules hourly, in this one process."""
    while True:
        connection = None
        try:
            from teledrive.s3.lifecycle import BucketLifecycleStore
            connection = db_connect()
            cat = BucketCatalog(ManifestStore(connection))
            BucketLifecycleStore(cat).apply_due(now=int(time.time()), limit=100)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log("lifecycle scheduler: " + type(exc).__name__, "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(3600)


async def tiering_scheduler_loop() -> None:
    """Apply enabled Intelligent-Tiering configurations hourly, bounded.

    The pass only updates this catalog's access gate; Telegram bytes are
    never moved or deleted. Disabled configurations are ignored.
    """
    while True:
        connection = None
        try:
            from teledrive.s3.tiering import TieringStore
            connection = db_connect()
            cat = BucketCatalog(ManifestStore(connection))
            TieringStore(cat).apply_due(now_ns=time.time_ns(), limit=1000)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log("tiering scheduler: " + type(exc).__name__, "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(3600)


async def notification_scheduler_loop() -> None:
    """Deliver due S3 webhook events with bounded exponential backoff."""
    while True:
        connection = None
        delivered = 0
        try:
            from teledrive.s3.credentials import load_master_key
            from teledrive.s3.notifications import NotificationDelivery
            connection = db_connect()
            cat = BucketCatalog(ManifestStore(connection))
            result = NotificationDelivery(
                cat, master_key=load_master_key(),
            ).deliver_due(now_ns=time.time_ns(), limit=50)
            delivered = result.delivered
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log("notification scheduler: " + type(exc).__name__, "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(30 if delivered else 60)


def folder_watch_scan() -> dict:
    """One auto-sync pass: enqueue new/changed files from the source root.

    Returns the enqueue_legacy_folder report (queued, already_queued,
    excluded, job_ids). Raises when the source root is not configured.
    """
    from teledrive.storage.legacy_bridge import enqueue_legacy_folder
    root = _storage_job_root()
    conn = db_connect()
    try:
        cfg = effective_config()
        source_root = Path(cfg.source_dir).resolve(strict=True)
        if not source_root.is_relative_to(root):
            raise RuntimeError("watch source is outside the job root")
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        report = enqueue_legacy_folder(
            cfg, manager, bucket=WATCH_BUCKET, prefix="",
            max_files=100, dry_run=False, lease_heartbeat=None,
        )
        conn.connection.commit()
        return {"queued": report.queued, "already_queued": report.already_queued,
                "excluded": report.excluded, "job_ids": list(report.job_ids)}
    finally:
        conn.close()


async def folder_watch_loop() -> None:
    """Optional folder auto-sync (jobs.watch in config/config.yaml).

    Every jobs.watch_interval_seconds the source root is scanned and
    new/changed files are enqueued as durable upload jobs targeting
    jobs.watch_bucket. Failures never crash the loop; the durable job
    scheduler performs the actual Telegram uploads.
    """
    while True:
        interval = max(5, int(WATCH_INTERVAL))
        try:
            if not WATCH_ENABLED:
                await asyncio.sleep(10)
                continue
            if not WATCH_BUCKET:
                _log("folder watch enabled but jobs.watch_bucket is not "
                     "configured; skipping scans", "watcher")
                await asyncio.sleep(60)
                continue
            report = folder_watch_scan()
            if report.get("queued"):
                _log(f"folder watch queued {report['queued']} file(s)",
                     "watcher")
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            # Source root not configured yet — expected on fresh installs.
            message = f"folder watch idle: {exc.detail}"
            if _SCHEDULER_IDLE_NOTICE.get("watch") != message:
                _log(message, "watcher")
                _SCHEDULER_IDLE_NOTICE["watch"] = message
            interval = max(interval, 60)
        except Exception as exc:
            _log("folder watch: " + type(exc).__name__, "watcher")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global upload_job_scheduler_task, lifecycle_scheduler_task
    global notification_scheduler_task
    global folder_watch_task
    global tiering_scheduler_task
    os.umask(0o077)
    # Settings first: ensure_config() mkdirs AUTH_DIR, which must already
    # reflect the config/env override (Docker only worked by accident
    # because the image pre-creates /data/auth).
    _reload_service_settings()
    ensure_config()
    # Migrate users table first: the bootstrap INSERT names `enabled`, so
    # a pre-`enabled` schema must be upgraded before the row is created.
    _migrate_users_enabled_column()
    _create_default_admin()
    # The schema coordinator runs inside db_connect()/_build_engine(); opening
    # the database here keeps a bad database loud at startup without a second
    # copy of the users.enabled ALTER.
    try:
        db_connect().close()
    except Exception:
        pass
    # Set up rotating compressed log file.
    try:
        cfg = read_raw_config()
        log_path = (cfg.get("logging") or {}).get("log_path", "/data/teledrive.log")
        log_dir = os.path.dirname(log_path) or "/data"
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingCompressedFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5,
            encoding="utf-8", delay=True
        )
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(user)s] [%(source)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        class _SourceFilter(logging.Filter):
            def filter(self, record):
                if not hasattr(record, "source"):
                    record.source = "app"
                return True
        file_handler.addFilter(_SourceFilter())
        global _FILE_LOG_HANDLER
        _FILE_LOG_HANDLER = file_handler
        logging.getLogger("teledrive").addHandler(file_handler)
        logging.getLogger("teledrive").setLevel(logging.INFO)
    except Exception as exc:
        _log(f"could not set up file logging: {exc}", "startup")
    transport_mode()  # Enforce Telethon USER mode at startup; Bot mode no longer exists.
    if DB_EXTRA_PACKAGES:
        from teledrive.settings import install_db_extra_packages
        install_db_extra_packages(DB_EXTRA_PACKAGES, "/data/site-packages")
    # Permit a new unconfigured installation to serve health/configuration;
    # writes fail closed until a USER session connects.
    try:
        await mtproto_storage_runtime.start()
    except Exception as exc:
        _log(_scrub_text(f"user session warning: {exc}"), "storage")
    global _main_event_loop
    _main_event_loop = asyncio.get_running_loop()
    try:
        conn = db_connect()
        # Notification/logging tables are created here, outside any request
        # transaction: the mutation hot path only INSERTs (creating tables
        # there deadlocks SQLite against the caller's write lock).
        from teledrive.s3.notifications import ensure_notification_tables
        ensure_notification_tables(conn.engine)
        # Object annotations (Phase O2) are created at startup for the same
        # reason: their store constructor must never issue DDL while a
        # mutation transaction holds SQLite's write lock.
        from teledrive.s3.annotations import ensure_annotation_tables
        ensure_annotation_tables(conn.engine)
        from teledrive.s3.tiering import ensure_tiering_tables
        ensure_tiering_tables(conn.engine)
        # S3 Metadata journal (Phase O3): same DDL rule as notifications —
        # created at startup, never inside a mutation transaction.
        from teledrive.s3.metadata_journal import ensure_metadata_tables
        ensure_metadata_tables(conn.engine)
        conn.close()
    except Exception as exc:
        _log(_scrub_text(f"startup database warning: {exc}"), "startup")
    upload_job_scheduler_task = asyncio.create_task(upload_job_scheduler_loop())
    lifecycle_scheduler_task = asyncio.create_task(lifecycle_scheduler_loop())
    tiering_scheduler_task = asyncio.create_task(tiering_scheduler_loop())
    notification_scheduler_task = asyncio.create_task(notification_scheduler_loop())
    folder_watch_task = asyncio.create_task(folder_watch_loop())
    session_health_task = asyncio.create_task(telegram_session_health_loop())
    yield
    if upload_job_scheduler_task:
        upload_job_scheduler_task.cancel()
        await asyncio.gather(upload_job_scheduler_task, return_exceptions=True)
    if lifecycle_scheduler_task:
        lifecycle_scheduler_task.cancel()
        await asyncio.gather(lifecycle_scheduler_task, return_exceptions=True)
    if tiering_scheduler_task:
        tiering_scheduler_task.cancel()
        await asyncio.gather(tiering_scheduler_task, return_exceptions=True)
    if notification_scheduler_task:
        notification_scheduler_task.cancel()
        await asyncio.gather(notification_scheduler_task, return_exceptions=True)
    if folder_watch_task:
        folder_watch_task.cancel()
        await asyncio.gather(folder_watch_task, return_exceptions=True)
    if session_health_task:
        session_health_task.cancel()
        await asyncio.gather(session_health_task, return_exceptions=True)
    await mtproto_storage_runtime.stop()


app = FastAPI(
    title="TeleDrive API",
    version="2.1.0",
    description=(
        "Authenticated management API for Telegram upload accounts, queue/history, "
        "application configuration, execution and Telegram login challenges. "
        "Authenticate via POST /api/auth/login (session token + httpOnly cookie); "
        "role-based access control applies (admin/operator/viewer). "
        "Set X-TeleDrive-CSRF: 1 for state-changing requests. "
        "Protect access with HTTPS or a trusted VPN."
    ),
    openapi_tags=[
        {"name": "System", "description": "Service state and health"},
        {"name": "Configuration", "description": "Settings, Telegram accounts, and database URL"},
        {"name": "Uploads", "description": "Queue/history and uploader lifecycle"},
        {"name": "Authentication", "description": "Telegram code and two-factor password handoff"},
        {"name": "API keys", "description": "Root-admin API key creation, rotation and revocation"},
        {"name": "Object catalog", "description": "Bearer-scoped bucket and object metadata"},
    ],
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
@app.middleware("http")
async def _trusted_host_middleware(request: Request, call_next):
    # ALLOWED_HOSTS reloads from config.yaml at runtime; resolve it per
    # request instead of capturing the import-time default.
    host = (request.headers.get("host") or "").split(":")[0]
    if host and host not in ALLOWED_HOSTS:
        return JSONResponse(status_code=400, content={"detail": "Invalid host header"})
    return await call_next(request)


_SHARE_TOKEN_PATH = re.compile(
    r"(?P<prefix>/share/|/api/v1/admin/storage/shares/)"
    r"(?P<token>[A-Za-z0-9_-]{16,64})(?P<rest>/?$)")


def _redact_log_path(path: str) -> str:
    """Hide share tokens from the request log.

    The token in ``/share/<token>`` is the whole credential: anything that
    can read it can download the object anonymously. Logging the path (as
    the audit middleware did) wrote a live credential into a buffer that
    ``viewer`` can read via /api/logs, so the token segment is masked.
    """
    return _SHARE_TOKEN_PATH.sub(
        lambda m: f"{m.group('prefix')}***{m.group('rest')}", path)


@app.middleware("http")
async def _audit_log_middleware(request: Request, call_next):
    start = time.time()
    path = _redact_log_path(request.url.path)
    method = request.method
    # Skip noisy health checks and static assets.
    if path not in {"/api/health", "/__health"} and not path.startswith("/static/"):
        client = request.client.host if request.client else "-"
        user = _extract_user(request)
        _log(f"{method} {path} from {client}", "http", user=user)
    try:
        response = await call_next(request)
    except Exception as exc:
        _log(f"{method} {path} -> EXCEPTION: {type(exc).__name__}: {exc}", "http")
        raise
    elapsed = (time.time() - start) * 1000
    if path not in {"/api/health", "/__health"} and not path.startswith("/static/"):
        _log(f"{method} {path} -> {response.status_code} ({elapsed:.0f}ms)", "http")
    return response


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    binary_upload = (request.method == "PUT" and (
        re.fullmatch(r"/api/v1/buckets/[A-Za-z0-9.-]+/content", request.url.path)
        or re.fullmatch(
            r"/api/v1/admin/storage/buckets/[A-Za-z0-9.-]+/content",
            request.url.path)))
    if request.method in {"POST", "PUT", "PATCH"} and not binary_upload:
        # Size-bound browser JSON requests. Cache on the ORIGINAL request:
        # Starlette's call_next() replays _CachedRequest's cached body.
        # Constructing a new Request here silently discards POST/PUT payloads.
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > MAX_REQUEST_BYTES:
                    return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        request._body = bytes(body)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path in {"/docs", "/redoc"}:
        # FastAPI's official interactive documentation assets are served from the CDN.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "object-src 'none'; connect-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
        )
    elif request.url.path == "/site" or request.url.path.startswith("/site/"):
        # Hosted website content shares the app origin. Sandboxing it into
        # an opaque origin plus default-src 'none' prevents it from reading
        # app cookies/API responses or loading any subresource.
        response.headers["Content-Security-Policy"] = (
            "sandbox; default-src 'none'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'; object-src 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; object-src 'none'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        )
    if (request.url.path in {"/", "/docs", "/redoc", "/openapi.json"}
            or request.url.path.startswith("/api/")
            or request.url.path.startswith("/site/")):
        response.headers["Cache-Control"] = "no-store"
    return response


class StartRequest(BaseModel):
    mode: Literal["run-once", "scan-only", "connect"] = Field(
        default="run-once", description="Run upload batch, scan only, or connect accounts."
    )


class TelegramAuthRequest(BaseModel):
    account: str = Field(min_length=1, max_length=64, examples=["primary"])
    kind: Literal["code", "password"]
    value: str = Field(min_length=1, max_length=1024, description="Telegram code or 2FA password; never logged.")


class OKResponse(BaseModel):
    ok: bool = True


class KeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=20)
    expires_at: int | None = Field(default=None, description="Optional Unix expiry time")


class GCToggleRequest(BaseModel):
    enabled: bool
    confirm: str | None = Field(
        default=None, description='Typed confirmation "PHYSICAL-GC" to enable')
    grace_seconds: int | None = Field(
        default=None, ge=3600, le=90 * 86400,
        description="Grace period for queued physical collections")


class GCCollectRequest(BaseModel):
    scope: str = Field(default="revoked", description="revoked | deleted")
    dry_run: bool = Field(default=True)
    min_age_seconds: int = Field(default=86400, ge=3600, le=90 * 86400)
    limit: int = Field(default=50, ge=1, le=1000)
    confirm: str | None = Field(
        default=None, description='Typed confirmation "DELETE-RETAINED" to execute')


# A new S3 credential with no explicit permission list gets READ-ONLY
# object access. It used to default to every known permission, so an omitted
# field silently produced a credential that could delete buckets and rewrite
# bucket policy -- the opposite of least privilege for the common case.
DEFAULT_NEW_CREDENTIAL_PERMISSIONS = [
    "s3:ListAllMyBuckets", "s3:ListBucket", "s3:GetBucketLocation",
    "s3:GetObject", "s3:GetObjectAttributes",
]


class S3KeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(
        default_factory=lambda: list(DEFAULT_NEW_CREDENTIAL_PERMISSIONS))
    expires_at: int | None = None


class S3CompletionRecoveryRequest(BaseModel):
    execute: bool = False
    min_age_seconds: int = Field(default=3600, ge=60, le=30 * 86400)


class PendingUploadRecoveryRequest(BaseModel):
    execute: bool = False
    min_age_seconds: int = Field(default=3600, ge=60, le=30 * 86400)


class StorageUploadJobRequest(BaseModel):
    bucket: str = Field(min_length=3, max_length=63)
    key: str = Field(min_length=1, max_length=1024)
    source_path: str = Field(min_length=1, max_length=4096)


class LegacyFolderImportRequest(BaseModel):
    bucket: str = Field(min_length=3, max_length=63)
    prefix: str = Field(default="", max_length=512)
    max_files: int = Field(default=100, ge=1, le=1000)
    execute: bool = False


class VersionRestoreRequest(BaseModel):
    bucket: str = Field(min_length=3, max_length=63)
    key: str = Field(min_length=1, max_length=1024)
    expected_generation: int | None = Field(default=None, ge=0)


class VersionIndexRequest(BaseModel):
    execute: bool = False
    limit: int = Field(default=100, ge=1, le=1000)


class BucketCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=63)

# Usernames are login identifiers AND appear in log lines. Restricting them
# to an ASCII subset with no whitespace/newlines prevents a name like
# "admin\n[2026-01-01] [system] ..." from forging a log record, and prevents
# homograph confusion with the reserved bootstrap account.
_USERNAME_RE = re.compile(r"[A-Za-z0-9._-]+\Z")


def _validate_username(username: str) -> str:
    if (not isinstance(username, str) or not 1 <= len(username) <= 64
            or not _USERNAME_RE.fullmatch(username)
            or username.strip() != username):
        raise HTTPException(
            400,
            "username must be 1-64 characters of letters, digits, dot, "
            "dash or underscore")
    if username.casefold() == "admin" and username != "admin":
        raise HTTPException(
            400, "the name 'admin' is reserved for the bootstrap account")
    return username


def _assert_not_last_admin(conn, current_role: str,
                            new_role: str | None = None) -> None:
    """Refuse role changes or deletion that would remove the last admin."""
    if current_role != "admin" or new_role == "admin":
        return
    if _user_store.count_enabled_admins(conn) <= 1:
        raise HTTPException(409, "cannot remove the last admin")


_main_event_loop: asyncio.AbstractEventLoop | None = None


async def _reload_storage_runtime() -> None:
    """Restart the USER MTProto runtime on the main event loop.

    New sessions, a changed routing strategy or a different write channel
    only take effect after a restart; the Telethon clients are bound to
    the running loop, so this must run there, never in a worker thread.
    """
    try:
        await mtproto_storage_runtime.stop()
    except Exception as exc:
        _log("runtime reload stop: " + type(exc).__name__, "storage")
    try:
        await mtproto_storage_runtime.start()
        _log("storage runtime reloaded", "storage")
    except Exception as exc:
        _log(_scrub_text(f"user session warning: {exc}"), "storage")


def _schedule_storage_runtime_reload() -> None:
    """Thread-safe handoff of a runtime reload to the main event loop."""
    if _main_event_loop is None or _main_event_loop.is_closed():
        return
    asyncio.run_coroutine_threadsafe(
        _reload_storage_runtime(), _main_event_loop)


def storage_transport(conn):
    """Build the live USER-MTProto transport for REST/S3/local-job payload I/O.

    A preauthorized Telethon user session must be connected. There is no Bot
    API transport; the unified runtime is Telethon USER MTProto only.
    """
    try:
        transport_mode()
        mtproto_storage_runtime.require()
        return UnifiedUserTransport(
            mtproto_storage_runtime, UserSendJournal(conn),
        )
    except RuntimeError:
        raise HTTPException(503, "Authorized Telethon USER session is required") from None


def _byte_range(value: str | None, size: int) -> tuple[int, int, bool]:
    """HTTP Range with inclusive input -> half-open output; 416 on invalid input."""
    if value is None:
        return 0, size, False
    # Bound the digit count BEFORE int(): CPython refuses to convert an
    # integer literal longer than ~4300 digits, and the ValueError escaped as
    # a 500. A range header that long can only be nonsense, so it is a 416.
    match = re.fullmatch(r"bytes=(\d{0,20})-(\d{0,20})", value.strip())
    if match is None or not (match.group(1) or match.group(2)):
        raise HTTPException(416, "Unsupported byte range",
                            headers={"Content-Range": f"bytes */{size}"})
    first, last = match.groups()
    if size == 0:
        raise HTTPException(416, "Empty object has no satisfiable range",
                            headers={"Content-Range": "bytes */0"})
    if not first:
        count = int(last)
        if count <= 0:
            raise HTTPException(416, "Invalid suffix range", headers={"Content-Range": f"bytes */{size}"})
        start, end = max(0, size - count), size
    else:
        start = int(first)
        end = min(size, int(last) + 1) if last else size
        if start >= size or end <= start:
            raise HTTPException(416, "Unsatisfiable range", headers={"Content-Range": f"bytes */{size}"})
    return start, end, True



def require_api_scope(required: str):
    """HTTP bearer authorization, independent of the browser session/CSRF flow."""
    def check(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth)) -> None:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, "API Bearer token required",
                                headers={"WWW-Authenticate": "Bearer"})
        conn = db_connect()
        try:
            authorized = ApiKeyStore(conn).authorize(credentials.credentials, required)
        finally:
            conn.close()
        if not authorized:
            raise HTTPException(403, "API token is invalid, expired or lacks permission")
    return check




app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/openapi.json", tags=["System"], include_in_schema=False)
def openapi_schema(_: None = Depends(require_auth)):
    return JSONResponse(app.openapi())


@app.get("/docs", tags=["System"], include_in_schema=False)
def swagger_docs(_: None = Depends(require_auth)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="TeleDrive API · Swagger UI")


@app.get("/redoc", tags=["System"], include_in_schema=False)
def redoc_docs(_: None = Depends(require_auth)):
    return get_redoc_html(openapi_url="/openapi.json", title="TeleDrive API · ReDoc")


@app.post("/api/v1/auth/login", tags=["Authentication"], summary="Login with username and password")
@app.post("/api/auth/login", tags=["Authentication"], include_in_schema=False)
def login(payload: dict, request: Request):
    _same_origin(request)
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    if not username or not password:
        raise HTTPException(400, "username and password are required")
    client = request.client.host if request.client else "-"
    throttle_key = f"login:{username}:{client}"
    _auth_throttle_check(throttle_key)
    conn = db_connect()
    try:
        record = _user_store.get_by_username(conn, username)
    finally:
        conn.close()
    # Always run a hash comparison so response timing never reveals
    # whether the username exists.
    stored_hash = (record["password_hash"] if record is not None
                   else _dummy_password_hash())
    valid = _verify_password(password, stored_hash)
    if record is None or not valid:
        _auth_failure_record(throttle_key)
        raise HTTPException(401, "Invalid credentials")
    if not record["enabled"]:
        _auth_failure_record(throttle_key)
        raise HTTPException(403, "Account is disabled")
    if not stored_hash.startswith("pbkdf2_sha256$"):
        # Transparently upgrade legacy password hashes on successful login.
        conn = db_connect()
        try:
            _user_store.set_password(
                conn, record["id"], _hash_password(password), int(time.time()))
        finally:
            conn.close()
    AUTH_FAILURES.pop(throttle_key, None)
    token = "td_sess_" + secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + 7 * 86400  # 7 days
    conn = db_connect()
    try:
        # Same transaction: sessions.create commits once, after both writes.
        _user_store.set_last_login(conn, record["id"], now, commit=False)
        _session_store.create(
            conn, token=_session_token_digest(token), user_id=record["id"],
            created_at=now, expires_at=expires)
    finally:
        conn.close()
    _log(f"login: username={username}", "auth")
    resp = JSONResponse(content={"token": token, "user": {"id": record["id"], "username": record["username"], "role": record["role"]},
                                  "expires_at": expires})
    # Behind a TLS-terminating reverse proxy the cookie must still be
    # Secure when the client connection is https (X-Forwarded-Proto).
    forwarded_https = (TRUSTED_PROXY and request.headers.get(
        "x-forwarded-proto", "").lower() == "https")
    resp.set_cookie(key="teledrive_session", value=token, httponly=True,
                    max_age=7 * 86400, samesite="lax", path="/",
                    secure=bool(SSL_CERTFILE) or forwarded_https)
    return resp


@app.post("/api/v1/auth/logout", tags=["Authentication"], summary="Logout and revoke session")
@app.post("/api/auth/logout", tags=["Authentication"], include_in_schema=False)
def logout(request: Request):
    _same_origin(request)
    user = _get_current_user(request)
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    else:
        token = request.cookies.get("teledrive_session")
    if token:
        # Revoke the server-side session for BOTH Bearer and cookie clients.
        conn = db_connect()
        try:
            _session_store.delete_token(conn, _session_token_digest(token))
        finally:
            conn.close()
    _log(f"logout: user={user['username'] if user else 'unknown'}", "auth")
    resp = JSONResponse(content={"ok": True})
    resp.delete_cookie(key="teledrive_session", path="/")
    return resp


@app.get("/api/v1/auth/me", tags=["Authentication"], summary="Get current user")
@app.get("/api/auth/me", tags=["Authentication"], include_in_schema=False)
def me(request: Request):
    user = _get_current_user(request)
    if user is None:
        raise HTTPException(401, "Not authenticated")
    return {
        "user": user,
        # The WebUI forces a password change screen while the hardcoded
        # first-boot admin/admin credential is still in use.
        "must_change_password": bool(
            user["username"] == "admin"
            and _default_admin_password_in_use("admin")),
    }


def _serve_static_page(page_name: str, request: Request):
    """Serve a static UI page; unauthenticated visitors are sent to /login."""
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=302)
    if page_name == "dashboard":
        page_name = "index"
    candidate = STATIC_DIR / f"{page_name}.html"
    if candidate.is_file():
        return FileResponse(candidate)
    raise HTTPException(404, "Page not found")


# --- Nested UI routes (user-facing information architecture) ---------------
# /settings/{general,telegram} and /s3/{credentials,buckets}; the flat
# legacy paths redirect so old bookmarks keep working.


@app.get("/settings/general", include_in_schema=False)
def settings_general_page(request: Request):
    return _serve_static_page("settings", request)


@app.get("/settings/telegram", include_in_schema=False)
def settings_telegram_page(request: Request):
    return _serve_static_page("telegram", request)


@app.get("/s3/credentials", include_in_schema=False)
def s3_credentials_page(request: Request):
    return _serve_static_page("credentials", request)


@app.get("/s3/buckets", include_in_schema=False)
def s3_buckets_page(request: Request):
    return _serve_static_page("buckets", request)


@app.get("/settings", include_in_schema=False)
def settings_legacy_redirect():
    return RedirectResponse(url="/settings/general", status_code=302)


@app.get("/storage", include_in_schema=False)
def storage_legacy_redirect():
    return RedirectResponse(url="/settings/telegram", status_code=302)


@app.get("/s3", include_in_schema=False)
def s3_legacy_redirect():
    return RedirectResponse(url="/s3/buckets", status_code=302)


@app.get("/", include_in_schema=False)
def index(request: Request):
    return _serve_static_page("index", request)


@app.get("/{page_name}.html", include_in_schema=False)
def page_html(page_name: str, request: Request):
    return _serve_static_page(page_name, request)


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(STATIC_DIR / "login.html")


# --- public certificate distribution -----------------------------------
# A self-signed deployment needs a way for clients (browsers, S3 Browser,
# rclone, Windows trust store) to obtain the certificate they must trust.
# /server.cer is DER (what Windows imports), /server.crt is the PEM chain.
# Only certificate blocks are emitted — a combined .pem's private key is
# stripped by web.certs. Both are unauthenticated: a certificate is public
# data, and requiring a login over the very TLS connection being
# bootstrapped would be a deadlock.
#
# Declared BEFORE the /{page_name} catch-all, which would otherwise shadow
# these paths and redirect them to /login.


@app.get("/server.cer", include_in_schema=False)
@app.get("/api/v1/certificate.cer", tags=["System"],
         summary="Public TLS certificate (DER/.cer, unauthenticated)")
def public_certificate_der():
    from web import certs
    try:
        payload = certs.public_cert_der()
    except certs.CertError as exc:
        raise HTTPException(404, str(exc)) from exc
    return Response(content=payload,
                    media_type="application/pkix-cert",
                    headers={"Content-Disposition":
                             'attachment; filename="teledrive.cer"'})


@app.get("/server.crt", include_in_schema=False)
@app.get("/api/v1/certificate.pem", tags=["System"],
         summary="Public TLS certificate (PEM chain, unauthenticated)")
def public_certificate_pem():
    from web import certs
    try:
        payload = certs.public_cert_pem()
    except certs.CertError as exc:
        raise HTTPException(404, str(exc)) from exc
    return Response(content=payload,
                    media_type="application/x-pem-file",
                    headers={"Content-Disposition":
                             'attachment; filename="teledrive.crt"'})

@app.get("/{page_name}", include_in_schema=False)
def page_route(page_name: str, request: Request):
    if page_name in {"api", "static", "openapi.json", "docs", "redoc",
                     "__health", "favicon.ico"}:
        raise HTTPException(404, "Not found")
    return _serve_static_page(page_name, request)


@app.get("/api/v1/config", tags=["Configuration"], summary="Read configuration (secrets redacted)")
@app.get("/api/config", tags=["Configuration"], include_in_schema=False)
def get_config(_: None = Depends(require_auth)):
    return _redacted_config(read_raw_config())


# Settings that can only be changed by editing config.yaml on disk, as a
# deployment decision made by someone with filesystem access. Exposing them
# over HTTP is a takeover primitive, not a feature:
#
#   state.database_url   redirects the whole application at a fresh database,
#                        after which the startup bootstrap creates
#                        admin/admin there -- verified end to end: a session
#                        save, then /api/v1/auth/login with admin/admin on the
#                        new DB. It also orphans the real data.
#   state.db_extra_packages
#                        is pip-installed at every boot (settings.py), so it
#                        is arbitrary code execution that survives restarts.
_FILE_ONLY_STATE_KEYS = ("database_url", "db_path", "db_extra_packages")


def _reject_file_only_settings(payload: dict[str, Any]) -> None:
    submitted = (payload or {}).get("state") or {}
    if not isinstance(submitted, dict):
        raise HTTPException(400, "state must be an object")
    current = (read_raw_config() or {}).get("state") or {}
    for key in _FILE_ONLY_STATE_KEYS:
        if key not in submitted:
            continue
        if submitted[key] == REDACTED:
            continue
        if submitted[key] != current.get(key):
            raise HTTPException(
                400,
                f"state.{key} cannot be changed from the API; edit "
                f"config.yaml on the server instead")


@app.put("/api/v1/config", tags=["Configuration"], response_model=OKResponse, summary="Validate and save configuration")
@app.put("/api/config", tags=["Configuration"], include_in_schema=False)
def put_config(request: Request, payload: dict[str, Any] = Body(...), _: None = Depends(require_auth)):
    _same_origin(request)
    # A configuration write can change allowed hosts, filesystem roots and
    # the job watcher, so it is a human/operator decision -- never something
    # a stored API key performs on its holder's behalf.
    actor = _require_interactive_session(request, "change the deployment "
                                                   "configuration")
    _log(f"settings save requested by {actor}", "config", user=actor)
    _reject_file_only_settings(payload)
    try:
        validate_and_write_config(payload, by=actor)
        _log("settings saved successfully", "config", user=actor)
        _audit(request, "config.write",
               detail={"sections": sorted(k for k in payload if k != "state")})
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(400, _scrub_text(str(exc))) from exc
    except Exception as exc:
        raise HTTPException(400, "Configuration/database validation failed") from exc
    return {"ok": True}


@app.get("/api/v1/admin/keys", tags=["API keys"], summary="List API key metadata; never returns secrets")
def list_api_keys(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        return {"keys": ApiKeyStore(conn).list()}
    finally:
        conn.close()


@app.get("/api/v1/admin/keys/permissions", tags=["API keys"],
         summary="The per-endpoint permission catalog for key issuance")
def list_api_key_permissions(_: None = Depends(require_auth)):
    """EVERY API route is individually permissionable — the catalog is
    derived from the live route table, so it can never drift. The nine
    REST bearer endpoints keep their curated short names; every other
    route carries a canonical "method:path" permission. Legacy grouped
    scopes remain valid as aliases (existing keys keep working)."""
    from teledrive.api_keys import (ENDPOINT_PERMISSIONS,
                                     LEGACY_SCOPE_EXPANSION)
    registry = permission_registry()
    routes = registry.catalog()
    curated = set(ENDPOINT_PERMISSIONS)
    for entry in routes:
        if entry["name"] in curated:
            entry["summary"] = ENDPOINT_PERMISSIONS[entry["name"]]
    return {
        "routes": routes,
        "groups": registry.groups(),
        "legacy_scopes": [
            {"name": name, "expands_to": sorted(expansion)}
            for name, expansion in sorted(LEGACY_SCOPE_EXPANSION.items())],
    }


def _delegation_limit(request: Request) -> frozenset[str] | None:
    """The permission ceiling of the CALLING principal.

    ``None`` means unrestricted (an authenticated session user, whose
    authority comes from the role policy). A bearer API key returns its
    own effective permission set: it may never create, rotate or revoke
    authority it does not itself hold — otherwise a key scoped to just
    this endpoint could mint or steal a fully privileged key.
    """
    scopes = getattr(request.state, "api_key_scopes", None)
    if scopes is None:
        return None
    return frozenset(scopes)


def _require_within_delegation(request: Request,
                               requested: frozenset[str],
                               what: str) -> None:
    limit = _delegation_limit(request)
    if limit is None:
        return
    excess = requested - limit
    if excess:
        _log(f"denied: api-key attempted {what} beyond its own scopes "
             f"({len(excess)} excess)", "auth")
        raise HTTPException(
            403,
            "An API key can only delegate permissions it already holds",
        )


def _require_within_lifetime(request: Request, expires_at: int | None) -> None:
    """A child key may not outlive the key that minted it.

    Without this a short-lived key scoped to the mint route can create a
    permanent descendant, so revoking the parent would not end the
    authority it delegated. Session users are unrestricted (``None``).
    """
    parent = getattr(request.state, "api_key_expires_at", None)
    if parent is None:
        return
    if expires_at is None or int(expires_at) > int(parent):
        _log("denied: api-key attempted to mint a key outliving itself",
             "auth")
        raise HTTPException(
            403,
            "An API key can only delegate authority that expires no later "
            "than its own",
        )


@app.post("/api/v1/admin/keys", tags=["API keys"], status_code=201, summary="Issue a scoped API key (secret returned once)")
def issue_api_key(request: Request, payload: KeyCreateRequest, _: None = Depends(require_auth)):
    _same_origin(request)
    from teledrive.api_keys import expand_scopes
    # A key may only mint a key whose effective permissions are a subset
    # of its own. The route permission is checked by require_auth; this
    # stops privilege escalation through minting.
    _require_within_delegation(
        request, expand_scopes(payload.scopes), "key creation")
    _require_within_lifetime(request, payload.expires_at)
    conn = db_connect()
    try:
        try:
            # Keys may carry ANY single-route permission from the live
            # registry plus the legacy grouped scopes.
            route_permissions = frozenset(
                entry["name"] for entry in permission_registry().catalog())
            key = ApiKeyStore(conn).create(
                payload.name, payload.scopes, expires_at=payload.expires_at,
                extra_allowed=route_permissions)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        # Log AFTER the row exists, with the actor and the new key's id:
        # logging before the store call made a rejected request read as a
        # successful issuance, and "system" made the entry unattributable.
        _audit(request, "api_key.issue", target=key.id,
               detail={"prefix": key.prefix, "scopes": list(key.scopes),
                       "expires_at": payload.expires_at})
        _log(f"issue api key: id={key.id} prefix={key.prefix} "
             f"scopes={key.scopes} expires_at={payload.expires_at}",
             "api-keys",
             user=(getattr(request.state, "user", None) or {}).get(
                 "username") or "system")
        return {"id": key.id, "token": key.value, "prefix": key.prefix,
                "scopes": key.scopes, "expires_at": payload.expires_at}
    finally:
        conn.close()


@app.delete("/api/v1/admin/keys/{identifier}", tags=["API keys"], summary="Revoke an API key immediately")
def revoke_api_key(identifier: str, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        target_scopes = ApiKeyStore(conn).scopes_for_identifier(identifier)
        # A key may not revoke authority above its own (that is a
        # denial-of-service lever against a more privileged key).
        _require_within_delegation(
            request, frozenset(target_scopes or ()), "key revocation")
        _log(f"revoke api key: id={identifier}", "api-keys")
        if not ApiKeyStore(conn).revoke(identifier):
            raise HTTPException(404, "API key not found or already revoked")
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/v1/admin/keys/{identifier}/rotate", tags=["API keys"], summary="Rotate an API key; secret returned once")
def rotate_api_key(identifier: str, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        # Rotation returns the NEW SECRET, so rotating a key with more
        # authority than the caller would hand over that authority.
        target_scopes = ApiKeyStore(conn).scopes_for_identifier(identifier)
        _require_within_delegation(
            request, frozenset(target_scopes or ()), "key rotation")
        try:
            key = ApiKeyStore(conn).rotate(identifier)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        _audit(request, "api_key.rotate", target=key.id,
               detail={"replaced": str(identifier)})
        _log(f"rotate api key: old={identifier} new={key.id} "
             f"prefix={key.prefix}", "api-keys",
             user=(getattr(request.state, "user", None) or {}).get(
                 "username") or "system")
        return {"id": key.id, "token": key.value, "prefix": key.prefix,
                "scopes": key.scopes}
    finally:
        conn.close()


@app.put("/api/v1/admin/users/{user_id}/password", tags=["Users"],
        summary="Change a user's password")
def change_user_password(user_id: int, request: Request, payload: dict,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    new_pw = str(payload.get("password", ""))
    if len(new_pw) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    pw_hash = _hash_password(new_pw)
    now = int(time.time())
    conn = db_connect()
    try:
        if _user_store.get_by_id(conn, user_id) is None:
            raise HTTPException(404, "user not found")
        # Revoke all sessions for this user (force re-login) in the same
        # transaction as the password change.
        _user_store.set_password(conn, user_id, pw_hash, now, commit=False)
        _session_store.delete_for_user(conn, user_id, commit=False)
        conn.commit()
        _invalidate_default_admin_cache()
        _log(f"change password: user_id={user_id}", "users")
    finally:
        conn.close()
    return {"ok": True}


@app.put("/api/v1/admin/users/{user_id}/role", tags=["Users"],
        summary="Change a user's role")
def change_user_role(user_id: int, request: Request, payload: dict,
                     _: None = Depends(require_auth)):
    _same_origin(request)
    role = str(payload.get("role", "")).strip()
    if role not in ("admin", "operator", "viewer"):
        raise HTTPException(400, "role must be admin, operator or viewer")
    conn = db_connect()
    try:
        record = _user_store.get_by_id(conn, user_id)
        if record is None:
            raise HTTPException(404, "user not found")
        _assert_not_last_admin(conn, record["role"], role)
        _user_store.set_role(conn, user_id, role, int(time.time()))
        _log(f"change role: user_id={user_id} {record['role']} -> {role}", "users")
    finally:
        conn.close()
    return {"ok": True}



# --- Detailed user management & role control --------------------------------

@app.get("/api/v1/admin/users/{user_id}", tags=["Users"],
         summary="Get user detail")
def get_user_detail(user_id: int, _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        record = _user_store.get_by_id(conn, user_id)
        if record is None:
            raise HTTPException(404, "user not found")
        sessions = _session_store.list_for_user(conn, user_id)
        return {
            "id": record["id"], "username": record["username"],
            "role": record["role"], "enabled": record["enabled"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "last_login": record["last_login"],
            "sessions": [{"token_prefix": s["token"][:12] + "...",
                          "created_at": s["created_at"],
                          "expires_at": s["expires_at"]} for s in sessions],
        }
    finally:
        conn.close()


@app.put("/api/v1/admin/users/{user_id}", tags=["Users"],
         summary="Update user (username, role, enabled)")
def update_user(user_id: int, request: Request, payload: dict,
                _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        record = _user_store.get_by_id(conn, user_id)
        if record is None:
            raise HTTPException(404, "user not found")

        username = payload.get("username")
        role = payload.get("role")
        enabled = payload.get("enabled")

        # Prevent removing the last admin. Disabling counts as removing: the
        # guard used to fire only on a role change, so an admin could disable
        # the last enabled admin (often themselves) and lock everyone out
        # with no recovery path, because the admin row still existed.
        if role is not None:
            _assert_not_last_admin(conn, record["role"], role)
        if enabled is False and record["role"] == "admin":
            _assert_not_last_admin(conn, record["role"])

        if username is not None:
            _validate_username(username)
            # Renaming the bootstrap account would make the next startup
            # re-create admin/admin, which the review proved by doing it.
            if record["username"] == "admin" and username != "admin":
                raise HTTPException(
                    400, "the bootstrap account 'admin' cannot be renamed")
            try:
                _user_store.rename(
                    conn, user_id, username, int(time.time()), commit=False)
            except Exception as exc:
                raise HTTPException(409, "username already exists") from exc

        if role is not None:
            if role not in ("admin", "operator", "viewer"):
                raise HTTPException(400, "role must be admin, operator or viewer")
            _user_store.set_role(
                conn, user_id, role, int(time.time()), commit=False)

        if enabled is not None:
            _user_store.set_enabled(
                conn, user_id, bool(enabled), int(time.time()), commit=False)
            if not enabled:
                # Revoke sessions for disabled users in the same transaction.
                _session_store.delete_for_user(conn, user_id, commit=False)

        conn.commit()
        _log(f"update user: id={user_id} username={username} role={role} enabled={enabled}", "users")
        _audit(request, "user.update", target=str(user_id),
               detail={"username": username, "role": role,
                       "enabled": enabled})
    finally:
        conn.close()
    return {"ok": True}


@app.delete("/api/v1/admin/users/{user_id}/sessions", tags=["Users"],
            summary="Revoke all sessions for a user")
def revoke_user_sessions(user_id: int, request: Request,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        revoked = _session_store.delete_for_user(conn, user_id)
        _log(f"revoke sessions: user_id={user_id} count={revoked}", "users")
    finally:
        conn.close()
    return {"ok": True, "revoked": revoked}


@app.get("/api/v1/admin/roles", tags=["Users"], summary="List available roles and permissions")
def list_roles(_: None = Depends(require_auth)):
    """The canonical role -> permission map, resolved against the live routes.

    Reporting from the registry (rather than a hand-written list) is what
    keeps this endpoint honest: it shows the groups each role actually
    holds after the admin-only surfaces are excluded.
    """
    return {"roles": permission_registry().role_map()}


@app.get("/api/v1/admin/storage/gc-candidates", tags=["Storage recovery"],
         summary="Retention-aware dry-run FAILED journal planning, never deletion")
def list_storage_gc_candidates(
    min_age_seconds: int = Query(default=7*86400, ge=86400, le=365*86400),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            candidates = StorageGCInventory(catalog.manifests).preview_failed_retention(
                now=int(time.time()), min_age_seconds=min_age_seconds, limit=limit
            )
        except RuntimeError as exc:
            raise HTTPException(409, "Reference graph is inconsistent; GC blocked") from exc
        return {
            "candidates": candidates,
            "dry_run": True, "physical_deletion_enabled": False,
            "remote_history_scan_required": True,
        }
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/gc-audit", tags=["API keys"],
         summary="Audit Telegram object references before any physical cleanup")
def get_storage_gc_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    """Root-admin-only, non-destructive inventory; never authorizes remote deletion."""
    from dataclasses import asdict

    conn = db_connect()
    try:
        # Also ensure the bucket/head metadata tables exist on a new DB.
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            inventory = StorageGCInventory(catalog.manifests).inspect()
        except RuntimeError as exc:
            raise HTTPException(409, "Reference graph is inconsistent; GC blocked") from exc
        return {
            "total_manifests": inventory.total_manifests,
            "total_telegram_messages": inventory.total_telegram_messages,
            "unjournaled_mtproto_receipts": inventory.unjournaled_mtproto_receipts,
            "unresolved_mtproto_intents": inventory.unresolved_mtproto_intents,
            "active_upload_jobs": inventory.active_upload_jobs,
            "live_object_heads": inventory.live_object_heads,
            "copy_aliases": inventory.copy_aliases,
            "multipart_parts": inventory.multipart_parts,
            "eligible_for_deletion": 0,
            "dry_run": True,
            "physical_deletion_enabled": False,
            "protected_chunks": [
                asdict(row) for row in inventory.protected_chunks[:limit]
            ],
            "truncated": len(inventory.protected_chunks) > limit,
        }
    finally:
        conn.close()


def _storage_job_root() -> Path:
    """Durable jobs may read only an operator-configured local source root."""
    raw = JOB_SOURCE_ROOT.strip()
    if not raw:
        raise HTTPException(503, "Configure TELEDRIVE_JOB_SOURCE_ROOT for local upload jobs")
    try:
        root = Path(raw).resolve(strict=True)
    except OSError as exc:
        raise HTTPException(503, "Upload source root does not exist") from exc
    if not root.is_dir():
        raise HTTPException(503, "Upload source root must be a directory")
    return root


@app.post("/api/v1/admin/storage/versions/index-current",
          tags=["Storage versions"],
          summary="Dry-run or explicitly index only verified historical HEAD references")
def index_legacy_current_versions(
    request: Request, payload: VersionIndexRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            registered = catalog.index_legacy_current_heads(
                dry_run=not payload.execute, limit=payload.limit,
            )
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ids": registered, "count": len(registered),
                "dry_run": not payload.execute,
                "indexed": bool(payload.execute and registered)}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/versions", tags=["Storage versions"],
         summary="Admin listing of published historical versions for restore")
def admin_list_published_versions(
    bucket: str = Query(..., min_length=3, max_length=63),
    key: str = Query(..., min_length=1, max_length=1024),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        try:
            current = catalog.get(bucket, key)
            generation = current.generation
        except FileNotFoundError:
            generation = 0
        return {"bucket": bucket, "key": key, "generation": generation,
                "versions": catalog.list_versions(bucket, key, limit=limit)}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/versions/{version_id}/restore",
          tags=["Storage versions"],
          summary="Restore a previously published immutable version without Telegram uploads")
def restore_published_version(
    version_id: str, request: Request, payload: VersionRestoreRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            head = catalog.get(payload.bucket, payload.key)
            generation, current_id = head.generation, head.item.id
        except FileNotFoundError:
            generation, current_id = 0, None
        if payload.expected_generation is not None and (
            payload.expected_generation != generation
        ):
            raise HTTPException(409, "Generation has changed since restore preview")
        try:
            restored = copy_object(
                catalog, payload.bucket, payload.key,
                payload.bucket, payload.key,
                source_version_id=version_id,
                expected_destination_generation=generation,
                expected_destination_object_id=current_id,
            )
        except FileNotFoundError as exc:
            raise HTTPException(404, "Published version does not exist") from exc
        except (CopyConflict, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "id": restored.object_id, "source_version_id": version_id,
            "etag": restored.etag, "size": restored.size,
            "generation": catalog.get(payload.bucket, payload.key).generation,
        }
    finally:
        conn.close()



# --- Telegram session management (WebUI-driven) -----------------------------

def _mask_phone(phone: str | None) -> str:
    if not phone:
        return "-"
    digits = str(phone).strip()
    if len(digits) <= 6:
        return "***"
    return digits[:4] + "***" + digits[-2:]


async def _probe_telegram_session(api_id: int, api_hash: str,
                                  session_string: str) -> bool:
    """One lightweight authorization probe: connect + is_authorized."""
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    try:
        client = TelegramClient(StringSession(session_string), api_id,
                                api_hash, receive_updates=False,
                                flood_sleep_threshold=0)
    except Exception:
        return False
    try:
        await client.connect()
        return bool(await client.is_user_authorized())
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def _store_session_health(account: str, authorized: bool) -> None:
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "UPDATE telegram_sessions SET authorized = :a, "
            "health_checked_at = :now WHERE account = :account"
        ), {"a": 1 if authorized else 0, "now": int(time.time()),
            "account": account})
        conn.connection.commit()
    finally:
        conn.close()


def _probe_account_now(account: str) -> dict:
    """Probe one account synchronously (endpoint context)."""
    import asyncio
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT api_id, api_hash, session_string FROM "
            "telegram_sessions WHERE account = :account"
        ), {"account": account}).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(404, "Unknown Telegram session account")
    api_id, api_hash, session_string = row
    try:
        authorized = asyncio.run(
            _probe_telegram_session(api_id, api_hash, session_string))
    except Exception as exc:
        _log(f"session health: account={account} probe error "
             f"{type(exc).__name__}", "telegram-session")
        authorized = False
    _store_session_health(account, authorized)
    if not authorized:
        _log(f"session health: account={account} UNAUTHORIZED "
             "(expired/revoked); re-login required", "telegram-session")
    return {"account": account, "authorized": authorized,
            "health_checked_at": int(time.time())}


async def telegram_session_health_loop() -> None:
    """Probe every Telegram session for expiry/revocation, periodically.

    A dead session silently turns uploads into failures; the probe keeps
    an explicit authorized flag on every account row and logs a warning
    the moment a previously-healthy session dies.
    """
    while True:
        try:
            conn = db_connect()
            try:
                from sqlalchemy import text as _text
                rows = conn.connection.execute(_text(
                    "SELECT account, api_id, api_hash, session_string, "
                    "authorized FROM telegram_sessions")).fetchall()
            finally:
                conn.close()
            for account, api_id, api_hash, session_string, previous in rows:
                try:
                    authorized = await _probe_telegram_session(
                        int(api_id), str(api_hash), str(session_string))
                except Exception as exc:
                    _log(f"session health: account={account} probe error "
                         f"{type(exc).__name__}", "telegram-session")
                    continue
                _store_session_health(str(account), authorized)
                if not authorized and previous not in (0, None):
                    _log(f"session health: account={account} UNAUTHORIZED "
                         "(expired/revoked); re-login required",
                         "telegram-session")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log("session health scheduler: " + type(exc).__name__,
                 "scheduler")
        await asyncio.sleep(1800)


@app.put("/api/v1/admin/storage/telegram-sessions/{account}/quota",
         tags=["Storage jobs"],
         summary="Set an account's soft quota (preferred routing headroom)")
def set_telegram_session_quota(account: str, request: Request,
                               payload: dict = Body(...),
                               _: None = Depends(require_auth)):
    _same_origin(request)
    account = account.strip()
    if not account:
        raise HTTPException(400, "account is required")
    raw = payload.get("soft_quota_bytes")
    if raw is not None:
        try:
            quota = int(raw)
        except (TypeError, ValueError):
            raise HTTPException(422, "soft_quota_bytes must be an integer "
                                     "or null") from None
        if not 0 <= quota <= 2**63 - 1:
            raise HTTPException(422, "soft_quota_bytes out of range")
    else:
        quota = None
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        changed = conn.connection.execute(_text(
            "UPDATE telegram_sessions SET soft_quota_bytes = :q, "
            "updated_at = :now WHERE account = :account"
        ), {"q": quota, "now": int(time.time()), "account": account}).rowcount
        conn.connection.commit()
    finally:
        conn.close()
    if not changed:
        raise HTTPException(404, "Unknown Telegram session account")
    _log(f"account soft quota set: account={account} "
         f"quota={quota if quota is not None else 'unlimited'}", "storage")
    return {"ok": True, "account": account, "soft_quota_bytes": quota}


@app.post("/api/v1/admin/storage/telegram-sessions/{account}/health-check",
          tags=["Storage jobs"],
          summary="Probe one Telegram session for authorization now")
def telegram_session_health_check(account: str, request: Request,
                                  _: None = Depends(require_auth)):
    _same_origin(request)
    account = account.strip()
    if not account:
        raise HTTPException(400, "account is required")
    result = _probe_account_now(account)
    return {"ok": True, **result}


@app.get("/api/v1/admin/storage/telegram-sessions", tags=["Storage jobs"],
         summary="List all Telegram sessions with per-account health")
def list_telegram_sessions(_: None = Depends(require_auth)):
    now_ms = int(time.time() * 1000)
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        rows = conn.connection.execute(_text(
            "SELECT account, api_id, phone, channel, strategy, created_at, "
            "updated_at, authorized, health_checked_at, soft_quota_bytes "
            "FROM telegram_sessions ORDER BY account")).fetchall()
        # Usage, cooldowns and flood observations live in the storage
        # catalog tables; degrade gracefully when this deployment's web
        # database does not carry them.
        # CURRENT usage joins the object heads: deleted-but-retained
        # objects (physical GC is owner-gated) do NOT count. The
        # physical chunk totals are reported separately as the retained
        # backlog the owner could eventually reclaim through GC.
        usage: dict[str, tuple[int, int]] = {}
        retained: dict[str, tuple[int, int]] = {}
        cooldowns: dict[str, int] = {}
        floods: dict[str, int] = {}
        try:
            for acct, objects, total in conn.connection.execute(_text(
                    "SELECT c.account, COUNT(DISTINCT c.object_id), "
                    "SUM(c.size) FROM storage_chunks c "
                    "JOIN storage_object_heads h "
                    "ON h.object_id = c.object_id GROUP BY c.account")):
                usage[str(acct)] = (int(objects or 0), int(total or 0))
        except Exception:
            pass
        try:
            for acct, objects, total in conn.connection.execute(_text(
                    "SELECT account, COUNT(DISTINCT object_id), SUM(size) "
                    "FROM storage_chunks GROUP BY account")):
                retained[str(acct)] = (int(objects or 0), int(total or 0))
        except Exception:
            pass
        try:
            for acct, until in conn.connection.execute(_text(
                    "SELECT account, MAX(cooldown_until_ms) FROM "
                    "storage_mtproto_chat_cooldowns GROUP BY account")):
                cooldowns[str(acct)] = int(until or 0)
        except Exception:
            pass
        try:
            for acct, obs in conn.connection.execute(_text(
                    "SELECT account, SUM(observations) FROM "
                    "storage_mtproto_flood_observations GROUP BY account")):
                floods[str(acct)] = int(obs or 0)
        except Exception:
            pass
    finally:
        conn.close()
    sessions = []
    for account, api_id, phone, channel, strategy, created, updated, \
            authorized, checked, soft_quota in rows:
        objects, total = usage.get(str(account), (0, 0))
        retained_objects, retained_total = retained.get(str(account), (0, 0))
        remaining_ms = max(0, cooldowns.get(str(account), 0) - now_ms)
        sessions.append({
            "account": account, "api_id": api_id,
            "phone": _mask_phone(phone), "channel": channel,
            "strategy": strategy or "round_robin",
            "created_at": created, "updated_at": updated,
            "objects": objects, "bytes": total,
            # Physical Telegram storage per account. The difference to
            # the current numbers is the retained (GC-reclaimable)
            # backlog: deleted objects whose media survives until the
            # owner authorizes physical GC.
            "retained_objects": retained_objects,
            "retained_bytes": retained_total,
            "cooldown_remaining_s": remaining_ms // 1000,
            "flood_observations": floods.get(str(account), 0),
            "authorized": None if authorized is None else bool(authorized),
            "health_checked_at": checked,
            "soft_quota_bytes": soft_quota,
        })
    try:
        active_strategy = str(((read_raw_config() or {})
                               .get("storage") or {})
                               .get("strategy") or "round_robin")
    except Exception:
        active_strategy = "round_robin"
    return {"sessions": sessions, "count": len(sessions),
            "strategy": active_strategy}


@app.delete("/api/v1/admin/storage/telegram-sessions/{account}",
            tags=["Storage jobs"],
            summary="Delete one account's Telegram session")
def delete_telegram_session_account(account: str, request: Request,
                                    force: bool = False,
                                    _: None = Depends(require_auth)):
    _same_origin(request)
    account = account.strip()
    if not account:
        raise HTTPException(400, "account is required")
    # Soft-guard: an account that still stores chunks must be deleted
    # explicitly with force=true. The catalog rows survive either way,
    # but reads of those objects need the session re-authorized first.
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        objects, total = 0, 0
        try:
            guard = conn.connection.execute(_text(
                "SELECT COUNT(DISTINCT object_id), SUM(size) FROM "
                "storage_chunks WHERE account = :account"
            ), {"account": account}).fetchone()
            if guard is not None:
                objects, total = int(guard[0] or 0), int(guard[1] or 0)
        except Exception:
            pass
        if objects and not force:
            raise HTTPException(409, {
                "message": "This account still stores objects in the "
                           "catalog. Deleting the session stops new "
                           "uploads from using it, but reading those "
                           "objects requires re-authorizing the account.",
                "account": account, "objects": objects, "bytes": total,
            })
        deleted = conn.connection.execute(_text(
            "DELETE FROM telegram_sessions WHERE account = :account"
        ), {"account": account}).rowcount
        conn.connection.commit()
    finally:
        conn.close()
    _log(f"telegram session deleted: account={account} rows={deleted}",
         "storage")
    _schedule_storage_runtime_reload()
    return {"ok": True, "deleted": deleted, "account": account}


@app.get("/api/v1/admin/storage/telegram-session", tags=["Storage jobs"],
         summary="Read the active Telegram USER session status")
def get_telegram_session(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT id, api_id, phone, account, channel, strategy, "
            "created_at, updated_at FROM telegram_sessions "
            "ORDER BY id DESC LIMIT 1"
        )).fetchone()
        if row is None:
            return {"configured": False, "session": None}
        return {
            "configured": True,
            "session": {
                "id": row[0], "api_id": row[1], "phone": row[2],
                "account": row[3], "channel": row[4], "strategy": row[5],
                "created_at": row[6], "updated_at": row[7],
            },
        }
    finally:
        conn.close()


class TelegramSessionRequestCode(BaseModel):
    api_id: int
    api_hash: str
    phone: str
    channel: str | None = None
    strategy: str | None = None


# Wrong-code budget per pending login. Five-digit codes: 5 tries leaves a
# 1-in-2000 chance of a blind guess, and Telegram's own FloodWait makes the
# real attack far slower than that.
_MAX_VERIFY_ATTEMPTS = 5


def _record_verify_attempt(token: str) -> None:
    """Count one failed verification without extending the request's life."""
    conn = db_connect()
    try:
        _pending_store.bump_attempts(conn, token)
    except Exception:
        pass
    finally:
        conn.close()


def _consume_pending_session_token(token: str) -> None:
    conn = db_connect()
    try:
        _pending_store.consume(conn, token)
    finally:
        conn.close()


def _telegram_error_response(exc: Exception, action: str) -> HTTPException:
    """Log the exact Telegram failure reason and map known errors to hints.

    The http middleware only records the status code, so the *why* behind a
    failed request-code/verify-code must be logged here, right before the
    http entry that shows the -> 400 line.
    """
    from telethon import errors as tg_errors
    name = type(exc).__name__
    hints = (
        (tg_errors.SessionPasswordNeededError,
         "Two-factor authentication is required: fill the 2FA password "
         "field and retry"),
        (tg_errors.PhoneCodeExpiredError,
         "The code has expired: request a new code"),
        (tg_errors.PhoneCodeInvalidError,
         "The code is invalid: check the code Telegram sent and retry"),
        (tg_errors.PhoneCodeEmptyError,
         "The code is empty: enter the code Telegram sent"),
        (tg_errors.PhoneNumberUnoccupiedError,
         "No Telegram account exists for this phone number"),
        (tg_errors.PasswordHashInvalidError,
         "The 2FA password is incorrect: check it and retry"),
    )
    message = next((hint for cls, hint in hints if isinstance(exc, cls)), None)
    if message is None:
        message = _scrub_text(str(exc)) or name
    _log(f"{action} FAILED: {name}: {message}", "telegram-session")
    return HTTPException(400, f"{message} [{name}]")


def _record_flood_wait(scope: str, seconds: int, detail: str = "") -> dict:
    """Persist a Telegram FloodWait and log the full countdown picture."""
    now = int(time.time())
    seconds = max(1, int(seconds))
    expires = now + seconds
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "INSERT INTO flood_waits (scope, started_at, wait_seconds, "
            "expires_at, detail) VALUES (:s, :n, :w, :e, :d)"
        ), {"s": scope, "n": now, "w": seconds, "e": expires, "d": detail})
        conn.connection.commit()
    finally:
        conn.close()
    _log(
        f"FLOODWAIT scope={scope} wait={seconds}s "
        f"({seconds // 3600}h {(seconds % 3600) // 60}m) "
        f"started={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))} "
        f"expires={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires))}",
        "telegram-session",
    )
    return {"scope": scope, "started_at": now, "wait_seconds": seconds,
            "expires_at": expires, "remaining_seconds": seconds,
            "detail": detail}


def _flood_wait_status() -> dict:
    """Latest FloodWait record with the live remaining countdown."""
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT scope, started_at, wait_seconds, expires_at, detail "
            "FROM flood_waits ORDER BY id DESC LIMIT 1")).fetchone()
    finally:
        conn.close()
    if row is None:
        return {"active": False, "remaining_seconds": 0, "last": None}
    now = int(time.time())
    remaining = max(0, int(row[3]) - now)
    return {
        "active": remaining > 0,
        "remaining_seconds": remaining,
        "now": now,
        "last": {"scope": row[0], "started_at": row[1],
                 "wait_seconds": row[2], "expires_at": row[3],
                 "remaining_seconds": remaining, "detail": row[4]},
    }


@app.get("/api/v1/admin/storage/telegram-session/floodwait",
         tags=["Storage jobs"],
         summary="Read the current Telegram FloodWait status and countdown")
def telegram_floodwait_status(_: None = Depends(require_auth)):
    return _flood_wait_status()


@app.post("/api/v1/admin/storage/telegram-session/request-code",
          tags=["Storage jobs"], summary="Send a Telegram login code to the phone")
def request_telegram_session_code(payload: TelegramSessionRequestCode,
                                 request: Request,
                                 _: None = Depends(require_auth)):
    from telethon.errors import FloodWaitError
    _same_origin(request)
    _log(f"request-code: api_id={payload.api_id} channel={payload.channel}", "telegram-session")
    if payload.api_id <= 0 or not payload.api_hash or not payload.phone:
        raise HTTPException(400, "api_id, api_hash and phone are required")
    import secrets as _secrets
    token = _secrets.token_urlsafe(16)
    now = int(time.time())
    # Resolve active channel if not provided.
    channel = payload.channel
    if not channel:
        try:
            conn_ch = db_connect()
            try:
                from sqlalchemy import text as _t
                row = conn_ch.connection.execute(_t(
                    "SELECT channel_id FROM telegram_channels WHERE is_active=1 LIMIT 1"
                )).fetchone()
                if row is None:
                    row = conn_ch.connection.execute(_t(
                        "SELECT channel_id FROM telegram_channels ORDER BY id LIMIT 1"
                    )).fetchone()
                if row is not None:
                    channel = row[0]
            finally:
                conn_ch.close()
        except Exception:
            pass
    # Send the code via Telethon (synchronously).
    phone_code_hash = None
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        import asyncio

        async def _send():
            client = TelegramClient(StringSession(), payload.api_id, payload.api_hash,
                                    receive_updates=False, flood_sleep_threshold=0)
            await client.connect()
            result = await client.send_code_request(payload.phone)
            h = result.phone_code_hash
            # The unauthorized session carries the auth key that
            # phone_code_hash is bound to. verify-code MUST sign in with
            # this exact session; a fresh one always gets
            # PHONE_CODE_EXPIRED from Telegram.
            sess = client.session.save()
            await client.disconnect()
            return h, sess

        phone_code_hash, request_session = asyncio.run(_send())
    except FloodWaitError as exc:
        info = _record_flood_wait(
            "send_code", int(getattr(exc, "seconds", 0)),
            "Telegram login code request")
        raise HTTPException(429, {
            "message": "Telegram FloodWait: too many code requests. "
                       "The code request is rate-limited by Telegram.",
            **info,
        }) from exc
    except Exception as exc:
        raise _telegram_error_response(exc, "request-code") from exc

    # Store pending state in DB (persistent across restarts).
    conn = db_connect()
    try:
        # One transaction: the stale-row purge and the new request commit
        # together when create() commits.
        _pending_store.purge_older_than(conn, now - 300, commit=False)
        _pending_store.create(
            conn, token=token, api_id=payload.api_id,
            api_hash=payload.api_hash, phone=payload.phone,
            phone_code_hash=phone_code_hash, session_string=request_session,
            channel=channel, strategy=payload.strategy or "round_robin",
            created_at=now)
    finally:
        conn.close()

    return {"token": token, "phone": payload.phone,
            "expires_in": 300}


class TelegramSessionVerifyCode(BaseModel):
    token: str
    code: str
    password: str | None = None


@app.post("/api/v1/admin/storage/telegram-session/verify-code",
          tags=["Storage jobs"], summary="Verify the code and save the session")
def verify_telegram_session_code(payload: TelegramSessionVerifyCode,
                                request: Request,
                                _: None = Depends(require_auth)):
    from telethon.errors import FloodWaitError, PhoneCodeExpiredError
    _same_origin(request)
    _log(f"verify-code: token={payload.token[:8]}...", "telegram-session")

    conn = db_connect()
    try:
        pending = _pending_store.get(conn, payload.token)
    finally:
        conn.close()
    if pending is None:
        raise HTTPException(404, "No pending code request (expired, invalid "
                                 "token, or already used). Request a new code.")
    api_id, api_hash, phone = (pending["api_id"], pending["api_hash"],
                               pending["phone"])
    phone_code_hash = pending["phone_code_hash"]
    request_session = pending["session_string"]
    channel, strategy = pending["channel"], pending["strategy"]
    created_at, attempts = pending["created_at"], pending["attempts"]
    # A Telegram login code is five digits. Telegram throttles the send, but
    # not the verify side reliably, so cap wrong attempts here: past the
    # budget the pending request is destroyed and a fresh code is required.
    if int(attempts or 0) >= _MAX_VERIFY_ATTEMPTS:
        _consume_pending_session_token(payload.token)
        _log(f"verify-code BLOCKED: {int(attempts)} failed attempts; "
             f"pending request destroyed", "telegram-session")
        raise HTTPException(
            429,
            "Too many incorrect codes for this request. Request a new code.",
        )
    _log(f"verify-code: token={payload.token[:8]}... request_age="
         f"{int(time.time()) - int(created_at)}s", "telegram-session")
    if int(time.time()) - int(created_at) > 300:
        _consume_pending_session_token(payload.token)
        raise HTTPException(410, "Code request expired; request a new one")
    if not request_session:
        # Pending row from before the session-binding fix: the hash can
        # never be verified without the requesting session.
        _consume_pending_session_token(payload.token)
        raise HTTPException(410, "This code request predates a server fix; "
                                 "request a new code")
    if not payload.code:
        raise HTTPException(400, "code is required")
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        import asyncio

        async def _verify():
            # Reuse the code-REQUEST session: phone_code_hash is bound to
            # its auth key. A fresh session here is the classic cause of
            # PhoneCodeExpiredError on a brand-new code.
            client = TelegramClient(StringSession(request_session), api_id, api_hash,
                                    receive_updates=False, flood_sleep_threshold=0)
            await client.connect()
            # Telethon's sign_in IGNORES `password` when a `code` is given
            # (elif code: branch in telethon/client/auth.py). The 2FA step
            # is a second, separate sign_in(password=...) call after
            # SessionPasswordNeededError — exactly what client.start()
            # does internally. One code attempt only; Telegram allows ~3.
            from telethon.errors import SessionPasswordNeededError
            try:
                await client.sign_in(phone, code=payload.code,
                                     phone_code_hash=phone_code_hash)
            except SessionPasswordNeededError:
                if not payload.password:
                    raise
                await client.sign_in(password=payload.password)
            if not await client.is_user_authorized():
                raise RuntimeError("Sign-in did not authorize the user")
            me = await client.get_me()
            if me is None or getattr(me, "bot", False):
                raise RuntimeError("Use a real Telegram USER session, not a bot token")
            session_string = client.session.save()
            await client.disconnect()
            return session_string, me

        session_string, me = asyncio.run(_verify())
    except FloodWaitError as exc:
        info = _record_flood_wait(
            "sign_in", int(getattr(exc, "seconds", 0)),
            "Telegram login verification")
        raise HTTPException(429, {
            "message": "Telegram FloodWait: the verification is "
                       "rate-limited by Telegram.",
            **info,
        }) from exc
    except PhoneCodeExpiredError as exc:
        # The hash is burned for good: retrying with this token can never
        # succeed, so consume it and force a fresh code request.
        _consume_pending_session_token(payload.token)
        _log("verify-code FAILED: PhoneCodeExpiredError: the code has "
             "expired", "telegram-session")
        raise HTTPException(410, "The code has expired. Request a new code "
                                 "and use the code from the NEWEST Telegram "
                                 "message (each request invalidates all "
                                 "previous codes).") from exc
    except Exception as exc:
        # A wrong code must NOT consume the pending request outright -- the
        # user can retry -- but the attempt is counted, and the counter is
        # what eventually destroys it (see _MAX_VERIFY_ATTEMPTS).
        _record_verify_attempt(payload.token)
        raise _telegram_error_response(exc, "verify-code") from exc
    # Success: consume the pending token.
    _consume_pending_session_token(payload.token)

    # Resolve the channel (optional).
    account = getattr(me, "username", None) or f"user-{me.id}"
    strategy = strategy or "round_robin"
    now = int(time.time())
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        # Remove any previous session for this account.
        conn.connection.execute(_text(
            "DELETE FROM telegram_sessions WHERE account = :account"
        ), {"account": account})
        conn.connection.execute(_text(
            "INSERT INTO telegram_sessions (api_id, api_hash, phone, "
            "session_string, account, channel, strategy, created_at, updated_at) "
            "VALUES (:api_id, :api_hash, :phone, :session_string, :account, "
            ":channel, :strategy, :now, :now)"
        ), {
            "api_id": api_id, "api_hash": api_hash, "phone": phone,
            "session_string": session_string, "account": account,
            "channel": channel, "strategy": strategy, "now": now,
        })
        conn.connection.commit()
    finally:
        conn.close()

    # Create or activate a channel entry for this session.
    if channel:
        conn2 = db_connect()
        try:
            from sqlalchemy import text as _text
            existing = conn2.connection.execute(_text(
                "SELECT id FROM telegram_channels WHERE channel_id = :cid"
            ), {"cid": channel}).fetchone()
            now2 = int(time.time())
            if existing:
                cid = existing[0]
                conn2.connection.execute(_text(
                    "UPDATE telegram_channels SET is_active = 0"
                ))
                conn2.connection.execute(_text(
                    "UPDATE telegram_channels SET is_active = 1, strategy = :s, "
                    "updated_at = :now WHERE id = :id"
                ), {"s": strategy, "now": now2, "id": cid})
            else:
                conn2.connection.execute(_text(
                    "UPDATE telegram_channels SET is_active = 0"
                ))
                conn2.connection.execute(_text(
                    "INSERT INTO telegram_channels (name, channel_id, strategy, "
                    "scratch_dir, is_active, created_at, updated_at) "
                    "VALUES (:name, :cid, :s, :sd, 1, :now, :now)"
                ), {"name": channel, "cid": channel, "s": strategy,
                    "sd": "/data/tmp", "now": now2})
            conn2.connection.commit()
        finally:
            conn2.close()

    # Also write the session file so the existing file-based runtime works.
    sessions_dir = AUTH_DIR.parent / "sessions"
    session_file = f"{sessions_dir}/{account}.session"
    try:
        _secure_mkdir(sessions_dir)
        _secure_write(Path(session_file), session_string + "\n")
    except Exception:
        pass

    _log(f"session verified and saved: account={account} user_id={me.id} channel={channel}", "telegram-session")
    _schedule_storage_runtime_reload()
    return {
        "ok": True,
        "account": account,
        "user_id": me.id,
        "session_file": session_file,
    }


@app.delete("/api/v1/admin/storage/telegram-session", tags=["Storage jobs"],
            summary="Revoke the stored Telegram session")
def delete_telegram_session(request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    _log("revoke telegram session", "storage")
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text("DELETE FROM telegram_sessions"))
        conn.connection.commit()
    finally:
        conn.close()
    _schedule_storage_runtime_reload()
    return {"ok": True}


# --- Telegram channel management (multi-channel) ----------------------------

@app.get("/api/v1/admin/storage/channels", tags=["Storage jobs"],
         summary="List configured Telegram storage channels")
def list_telegram_channels(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        rows = conn.connection.execute(_text(
            "SELECT id, name, channel_id, strategy, scratch_dir, is_active, "
            "created_at, updated_at FROM telegram_channels ORDER BY id"
        )).fetchall()
        return {"channels": [
            {"id": r[0], "name": r[1], "channel_id": r[2], "strategy": r[3],
             "scratch_dir": r[4], "is_active": bool(r[5]),
             "created_at": r[6], "updated_at": r[7]} for r in rows]}
    finally:
        conn.close()


class TelegramChannelCreate(BaseModel):
    name: str
    channel_id: str
    strategy: str | None = None
    scratch_dir: str | None = None


@app.post("/api/v1/admin/storage/channels", tags=["Storage jobs"],
          status_code=201, summary="Add a Telegram storage channel")
def create_telegram_channel(payload: TelegramChannelCreate, request: Request,
                           _: None = Depends(require_auth)):
    _same_origin(request)
    _log(f"create channel: name={payload.name} channel_id={payload.channel_id}", "storage")
    if not payload.name or not payload.channel_id:
        raise HTTPException(400, "name and channel_id are required")
    strategy = (payload.strategy or "round_robin").strip().lower()
    if strategy not in ("single", "round_robin", "failover", "parallel"):
        raise HTTPException(400, "invalid strategy")
    now = int(time.time())
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        result = conn.connection.execute(_text(
            "INSERT INTO telegram_channels (name, channel_id, strategy, "
            "scratch_dir, is_active, created_at, updated_at) "
            "VALUES (:name, :channel_id, :strategy, :scratch_dir, 0, :now, :now) "
            "RETURNING id"
        ), {"name": payload.name, "channel_id": payload.channel_id,
            "strategy": strategy, "scratch_dir": payload.scratch_dir or "/data/tmp",
            "now": now})
        new_id = result.scalar()
        conn.connection.commit()
    finally:
        conn.close()
    return {"id": new_id, "name": payload.name, "channel_id": payload.channel_id}


@app.delete("/api/v1/admin/storage/channels/{channel_id}", tags=["Storage jobs"],
            summary="Remove a Telegram storage channel")
def delete_telegram_channel(channel_id: int, request: Request,
                           _: None = Depends(require_auth)):
    _same_origin(request)
    _log(f"delete channel: id={channel_id}", "storage")
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "DELETE FROM telegram_channels WHERE id = :id"
        ), {"id": channel_id})
        conn.connection.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.put("/api/v1/admin/storage/strategy", tags=["Storage jobs"],
         summary="Set the cross-account upload routing strategy")
def set_storage_strategy(request: Request, payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    _same_origin(request)
    strategy = str(payload.get("strategy", "")).strip().lower()
    if strategy not in ("single", "round_robin", "failover", "parallel"):
        raise HTTPException(400, "Strategy must be one of single, "
                                 "round_robin, failover, parallel")
    cfg = read_raw_config()
    if not isinstance(cfg, dict):
        raise HTTPException(400, "Configuration is not readable")
    # Surgical single-key update: a full config validation would also
    # demand an existing upload source_dir, which is unrelated to the
    # routing strategy. The value itself is whitelisted above.
    cfg.setdefault("storage", {})["strategy"] = strategy
    tmp = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    _secure_write(tmp, yaml.safe_dump(cfg, sort_keys=False))
    os.replace(tmp, CONFIG_PATH)
    _reload_service_settings()
    _log(f"storage strategy set: {strategy} (runtime reloaded)", "config")
    _schedule_storage_runtime_reload()
    return {"ok": True, "strategy": strategy}


@app.get("/api/v1/admin/storage/replication", tags=["Storage jobs"],
         summary="Cross-account replication status and coverage")
def get_replication_status(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        coverage = BucketCatalog(ManifestStore(conn)).manifests.replica_coverage()
    finally:
        conn.close()
    try:
        account = str(((read_raw_config() or {}).get("storage") or {})
                      .get("replica_account") or "").strip() or None
    except Exception:
        account = None
    runtime_account = getattr(mtproto_storage_runtime, "replica_account", None)
    return {
        "account": account,
        "runtime_account": runtime_account,
        "enabled": bool(runtime_account),
        "coverage": coverage,
    }


@app.put("/api/v1/admin/storage/replication", tags=["Storage jobs"],
         summary="Set or disable the cross-account replication target")
def set_replication_account(request: Request, payload: dict = Body(...),
                            _: None = Depends(require_auth)):
    _same_origin(request)
    account = str(payload.get("account", "")).strip()
    if account:
        conn = db_connect()
        try:
            from sqlalchemy import text as _text
            if not conn.connection.execute(_text(
                    "SELECT 1 FROM telegram_sessions WHERE account = :a"),
                    {"a": account}).first():
                raise HTTPException(404, "Unknown Telegram session account")
        finally:
            conn.close()
    cfg = read_raw_config()
    if not isinstance(cfg, dict):
        raise HTTPException(400, "Configuration is not readable")
    # Surgical single-key update, mirroring the strategy setter. An
    # account that is not among the loaded credential sets degrades to
    # disabled at runtime (with a log) rather than failing startup.
    cfg.setdefault("storage", {})["replica_account"] = account
    tmp = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    _secure_write(tmp, yaml.safe_dump(cfg, sort_keys=False))
    os.replace(tmp, CONFIG_PATH)
    _reload_service_settings()
    _log(f"storage replica account set: {account or '(disabled)'} "
         "(runtime reloaded)", "config")
    _schedule_storage_runtime_reload()
    return {"ok": True, "account": account or None}


@app.post("/api/v1/admin/storage/replication/repair", tags=["Storage jobs"],
          summary="Re-send missing replica chunks for under-replicated objects")
async def repair_replication(request: Request, payload: dict = Body(None),
                             _: None = Depends(require_auth)):
    _same_origin(request)
    try:
        limit = int((payload or {}).get("limit", 5))
    except (TypeError, ValueError):
        limit = 5
    limit = max(1, min(limit, 25))
    conn = db_connect()
    try:
        manifests = BucketCatalog(ManifestStore(conn)).manifests
        missing = manifests.objects_missing_replicas(limit=limit)
        if not missing:
            return {"ok": True, "repaired_objects": 0, "chunks": 0}
        transport = storage_transport(conn)
        await transport.verify_target()
        engine = TelegramObjectStorage(
            manifests, transport, chunk_size=RECOMMENDED_CHUNK_SIZE)
        repaired_objects = 0
        total_chunks = 0
        errors = []
        for object_id in missing:
            try:
                count = await engine.repair_replicas(object_id)
                if count:
                    repaired_objects += 1
                    total_chunks += count
            except Exception as exc:
                errors.append({"object_id": object_id,
                               "error": type(exc).__name__})
        if errors:
            _log(f"replica repair finished with {len(errors)} object "
                 "error(s)", "storage")
        return {"ok": True, "repaired_objects": repaired_objects,
                "chunks": total_chunks, "errors": errors}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/channels/{channel_id}/activate",
          tags=["Storage jobs"], summary="Set the active write channel")
def activate_telegram_channel(channel_id: int, request: Request,
                             _: None = Depends(require_auth)):
    _same_origin(request)
    _log(f"activate channel: id={channel_id}", "storage")
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "UPDATE telegram_channels SET is_active = 0"
        ))
        conn.connection.execute(_text(
            "UPDATE telegram_channels SET is_active = 1 WHERE id = :id"
        ), {"id": channel_id})
        conn.connection.commit()
    finally:
        conn.close()
    _schedule_storage_runtime_reload()
    return {"ok": True}


@app.get("/api/v1/admin/storage/active-channel", tags=["Storage jobs"],
         summary="Read the active write channel")
def get_active_channel(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT id, name, channel_id, strategy, scratch_dir FROM "
            "telegram_channels WHERE is_active = 1 LIMIT 1"
        )).fetchone()
        if row is None:
            # Fall back to first channel
            row = conn.connection.execute(_text(
                "SELECT id, name, channel_id, strategy, scratch_dir FROM "
                "telegram_channels ORDER BY id LIMIT 1"
            )).fetchone()
        if row is None:
            return {"active": None}
        return {"active": {"id": row[0], "name": row[1], "channel_id": row[2],
                           "strategy": row[3], "scratch_dir": row[4]}}
    finally:
        conn.close()

@app.websocket("/api/v1/logs/stream")
async def logs_stream(websocket: WebSocket):
    """Live log stream: the initial backlog plus every new entry.

    Authentication mirrors the REST API (session cookie on the
    handshake, Bearer via query is NOT offered — tokens must not live
    in URLs). Unauthenticated sockets close before accepting.
    """
    token = websocket.cookies.get("teledrive_session") if websocket.cookies else None
    user = None
    if token:
        class _Shim:
            headers = {}
            cookies = {"teledrive_session": token}
        user = _get_current_user(_Shim())  # type: ignore[arg-type]
    if user is None:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    # Bootstrap the main-loop reference when lifespan did not run (e.g.
    # test harnesses): the push path in _log needs it for the
    # thread-safe handoff.
    global _main_event_loop
    if _main_event_loop is None:
        _main_event_loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    _LOG_WAITERS.add(queue)
    try:
        for entry in list(LOG_BUFFER)[-200:]:
            await websocket.send_text(entry)
        while True:
            entry = await queue.get()
            await websocket.send_text(entry)
    except WebSocketDisconnect:
        pass
    finally:
        _LOG_WAITERS.discard(queue)


@app.get("/api/v1/logs", tags=["System"], summary="Read recent redacted activity logs")
@app.get("/api/logs", tags=["System"], include_in_schema=False)
def logs(limit: int = Query(default=1000, ge=1, le=1500),
         _: None = Depends(require_auth)):
    combined = list(LOG_BUFFER)[-limit:]
    combined = list(reversed(combined))
    entries = []
    for line in combined:
        # Parse "[ts] [user] [source] msg" format.
        m = re.match(r"^\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)$", line)
        if m:
            entries.append({"ts": m.group(1), "user": m.group(2),
                           "source": m.group(3), "message": m.group(4)})
        else:
            entries.append({"ts": "", "user": "", "source": "", "message": line})
    return {"entries": entries}



# --- User management (multi-user WebUI) ------------------------------------

@app.get("/api/v1/admin/users", tags=["Users"], summary="List WebUI users")
def list_users(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        return {"users": _user_store.list(conn)}
    finally:
        conn.close()


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


@app.post("/api/v1/admin/users", tags=["Users"], status_code=201,
          summary="Create a WebUI user")
def create_user(request: Request, payload: UserCreateRequest,
                _: None = Depends(require_auth)):
    _same_origin(request)
    if not payload.username or not payload.password:
        raise HTTPException(400, "username and password are required")
    _validate_username(payload.username)
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(400, "role must be admin, operator or viewer")
    if len(payload.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    pw_hash = _hash_password(payload.password)
    now = int(time.time())
    conn = db_connect()
    try:
        try:
            record = _user_store.create(
                conn, username=payload.username, password_hash=pw_hash,
                role=payload.role, now=now)
        except Exception as exc:
            raise HTTPException(409, "username already exists") from exc
    finally:
        conn.close()
    _log(f"create user: username={payload.username} role={payload.role}", "users")
    _audit(request, "user.create", target=payload.username,
           detail={"role": payload.role})
    return {"id": record["id"], "username": payload.username, "role": payload.role}


@app.delete("/api/v1/admin/users/{user_id}", tags=["Users"],
            summary="Delete a WebUI user")
def delete_user(user_id: int, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        record = _user_store.get_by_id(conn, user_id)
        if record is None:
            raise HTTPException(404, "user not found")
        _assert_not_last_admin(conn, record["role"])
        # Sessions MUST die with the account. user_sessions has no foreign
        # key, and an Integer primary key reuses rowids on SQLite, so an
        # orphan session row could be inherited by a later account -- the
        # review proved a deleted viewer's token authenticating as a newly
        # created admin. Deleting the sessions in the same transaction makes
        # that impossible: the store does not commit here, the user delete
        # below does it once.
        _session_store.delete_for_user(conn, user_id, commit=False)
        _user_store.delete(conn, user_id, commit=False)
        conn.commit()
        _log(f"delete user: id={user_id} username={record['username']}", "users")
        _audit(request, "user.delete", target=str(user_id),
               detail={"username": record["username"]})
    finally:
        conn.close()
    return {"ok": True}


# --- S3 bucket browser & quota (WebUI session auth) -------------------------

@app.get("/api/v1/admin/storage/buckets", tags=["Object catalog"],
         summary="List buckets with metadata and quota (WebUI)")
def admin_list_buckets(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        buckets = catalog.list_buckets()
        result = []
        for b in buckets:
            # Current object count and total size (heads join).
            count, size = _bucket_current_usage(conn, b)
            max_size, max_objects = _bucket_quota(conn, b)
            quota = None
            if max_size is not None or max_objects is not None:
                quota = {"max_size_bytes": max_size, "max_objects": max_objects}
            result.append({"name": b, "object_count": count,
                           "total_size": size, "quota": quota})
        return {"buckets": result}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/buckets", tags=["Object catalog"],
          status_code=201, summary="Create a bucket (WebUI session)")
def admin_create_bucket(payload: BucketCreateRequest, request: Request,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).create_bucket(
                payload.name, int(time.time()))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        _log(f"create bucket: name={payload.name}", "storage")
        return {"name": payload.name}
    finally:
        conn.close()


@app.delete("/api/v1/admin/storage/buckets/{bucket}", tags=["Object catalog"],
            summary="Remove a physically empty bucket (WebUI session)")
def admin_delete_bucket(bucket: str, request: Request,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).delete_bucket(bucket)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Bucket not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        _log(f"delete bucket: name={bucket}", "storage")
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/buckets/{bucket}/objects", tags=["Object catalog"],
         summary="List objects in a bucket (WebUI)")
def admin_list_objects(bucket: str,
                       prefix: str = Query("", max_length=1024),
                       limit: int = Query(100, ge=1, le=1000),
                       _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        items = catalog.list_objects(bucket, prefix=prefix, limit=limit)
        return {"objects": [
            {"id": x.item.id, "key": x.item.key, "size": x.item.size,
             "sha256": x.item.sha256, "created_at": x.item.created_at,
             "generation": x.generation} for x in items]}
    finally:
        conn.close()


@app.delete("/api/v1/admin/storage/buckets/{bucket}/objects", tags=["Object catalog"],
            summary="Delete an object (WebUI)")
def admin_delete_object(bucket: str, request: Request,
                        key: str = Query(..., min_length=1, max_length=1024),
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        try:
            deleted = BucketCatalog(ManifestStore(conn)).remove_current(bucket, key)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ok": True, "unlinked": deleted}
    finally:
        conn.close()


def _rest_read_gate(manifests, catalog, item) -> dict:
    """The access gate every REST read applies before any byte is produced.

    Two things the S3 data plane already enforces were missing here:

    * an archived object (ARCHIVE_ACCESS / DEEP_ARCHIVE_ACCESS) must answer
      403 InvalidObjectState until a RestoreObject window is open, and
    * an SSE-C object cannot be read without the customer key, so the REST
      surface -- which cannot supply one -- must refuse instead of sending
      200 with Content-Length and an empty body (probe-confirmed: curl -f
      treated that as a successful empty download).

    Returns the encryption marker when the object is readable.
    """
    state = catalog.object_read_state(item.id)
    if state["archived"]:
        raise HTTPException(
            403,
            "Object is archived; restore it first "
            "(InvalidObjectState)")
    encryption = manifests.encryption_info(item.id)
    if encryption is not None:
        raise HTTPException(
            400,
            "This object requires an SSE-C customer key; use the S3 API "
            "with x-amz-server-side-encryption-customer-* headers")
    return encryption


def _valid_rest_key(key: str) -> str:
    if not isinstance(key, str) or not (1 <= len(key.encode("utf-8")) <= 1024):
        raise HTTPException(422, "Object key must contain 1..1024 UTF-8 bytes")
    return key


async def _stream_object_response(bucket: str, key: str, request: Request, *,
                                  allow_range: bool = True,
                                  content_disposition: str | None = None,
                                  count_access: bool = True) -> StreamingResponse:
    """The ONE object-read implementation for every session/REST surface.

    ``admin_download_object`` and ``get_object_content`` were duplicated
    copies of this logic, so the archive gate, the SSE-C refusal and the
    access counter all had to be fixed twice -- and were not: the admin
    download shipped without any of them. There is one path now, and a new
    read surface either calls it or is wrong.
    """
    _valid_rest_key(key)
    conn = db_connect()
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        try:
            item = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        _rest_read_gate(manifests, catalog, item)
        # Parse the range BEFORE counting: a 416 is not a read, and counting
        # it kept objects warm and inflated the statistics -- the opposite of
        # what the counter exists for.
        if allow_range:
            start, end, partial = _byte_range(
                request.headers.get("range"), item.size)
        else:
            start, end, partial = 0, item.size, False
        if count_access:
            # Without this, tiering's idle clock demotes an object that is
            # actively read, and the next S3 GET answers 403.
            catalog.record_object_access(item.id)
            conn.commit()
        transport = storage_transport(conn)
        root = Path(STORAGE_SCRATCH_DIR)
        _secure_mkdir(root)
        engine = TelegramObjectStorage(
            manifests, transport, chunk_size=RECOMMENDED_CHUNK_SIZE,
            scratch_directory=root)
    except BaseException:
        conn.close()
        raise

    async def stream():
        try:
            async for piece in engine.iter_bytes(item.id, start=start, end=end):
                yield piece
        finally:
            conn.close()

    headers = {"ETag": '"' + item.sha256 + '"', "Accept-Ranges": "bytes",
               "Content-Length": str(end - start),
               "X-TeleDrive-Object-ID": item.id}
    if content_disposition:
        headers["Content-Disposition"] = content_disposition
    if partial:
        headers["Content-Range"] = f"bytes {start}-{end-1}/{item.size}"
    return StreamingResponse(stream(), status_code=206 if partial else 200,
                             media_type="application/octet-stream",
                             headers=headers)


@app.get("/api/v1/admin/storage/buckets/{bucket}/content",
         tags=["Object catalog"],
         summary="Download object bytes through the WebUI session (Range supported)")
async def admin_download_object(bucket: str, request: Request,
                                key: str = Query(..., min_length=1, max_length=1024),
                                _: None = Depends(require_auth)):
    """Stream verified object bytes for the S3 browser's download button.

    Session-authenticated twin of the API-key-scoped
    GET /api/v1/buckets/{bucket}/content. Both delegate to the same core, so
    the archive gate, the SSE-C refusal and the access counter cannot drift
    apart again -- the previous duplicate had none of the three.
    """
    # Only the final path segment becomes the suggested filename; strip
    # everything that could break the header or traverse paths.
    filename = re.sub(r"[^A-Za-z0-9._ -]", "_", key.rsplit("/", 1)[-1]) or "download"
    _log(f"download: {bucket}/{key}", "storage",
         user=(getattr(request.state, "user", None) or {}).get(
             "username") or "system")
    return await _stream_object_response(
        bucket, key, request,
        content_disposition=f'attachment; filename="{filename}"')


@app.put("/api/v1/admin/storage/buckets/{bucket}/content",
         tags=["Object catalog"], status_code=201,
         summary="Upload object bytes through the WebUI session")
async def admin_upload_object(bucket: str, request: Request,
                              key: str = Query(..., min_length=1, max_length=1024),
                              generation: int | None = Query(None, ge=0),
                              _: None = Depends(require_auth)):
    """Session-authenticated twin of the API-key-scoped content upload."""
    _same_origin(request)
    return await _stream_object_upload(bucket, key, request, generation)


class ObjectCopyRequest(BaseModel):
    destination_bucket: str | None = Field(default=None, min_length=3, max_length=63)
    destination_key: str = Field(min_length=1, max_length=1024)


@app.get("/api/v1/admin/storage/buckets/{bucket}/cors",
         tags=["Object catalog"],
         summary="Read the bucket CORS rules")
def admin_get_bucket_cors(bucket: str, _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        from teledrive.s3.cors import BucketCORSStore
        rules = BucketCORSStore(catalog).get(bucket)
        return {"rules": rules or []}
    finally:
        conn.close()


@app.put("/api/v1/admin/storage/buckets/{bucket}/cors",
         tags=["Object catalog"],
         summary="Replace the bucket CORS rules")
def admin_put_bucket_cors(bucket: str, request: Request,
                          payload: dict = Body(...),
                          _: None = Depends(require_auth)):
    _same_origin(request)
    rules = payload.get("rules")
    if not isinstance(rules, list) or len(rules) > 20:
        raise HTTPException(422, "rules must be a list of at most 20")
    allowed_methods = {"GET", "PUT", "POST", "DELETE", "HEAD"}
    origin_re = re.compile(r"\*|https?://[A-Za-z0-9.*-]+(:\d+)?(/\*)?")
    for rule in rules:
        methods = [str(m).upper() for m in rule.get("methods", [])]
        origins = [str(o) for o in rule.get("origins", [])]
        if not methods or not origins:
            raise HTTPException(422, "Each rule needs methods and origins")
        if not set(methods) <= allowed_methods:
            raise HTTPException(422, "Unsupported CORS method")
        if any(not origin_re.fullmatch(o) for o in origins):
            raise HTTPException(422, "Invalid origin (use * or "
                                     "scheme://host[:port])")
        try:
            max_age = int(rule.get("max_age") or 0)
        except (TypeError, ValueError):
            raise HTTPException(422, "max_age must be an integer") from None
        if not 0 <= max_age <= 86400:
            raise HTTPException(422, "max_age must be 0..86400")
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        from teledrive.s3.cors import BucketCORSStore
        BucketCORSStore(catalog).replace(bucket, [
            {"origins": [str(o) for o in r.get("origins", [])],
             "methods": [str(m).upper() for m in r.get("methods", [])],
             "allowed_headers": [str(h) for h in
                                 r.get("allowed_headers", [])],
             "expose_headers": [str(h) for h in
                                r.get("expose_headers", [])],
             "max_age": int(r.get("max_age") or 0),
             "id": r.get("id")}
            for r in rules
        ])
        conn.connection.commit()
    finally:
        conn.close()
    _log(f"bucket cors replaced: bucket={bucket} rules={len(rules)}",
         "storage")
    return {"ok": True, "rules": len(rules)}


@app.get("/api/v1/admin/storage/buckets/{bucket}/website",
         tags=["Object catalog"],
         summary="Read the bucket website configuration and public-read gate")
def admin_get_bucket_website(bucket: str, _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        config = WebsiteConfigStore(catalog).get(bucket)
        return {
            "configured": config is not None,
            "index_document": config["index_document"] if config else None,
            "error_document": config["error_document"] if config else None,
            "public_read": catalog.public_read(bucket),
        }
    finally:
        conn.close()


@app.put("/api/v1/admin/storage/buckets/{bucket}/website",
         tags=["Object catalog"],
         summary="Configure website hosting and the public-read gate")
def admin_put_bucket_website(bucket: str, request: Request,
                             payload: dict = Body(...),
                             _: None = Depends(require_auth)):
    """Owner/admin-only website configuration.

    ``public_read=true`` PUBLISHES the bucket's current objects anonymously
    at ``/site/{bucket}/...``. It is a deliberate public-exposure decision:
    every current ready object becomes readable by anyone who can reach the
    app origin. The flag is stored in bucket metadata, defaults to FALSE,
    and is cleared by DeleteBucketWebsite and bucket deletion.

    The separate S3 PutBucketWebsite API writes only the index/error
    document and never flips this gate.
    """
    _same_origin(request)
    # An API key is not a role: even a key holding this endpoint's
    # permission must not publish a bucket. Public exposure stays an
    # owner/admin session decision.
    role = (getattr(request.state, "user", None) or {}).get("role")
    if role != "admin":
        raise HTTPException(403, "Website public exposure requires admin role")
    index_document = payload.get("index_document")
    error_document = payload.get("error_document")
    public_read = payload.get("public_read")
    if not isinstance(public_read, bool):
        raise HTTPException(422, "public_read must be a boolean")
    try:
        index_document = validate_document_name(index_document, "index_document")
        error_document = (None if error_document in (None, "")
                          else validate_document_name(error_document,
                                                      "error_document"))
    except WebsiteError as exc:
        raise HTTPException(422, str(exc)) from exc
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        WebsiteConfigStore(catalog).replace(bucket, {
            "index_document": index_document,
            "error_document": error_document,
            "enabled": True,
        }, public_read=public_read)
    finally:
        conn.close()
    actor = (getattr(request.state, "user", None) or {}).get(
        "username", "system")
    _log(f"bucket website configured: bucket={bucket} "
         f"index={index_document} error={error_document} "
         f"public_read={public_read}", "storage", user=actor)
    result = {
        "ok": True,
        "index_document": index_document,
        "error_document": error_document,
        "public_read": public_read,
    }
    if public_read:
        result["notice"] = (
            "public_read publishes the bucket's current objects anonymously "
            f"at /site/{bucket}/")
    return result


def _public_s3_origin(request: Request) -> str:
    """Public base URL of the S3 listener, for presigned links.

    Works in every supported deployment shape, independently:

    * direct mode — the app terminates TLS on the S3 listener (scheme from
      TELEDRIVE_S3_SSL_CERTFILE), or serves plain HTTP;
    * reverse-proxy mode — TLS terminates in front (TRUSTED_PROXY honors
      X-Forwarded-Proto/Host/Port), or the proxy is plain HTTP;
    * both at once — an HTTPS proxy in front of an app that also speaks
      HTTPS.

    In proxy mode the client-facing host/port come from the forwarded
    headers; in direct mode from the Host header plus the S3 listener
    port, with the default port of the scheme elided.
    """
    forwarded = False
    if TRUSTED_PROXY:
        forwarded = request.headers.get(
            "x-forwarded-proto", "").lower() == "https"
    scheme = "https" if (S3_SSL_CERTFILE or forwarded) else "http"

    host = ""
    if TRUSTED_PROXY:
        host = (request.headers.get("x-forwarded-host") or "").strip()
    host = host or (request.headers.get("host") or "").strip()
    host = host.split("/")[0].strip()
    if not host:
        host = "localhost"

    # Split host / port, tolerating bracketed IPv6 literals. In DIRECT mode
    # any port on the Host header is the WebUI's (the admin calls this from
    # the UI), so it is discarded and the S3 listener port is used. In
    # proxy mode the forwarded host's port IS the public S3 port.
    port: int | None = None
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            bracket, tail = host[:end + 1], host[end + 1:]
            if tail.startswith(":"):
                host, port = bracket, int(tail[1:] or 0) or None
    elif host.count(":") == 1:
        name, _, raw_port = host.partition(":")
        host, port = name, int(raw_port or 0) or None
    if not TRUSTED_PROXY:
        port = None

    if port is None:
        if TRUSTED_PROXY:
            raw_port = request.headers.get("x-forwarded-port", "")
            port = int(raw_port) if raw_port.isdigit() else None
        if port is None:
            port = settings_s3_port()

    if (scheme, port) in (("https", 443), ("http", 80)):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


@app.post("/api/v1/admin/storage/buckets/{bucket}/presign",
          tags=["Object catalog"],
          summary="Create a presigned GET URL for one object")
def admin_presign_object(bucket: str, request: Request,
                         payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    """Server-side SigV4 query signing; the credential secret never
    leaves the process, only the signed URL is returned."""
    _same_origin(request)
    # A presigned URL is durable, anonymous authority: it keeps working for
    # up to seven days after the caller's session, API key or role is gone,
    # and only revoking the SIGNING credential ends it. Delegating that from
    # an API key would let a key plant access that outlives its own
    # revocation, so it is an interactive action like share links and
    # credential reveal.
    actor = _require_interactive_session(request, "presign")
    key = str(payload.get("key", "")).strip()
    if len(key.encode("utf-8")) > 1024:
        raise HTTPException(422, "Object key must contain 1..1024 UTF-8 bytes")
    if not key:
        raise HTTPException(422, "key is required")
    try:
        expires = int(payload.get("expires") or 3600)
    except (TypeError, ValueError):
        raise HTTPException(422, "expires must be an integer") from None
    # SigV4 caps a presigned URL at seven days; validate before signing so
    # an out-of-range value is a 422 rather than an unhandled 500.
    if not 1 <= expires <= 604800:
        raise HTTPException(
            422, "expires must be between 1 and 604800 seconds (7 days)")
    credential_id = payload.get("credential_id")
    conn = db_connect()
    try:
        if bucket not in BucketCatalog(ManifestStore(conn)).list_buckets():
            raise HTTPException(404, "Bucket not found")
        if not _bucket_has_current_key(conn, bucket, key):
            raise HTTPException(404, "Object not found")
        try:
            store = S3CredentialStore(conn, load_master_key())
            if credential_id:
                revealed = store.reveal(str(credential_id))
                # A presigned GET needs this exact scope; issuing a URL
                # for a credential that cannot read would fail later and
                # leak a secret for nothing.
                if "s3:GetObject" not in revealed.get("permissions", ()):
                    raise HTTPException(
                        422, "Credential lacks the s3:GetObject permission")
            else:
                candidates = [c for c in store.list() if not c["revoked"]
                              and "s3:GetObject" in c["permissions"]]
                if not candidates:
                    raise HTTPException(
                        422, "No active S3 credential with s3:GetObject")
                revealed = store.reveal(candidates[0]["id"])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        _audit(request, "object.presign", target=f"{bucket}/{key}",
               detail={"expires": expires,
                       "credential": revealed["access_key"]})
        _log(f"presigned GET: bucket={bucket} key={key} "
             f"expires={expires}s credential={revealed['access_key']}",
             "storage", user=actor)
    finally:
        conn.close()
    from teledrive.s3.sigv4 import presign_get_url
    url = presign_get_url(_public_s3_origin(request),
                          bucket, key, revealed["access_key"],
                          revealed["secret_key"], expires)
    _log(f"presigned URL issued: bucket={bucket} key={key} "
         f"expires={expires}s credential={revealed['access_key']}",
         "security")
    return {"url": url, "expires_in": expires}


@app.post("/api/v1/admin/storage/buckets/{bucket}/shares",
          tags=["Object catalog"],
          summary="Create a signed public share link for one object")
def admin_create_share(bucket: str, request: Request,
                       payload: dict = Body(...),
                       _: None = Depends(require_auth)):
    """Unauthenticated URL bounded by expiry, download count and an
    optional password (PBKDF2-hashed; the plaintext is never stored)."""
    _same_origin(request)
    key = str(payload.get("key", "")).strip()
    if not key:
        raise HTTPException(422, "key is required")
    expires_in = payload.get("expires_in")
    if expires_in is not None:
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            raise HTTPException(422, "expires_in must be an integer") from None
        if not 60 <= expires_in <= 30 * 86400:
            raise HTTPException(422, "expires_in must be 60..2592000 seconds")
    max_downloads = payload.get("max_downloads")
    if max_downloads is not None:
        try:
            max_downloads = int(max_downloads)
        except (TypeError, ValueError):
            raise HTTPException(422, "max_downloads must be an integer") from None
        if not 1 <= max_downloads <= 1_000_000:
            raise HTTPException(422, "max_downloads must be 1..1000000")
    password = payload.get("password")
    if password is not None and not (
            isinstance(password, str) and 1 <= len(password) <= 128):
        raise HTTPException(422, "password must be 1..128 characters")

    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        try:
            shared = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        token = secrets.token_urlsafe(24)
        now = int(time.time())
        salt = digest = None
        if password is not None:
            salt, digest = _hash_share_password(password)
        _share_store.create(
            conn,
            token=token, bucket=bucket, object_key=key,
            # Pin the exact version. A key-bound link would serve whatever
            # the key pointed at later, and recover after an unlink + re-upload.
            object_id=shared.id,
            created_by=(request.state.user or {}).get("username", "-"),
            created_at=now,
            expires_at=now + expires_in if expires_in else None,
            max_downloads=max_downloads,
            password_salt=salt, password_hash=digest,
        )
    finally:
        conn.close()
    _audit(request, "share.create", target=f"{bucket}/{key}",
           detail={"max_downloads": max_downloads,
                   "expires_in": expires_in,
                   "password": password is not None})
    _log(f"share link created: bucket={bucket} key={key} token={token[:6]}… "
         f"expires_in={expires_in} max_downloads={max_downloads} "
         f"password={'yes' if password is not None else 'no'}", "share")
    return {"token": token, "path": f"/share/{token}"}


@app.get("/api/v1/admin/storage/shares", tags=["Object catalog"],
         summary="List all share links with live status")
def admin_list_shares(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        rows = _share_store.list(conn)
        now = int(time.time())
        shares = []
        for share in rows:
            expires = share["expires_at"]
            max_downloads = share["max_downloads"]
            count = share["download_count"]
            if share["revoked"]:
                status = "revoked"
            elif expires is not None and expires <= now:
                status = "expired"
            elif max_downloads is not None and count >= max_downloads:
                status = "exhausted"
            else:
                status = "active"
            shares.append({
                "token": share["token"], "bucket": share["bucket"],
                "key": share["object_key"],
                "created_by": share["created_by"],
                "created_at": share["created_at"],
                "expires_at": expires, "max_downloads": max_downloads,
                "download_count": count,
                "password": bool(share["has_password"]),
                "revoked": share["revoked"], "status": status,
            })
        return {"shares": shares, "count": len(shares)}
    finally:
        conn.close()


@app.delete("/api/v1/admin/storage/shares/{token}", tags=["Object catalog"],
            summary="Revoke a share link")
def admin_revoke_share(token: str, request: Request,
                       _: None = Depends(require_auth)):
    _same_origin(request)
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
        raise HTTPException(404, "Unknown share link")
    conn = db_connect()
    try:
        deleted = _share_store.revoke(conn, token)
    finally:
        conn.close()
    if not deleted:
        raise HTTPException(404, "Unknown share link")
    _log(f"share link revoked: token={token[:6]}…", "share")
    return {"ok": True}


@app.post("/api/v1/admin/storage/buckets/{bucket}/objects/copy",
          tags=["Object catalog"],
          summary="Copy (rename/move) an object at the catalog level")
def admin_copy_object(bucket: str, request: Request,
                      payload: ObjectCopyRequest,
                      key: str = Query(..., min_length=1, max_length=1024),
                      _: None = Depends(require_auth)):
    """Metadata-level copy: no Telegram bytes move, quota is enforced."""
    _same_origin(request)
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        destination_bucket = payload.destination_bucket or bucket
        if destination_bucket not in catalog.list_buckets():
            raise HTTPException(404, "Destination bucket not found")
        if destination_bucket == bucket and payload.destination_key == key:
            raise HTTPException(400, "Destination equals source")
        # The copy ADDS the source's full size to the destination, so the
        # quota must be checked with that size -- not 0, which only ever
        # enforced the object count and let a 50-byte bucket accept a
        # 100-byte copy.
        try:
            source_item = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        _enforce_bucket_quota(conn, destination_bucket,
                              payload.destination_key, source_item.size)
        try:
            dest_head = catalog.get(destination_bucket, payload.destination_key)
            dest_generation = dest_head.generation
            dest_id = dest_head.item.id
        except FileNotFoundError:
            dest_generation, dest_id = 0, None
        try:
            restored = copy_object(
                catalog, bucket, key,
                destination_bucket, payload.destination_key,
                expected_destination_generation=dest_generation,
                expected_destination_object_id=dest_id,
            )
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        except (CopyConflict, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        _log(f"copy object: {bucket}/{key} -> "
             f"{destination_bucket}/{payload.destination_key} "
             f"id={restored.object_id}", "storage",
             user=(getattr(request.state, "user", None) or {}).get(
                 "username") or "system")
        return {"id": restored.object_id, "bucket": destination_bucket,
                "key": payload.destination_key, "etag": restored.etag,
                "size": restored.size,
                "generation": catalog.get(
                    destination_bucket, payload.destination_key).generation}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/search", tags=["Object catalog"],
         summary="Search object keys or indexed file contents")
def admin_search_objects(q: str = Query(..., min_length=1, max_length=256),
                         mode: str = Query("key"),
                         limit: int = Query(100, ge=1, le=1000),
                         _: None = Depends(require_auth)):
    """mode=key (default): case-insensitive key search over the unified
    catalog. mode=content: full-text search over indexed file contents
    (text-extractable uploads, FTS5/tsvector) with snippets."""
    from sqlalchemy import func, select as _select
    from teledrive.storage.manifest import objects as _objects
    conn = db_connect()
    try:
        from teledrive.storage.catalog import heads as _heads
        if mode == "content":
            from teledrive.storage.content_index import search_content
            matches = search_content(conn, q, limit)
            if not matches:
                return {"query": q, "mode": "content", "objects": []}
            by_id = {object_id: snippet for object_id, snippet in matches}
            rows = conn.connection.execute(
                _select(_objects.c.id, _objects.c.bucket,
                        _objects.c.object_key, _objects.c.size,
                        _objects.c.sha256, _objects.c.created_at)
                .select_from(_heads.join(
                    _objects, _objects.c.id == _heads.c.object_id))
                .where(_objects.c.id.in_(list(by_id)))
                .limit(limit)
            ).all()
            return {"query": q, "mode": "content", "objects": [
                {"id": r[0], "bucket": r[1], "key": r[2], "size": r[3],
                 "sha256": r[4], "created_at": r[5],
                 "snippet": by_id.get(r[0], "")} for r in rows]}
        if mode != "key":
            raise HTTPException(422, "mode must be key or content")
        # Escape LIKE wildcards so user input cannot broaden the pattern.
        escaped = (q.replace(chr(92), chr(92) * 2)
                .replace("%", chr(92) + "%")
                .replace("_", chr(92) + "_")).lower()
        pattern = "%" + escaped + "%"
        escape_char = chr(92)
        rows = conn.connection.execute(
            _select(_objects.c.id, _objects.c.bucket, _objects.c.object_key,
                    _objects.c.size, _objects.c.sha256, _objects.c.created_at)
            .select_from(_heads.join(
                _objects, _objects.c.id == _heads.c.object_id))
            .where(func.lower(_objects.c.object_key).like(
                pattern, escape=escape_char))
            .order_by(_objects.c.bucket, _objects.c.object_key)
            .limit(limit)
        ).all()
        return {"query": q, "objects": [
            {"id": r[0], "bucket": r[1], "key": r[2], "size": r[3],
             "sha256": r[4], "created_at": r[5]} for r in rows]}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/search/reindex", tags=["Object catalog"],
          summary="Index file contents of existing objects (backfill)")
async def reindex_object_contents(request: Request,
                                  payload: dict = Body(None),
                                  _: None = Depends(require_auth)):
    """Downloads the head of current, unindexed, text-extractable objects
    and indexes their contents. Bounded per call; repeated calls make
    progress until everything searchable is indexed."""
    _same_origin(request)
    try:
        limit = int((payload or {}).get("limit", 25))
    except (TypeError, ValueError):
        limit = 25
    limit = max(1, min(limit, 100))
    conn = db_connect()
    try:
        from teledrive.storage.content_index import (
            MAX_INDEX_BYTES, extract_text, index_object_content)
        from sqlalchemy import text as _text
        candidates = conn.connection.execute(_text(
            "SELECT o.id, o.bucket, o.object_key FROM storage_objects o "
            "JOIN storage_object_heads h ON h.object_id = o.id "
            "WHERE o.status = 'ready' AND o.size > 0 "
            "AND NOT EXISTS (SELECT 1 FROM object_content_index c "
            "WHERE c.object_id = o.id) "
            "AND (o.object_key LIKE '%.' || :txt OR o.object_key LIKE '%.' || :json "
            "OR o.object_key LIKE '%.' || :csv OR o.object_key LIKE '%.' || :md "
            "OR o.object_key LIKE '%.' || :log OR o.object_key LIKE '%.' || :yaml "
            "OR o.object_key LIKE '%.' || :yml OR o.object_key LIKE '%.' || :xml "
            "OR o.object_key LIKE '%.' || :py OR o.object_key LIKE '%.' || :conf) "
            "LIMIT :n"
        ), {"txt": "txt", "json": "json", "csv": "csv", "md": "md",
            "log": "log", "yaml": "yaml", "yml": "yml", "xml": "xml",
            "py": "py", "conf": "conf", "n": limit}).fetchall()
        if not candidates:
            return {"ok": True, "indexed": 0, "candidates": 0}
        transport = storage_transport(conn)
        await transport.verify_target()
        manifests = ManifestStore(conn)
        engine = TelegramObjectStorage(
            manifests, transport, chunk_size=RECOMMENDED_CHUNK_SIZE,
            scratch_directory=Path(STORAGE_SCRATCH_DIR))
        indexed = 0
        errors = []
        for object_id, bucket, key in candidates:
            scratch = Path(tempfile.mkdtemp(prefix="reindex-",
                                            dir=STORAGE_SCRATCH_DIR))
            try:
                target = scratch / "head"
                # Only the extraction cap is needed, never the whole file.
                obj = manifests.get(object_id)
                end = min(MAX_INDEX_BYTES, obj.size)
                if end > 0:
                    async for piece in engine.iter_bytes(
                            object_id, start=0, end=end):
                        with open(target, "ab") as out:
                            out.write(piece)
                if extract_text(target, key) is None:
                    # Mark non-text objects as examined so they are not
                    # retried forever: an empty index row.
                    # Portable idempotent insert: the row may already exist
                    # (reindex of an unchanged object). "INSERT OR IGNORE" is
                    # SQLite-only; check first, and let the primary key catch
                    # a concurrent insert.
                    already = conn.connection.execute(_text(
                        "SELECT 1 FROM object_content_index "
                        "WHERE object_id = :i"), {"i": object_id}).first()
                    if already is None:
                        try:
                            conn.connection.execute(_text(
                                "INSERT INTO object_content_index "
                                "(object_id, text, indexed_at) "
                                "VALUES (:i, '', :n)"),
                                {"i": object_id, "n": int(time.time())})
                        except Exception:
                            conn.connection.rollback()
                    conn.commit()
                    continue
                if index_object_content(conn, object_id, target, key):
                    indexed += 1
            except Exception as exc:
                errors.append({"object_id": object_id,
                               "error": type(exc).__name__})
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
        _log(f"content reindex: indexed={indexed} candidates={len(candidates)}",
             "storage")
        return {"ok": True, "indexed": indexed, "candidates": len(candidates),
                "errors": errors}
    finally:
        conn.close()


class BucketQuotaRequest(BaseModel):
    max_size_bytes: int | None = None
    max_objects: int | None = None


# The implementation lives in the storage layer so the job worker enforces
# the same rules as the REST/S3 handlers (a job previously bypassed them).
def _bucket_quota(conn, bucket: str) -> tuple[int | None, int | None]:
    from teledrive.storage import quota as _quota
    return _quota.bucket_quota(conn, bucket)


def _bucket_current_usage(conn, bucket: str) -> tuple[int, int]:
    from teledrive.storage import quota as _quota
    return _quota.bucket_current_usage(conn, bucket)


def _bucket_has_current_key(conn, bucket: str, key: str) -> bool:
    from teledrive.storage import quota as _quota
    return _quota.has_current_key(conn, bucket, key)


def _enforce_bucket_quota(conn, bucket: str, key: str, incoming_size: int) -> None:
    """TeleDrive-level per-bucket quota enforcement (HTTP 413 on breach)."""
    from teledrive.storage import quota as _quota
    try:
        _quota.enforce_bucket_quota(conn, bucket, key, incoming_size)
    except _quota.QuotaExceeded as exc:
        raise HTTPException(413, str(exc)) from exc


@app.get("/api/v1/admin/storage/buckets/{bucket}/quota", tags=["Object catalog"],
         summary="Get bucket quota")
def admin_get_quota(bucket: str, _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        max_size, max_objects = _bucket_quota(conn, bucket)
        return {"bucket": bucket, "max_size_bytes": max_size, "max_objects": max_objects}
    finally:
        conn.close()


@app.put("/api/v1/admin/storage/buckets/{bucket}/quota", tags=["Object catalog"],
         summary="Set bucket quota")
def admin_set_quota(bucket: str, payload: BucketQuotaRequest, request: Request,
                    _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        from teledrive.storage import quota as _quota
        _quota.set_bucket_quota(
            conn, bucket, payload.max_size_bytes, payload.max_objects,
            int(time.time()))
        _log(f"set quota: bucket={bucket} max_size={payload.max_size_bytes} max_objects={payload.max_objects}", "storage")
    finally:
        conn.close()
    return {"ok": True}

def _prom_escape(value: str) -> str:
    return (str(value).replace("\\", "\\\\")
            .replace('"', '\\"').replace("\n", "\\n"))


@app.get("/api/v1/metrics", tags=["Observability"],
         summary="Prometheus metrics: jobs, quotas, Telegram sessions, floods")
def prometheus_metrics(_: None = Depends(require_auth)):
    """Text exposition format 0.0.4; scrape with HTTP auth like any API route."""
    from sqlalchemy import text as _text, func, select
    from teledrive.storage import quota as _quota

    lines: list[str] = [
        "# HELP teledrive_up Service is running and answering.",
        "# TYPE teledrive_up gauge",
        "teledrive_up 1",
    ]
    conn = db_connect()
    try:
        try:
            counts = conn.connection.execute(
                select(storage_job_rows.c.state, func.count())
                .group_by(storage_job_rows.c.state)).all()
        except Exception:
            counts = []
        if counts:
            lines += ["# HELP teledrive_storage_jobs Upload jobs by state.",
                      "# TYPE teledrive_storage_jobs gauge"]
            for state, count in counts:
                lines.append('teledrive_storage_jobs{state="%s"} %d'
                             % (_prom_escape(state), int(count)))

        quotas = _quota.all_bucket_quotas(conn)
        if quotas:
            lines += ["# HELP teledrive_quota_limit_bytes Bucket size quota.",
                      "# TYPE teledrive_quota_limit_bytes gauge",
                      "# HELP teledrive_quota_limit_objects Bucket object-count quota.",
                      "# TYPE teledrive_quota_limit_objects gauge",
                      "# HELP teledrive_quota_used_bytes Current bucket size.",
                      "# TYPE teledrive_quota_used_bytes gauge",
                      "# HELP teledrive_quota_used_objects Current bucket objects.",
                      "# TYPE teledrive_quota_used_objects gauge"]
        for bucket, max_size, max_objects in quotas:
            label = 'bucket="%s"' % _prom_escape(bucket)
            if max_size is not None:
                lines.append("teledrive_quota_limit_bytes{%s} %d"
                             % (label, int(max_size)))
            if max_objects is not None:
                lines.append("teledrive_quota_limit_objects{%s} %d"
                             % (label, int(max_objects)))
            try:
                used_count, used_size = _bucket_current_usage(
                    conn, str(bucket))
                lines.append("teledrive_quota_used_bytes{%s} %d"
                             % (label, used_size))
                lines.append("teledrive_quota_used_objects{%s} %d"
                             % (label, used_count))
            except Exception:
                pass  # catalog tables live in another database

        sessions = conn.connection.execute(_text(
            "SELECT account, authorized FROM telegram_sessions")).fetchall()
        if sessions:
            lines += [
                "# HELP teledrive_telegram_session_authorized "
                "1 = authorized, 0 = expired/revoked.",
                "# TYPE teledrive_telegram_session_authorized gauge",
            ]
        quotas = conn.connection.execute(_text(
            "SELECT account, soft_quota_bytes FROM telegram_sessions"
        )).fetchall()
        for account, authorized in sessions:
            label = 'account="%s"' % _prom_escape(account)
            if authorized is not None:
                lines.append("teledrive_telegram_session_authorized{%s} %d"
                             % (label, int(authorized)))
        if quotas:
            lines += ["# HELP teledrive_telegram_session_soft_quota_bytes "
                      "Configured soft quota (omitted = unlimited).",
                      "# TYPE teledrive_telegram_session_soft_quota_bytes gauge"]
            for account, quota in quotas:
                if quota is not None:
                    lines.append('teledrive_telegram_session_soft_quota_bytes'
                                 '{account="%s"} %d'
                                 % (_prom_escape(account), int(quota)))

        # Rate-guard tables live in the storage catalog; degrade quietly
        # when this deployment's web database does not carry them.
        try:
            floods = conn.connection.execute(_text(
                "SELECT account, COALESCE(SUM(observations), 0) FROM "
                "storage_mtproto_flood_observations GROUP BY account")).fetchall()
            if floods:
                lines += ["# HELP teledrive_flood_observations_total "
                          "Observed Telegram flood-waits per account.",
                          "# TYPE teledrive_flood_observations_total counter"]
                for account, obs in floods:
                    lines.append('teledrive_flood_observations_total'
                                 '{account="%s"} %d'
                                 % (_prom_escape(account), int(obs)))
        except Exception:
            pass
        now_ms = int(time.time() * 1000)
        try:
            cooldowns = conn.connection.execute(_text(
                "SELECT account, MAX(cooldown_until_ms) FROM "
                "storage_mtproto_chat_cooldowns GROUP BY account")).fetchall()
            if cooldowns:
                lines += ["# HELP teledrive_flood_cooldown_remaining_seconds "
                          "Active shared flood cooldown per account.",
                          "# TYPE teledrive_flood_cooldown_remaining_seconds gauge"]
                for account, until in cooldowns:
                    lines.append('teledrive_flood_cooldown_remaining_seconds'
                                 '{account="%s"} %d'
                                 % (_prom_escape(account),
                                    max(0, (int(until or 0) - now_ms) // 1000)))
        except Exception:
            pass
    finally:
        conn.close()
    return Response(content="\n".join(lines) + "\n",
                    media_type="text/plain; charset=utf-8")


@app.get("/api/v1/admin/storage/buckets/{bucket}/pin",
         tags=["Object catalog"],
         summary="Read the bucket's account pin")
def admin_get_bucket_pin(bucket: str, _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        pin = _pin_store.get(conn, bucket)
        return {"bucket": bucket, "account": pin}
    finally:
        conn.close()


@app.put("/api/v1/admin/storage/buckets/{bucket}/pin",
         tags=["Object catalog"],
         summary="Pin the bucket's uploads to a Telegram account")
def admin_put_bucket_pin(bucket: str, request: Request,
                         payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    _same_origin(request)
    account = str(payload.get("account", "")).strip()
    if not account:
        raise HTTPException(422, "account is required")
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        if not conn.connection.execute(_text(
                "SELECT 1 FROM telegram_sessions WHERE account = :a"),
                {"a": account}).first():
            raise HTTPException(404, "Unknown Telegram session account")
        _pin_store.set(conn, bucket, account, int(time.time()))
    finally:
        conn.close()
    _log(f"bucket pin set: bucket={bucket} account={account}", "storage")
    return {"ok": True, "bucket": bucket, "account": account}


@app.delete("/api/v1/admin/storage/buckets/{bucket}/pin",
            tags=["Object catalog"],
            summary="Remove the bucket's account pin")
def admin_delete_bucket_pin(bucket: str, request: Request,
                            _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        _pin_store.delete(conn, bucket)
    finally:
        conn.close()
    return {"ok": True}


@app.get("/api/v1/admin/storage/version-history", tags=["Object catalog"],
         summary="Object version history incl. delete markers (WebUI)")
def admin_list_object_versions(
        bucket: str | None = Query(None),
        limit: int = Query(200, ge=1, le=1000),
        _: None = Depends(require_auth)):
    """Published versions and delete markers, newest first.

    This is the UI's object-history view: unlike the upload-job history,
    it covers EVERY write path (S3 browser, REST, multipart, copies)
    and shows delete markers, so deleted objects remain traceable until
    physical GC removes their retained media. Distinct from
    /storage/versions, which lists ONE key's versions for restore."""
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        buckets = [bucket] if bucket else catalog.list_buckets()
        entries = []
        for name in buckets:
            try:
                page, _ = catalog.list_bucket_versions(
                    name, prefix="", key_marker="", version_marker="",
                    limit=limit)
            except Exception:
                continue
            for entry in page:
                entries.append({
                    "bucket": name, "key": entry["key"],
                    "version_id": entry["version_id"],
                    "is_current": entry["is_current"],
                    "is_delete_marker": entry["is_delete_marker"],
                    "size": entry.get("size"),
                    "sha256": entry.get("sha256"),
                    "committed_at": entry["committed_ns"] // 1_000_000_000,
                })
        entries.sort(key=lambda e: (e["committed_at"], e["version_id"]),
                     reverse=True)
        return {"versions": entries[:limit], "count": len(entries)}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/gc", tags=["Storage GC"],
         summary="Physical GC state, logical vs physical metrics (WebUI)")
def gc_status(_: None = Depends(require_auth)):
    """Owner-facing GC view: the toggle state, the split between
    LOGICAL usage (current heads) and PHYSICAL Telegram storage, the
    reclaimable backlog and what previous collections removed. The
    informational gates mirror the GC plan contract."""
    conn = db_connect()
    try:
        gcx = RetainedMediaGC(conn)
        return {
            "state": gcx.state(),
            "metrics": gcx.metrics(),
            "gates": {
                "independent_payload_backup_verified": False,
                "restore_drill_verified": False,
                "writer_barrier_verified": True,
                "owner_toggle_required": not gcx.state()["enabled"],
            },
        }
    finally:
        conn.close()


@app.put("/api/v1/admin/storage/gc", tags=["Storage GC"],
         summary="Enable or disable physical GC (owner decision)")
def gc_toggle(request: Request, payload: GCToggleRequest,
              _: None = Depends(require_auth)):
    _same_origin(request)
    if payload.enabled and payload.confirm != "PHYSICAL-GC":
        raise HTTPException(
            422, 'Enabling physical GC requires confirm="PHYSICAL-GC"')
    user = getattr(request.state, "user", {}) or {}
    conn = db_connect()
    try:
        gcx = RetainedMediaGC(conn)
        try:
            gcx.set_enabled(payload.enabled, by=str(user.get("username", "?")),
                            grace_seconds=payload.grace_seconds)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        _log(f"physical gc {'ENABLED' if payload.enabled else 'disabled'} "
             f"by {user.get('username', '?')} — Telegram media of logically "
             f"deleted objects becomes reclaimable via collect",
             "gc")
        return {"ok": True, "state": gcx.state()}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/gc/collect", tags=["Storage GC"],
          summary="Preview (dry-run) or execute physical collection of retained media")
async def gc_collect(request: Request, payload: GCCollectRequest,
                     _: None = Depends(require_auth)):
    """Dry-run (default) enumerates the fail-closed candidate set.
    Execution additionally requires GC enabled and the typed
    confirmation. Every candidate is re-verified immediately before its
    Telegram messages are deleted; partial failures stay retryable."""
    _same_origin(request)
    conn = db_connect()
    try:
        gcx = RetainedMediaGC(conn)
        try:
            candidates = gcx.candidates(
                scope=payload.scope, min_age_seconds=payload.min_age_seconds,
                limit=payload.limit)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if payload.dry_run:
            return {"dry_run": True, "scope": payload.scope,
                    "count": len(candidates), "candidates": candidates}
        if payload.confirm != "DELETE-RETAINED":
            raise HTTPException(
                422, 'Executing collection requires confirm="DELETE-RETAINED"')
        if not gcx.state()["enabled"]:
            raise HTTPException(
                409, "Physical GC is disabled; enable it first (owner gate)")
        transport = storage_transport(conn)
        user = getattr(request.state, "user", {}) or {}
        # A physical collection is the one irreversible action in the
        # product: it gets a durable trail with the candidate count, the
        # scope and the real actor, before and after.
        _audit(request, "gc.collect.start", target=payload.scope,
               detail={"candidates": len(candidates),
                       "min_age_seconds": payload.min_age_seconds})
        _log(f"physical gc collect START scope={payload.scope} "
             f"candidates={len(candidates)} by {user.get('username', '?')}",
             "gc")
        report = await gcx.collect(
            transport, scope=payload.scope,
            min_age_seconds=payload.min_age_seconds,
            chunk_refs=candidates)
        _audit(request, "gc.collect.done", target=payload.scope,
               outcome="partial" if report["failed"] else "ok",
               detail={"collected": len(report["collected"]),
                       "skipped": len(report["skipped"]),
                       "failed": len(report["failed"]),
                       "bytes": sum(c.get("bytes", 0)
                                    for c in report["collected"])})
        _log(f"physical gc collect DONE scope={payload.scope} "
             f"collected={len(report['collected'])} "
             f"skipped={len(report['skipped'])} "
             f"failed={len(report['failed'])}", "gc")
        return {"dry_run": False, "scope": payload.scope, **report,
                "metrics": gcx.metrics()}
    finally:
        conn.close()


@app.get("/api/v1/admin/audit", tags=["Users"],
         summary="Durable security-event trail (admin only)")
def list_security_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    action: str | None = Query(default=None, max_length=64),
    actor: str | None = Query(default=None, max_length=128),
    _: None = Depends(require_auth),
):
    """Who changed what authority, and when.

    Admin-only because the entries name users, buckets, keys and objects.
    The in-memory log buffer is a debugging aid; this is the trail.
    """
    from teledrive.storage import audit as _audit_store
    conn = db_connect()
    try:
        return {"events": _audit_store.recent(
            conn, limit=limit, action=action, actor=actor)}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/usage", tags=["Storage jobs"],
         summary="Daily upload volume (objects, bytes) for the last N days")
def storage_usage_series(days: int = Query(default=30, ge=1, le=365),
                         _: None = Depends(require_auth)):
    """Publication-timestamped usage series for the dashboard chart.

    Aggregation happens in Python: portable across SQLite and
    PostgreSQL, and defensive when the catalog tables live in another
    database.
    """
    cutoff_ns = (int(time.time()) - days * 86400) * 1_000_000_000
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        try:
            rows = conn.connection.execute(_text(
                "SELECT p.committed_ns, o.size FROM "
                "storage_published_versions p JOIN storage_objects o "
                "ON o.id = p.object_id WHERE p.committed_ns >= :cutoff "
                "ORDER BY p.committed_ns"
            ), {"cutoff": cutoff_ns}).fetchall()
        except Exception:
            rows = []
    finally:
        conn.close()
    daily: dict[str, dict] = {}
    for committed_ns, size in rows:
        day = time.strftime("%Y-%m-%d",
                            time.localtime(int(committed_ns) / 1e9))
        entry = daily.setdefault(day, {"date": day, "objects": 0,
                                       "bytes": 0})
        entry["objects"] += 1
        entry["bytes"] += int(size or 0)
    return {"days": days, "series": [daily[k] for k in sorted(daily)],
            "total_objects": len(rows),
            "total_bytes": sum(int(r[1] or 0) for r in rows)}


@app.get("/api/v1/admin/storage/health", tags=["Storage jobs"],
         summary="Read storage jobs, stale leases and protected-media metrics")
def storage_operations_health(_: None = Depends(require_auth)):
    from sqlalchemy import func, select

    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        queue = StorageUploadJobs(catalog)
        counts = conn.connection.execute(
            select(storage_job_rows.c.state, func.count())
            .group_by(storage_job_rows.c.state)
        ).all()
        now = int(time.time())
        pending = catalog.manifests.stale_pending(now=now, limit=1000)
        completing = MultipartStore(catalog).stale_completions(now=now, limit=1000)
        try:
            gc = StorageGCInventory(catalog.manifests).inspect()
        except RuntimeError as exc:
            raise HTTPException(409, "Reference graph is inconsistent; GC blocked") from exc
        states = {state: int(count) for state, count in counts}
        alerts = []
        if gc.unresolved_mtproto_intents:
            alerts.append({
                "code": "unresolved_mtproto_sends", "severity": "critical",
                "count": gc.unresolved_mtproto_intents,
                "message": "MTProto sends have unknown acceptance; do not retry until owner-verified reconciliation",
            })
        if gc.unjournaled_mtproto_receipts:
            alerts.append({
                "code": "unjournaled_mtproto_receipts", "severity": "warning",
                "count": gc.unjournaled_mtproto_receipts,
                "message": "MTProto send receipts not yet linked to a chunk journal; review persistent samples",
            })
        if states.get("failed", 0):
            alerts.append({
                "code": "failed_upload_jobs", "severity": "warning",
                "count": states["failed"],
                "message": "Failed upload jobs require explicit operator retry or cancellation",
            })
        if pending:
            alerts.append({
                "code": "stale_pending_uploads", "severity": "warning",
                "count": len(pending),
                "message": "Expired PENDING writers need dry-run recovery review",
            })
        if completing:
            alerts.append({
                "code": "stale_multipart_completions", "severity": "warning",
                "count": len(completing),
                "message": "Stale multipart completion leases need dry-run review",
            })
        truncated = len(pending) >= 1000 or len(completing) >= 1000
        if truncated:
            alerts.append({
                "code": "sample_limit_reached", "severity": "critical",
                "count": None,
                "message": "Recovery sample limit reached; inventory may be incomplete",
            })
        return {
            "job_states": states,
            "alerts": alerts,
            "unresolved_alert_count": len(alerts),
            "stale_pending_sample_count": len(pending),
            "stale_multipart_sample_count": len(completing),
            "unjournaled_mtproto_receipt_count": gc.unjournaled_mtproto_receipts,
            "unresolved_mtproto_send_count": gc.unresolved_mtproto_intents,
            "mtproto_explicit_flood_total": MtprotoRateGuard(
                conn
            ).total_explicit_flood_observations(),
            "samples_truncated": truncated,
            "telegram_messages_retained": gc.total_telegram_messages,
            "live_object_heads": gc.live_object_heads,
            "copy_aliases": gc.copy_aliases,
            "physical_deletion_enabled": False,
        }
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/mtproto-unresolved", tags=["Storage jobs"],
         summary="Inspect unresolved USER-MTProto send intents without modifying Telegram")
def list_unresolved_mtproto_sends(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    # Operator-only diagnostic: return immutable source identity for
    # independent channel proof. Never accept unverified receipt IDs or
    # perform a retry/deletion as a side effect of inspecting this list.
    from sqlalchemy import func, select
    from teledrive.storage.user_mode import mtproto_send_intents

    conn = db_connect()
    try:
        rows = conn.connection.execute(
            select(
                mtproto_send_intents.c.account, mtproto_send_intents.c.chat_id,
                mtproto_send_intents.c.object_id, mtproto_send_intents.c.ordinal,
                mtproto_send_intents.c.sha256, mtproto_send_intents.c.size,
            ).where(mtproto_send_intents.c.message_id.is_(None))
            .order_by(mtproto_send_intents.c.object_id,
                      mtproto_send_intents.c.ordinal)
            .limit(limit)
        ).all()
        total = conn.connection.execute(
            select(func.count()).select_from(mtproto_send_intents).where(
                mtproto_send_intents.c.message_id.is_(None)
            )
        ).scalar_one()
        return {
            "total": int(total),
            "intents": [
                {
                    "account": account, "chat_id": int(chat_id),
                    "object_id": object_id, "ordinal": int(ordinal),
                    "sha256": sha256, "size": int(size),
                }
                for account, chat_id, object_id, ordinal, sha256, size in rows
            ],
            "message": (
                "Possible remotely accepted USER-MTProto sends. Independently "
                "verify the original channel message ID and full Telegram "
                "bytes before recording any recovery receipt. No automatic retry."
            ),
        }
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/jobs", tags=["Storage jobs"],
         summary="Inspect durable local-source upload jobs (no worker tokens)")
def list_storage_upload_jobs(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = db_connect()
    try:
        return {"jobs": StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
                .list_jobs(limit=limit)}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/jobs", tags=["Storage jobs"],
          status_code=201, summary="Queue an allowed-root file for Telegram upload")
def create_storage_upload_job(
    request: Request, payload: StorageUploadJobRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    _log(f"queue job: bucket={payload.bucket} key={payload.key} source={payload.source_path}", "jobs")
    root = _storage_job_root()
    conn = db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        try:
            job_id = manager.enqueue(
                payload.bucket, payload.key, Path(payload.source_path),
                allowed_root=root,
            )
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except (UploadJobError, ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": job_id, "state": "queued"}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/jobs/import-legacy",
          tags=["Storage jobs"], summary="Preview or queue legacy folder files without uploading")
def import_legacy_folder_jobs(
    request: Request, payload: LegacyFolderImportRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    from teledrive.storage.legacy_bridge import enqueue_legacy_folder
    approved_root = _storage_job_root()
    cfg = effective_config()
    try:
        source_root = Path(cfg.source_dir).resolve(strict=True)
    except OSError as exc:
        raise HTTPException(503, "Legacy source folder unavailable") from exc
    if not source_root.is_relative_to(approved_root):
        raise HTTPException(403, "Legacy source is outside the configured job root")
    conn = db_connect()
    try:
        now = int(time.time())
        holder = "legacy-bridge-" + os.urandom(16).hex()
        if not conn.acquire_lease(
            uploader.LEASE_NAME, holder, now, uploader.LEASE_TTL_SECONDS
        ):
            raise HTTPException(409, "Legacy uploader currently holds a lease")
        try:
            last_renew = time.monotonic()

            def heartbeat():
                nonlocal last_renew
                if time.monotonic() - last_renew < 10:
                    return
                if not conn.renew_lease(
                    uploader.LEASE_NAME, holder,
                    int(time.time()), uploader.LEASE_TTL_SECONDS
                ):
                    raise RuntimeError("Legacy uploader lease lost during import")
                last_renew = time.monotonic()

            manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
            try:
                report = enqueue_legacy_folder(
                    cfg, manager, bucket=payload.bucket, prefix=payload.prefix,
                    max_files=payload.max_files,
                    dry_run=not payload.execute, lease_heartbeat=heartbeat,
                )
            except FileNotFoundError as exc:
                raise HTTPException(404, "Destination object bucket not found") from exc
            except (UploadJobError, ValueError, OSError) as exc:
                raise HTTPException(422, str(exc)) from exc
            return {
                "dry_run": not payload.execute,
                "queued": report.queued if payload.execute else 0,
                "would_queue": report.queued,
                "already_queued": report.already_queued,
                "excluded": report.excluded,
                "job_ids": list(report.job_ids) if payload.execute else [],
                "uploads_started": 0,
            }
        finally:
            conn.release_lease(uploader.LEASE_NAME, holder)
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/jobs/run-next", tags=["Storage jobs"],
          summary="Process one queued upload with SQL lease, checksums and CAS")
async def run_next_storage_upload_job(
    request: Request, _: None = Depends(require_auth),
):
    _same_origin(request)
    _log("run-next job triggered", "jobs")
    root = _storage_job_root()
    conn = db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        transport = storage_transport(conn)
        scratch = Path(STORAGE_SCRATCH_DIR)
        _secure_mkdir(scratch)
        try:
            result = await manager.run_next(
                transport, allowed_root=root, scratch_directory=scratch,
                chunk_size=RECOMMENDED_CHUNK_SIZE,
            )
        except (UploadJobError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(503, "Telegram upload failed; job retained for retry") from exc
        return {"job": result}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/jobs/{job_id}/retry", tags=["Storage jobs"],
          summary="Explicitly retry a failed job; never remove Telegram messages")
def retry_storage_upload_job(
    job_id: str, request: Request, _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        if not manager.retry(job_id):
            raise HTTPException(409, "Job is not failed or does not exist")
        return {"id": job_id, "state": "queued"}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/jobs/{job_id}/cancel", tags=["Storage jobs"],
          summary="Cancel only inactive jobs; preserve all Telegram media")
def cancel_storage_upload_job(
    job_id: str, request: Request, _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        if not manager.cancel(job_id):
            raise HTTPException(409, "Job is active, completed, cancelled or does not exist")
        return {"id": job_id, "state": "cancelled"}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/pending-stale", tags=["Storage recovery"],
         summary="Preview aged PENDING upload leases; no Telegram deletion")
def list_stale_pending_objects(
    min_age_seconds: int = Query(default=3600, ge=60, le=30 * 86400),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = db_connect()
    try:
        items = ManifestStore(conn).stale_pending(
            now=int(time.time()), min_age_seconds=min_age_seconds, limit=limit
        )
        return {"uploads": items, "dry_run": True, "physical_deletion_enabled": False}
    finally:
        conn.close()


@app.post("/api/v1/admin/storage/pending-stale/{object_id}/abandon",
          tags=["Storage recovery"],
          summary="Explicitly fence an aged PENDING writer and retain Telegram journal")
def abandon_stale_pending_object(
    object_id: str, request: Request,
    payload: PendingUploadRecoveryRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = db_connect()
    try:
        manifests = ManifestStore(conn)
        now = int(time.time())
        # A preview never mutates the writer's lease, even after a restart.
        if not payload.execute:
            matches = manifests.stale_pending(
                now=now, min_age_seconds=payload.min_age_seconds, limit=1000
            )
            return {"object_id": object_id,
                    "eligible": any(item["id"] == object_id for item in matches),
                    "abandoned": False, "dry_run": True}
        # Only this object can be transitioned. The SQL conditional update
        # ensures a heartbeat, completed object or another admin wins safely.
        affected = manifests.abandon_stale_pending(
            now=now, min_age_seconds=payload.min_age_seconds,
            limit=1, object_id=object_id,
        )
        return {"object_id": object_id, "eligible": bool(affected),
                "abandoned": bool(affected), "dry_run": False}
    finally:
        conn.close()


@app.get("/api/v1/admin/storage/channel-history", tags=["Storage history"],
         summary="Bounded read-only user-MTProto channel history (unverified candidates)")
async def inspect_user_channel_history(
    limit: int = Query(default=100, ge=1, le=1000),
    before_message_id: int | None = Query(default=None, ge=1),
    include_external_markers: bool = Query(default=False),
    _: None = Depends(require_auth),
):
    """Never download media, change catalog mappings or delete channel posts.

    Other senders' markers are NOT trusted ownership/manifest evidence.
    The endpoint deliberately only runs with the already-connected USER
    transport; only an authorized user session can enumerate channel history.
    """
    try:
        runtime = mtproto_storage_runtime
        runtime.require()
        target = runtime.transport.accounts[runtime.account][1]
        return await inventory_channel(
            runtime.client, target, account=runtime.account,
            scan_limit=limit, before_message_id=before_message_id,
            include_external_markers=include_external_markers,
        )
    except (ValueError, RuntimeError, OSError):
        raise HTTPException(503, "Authorized channel history inspection unavailable") from None


@app.get("/api/v1/admin/s3-multipart/stale", tags=["API keys"],
         summary="Preview expired multipart completion leases (never deletes chunks)")
def list_stale_s3_completions(
    min_age_seconds: int = Query(default=3600, ge=60, le=30 * 86400),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = db_connect()
    try:
        mpu = MultipartStore(BucketCatalog(ManifestStore(conn)))
        return {"uploads": mpu.stale_completions(
            min_age_seconds=min_age_seconds, limit=limit
        )}
    finally:
        conn.close()


@app.post("/api/v1/admin/s3-multipart/{upload_id}/recover", tags=["API keys"],
          summary="Dry-run or explicitly recover an expired multipart completion lease")
def recover_stale_s3_completion(
    request: Request, upload_id: str, payload: S3CompletionRecoveryRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = db_connect()
    try:
        mpu = MultipartStore(BucketCatalog(ManifestStore(conn)))
        eligible = mpu.recover_stale_completion(
            upload_id, dry_run=not payload.execute,
            min_age_seconds=payload.min_age_seconds,
        )
        return {"upload_id": upload_id, "eligible": eligible,
                "recovered": bool(eligible and payload.execute),
                "dry_run": not payload.execute}
    finally:
        conn.close()


@app.get("/api/v1/admin/s3/credentials", tags=["API keys"],
         summary="List S3 access key metadata (secrets never returned)")
@app.get("/api/v1/admin/s3-credentials", tags=["API keys"],
         include_in_schema=False)
def list_s3_credentials(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        try:
            return {"credentials": S3CredentialStore(conn, load_master_key()).list()}
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
    finally:
        conn.close()


def _require_interactive_session(request: Request, what: str) -> str:
    """Refuse an API-key caller for a secret-bearing S3 credential action.

    An S3 credential IS a secret and its permission set is the whole
    authorization surface of the S3 gateway. Letting an API key mint, edit,
    revoke or reveal one creates a chain of secrets that bypasses the
    delegation ceiling: the review proved a key scoped to only
    ``post:/api/v1/admin/s3/credentials`` could create a credential with all
    90 permissions (including s3:PutBucketPolicy and s3:DeleteBucket) and
    receive its secret, then edit an existing least-privilege credential to
    add destructive permissions. A human session is interactive, CSRF-fenced
    and revocable, so that is the only principal allowed here.

    Returns the actor name for the audit line.
    """
    if getattr(request.state, "api_key_scopes", None) is not None:
        _log(f"denied: api-key attempted to {what} an S3 credential",
             "security")
        raise HTTPException(
            403,
            "S3 credentials can only be managed from an interactive "
            "session, never with an API key",
        )
    return (getattr(request.state, "user", None) or {}).get("username") \
        or "unknown"


def _credential_error(exc: Exception) -> HTTPException:
    """Map a credential-store failure without leaking the master-key path."""
    if isinstance(exc, (RuntimeError, OSError)):
        return HTTPException(
            503, "S3 credentials are unavailable: the master key cannot be "
                 "loaded")
    return HTTPException(422, str(exc))


@app.post("/api/v1/admin/s3/credentials", tags=["API keys"], status_code=201,
          summary="Issue encrypted S3 access credentials (secret displayed once)")
@app.post("/api/v1/admin/s3-credentials", tags=["API keys"], status_code=201,
          include_in_schema=False)
def issue_s3_credentials(request: Request, payload: S3KeyCreateRequest,
                         _: None = Depends(require_auth)):
    _same_origin(request)
    actor = _require_interactive_session(request, "issue")
    conn = db_connect()
    try:
        try:
            key = S3CredentialStore(conn, load_master_key()).create(
                payload.name, payload.permissions, expires_at=payload.expires_at
            )
        except (RuntimeError, OSError, ValueError) as exc:
            raise _credential_error(exc) from exc
        _log(f"s3 credential issued: id={key.id} access={key.access_key} "
             f"permissions={len(key.permissions)} "
             f"expires_at={payload.expires_at}", "security", user=actor)
        _audit(request, "credential.issue", target=key.id,
               detail={"access_key": key.access_key,
                       "permissions": len(key.permissions),
                       "expires_at": payload.expires_at})
        return {"id": key.id, "access_key": key.access_key,
                "secret_key": key.secret_key, "permissions": key.permissions}
    finally:
        conn.close()


@app.get("/api/v1/admin/s3/credentials/{identifier}/secret",
         tags=["API keys"],
         summary="Reveal an S3 credential secret (session only, audit-logged)")
@app.get("/api/v1/admin/s3-credentials/{identifier}/secret",
         tags=["API keys"], include_in_schema=False)
def reveal_s3_credential_secret(request: Request, identifier: str,
                                _: None = Depends(require_auth)):
    """Hand out a decrypted S3 secret. Interactive sessions only.

    Why API keys are refused here: an API key is itself a credential, so
    letting one reveal another credential's secret creates a chain of secret
    holders and bypasses the delegation ceiling that blocks minting or
    rotating a more privileged key. A key scoped to just this route could
    otherwise read the secret of a credential holding s3:PutBucketPolicy,
    which is a privilege escalation with no audit trail tying it to a person.
    A human session is interactive, CSRF-fenced and revocable, so it is the
    only principal allowed to see a secret.
    """
    actor = _require_interactive_session(request, "reveal the secret of")
    if not isinstance(identifier, str) or not 1 <= len(identifier) <= 200:
        raise HTTPException(422, "Invalid credential identifier")
    conn = db_connect()
    try:
        try:
            revealed = S3CredentialStore(
                conn, load_master_key()).reveal(identifier)
        except RuntimeError as exc:
            # Never echo a path or key state; the audit line carries the
            # reason class only.
            _log(f"s3 credential secret reveal failed: id={identifier} "
                 f"reason=runtime", "security", user=actor)
            raise HTTPException(
                503, "Credential secrets are unavailable: the master key "
                     "cannot be loaded") from exc
        except OSError as exc:
            _log(f"s3 credential secret reveal failed: id={identifier} "
                 f"reason=master-key-io", "security", user=actor)
            raise HTTPException(
                503, "Credential secrets are unavailable: the master key "
                     "cannot be loaded") from exc
        except ValueError as exc:
            _log(f"s3 credential secret reveal failed: id={identifier} "
                 f"reason=invalid-target", "security", user=actor)
            raise HTTPException(422, str(exc)) from exc
        _log(f"s3 credential secret revealed: id={identifier} "
             f"access={revealed['access_key']}", "security", user=actor)
        _audit(request, "credential.reveal", target=str(identifier),
               detail={"access_key": revealed["access_key"]})
        return revealed
    finally:
        conn.close()


@app.put("/api/v1/admin/s3/credentials/{identifier}", tags=["API keys"],
         summary="Edit an active S3 credential (name, permissions, expiry)")
@app.put("/api/v1/admin/s3-credentials/{identifier}", tags=["API keys"],
         include_in_schema=False)
def update_s3_credentials(request: Request, identifier: str,
                          payload: dict = Body(...),
                          _: None = Depends(require_auth)):
    _same_origin(request)
    actor = _require_interactive_session(request, "edit")
    conn = db_connect()
    try:
        try:
            store = S3CredentialStore(conn, load_master_key())
            updated = store.update(
                identifier,
                name=payload.get("name"),
                permissions=payload.get("permissions"),
                expires_at=payload.get("expires_at"),
                clear_expiry=payload.get("clear_expiry") is True,
            )
        except (RuntimeError, OSError, ValueError) as exc:
            raise _credential_error(exc) from exc
        _audit(request, "credential.edit", target=str(identifier),
               detail={"permissions_changed": payload.get("permissions")
                       is not None,
                       "expires_at": payload.get("expires_at")})
        _log(f"s3 credential edited: id={identifier} "
             f"permissions={None if payload.get('permissions') is None else len(payload['permissions'])} "
             f"expires_at={payload.get('expires_at')} "
             f"clear_expiry={payload.get('clear_expiry') is True}",
             "security", user=actor)
        return {"ok": True, "credential": updated}
    finally:
        conn.close()


@app.delete("/api/v1/admin/s3/credentials/{identifier}", tags=["API keys"],
            summary="Revoke an S3 access key immediately")
@app.delete("/api/v1/admin/s3-credentials/{identifier}", tags=["API keys"],
            include_in_schema=False)
def revoke_s3_credentials(request: Request, identifier: str,
                          _: None = Depends(require_auth)):
    _same_origin(request)
    actor = _require_interactive_session(request, "revoke")
    conn = db_connect()
    try:
        try:
            changed = S3CredentialStore(conn, load_master_key()).revoke(identifier)
        except (RuntimeError, OSError, ValueError) as exc:
            raise _credential_error(exc) from exc
        if not changed:
            raise HTTPException(404, "S3 key not found or already revoked")
        _log(f"s3 credential revoked: id={identifier}", "security", user=actor)
        _audit(request, "credential.revoke", target=str(identifier))
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/v1/buckets", tags=["Object catalog"], summary="List Telegram-backed storage buckets")
def list_storage_buckets(_: None = Depends(require_api_scope("rest:buckets:list"))):
    conn = db_connect()
    try:
        return {"buckets": BucketCatalog(ManifestStore(conn)).list_buckets()}
    finally:
        conn.close()


@app.post("/api/v1/buckets", tags=["Object catalog"], status_code=201, summary="Create a bucket")
def create_storage_bucket(payload: BucketCreateRequest,
                          _: None = Depends(require_api_scope("rest:buckets:create"))):
    conn = db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).create_bucket(payload.name, int(time.time()))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"name": payload.name}
    finally:
        conn.close()


@app.delete("/api/v1/buckets/{bucket}", tags=["Object catalog"], summary="Remove a physically empty bucket")
def remove_storage_bucket(bucket: str, _: None = Depends(require_api_scope("rest:buckets:delete"))):
    conn = db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).delete_bucket(bucket)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/v1/buckets/{bucket}/versions", tags=["Object catalog"],
         summary="List proven published immutable versions of a key")
def list_published_object_versions(
    bucket: str, key: str = Query(..., min_length=1, max_length=1024),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_api_scope("rest:objects:list-versions")),
):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        return {"bucket": bucket, "key": key,
                "versions": catalog.list_versions(bucket, key, limit=limit)}
    finally:
        conn.close()


@app.get("/api/v1/buckets/{bucket}/objects", tags=["Object catalog"], summary="List current object metadata")
def list_current_objects(bucket: str,
                         prefix: str = Query("", max_length=1024),
                         after: str | None = Query(None, max_length=1024),
                         limit: int = Query(100, ge=1, le=1000),
                         _: None = Depends(require_api_scope("rest:objects:list"))):
    conn = db_connect()
    try:
        items = BucketCatalog(ManifestStore(conn)).list_objects(bucket, prefix=prefix, after=after, limit=limit)
        return {"objects": [
            {"id": x.item.id, "key": x.item.key, "bucket": x.item.bucket,
             "size": x.item.size, "sha256": x.item.sha256,
             "created_at": x.item.created_at, "generation": x.generation}
            for x in items
        ]}
    finally:
        conn.close()


@app.delete("/api/v1/buckets/{bucket}/objects", tags=["Object catalog"], summary="Unlink a current object (Telegram data retained)")
def unlink_current_object(bucket: str, key: str = Query(..., min_length=1, max_length=1024),
                          generation: int | None = Query(None, ge=1),
                          _: None = Depends(require_api_scope("rest:objects:delete"))):
    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        # A legal hold or an open retention window forbids removing the
        # object, and the S3 path already answers AccessDenied for it. The
        # REST unlink only hid the head, so the same logical delete behaved
        # differently depending on which surface it came from.
        try:
            held_item = catalog.get(bucket, key).item
        except FileNotFoundError:
            held_item = None
        if held_item is not None:
            lock_row = catalog.db.connection.execute(
                _sa_select(objects.c.legal_hold,
                           objects.c.retention_until_ns)
                .where(objects.c.id == held_item.id)).first()
            if lock_row is not None:
                if bool(lock_row[0]):
                    raise HTTPException(
                        403, "Object is under legal hold and cannot be "
                             "unlinked")
                if (lock_row[1] is not None
                        and int(lock_row[1]) > time.time_ns()):
                    raise HTTPException(
                        403, "Object is under retention and cannot be "
                             "unlinked")
        try:
            # A versioned bucket must keep history: a permanent head removal
            # there destroys the only record of the previous version, and
            # nothing in storage_removed_versions or the metadata journal
            # would describe what happened. AWS semantics are a delete
            # marker, which is exactly what delete_marker() writes.
            if catalog.versioning_state(bucket) == "Enabled":
                marker = catalog.delete_marker(bucket, key,
                                               expected_generation=generation)
                _log(f"unlink {bucket}/{key}: delete marker {marker}", "storage")
                return {"ok": True, "unlinked": True, "delete_marker": marker}
            deleted = catalog.remove_current(
                bucket, key, expected_generation=generation
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(404, "Bucket not found") from exc
        _log(f"unlink {bucket}/{key}: removed current head", "storage")
        return {"ok": True, "unlinked": deleted}
    finally:
        conn.close()


async def _stream_object_upload(bucket: str, key: str, request: Request,
                                generation: int | None) -> dict:
    """Shared upload core: validate, stage, enforce quota, upload, publish."""
    # The key must be valid BEFORE a single byte is staged or uploaded.
    # The catalog enforces 1..1024 UTF-8 BYTES, while the query parameter
    # enforces 1024 CHARACTERS, so a multibyte key (e.g. 600 x "é" = 1200
    # bytes) passed validation, uploaded the whole payload to Telegram, and
    # only then failed at publish -- leaving a ready manifest with no
    # published version, which physical GC deliberately never collects.
    # Unreclaimable bytes are worse than a rejected request.
    if not isinstance(key, str) or not (1 <= len(key.encode("utf-8")) <= 1024):
        raise HTTPException(422, "Object key must contain 1..1024 UTF-8 bytes")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/octet-stream":
        raise HTTPException(415, "Content-Type must be application/octet-stream")
    max_size = REST_MAX_UPLOAD_BYTES
    if max_size < 1:
        raise HTTPException(503, "REST uploads are disabled by policy")
    stage_root = Path(STORAGE_SCRATCH_DIR)
    _secure_mkdir(stage_root)
    conn = db_connect()
    staged = None
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        if generation is not None:
            try:
                current_generation = catalog.get(bucket, key).generation
            except FileNotFoundError:
                current_generation = 0
            if current_generation != generation:
                # Reject stale conditional writes BEFORE staging/uploading any
                # bytes to Telegram. Recheck atomically at final publication.
                raise HTTPException(409, "Object generation precondition failed")
        transport = storage_transport(conn)
        # Verify Telegram access BEFORE consuming a potentially large body.
        await transport.verify_target()
        fd, pathname = tempfile.mkstemp(dir=stage_root, prefix="api-upload-")
        staged = Path(pathname)
        transferred = 0
        with os.fdopen(fd, "wb") as sink:
            async for data in request.stream():
                transferred += len(data)
                if transferred > max_size:
                    raise HTTPException(413, "Upload exceeds configured limit")
                sink.write(data)
            sink.flush()
            os.fsync(sink.fileno())
        # Enforce bucket quota (TeleDrive-level; S3 has no native quota).
        _enforce_bucket_quota(conn, bucket, key, transferred)
        engine = TelegramObjectStorage(manifests, transport,
                                       chunk_size=RECOMMENDED_CHUNK_SIZE,
                                       scratch_directory=stage_root)
        result = await engine.put_file(bucket, key, staged)
        try:
            head = catalog.publish(result.id, now=int(time.time()),
                                   expected_generation=generation)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"id": result.id, "bucket": bucket, "key": key,
                "size": result.size, "sha256": result.sha256,
                "generation": head.generation}
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
        conn.close()


@app.put("/api/v1/buckets/{bucket}/content", tags=["Uploads"],
         summary="Upload raw binary content to Telegram (synchronous commit)", status_code=201)
async def put_object_content(
    bucket: str, request: Request, key: str = Query(..., min_length=1, max_length=1024),
    generation: int | None = Query(None, ge=0),
    _: None = Depends(require_api_scope("rest:objects:put")),
):
    return await _stream_object_upload(bucket, key, request, generation)


@app.head("/api/v1/buckets/{bucket}/content", tags=["Uploads"],
          summary="Read object headers without downloading Telegram bytes")
def head_object_content(
    bucket: str, key: str = Query(..., min_length=1, max_length=1024),
    _: None = Depends(require_api_scope("rest:objects:head")),
):
    _valid_rest_key(key)
    conn = db_connect()
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        try:
            item = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        _rest_read_gate(manifests, catalog, item)
        return Response(status_code=200, headers={
            "ETag": '"' + item.sha256 + '"',
            "Content-Length": str(item.size),
            "Accept-Ranges": "bytes",
            "X-TeleDrive-Object-ID": item.id,
            "Content-Type": "application/octet-stream",
        })
    finally:
        conn.close()


@app.get("/api/v1/buckets/{bucket}/content", tags=["Uploads"],
         summary="Stream verified object bytes from Telegram; supports HTTP Range")
async def get_object_content(
    bucket: str, request: Request, key: str = Query(..., min_length=1, max_length=1024),
    _: None = Depends(require_api_scope("rest:objects:get")),
):
    return await _stream_object_response(bucket, key, request)


# --- Signed public share links -------------------------------------------
#
# An unauthenticated URL streaming exactly one object, bounded by
# expiry, download count and an optional password. Tokens carry 192
# bits of entropy; invalid states answer a uniform 404 so the link's
# existence is never leaked.

_SHARE_RATE_LIMIT = 60          # requests
_SHARE_RATE_WINDOW = 60.0       # seconds
_share_rate: dict[str, deque] = {}
_share_rate_lock = threading.Lock()


def _share_rate_limited(client_ip: str) -> bool:
    """Small in-memory sliding window per client IP (public surface)."""
    now = time.monotonic()
    with _share_rate_lock:
        window = _share_rate.setdefault(client_ip, deque())
        while window and now - window[0] > _SHARE_RATE_WINDOW:
            window.popleft()
        if len(window) >= _SHARE_RATE_LIMIT:
            return True
        window.append(now)
        if len(_share_rate) > 10_000:
            stale = [ip for ip, hits in _share_rate.items()
                     if not hits or now - hits[-1] > _SHARE_RATE_WINDOW]
            for ip in stale:
                del _share_rate[ip]
        return False


def _hash_share_password(password: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt),
        200_000).hex()
    return salt, digest


def _share_html(title: str, body: str, status_code: int = 200) -> Response:
    page = ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_html.escape(title)}</title><style>"
            "body{background:#111827;color:#e5e7eb;font-family:system-ui,"
            "sans-serif;display:flex;align-items:center;justify-content:"
            "center;min-height:100vh;margin:0}"
            ".card{background:#1f2937;border:1px solid #374151;border-radius:"
            "8px;padding:2rem;max-width:24rem;text-align:center}"
            "input{width:100%;box-sizing:border-box;padding:.5rem;margin:"
            ".75rem 0;border-radius:4px;border:1px solid #4b5563;"
            "background:#111827;color:#e5e7eb}"
            "button{background:#2563eb;color:#fff;border:0;border-radius:4px;"
            "padding:.5rem 1.5rem;cursor:pointer;font-weight:600}"
            ".err{color:#f87171;font-size:.9rem}"
            "</style></head><body><div class='card'>" + body +
            "</div></body></html>")
    return Response(page, status_code=status_code,
                    media_type="text/html; charset=utf-8")


def _load_active_share(token: str):
    """Fetch a usable share row; anything else collapses to 404."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
        return None
    conn = db_connect()
    try:
        return _share_store.resolve_token(conn, token, int(time.time()))
    except Exception:
        return None
    finally:
        conn.close()


async def _stream_share(row) -> StreamingResponse:
    """Stream the PINNED version, and charge a slot only if it will be sent.

    Two defects the review proved: (1) the counter was incremented BEFORE
    the object was resolved or read, so every 404, every link-preview fetch
    and every failed transfer permanently burned a download slot; (2) the
    link followed the live head by key, so it served replaced content and
    came back to life after an unlink plus a re-upload.
    """
    token, bucket, key = row["token"], row["bucket"], row["object_key"]
    pinned_id = row["object_id"]
    conn = db_connect()
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        # Resolve BEFORE claiming, and refuse anything that cannot be served.
        try:
            item = (manifests.get(pinned_id) if pinned_id
                    else catalog.get(bucket, key).item)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Link not found or expired") from exc
        # A pinned version must still describe the bucket/key it was issued
        # for: if the row no longer does, the link is dead, not re-targeted.
        if item.bucket != bucket or item.key != key:
            raise HTTPException(404, "Link not found or expired")
        if not _share_store.claim_download(conn, token, int(time.time())):
            raise HTTPException(404, "Link not found or expired")
        transport = storage_transport(conn)
        root = Path(STORAGE_SCRATCH_DIR)
        _secure_mkdir(root)
        engine = TelegramObjectStorage(
            ManifestStore(conn), transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=root)
    except BaseException:
        conn.close()
        raise

    async def stream():
        try:
            async for piece in engine.iter_bytes(item.id):
                yield piece
        finally:
            conn.close()

    filename = key.rsplit("/", 1)[-1] or "download"
    quoted = _url_quote(filename)
    return StreamingResponse(stream(), media_type="application/octet-stream",
                             headers={
                                 "Content-Length": str(item.size),
                                 "Content-Disposition":
                                     f"attachment; filename*=UTF-8''{quoted}",
                                 "X-Content-Type-Options": "nosniff",
                                 # A cache could otherwise serve the bytes
                                 # again without consuming a slot.
                                 "Cache-Control": "no-store",
                             })


@app.get("/share/{token}", tags=["Sharing"],
         summary="Public share link: stream the shared object")
async def public_share_get(token: str, request: Request):
    client_ip = request.client.host if request.client else "-"
    if _share_rate_limited(client_ip):
        raise HTTPException(429, "Too many requests")
    row = _load_active_share(token)
    if row is None:
        return _share_html(
            "Link unavailable",
            "<h2>Link not found or expired</h2>", status_code=404)
    if row["password_salt"] is not None:  # password protected
        return _share_html(
            "Protected download",
            "<h2>Protected download</h2>"
            "<p>This link requires a password.</p>"
            f"<form method='post' action='/share/{_html.escape(token)}'>"
            "<input type='password' name='password' placeholder='Password' "
            "autofocus required><button type='submit'>Download</button></form>")
    return await _stream_share(row)


@app.post("/share/{token}", tags=["Sharing"],
          summary="Public share link: unlock a password-protected object")
async def public_share_post(token: str, request: Request):
    client_ip = request.client.host if request.client else "-"
    if _share_rate_limited(client_ip):
        raise HTTPException(429, "Too many requests")
    row = _load_active_share(token)
    if row is None:
        return _share_html(
            "Link unavailable",
            "<h2>Link not found or expired</h2>", status_code=404)
    if row["password_salt"] is None:
        return await _stream_share(row)
    # The share form is always application/x-www-form-urlencoded (our
    # own HTML); parse it directly instead of pulling in python-multipart.
    raw = (await request.body()).decode("utf-8", "replace")
    fields = urllib.parse.parse_qs(raw)
    password = str((fields.get("password") or [""])[0])
    _, candidate = _hash_share_password(password, row["password_salt"])
    if not hmac.compare_digest(candidate, row["password_hash"] or ""):
        _log(f"share password rejected: token={token[:6]}… ip={client_ip}",
             "share")
        return _share_html(
            "Protected download",
            "<h2>Protected download</h2>"
            "<p class='err'>Incorrect password.</p>"
            f"<form method='post' action='/share/{_html.escape(token)}'>"
            "<input type='password' name='password' placeholder='Password' "
            "autofocus required><button type='submit'>Download</button></form>",
            status_code=401)
    return await _stream_share(row)


@app.get("/api/health", tags=["System"], response_model=OKResponse, summary="Liveness health check (unauthenticated)")
def health():
    return {"ok": True}


# --- Public website hosting (Phase I) ------------------------------------
#
# Website content is served on the APP ORIGIN, so the response must not be
# usable as a same-origin attack surface. Every response carries
# ``Content-Security-Policy: sandbox; default-src 'none'; ...``: the sandbox
# moves the document into an opaque origin (no cookies, no same-origin API
# reads) and default-src 'none' forbids scripts, styles, images and frames.
# The bucket's current ready objects only are addressable: staging manifests,
# delete markers, removed versions and ACL metadata never enter this path.

_SITE_CSP = ("sandbox; default-src 'none'; base-uri 'none'; "
             "form-action 'none'; frame-ancestors 'none'; object-src 'none'")
_SITE_MIME = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")


def _site_not_found() -> Response:
    """Uniform 404: nonexistent bucket, disabled gate and no config look alike."""
    return Response(b"Not Found\n", status_code=404, headers={
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Security-Policy": _SITE_CSP,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


def _site_path(value: str) -> str | None:
    """Decode repeatedly and reject traversal / absolute filesystem paths.

    Starlette already decodes the path parameter once; a second and third
    decode catch ``%252e%252e`` style double encoding. ``..`` and ``.``
    segments, backslashes, NUL/control characters, absolute paths and
    ``scheme://`` values are refused before any key lookup.
    """
    candidate = value
    for _ in range(3):
        if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
            return None
        if "\\" in candidate or "://" in candidate:
            return None
        if candidate.startswith("/") or candidate.startswith("~"):
            return None
        if re.match(r"[A-Za-z]:[/\\]", candidate):
            return None
        # A single trailing slash is the directory form; empty/interior
        # double slashes are ambiguous and refused.
        segments = candidate.split("/") if candidate else []
        if segments and segments[-1] == "":
            segments = segments[:-1]
        if any(segment in {"", ".", ".."} for segment in segments):
            return None
        decoded = urllib.parse.unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    else:
        return None
    return candidate


def _site_content_type(catalog, item) -> str:
    """Stored Content-Type when it is a plain media type, else a safe default."""
    try:
        stored = ObjectMetadataStore(catalog).get(item.id).get("content-type")
    except Exception:
        stored = None
    base = (stored or "").split(";", 1)[0].strip().lower()
    if not _SITE_MIME.fullmatch(base):
        return "application/octet-stream"
    if base.startswith("text/"):
        return base + "; charset=utf-8"
    return base


def _site_headers(catalog, item, status_code: int) -> tuple[dict, int]:
    headers = {
        "Content-Type": _site_content_type(catalog, item),
        "Content-Length": str(item.size),
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": _SITE_CSP,
        "Cache-Control": "no-store",
        "ETag": '"' + item.sha256 + '"',
        "Last-Modified": time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(item.created_at)),
    }
    return headers, status_code


async def _serve_site(bucket: str, path: str, request: Request) -> Response:
    try:
        BucketCatalog.validate_bucket(bucket)
    except ValueError:
        return _site_not_found()
    safe_path = _site_path(path)
    if safe_path is None:
        return _site_not_found()

    conn = db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            config = WebsiteConfigStore(catalog).get(bucket)
            public_read = catalog.public_read(bucket)
        except FileNotFoundError:
            conn.close()
            return _site_not_found()
        if not config or not config.get("enabled", True) or not public_read:
            conn.close()
            return _site_not_found()

        index_document = config["index_document"]
        if safe_path == "" or safe_path.endswith("/"):
            candidates = [safe_path + index_document]
        else:
            candidates = [safe_path, safe_path + "/" + index_document]
        item = None
        status_code = 200
        for key in candidates:
            try:
                item = catalog.get(bucket, key).item
                break
            except FileNotFoundError:
                continue
        if item is None and config.get("error_document"):
            try:
                item = catalog.get(bucket, config["error_document"]).item
                status_code = 404
            except FileNotFoundError:
                item = None
        if item is None:
            conn.close()
            return _site_not_found()

        # The public site is a READ surface, so it must obey the same gate as
        # every other one. Without this, an SSE-C object answered 200 with a
        # non-zero Content-Length and zero body bytes (a client reads that as
        # a successful empty page), and an archived object streamed normally
        # instead of answering InvalidObjectState.
        manifests = ManifestStore(conn)
        try:
            _rest_read_gate(manifests, catalog, item)
        except HTTPException:
            # A public site never explains WHY: an anonymous client gets the
            # same uniform 404 as a missing key.
            conn.close()
            return _site_not_found()

        headers, status_code = _site_headers(catalog, item, status_code)
        if request.method == "HEAD":
            conn.close()
            return Response(status_code=status_code, headers=headers)
        transport = storage_transport(conn)
        root = Path(STORAGE_SCRATCH_DIR)
        _secure_mkdir(root)
        engine = TelegramObjectStorage(
            manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=root)
    except BaseException:
        conn.close()
        raise

    async def stream():
        try:
            async for piece in engine.iter_bytes(item.id):
                yield piece
        finally:
            conn.close()

    return StreamingResponse(stream(), status_code=status_code,
                             headers=headers)


@app.get("/site/{bucket}", include_in_schema=False)
async def public_website_root(bucket: str, request: Request):
    return await _serve_site(bucket, "", request)


@app.get("/site/{bucket}/{path:path}", include_in_schema=False)
async def public_website_object(bucket: str, path: str, request: Request):
    return await _serve_site(bucket, path, request)

from web import s3_governance_api  # noqa: E402  (router import, no app logic)
app.include_router(s3_governance_api.router)
