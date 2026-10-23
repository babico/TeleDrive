from __future__ import annotations

import asyncio
import base64
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
from teledrive.storage.gc import StorageGCInventory
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.jobs import StorageUploadJobs, UploadJobError, jobs as storage_job_rows
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.copy import copy_object, CopyConflict
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from teledrive.storage.user_mode import (
    UserSessionRuntime, UserSendJournal, UnifiedUserTransport, transport_mode,
)
from teledrive.storage.history_inventory import inventory_channel
from teledrive.storage.mtproto_rate_guard import MtprotoRateGuard
mtproto_storage_runtime = UserSessionRuntime()

CONFIG_PATH = Path(os.environ.get("TELEDRIVE_CONFIG", "config/config.yaml"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
REDACTED = "__REDACTED__"

# Service settings come ONLY from config/config.yaml (owner policy); the
# TELEDRIVE_CONFIG env var just points at the file. Tests override the
# module attributes below directly.
WEB_USER = "admin"
WEB_PASSWORD = ""
WEB_PASSWORD_FILE = ""
ALLOW_INSECURE = False
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
    global WEB_USER, WEB_PASSWORD, WEB_PASSWORD_FILE, ALLOW_INSECURE
    global MAX_REQUEST_BYTES, ALLOWED_HOSTS, AUTH_DIR, STORAGE_SCRATCH_DIR
    global REST_MAX_UPLOAD_BYTES, JOB_SOURCE_ROOT, JOB_AUTO_RUN
    global ALLOWED_SQLITE_ROOTS, AUTH_FAILURE_WINDOW_SECONDS, AUTH_FAILURE_LIMIT
    global WATCH_ENABLED, WATCH_INTERVAL, WATCH_BUCKET
    global SSL_CERTFILE, SSL_KEYFILE, DB_EXTRA_PACKAGES
    global S3_SSL_CERTFILE, S3_SSL_KEYFILE, TRUSTED_PROXY

    from teledrive.settings import load_settings
    cfg = uploader.load_config(str(CONFIG_PATH))
    settings = load_settings(cfg, str(CONFIG_PATH))
    WEB_USER = settings.web_user
    WEB_PASSWORD = settings.web_password
    WEB_PASSWORD_FILE = settings.web_password_file
    ALLOW_INSECURE = settings.allow_insecure
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
                from sqlalchemy import text as _text
                row = conn.connection.execute(_text(
                    "SELECT u.username FROM user_sessions s "
                    "JOIN users u ON u.id = s.user_id WHERE s.token = :t"
                ), {"t": _session_token_digest(token)}).fetchone()
                if row:
                    return row[0]
            finally:
                conn.close()
        except Exception:
            pass
    # Basic auth
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
            username = decoded.split(":", 1)[0]
            if username:
                return username
        except Exception:
            pass
    # Bearer token (API key) — resolve to the key name if possible.
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        try:
            conn = db_connect()
            try:
                name = ApiKeyStore(conn).name_for_token(token)
                if name:
                    return name
            finally:
                conn.close()
        except Exception:
            pass
        return "api-key"
    return "anonymous"


def _log(msg: str, source: str = "web", user: str = "system") -> None:
    """Append a timestamped, user-tagged, source-tagged entry to LOG_BUFFER."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    entry = f"[{ts}] [{user}] [{source}] {msg}"
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
            msg=msg, args=(), exc_info=None
        )
        record.source = source
        record.user = user
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


_DEFAULT_ADMIN_PW_CACHE: dict = {"in_use": None}


def _default_admin_password_in_use() -> bool:
    """True while the shipped admin/admin credential still verifies.

    The PBKDF2 comparison is cached per process; every password change
    invalidates the cache via _invalidate_default_admin_cache().
    """
    if _DEFAULT_ADMIN_PW_CACHE["in_use"] is None:
        try:
            conn = db_connect()
            try:
                from sqlalchemy import text as _text
                row = conn.connection.execute(_text(
                    "SELECT password_hash FROM users WHERE username = 'admin'"
                )).fetchone()
            finally:
                conn.close()
            _DEFAULT_ADMIN_PW_CACHE["in_use"] = bool(
                row is not None and _verify_password("admin", row[0]))
        except Exception:
            _DEFAULT_ADMIN_PW_CACHE["in_use"] = False
    return _DEFAULT_ADMIN_PW_CACHE["in_use"]


def _invalidate_default_admin_cache() -> None:
    _DEFAULT_ADMIN_PW_CACHE["in_use"] = None


def _auth_throttle_check(key: str) -> None:
    """Reject authentication attempts after repeated failures (brute-force guard)."""
    now = time.time()
    window = max(1, int(AUTH_FAILURE_WINDOW_SECONDS))
    limit = max(1, int(AUTH_FAILURE_LIMIT))
    failures = AUTH_FAILURES.get(key)
    if failures:
        while failures and failures[0] <= now - window:
            failures.popleft()
        if len(failures) >= limit:
            raise HTTPException(429, "Too many failed attempts; try again later")


def _auth_failure_record(key: str) -> None:
    AUTH_FAILURES.setdefault(key, deque()).append(time.time())


def _create_default_admin() -> None:
    """Ensure at least one admin user exists."""
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        count = conn.connection.execute(_text("SELECT COUNT(*) FROM users")).scalar() or 0
        if count == 0:
            now = int(time.time())
            conn.connection.execute(_text(
                "INSERT INTO users (username, password_hash, role, created_at, updated_at) "
                "VALUES (:u, :ph, 'admin', :now, :now)"
            ), {"u": "admin", "ph": _hash_password("admin"), "now": now})
            conn.connection.commit()
            _log("default admin account 'admin' created with password 'admin' — "
                 "change this password immediately", "startup")
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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT u.id, u.username, u.role, s.expires_at, u.enabled "
            "FROM user_sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = :token"
        ), {"token": digest}).fetchone()
        if row is None:
            return None
        if not row[4]:
            # Disabled users must not hold live sessions.
            conn.connection.execute(_text(
                "DELETE FROM user_sessions WHERE user_id = :uid"
            ), {"uid": row[0]})
            conn.connection.commit()
            return None
        if int(time.time()) > int(row[3]):
            # Expired — clean up.
            conn.connection.execute(_text(
                "DELETE FROM user_sessions WHERE token = :token"
            ), {"token": digest})
            conn.connection.commit()
            return None
        return {"id": row[0], "username": row[1], "role": row[2]}
    except Exception:
        return None
    finally:
        conn.close()


_ROLE_ADMIN = frozenset({"admin"})
_ROLE_WRITE = frozenset({"admin", "operator"})


def _required_roles(method: str, path: str) -> frozenset[str] | None:
    """Central role policy for the admin API. None = any authenticated role.

    - viewer: read-only access to listings, config (redacted) and logs
    - operator: additionally all storage operations (jobs, channels, versions, recovery)
    - admin: additionally user management, API keys, S3 credentials, config and quotas
    """
    # Canonicalize legacy aliases (/api/auth/*, /api/config, /api/logs)
    # onto the /api/v1/* namespace before policy matching.
    if path.startswith("/api/") and not path.startswith("/api/v1/") \
            and not path.startswith("/api/health"):
        path = "/api/v1/" + path[len("/api/"):]
    if path.startswith("/api/v1/admin/users"):
        return _ROLE_ADMIN
    if method == "GET":
        return None
    if path == "/api/v1/config":
        return _ROLE_ADMIN
    if path.startswith("/api/v1/admin/keys"):
        return _ROLE_ADMIN
    if (path.startswith("/api/v1/admin/s3/credentials")
            or path.startswith("/api/v1/admin/s3-credentials")):
        return _ROLE_ADMIN
    if path.startswith("/api/v1/admin/storage/buckets") and path.endswith("/quota"):
        return _ROLE_ADMIN
    return _ROLE_WRITE


def _enforce_role_policy(request: Request, user: dict) -> None:
    roles = _required_roles(request.method, request.url.path)
    if roles is not None and user.get("role") not in roles:
        _log(f"denied: user={user.get('username')} role={user.get('role')} "
             f"{request.method} {request.url.path}", "auth")
        raise HTTPException(403, "Insufficient permissions for this action")


def require_auth(request: Request) -> None:
    # Session token (Bearer header or httpOnly cookie) is the primary mechanism.
    user = _get_current_user(request)
    if user is not None:
        request.state.user = user
        _enforce_role_policy(request, user)
        return

    # Fall back to HTTP Basic auth (backward compat for tests/API clients).
    if WEB_PASSWORD:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            client = request.client.host if request.client else "-"
            throttle_key = f"basic:{client}"
            _auth_throttle_check(throttle_key)
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                u, p_ = decoded.split(":", 1)
            except Exception:
                u, p_ = "", ""
            if (hmac.compare_digest(u, WEB_USER)
                    and hmac.compare_digest(p_, WEB_PASSWORD)):
                request.state.user = {"id": 0, "username": u, "role": "admin"}
                _enforce_role_policy(request, request.state.user)
                return
            _auth_failure_record(throttle_key)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="TeleDrive"'},
    )


def default_config() -> dict[str, Any]:
    return {
        "web": {
            "user": "admin",
            "password": "",
            "allowed_hosts": "localhost,127.0.0.1,[::1]",
            "allow_insecure": False,
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


def read_raw_config() -> dict[str, Any]:
    ensure_config()
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


def _redacted_config(raw: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(raw)
    web_cfg = result.get("web", {})
    if isinstance(web_cfg, dict) and web_cfg.get("password"):
        web_cfg["password"] = REDACTED
    tg = result.get("telegram", {})
    if tg.get("api_hash"):
        tg["api_hash"] = REDACTED
    for account in tg.get("accounts", []) or []:
        if isinstance(account, dict) and account.get("api_hash"):
            account["api_hash"] = REDACTED
    state_cfg = result.get("state", {})
    db_url = state_cfg.get("database_url") or state_cfg.get("db_path")
    if db_url:
        state_cfg["database_url"] = redact_database_url(str(db_url))
        state_cfg.pop("db_path", None)
    return result


def _restore_secrets(candidate: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(candidate)
    new_web = result.setdefault("web", {})
    old_web = current.get("web", {})
    if isinstance(new_web, dict) and new_web.get("password") == REDACTED:
        new_web["password"] = old_web.get("password", "")
    new_tg = result.setdefault("telegram", {})
    old_tg = current.get("telegram", {})
    if new_tg.get("api_hash") == REDACTED:
        new_tg["api_hash"] = old_tg.get("api_hash", "")

    old_accounts = {
        str(a.get("name")): a
        for a in (old_tg.get("accounts") or [])
        if isinstance(a, dict) and a.get("name")
    }
    for account in new_tg.get("accounts", []) or []:
        if not isinstance(account, dict):
            continue
        if account.get("api_hash") == REDACTED:
            account["api_hash"] = old_accounts.get(str(account.get("name")), {}).get("api_hash", "")

    new_state = result.setdefault("state", {})
    old_state = current.get("state", {})
    old_url = old_state.get("database_url") or old_state.get("db_path")
    submitted = new_state.get("database_url")
    if old_url and submitted == redact_database_url(str(old_url)):
        new_state["database_url"] = old_url
    return result


def effective_config():
    # Cache the parsed config by file mtime: every request used to re-read
    # and re-parse the YAML (plus path validation) through db_connect().
    try:
        mtime = CONFIG_PATH.stat().st_mtime_ns
    except OSError:
        mtime = None
    if _CONFIG_CACHE["config"] is None or _CONFIG_CACHE["mtime"] != mtime:
        ensure_config()
        _CONFIG_CACHE["config"] = uploader.load_config(str(CONFIG_PATH))
        _CONFIG_CACHE["mtime"] = mtime
    return _CONFIG_CACHE["config"]


_CONFIG_CACHE: dict = {"mtime": None, "config": None}


def validate_and_write_config(raw: dict[str, Any]) -> None:
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
    _reload_service_settings()
    _create_default_admin()
    # Migrate users table: add enabled column if missing.
    try:
        conn = db_connect()
        try:
            from sqlalchemy import text as _text, inspect as _inspect
            cols = {c['name'] for c in _inspect(conn.engine).get_columns('users')}
            if 'enabled' not in cols:
                conn.connection.execute(_text('ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1'))
                conn.connection.commit()
        finally:
            conn.close()
    except Exception:
        pass


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
    global folder_watch_task
    os.umask(0o077)
    # Settings first: ensure_config() mkdirs AUTH_DIR, which must already
    # reflect the config/env override (Docker only worked by accident
    # because the image pre-creates /data/auth).
    _reload_service_settings()
    ensure_config()
    _create_default_admin()
    # Migrate users table: add enabled column if missing.
    try:
        conn = db_connect()
        try:
            from sqlalchemy import text as _text, inspect as _inspect
            cols = {c['name'] for c in _inspect(conn.engine).get_columns('users')}
            if 'enabled' not in cols:
                conn.connection.execute(_text('ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1'))
                conn.connection.commit()
        finally:
            conn.close()
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
    if not WEB_PASSWORD and not ALLOW_INSECURE:
        raise RuntimeError(
            "config.yaml web.password is required (or web.allow_insecure for "
            "explicitly trusted local deployments only)."
        )
    if WEB_PASSWORD and len(WEB_PASSWORD) < 16:
        raise RuntimeError("config.yaml web.password must be at least 16 characters")
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
        conn.close()
    except Exception as exc:
        _log(_scrub_text(f"startup database warning: {exc}"), "startup")
    upload_job_scheduler_task = asyncio.create_task(upload_job_scheduler_loop())
    lifecycle_scheduler_task = asyncio.create_task(lifecycle_scheduler_loop())
    folder_watch_task = asyncio.create_task(folder_watch_loop())
    session_health_task = asyncio.create_task(telegram_session_health_loop())
    yield
    if upload_job_scheduler_task:
        upload_job_scheduler_task.cancel()
        await asyncio.gather(upload_job_scheduler_task, return_exceptions=True)
    if lifecycle_scheduler_task:
        lifecycle_scheduler_task.cancel()
        await asyncio.gather(lifecycle_scheduler_task, return_exceptions=True)
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


@app.middleware("http")
async def _audit_log_middleware(request: Request, call_next):
    start = time.time()
    path = request.url.path
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
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; object-src 'none'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        )
    if request.url.path in {"/", "/docs", "/redoc", "/openapi.json"} or request.url.path.startswith("/api/"):
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


class S3KeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(default_factory=lambda: list(DEFAULT_PERMISSIONS))
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

def _assert_not_last_admin(conn, current_role: str,
                            new_role: str | None = None) -> None:
    """Refuse role changes or deletion that would remove the last admin."""
    if current_role != "admin" or new_role == "admin":
        return
    from sqlalchemy import text as _text
    admin_count = conn.connection.execute(_text(
        "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    )).scalar()
    if admin_count <= 1:
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
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value.strip())
    if match is None or not (match.group(1) or match.group(2)):
        raise HTTPException(416, "Unsupported byte range", headers={"Content-Range": f"bytes */{size}"})
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
    """HTTP bearer authorization, independent of the browser Basic/CSRF flow."""
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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT id, username, password_hash, role, enabled FROM users "
            "WHERE username = :u"
        ), {"u": username}).fetchone()
    finally:
        conn.close()
    # Always run a hash comparison so response timing never reveals
    # whether the username exists.
    stored_hash = row[2] if row is not None else _dummy_password_hash()
    valid = _verify_password(password, stored_hash)
    if row is None or not valid:
        _auth_failure_record(throttle_key)
        raise HTTPException(401, "Invalid credentials")
    if not row[4]:
        _auth_failure_record(throttle_key)
        raise HTTPException(403, "Account is disabled")
    if not stored_hash.startswith("pbkdf2_sha256$"):
        # Transparently upgrade legacy password hashes on successful login.
        conn = db_connect()
        try:
            from sqlalchemy import text as _text
            conn.connection.execute(_text(
                "UPDATE users SET password_hash = :ph, updated_at = :now "
                "WHERE id = :id"
            ), {"ph": _hash_password(password), "now": int(time.time()),
                "id": row[0]})
            conn.connection.commit()
        finally:
            conn.close()
    AUTH_FAILURES.pop(throttle_key, None)
    token = "td_sess_" + secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + 7 * 86400  # 7 days
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "INSERT INTO user_sessions (token, user_id, created_at, expires_at) "
            "VALUES (:token, :uid, :now, :exp)"
        ), {"token": _session_token_digest(token), "uid": row[0],
            "now": now, "exp": expires})
        conn.connection.execute(_text(
            "UPDATE users SET last_login = :now WHERE id = :id"
        ), {"now": now, "id": row[0]})
        conn.connection.commit()
    finally:
        conn.close()
    _log(f"login: username={username}", "auth")
    resp = JSONResponse(content={"token": token, "user": {"id": row[0], "username": row[1], "role": row[3]},
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
            from sqlalchemy import text as _text
            conn.connection.execute(_text(
                "DELETE FROM user_sessions WHERE token = :token"
            ), {"token": _session_token_digest(token)})
            conn.connection.commit()
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
        # The WebUI forces a password change screen while the default
        # admin/admin credential is still in use.
        "must_change_password": (user["username"] == "admin"
                                 and _default_admin_password_in_use()),
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


@app.put("/api/v1/config", tags=["Configuration"], response_model=OKResponse, summary="Validate and save configuration")
@app.put("/api/config", tags=["Configuration"], include_in_schema=False)
def put_config(request: Request, payload: dict[str, Any] = Body(...), _: None = Depends(require_auth)):
    _same_origin(request)
    _log("settings save requested", "config")
    try:
        validate_and_write_config(payload)
        _log("settings saved successfully", "config")
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
    """Every REST bearer endpoint is individually permissionable. Legacy
    grouped scopes remain valid as aliases (existing keys keep working)
    and are shown for reference; new keys should use endpoint names."""
    from teledrive.api_keys import (ENDPOINT_PERMISSIONS,
                                     LEGACY_SCOPE_EXPANSION)
    return {
        "endpoint_permissions": [
            {"name": name, "description": description}
            for name, description in sorted(ENDPOINT_PERMISSIONS.items())],
        "legacy_scopes": [
            {"name": name, "expands_to": sorted(expansion)}
            for name, expansion in sorted(LEGACY_SCOPE_EXPANSION.items())],
    }


@app.post("/api/v1/admin/keys", tags=["API keys"], status_code=201, summary="Issue a scoped API key (secret returned once)")
def issue_api_key(request: Request, payload: KeyCreateRequest, _: None = Depends(require_auth)):
    _same_origin(request)
    _log(f"issue api key: name={payload.name} scopes={payload.scopes}", "api-keys")
    conn = db_connect()
    try:
        try:
            key = ApiKeyStore(conn).create(payload.name, payload.scopes, expires_at=payload.expires_at)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": key.id, "token": key.value, "prefix": key.prefix, "scopes": key.scopes}
    finally:
        conn.close()


@app.delete("/api/v1/admin/keys/{identifier}", tags=["API keys"], summary="Revoke an API key immediately")
def revoke_api_key(identifier: str, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    _log(f"revoke api key: id={identifier}", "api-keys")
    conn = db_connect()
    try:
        if not ApiKeyStore(conn).revoke(identifier):
            raise HTTPException(404, "API key not found or already revoked")
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/v1/admin/keys/{identifier}/rotate", tags=["API keys"], summary="Rotate an API key; secret returned once")
def rotate_api_key(identifier: str, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    _log(f"rotate api key: id={identifier}", "api-keys")
    conn = db_connect()
    try:
        try:
            key = ApiKeyStore(conn).rotate(identifier)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"id": key.id, "token": key.value, "prefix": key.prefix, "scopes": key.scopes}
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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT id FROM users WHERE id = :id"
        ), {"id": user_id}).fetchone()
        if row is None:
            raise HTTPException(404, "user not found")
        conn.connection.execute(_text(
            "UPDATE users SET password_hash = :ph, updated_at = :now WHERE id = :id"
        ), {"ph": pw_hash, "now": now, "id": user_id})
        # Revoke all sessions for this user (force re-login)
        conn.connection.execute(_text(
            "DELETE FROM user_sessions WHERE user_id = :uid"
        ), {"uid": user_id})
        conn.connection.commit()
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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT username, role FROM users WHERE id = :id"
        ), {"id": user_id}).fetchone()
        if row is None:
            raise HTTPException(404, "user not found")
        _assert_not_last_admin(conn, row[1], role)
        conn.connection.execute(_text(
            "UPDATE users SET role = :role, updated_at = :now WHERE id = :id"
        ), {"role": role, "now": int(time.time()), "id": user_id})
        conn.connection.commit()
        _log(f"change role: user_id={user_id} {row[1]} -> {role}", "users")
    finally:
        conn.close()
    return {"ok": True}



# --- Detailed user management & role control --------------------------------

@app.get("/api/v1/admin/users/{user_id}", tags=["Users"],
         summary="Get user detail")
def get_user_detail(user_id: int, _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT id, username, role, enabled, created_at, updated_at, last_login "
            "FROM users WHERE id = :id"
        ), {"id": user_id}).fetchone()
        if row is None:
            raise HTTPException(404, "user not found")
        sessions = conn.connection.execute(_text(
            "SELECT token, created_at, expires_at FROM user_sessions "
            "WHERE user_id = :uid ORDER BY created_at DESC"
        ), {"uid": user_id}).fetchall()
        return {
            "id": row[0], "username": row[1], "role": row[2],
            "enabled": bool(row[3]), "created_at": row[4],
            "updated_at": row[5], "last_login": row[6],
            "sessions": [{"token_prefix": s[0][:12] + "...", "created_at": s[1],
                          "expires_at": s[2]} for s in sessions],
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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT id, username, role FROM users WHERE id = :id"
        ), {"id": user_id}).fetchone()
        if row is None:
            raise HTTPException(404, "user not found")

        username = payload.get("username")
        role = payload.get("role")
        enabled = payload.get("enabled")

        # Prevent removing the last admin (row[2] is the current role).
        if role is not None:
            _assert_not_last_admin(conn, row[2], role)

        if username is not None:
            if not username or len(username) > 128:
                raise HTTPException(400, "invalid username")
            try:
                conn.connection.execute(_text(
                    "UPDATE users SET username = :u, updated_at = :now WHERE id = :id"
                ), {"u": username, "now": int(time.time()), "id": user_id})
            except Exception as exc:
                raise HTTPException(409, "username already exists") from exc

        if role is not None:
            if role not in ("admin", "operator", "viewer"):
                raise HTTPException(400, "role must be admin, operator or viewer")
            conn.connection.execute(_text(
                "UPDATE users SET role = :role, updated_at = :now WHERE id = :id"
            ), {"role": role, "now": int(time.time()), "id": user_id})

        if enabled is not None:
            conn.connection.execute(_text(
                "UPDATE users SET enabled = :en, updated_at = :now WHERE id = :id"
            ), {"en": 1 if enabled else 0, "now": int(time.time()), "id": user_id})
            if not enabled:
                # Revoke sessions for disabled users
                conn.connection.execute(_text(
                    "DELETE FROM user_sessions WHERE user_id = :uid"
                ), {"uid": user_id})

        conn.connection.commit()
        _log(f"update user: id={user_id} username={username} role={role} enabled={enabled}", "users")
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
        from sqlalchemy import text as _text
        result = conn.connection.execute(_text(
            "DELETE FROM user_sessions WHERE user_id = :uid"
        ), {"uid": user_id})
        conn.connection.commit()
        _log(f"revoke sessions: user_id={user_id} count={result.rowcount}", "users")
    finally:
        conn.close()
    return {"ok": True, "revoked": result.rowcount}


@app.get("/api/v1/admin/roles", tags=["Users"], summary="List available roles and permissions")
def list_roles(_: None = Depends(require_auth)):
    return {"roles": [
        {"name": "admin", "description": "Full access to all features",
         "permissions": ["settings:read", "settings:manage", "users:read", "users:manage",
                        "storage:read", "storage:manage", "keys:manage", "logs:read",
                        "s3:manage", "jobs:manage"]},
        {"name": "operator", "description": "Manage storage and jobs, view logs",
         "permissions": ["storage:read", "storage:manage", "jobs:read", "jobs:manage",
                        "logs:read", "s3:read"]},
        {"name": "viewer", "description": "Read-only access",
         "permissions": ["storage:read", "jobs:read", "logs:read", "s3:read"]},
    ]}

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


def _consume_pending_session_token(token: str) -> None:
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "DELETE FROM telegram_session_pending WHERE token = :token"
        ), {"token": token})
        conn.connection.commit()
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
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "DELETE FROM telegram_session_pending WHERE created_at < :cutoff"
        ), {"cutoff": now - 300})
        conn.connection.execute(_text(
            "INSERT INTO telegram_session_pending (token, api_id, api_hash, phone, "
            "phone_code_hash, session_string, channel, strategy, created_at) "
            "VALUES (:token, :api_id, :api_hash, :phone, :pch, :sess, :channel, "
            ":strategy, :now)"
        ), {"token": token, "api_id": payload.api_id, "api_hash": payload.api_hash,
            "phone": payload.phone, "pch": phone_code_hash, "sess": request_session,
            "channel": channel, "strategy": payload.strategy or "round_robin",
            "now": now})
        conn.connection.commit()
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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT api_id, api_hash, phone, phone_code_hash, session_string, "
            "channel, strategy, created_at FROM telegram_session_pending "
            "WHERE token = :token"
        ), {"token": payload.token}).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(404, "No pending code request (expired, invalid "
                                 "token, or already used). Request a new code.")
    api_id, api_hash, phone, phone_code_hash, request_session, channel, \
        strategy, created_at = row
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
        # A wrong code must NOT consume the pending request: the user can
        # retry with the correct code. The token ages out after 5 minutes
        # and is consumed only on success (below).
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
        from sqlalchemy import text as _text
        rows = conn.connection.execute(_text(
            "SELECT id, username, role, enabled, created_at, updated_at, last_login "
            "FROM users ORDER BY id"
        )).fetchall()
        return {"users": [
            {"id": r[0], "username": r[1], "role": r[2], "enabled": bool(r[3]),
             "created_at": r[4], "updated_at": r[5], "last_login": r[6]}
            for r in rows]}
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
    if payload.role not in ("admin", "operator", "viewer"):
        raise HTTPException(400, "role must be admin, operator or viewer")
    if len(payload.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    pw_hash = _hash_password(payload.password)
    now = int(time.time())
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        try:
            conn.connection.execute(_text(
                "INSERT INTO users (username, password_hash, role, created_at, updated_at) "
                "VALUES (:u, :ph, :r, :now, :now)"
            ), {"u": payload.username, "ph": pw_hash, "r": payload.role, "now": now})
            conn.connection.commit()
        except Exception as exc:
            raise HTTPException(409, "username already exists") from exc
        row = conn.connection.execute(_text(
            "SELECT id FROM users WHERE username = :u"
        ), {"u": payload.username}).fetchone()
    finally:
        conn.close()
    _log(f"create user: username={payload.username} role={payload.role}", "users")
    return {"id": row[0], "username": payload.username, "role": payload.role}


@app.delete("/api/v1/admin/users/{user_id}", tags=["Users"],
            summary="Delete a WebUI user")
def delete_user(user_id: int, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT username, role FROM users WHERE id = :id"
        ), {"id": user_id}).fetchone()
        if row is None:
            raise HTTPException(404, "user not found")
        _assert_not_last_admin(conn, row[1])
        conn.connection.execute(_text(
            "DELETE FROM users WHERE id = :id"
        ), {"id": user_id})
        conn.connection.commit()
        _log(f"delete user: id={user_id} username={row[0]}", "users")
    finally:
        conn.close()
    return {"ok": True}


# --- S3 bucket browser & quota (WebUI, Basic auth) --------------------------

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


@app.get("/api/v1/admin/storage/buckets/{bucket}/content",
         tags=["Object catalog"],
         summary="Download object bytes through the WebUI session (Range supported)")
async def admin_download_object(bucket: str, request: Request,
                                key: str = Query(..., min_length=1, max_length=1024),
                                _: None = Depends(require_auth)):
    """Stream verified object bytes for the S3 browser's download button.

    Session-authenticated twin of the API-key-scoped
    GET /api/v1/buckets/{bucket}/content; any authenticated role may read.
    """
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
        start, end, partial = _byte_range(request.headers.get("range"), item.size)
        transport = storage_transport(conn)
        root = Path(STORAGE_SCRATCH_DIR)
        _secure_mkdir(root)
        engine = TelegramObjectStorage(
            manifests, transport, chunk_size=RECOMMENDED_CHUNK_SIZE,
            scratch_directory=root,
        )
    except BaseException:
        conn.close()
        raise

    async def stream():
        try:
            async for piece in engine.iter_bytes(item.id, start=start, end=end):
                yield piece
        finally:
            conn.close()

    # Only the final path segment becomes the suggested filename; strip
    # everything that could break the header or traverse paths.
    filename = re.sub(r"[^A-Za-z0-9._ -]", "_", key.rsplit("/", 1)[-1]) or "download"
    headers = {
        "ETag": '"' + item.sha256 + '"',
        "Accept-Ranges": "bytes",
        "Content-Length": str(end - start),
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    if partial:
        headers["Content-Range"] = f"bytes {start}-{end-1}/{item.size}"
    return StreamingResponse(stream(), status_code=206 if partial else 200,
                             media_type="application/octet-stream", headers=headers)


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


@app.post("/api/v1/admin/storage/buckets/{bucket}/presign",
          tags=["Object catalog"],
          summary="Create a presigned GET URL for one object")
def admin_presign_object(bucket: str, request: Request,
                         payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    """Server-side SigV4 query signing; the credential secret never
    leaves the process, only the signed URL is returned."""
    _same_origin(request)
    key = str(payload.get("key", "")).strip()
    if not key:
        raise HTTPException(422, "key is required")
    try:
        expires = int(payload.get("expires") or 3600)
    except (TypeError, ValueError):
        raise HTTPException(422, "expires must be an integer") from None
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
            else:
                candidates = [c for c in store.list() if not c["revoked"]
                              and "s3:GetObject" in c["permissions"]]
                if not candidates:
                    raise HTTPException(
                        422, "No active S3 credential with s3:GetObject")
                revealed = store.reveal(candidates[0]["id"])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    finally:
        conn.close()
    host = (request.headers.get("host") or "").split(":")[0]
    scheme = "https" if S3_SSL_CERTFILE else "http"
    from teledrive.s3.sigv4 import presign_get_url
    url = presign_get_url(f"{scheme}://{host}:{settings_s3_port()}",
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
            catalog.get(bucket, key)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        from sqlalchemy import insert as _insert
        from teledrive.db import share_links
        token = secrets.token_urlsafe(24)
        now = int(time.time())
        salt = digest = None
        if password is not None:
            salt, digest = _hash_share_password(password)
        conn.connection.execute(_insert(share_links).values(
            token=token, bucket=bucket, object_key=key,
            created_by=(request.state.user or {}).get("username", "-"),
            created_at=now,
            expires_at=now + expires_in if expires_in else None,
            max_downloads=max_downloads, download_count=0,
            password_salt=salt, password_hash=digest, revoked=0,
        ))
        conn.connection.commit()
    finally:
        conn.close()
    _log(f"share link created: bucket={bucket} key={key} token={token[:6]}… "
         f"expires_in={expires_in} max_downloads={max_downloads} "
         f"password={'yes' if password is not None else 'no'}", "share")
    return {"token": token, "path": f"/share/{token}"}


@app.get("/api/v1/admin/storage/shares", tags=["Object catalog"],
         summary="List all share links with live status")
def admin_list_shares(_: None = Depends(require_auth)):
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        rows = conn.connection.execute(_text(
            "SELECT token, bucket, object_key, created_by, created_at, "
            "expires_at, max_downloads, download_count, "
            "password_salt IS NOT NULL, revoked FROM share_links "
            "ORDER BY created_at DESC")).all()
        now = int(time.time())
        shares = []
        for (token, bucket, key, author, created, expires, max_downloads,
             count, has_password, revoked) in rows:
            if revoked:
                status = "revoked"
            elif expires is not None and expires <= now:
                status = "expired"
            elif max_downloads is not None and count >= max_downloads:
                status = "exhausted"
            else:
                status = "active"
            shares.append({
                "token": token, "bucket": bucket, "key": key,
                "created_by": author, "created_at": created,
                "expires_at": expires, "max_downloads": max_downloads,
                "download_count": count, "password": bool(has_password),
                "revoked": bool(revoked), "status": status,
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
        from sqlalchemy import text as _text
        deleted = conn.connection.execute(_text(
            "DELETE FROM share_links WHERE token = :t"
        ), {"t": token}).rowcount
        conn.connection.commit()
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
        # Enforce the destination bucket's object-count quota for new keys.
        _enforce_bucket_quota(conn, destination_bucket,
                              payload.destination_key, 0)
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
             f"{destination_bucket}/{payload.destination_key}", "storage")
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
                    conn.connection.execute(_text(
                        "INSERT OR IGNORE INTO object_content_index "
                        "(object_id, text, indexed_at) VALUES (:i, '', :n)"),
                        {"i": object_id, "n": int(time.time())})
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


def _bucket_quota(conn, bucket: str) -> tuple[int | None, int | None]:
    """Return (max_size_bytes, max_objects) for a bucket; (None, None) if unset."""
    from sqlalchemy import text as _text
    row = conn.connection.execute(_text(
        "SELECT max_size_bytes, max_objects FROM bucket_quotas WHERE bucket = :b"
    ), {"b": bucket}).fetchone()
    return (row[0], row[1]) if row else (None, None)


def _bucket_current_usage(conn, bucket: str) -> tuple[int, int]:
    """(object_count, total_size) of a bucket's CURRENT objects (heads join)."""
    from sqlalchemy import text as _text
    row = conn.connection.execute(_text(
        "SELECT COUNT(o.id), COALESCE(SUM(o.size), 0) "
        "FROM storage_object_heads h "
        "JOIN storage_objects o ON o.id = h.object_id "
        "WHERE h.bucket = :b"
    ), {"b": bucket}).fetchone()
    return (int(row[0]) if row else 0, int(row[1]) if row else 0)


def _bucket_has_current_key(conn, bucket: str, key: str) -> bool:
    import hashlib as _hl
    from sqlalchemy import text as _text
    key_hash = _hl.sha256(key.encode("utf-8")).hexdigest()
    row = conn.connection.execute(_text(
        "SELECT COUNT(*) FROM storage_object_heads "
        "WHERE bucket = :b AND key_hash = :kh"
    ), {"b": bucket, "kh": key_hash}).scalar()
    return bool(row)


def _enforce_bucket_quota(conn, bucket: str, key: str, incoming_size: int) -> None:
    """TeleDrive-level per-bucket quota enforcement (S3 has no native quota).

    Raises HTTPException 413 when the upload would exceed the configured
    maximum total size or object count. Overwrites of an existing key do not
    count against the object limit.
    """
    max_size_q, max_objects_q = _bucket_quota(conn, bucket)
    if max_size_q is None and max_objects_q is None:
        return
    if max_size_q is not None:
        _count, cur_size = _bucket_current_usage(conn, bucket)
        if cur_size + incoming_size > max_size_q:
            raise HTTPException(413, "Upload exceeds bucket quota (max size)")
    if max_objects_q is not None:
        cur_count, _size = _bucket_current_usage(conn, bucket)
        if not _bucket_has_current_key(conn, bucket, key) \
                and cur_count >= max_objects_q:
            raise HTTPException(413, "Upload exceeds bucket quota (max objects)")


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
        from sqlalchemy import text as _text
        now = int(time.time())
        conn.connection.execute(_text(
            "INSERT INTO bucket_quotas (bucket, max_size_bytes, max_objects, created_at, updated_at) "
            "VALUES (:b, :ms, :mo, :now, :now) "
            "ON CONFLICT (bucket) DO UPDATE SET max_size_bytes = :ms, max_objects = :mo, updated_at = :now"
        ), {"b": bucket, "ms": payload.max_size_bytes, "mo": payload.max_objects, "now": now})
        conn.connection.commit()
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

        quotas = conn.connection.execute(_text(
            "SELECT bucket, max_size_bytes, max_objects FROM bucket_quotas"
        )).fetchall()
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
        from sqlalchemy import text as _text
        pin = conn.connection.execute(_text(
            "SELECT account FROM bucket_account_pins WHERE bucket = :b"
        ), {"b": bucket}).scalar_one_or_none()
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
        conn.connection.execute(_text(
            "INSERT INTO bucket_account_pins (bucket, account, updated_at) "
            "VALUES (:b, :a, :now) ON CONFLICT(bucket) DO UPDATE SET "
            "account = :a, updated_at = :now"
        ), {"b": bucket, "a": account, "now": int(time.time())})
        conn.connection.commit()
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
        from sqlalchemy import text as _text
        conn.connection.execute(_text(
            "DELETE FROM bucket_account_pins WHERE bucket = :b"),
            {"b": bucket})
        conn.connection.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/api/v1/admin/storage/versions", tags=["Object catalog"],
         summary="Object version history incl. delete markers (WebUI)")
def admin_list_object_versions(
        bucket: str | None = Query(None),
        limit: int = Query(200, ge=1, le=1000),
        _: None = Depends(require_auth)):
    """Published versions and delete markers, newest first.

    This is the UI's object-history view: unlike the upload-job history,
    it covers EVERY write path (S3 browser, REST, multipart, copies)
    and shows delete markers, so deleted objects remain traceable until
    physical GC removes their retained media."""
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


@app.post("/api/v1/admin/s3/credentials", tags=["API keys"], status_code=201,
          summary="Issue encrypted S3 access credentials (secret displayed once)")
@app.post("/api/v1/admin/s3-credentials", tags=["API keys"], status_code=201,
          include_in_schema=False)
def issue_s3_credentials(request: Request, payload: S3KeyCreateRequest,
                         _: None = Depends(require_auth)):
    _same_origin(request)
    conn = db_connect()
    try:
        try:
            key = S3CredentialStore(conn, load_master_key()).create(
                payload.name, payload.permissions, expires_at=payload.expires_at
            )
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": key.id, "access_key": key.access_key,
                "secret_key": key.secret_key, "permissions": key.permissions}
    finally:
        conn.close()


@app.get("/api/v1/admin/s3/credentials/{identifier}/secret",
         tags=["API keys"],
         summary="Reveal an S3 credential secret (admin only, audit-logged)")
@app.get("/api/v1/admin/s3-credentials/{identifier}/secret",
         tags=["API keys"], include_in_schema=False)
def reveal_s3_credential_secret(identifier: str,
                                _: None = Depends(require_auth)):
    conn = db_connect()
    try:
        try:
            revealed = S3CredentialStore(
                conn, load_master_key()).reveal(identifier)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        _log(f"s3 credential secret revealed: id={identifier} "
             f"access={revealed['access_key']}", "security")
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
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
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
    conn = db_connect()
    try:
        try:
            changed = S3CredentialStore(conn, load_master_key()).revoke(identifier)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        if not changed:
            raise HTTPException(404, "S3 key not found or already revoked")
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
        try:
            deleted = BucketCatalog(ManifestStore(conn)).remove_current(
                bucket, key, expected_generation=generation
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ok": True, "unlinked": deleted}
    finally:
        conn.close()


async def _stream_object_upload(bucket: str, key: str, request: Request,
                                generation: int | None) -> dict:
    """Shared upload core: validate, stage, enforce quota, upload, publish."""
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
    conn = db_connect()
    try:
        try:
            item = BucketCatalog(ManifestStore(conn)).get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
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
    conn = db_connect()
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        try:
            item = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        start, end, partial = _byte_range(request.headers.get("range"), item.size)
        transport = storage_transport(conn)
        root = Path(STORAGE_SCRATCH_DIR)
        _secure_mkdir(root)
        engine = TelegramObjectStorage(manifests, transport,
                                       chunk_size=RECOMMENDED_CHUNK_SIZE,
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
               "Content-Length": str(end-start), "X-TeleDrive-Object-ID": item.id}
    if partial:
        headers["Content-Range"] = f"bytes {start}-{end-1}/{item.size}"
    return StreamingResponse(stream(), status_code=206 if partial else 200,
                             media_type="application/octet-stream", headers=headers)


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
        from sqlalchemy import text as _text
        row = conn.connection.execute(_text(
            "SELECT token, bucket, object_key, password_salt, password_hash "
            "FROM share_links WHERE token = :t AND revoked = 0 "
            "AND (expires_at IS NULL OR expires_at > :now) "
            "AND (max_downloads IS NULL OR download_count < max_downloads)"
        ), {"t": token, "now": int(time.time())}).first()
        return row
    except Exception:
        return None
    finally:
        conn.close()


async def _stream_share(row) -> StreamingResponse:
    """Consume one download slot atomically, then stream the object."""
    token, bucket, key = row[0], row[1], row[2]
    conn = db_connect()
    try:
        from sqlalchemy import text as _text
        claimed = conn.connection.execute(_text(
            "UPDATE share_links SET download_count = download_count + 1 "
            "WHERE token = :t AND revoked = 0 "
            "AND (max_downloads IS NULL OR download_count < max_downloads)"
        ), {"t": token}).rowcount
        conn.connection.commit()
        if claimed != 1:
            raise HTTPException(404, "Link not found or expired")
        try:
            item = BucketCatalog(ManifestStore(conn)).get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Link not found or expired") from exc
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
    if row[3] is not None:  # password protected
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
    if row[3] is None:
        return await _stream_share(row)
    # The share form is always application/x-www-form-urlencoded (our
    # own HTML); parse it directly instead of pulling in python-multipart.
    raw = (await request.body()).decode("utf-8", "replace")
    fields = urllib.parse.parse_qs(raw)
    password = str((fields.get("password") or [""])[0])
    _, candidate = _hash_share_password(password, row[3])
    if not hmac.compare_digest(candidate, row[4] or ""):
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
