"""TeleDrive web application.

There is exactly one authentication mechanism for people: ``POST
/api/v1/auth/login`` verifies a row in the local ``users`` table and sets
an httpOnly session cookie. The user's role is mapped to endpoint
permissions by ``web.permissions``. HTTP Basic is not implemented at all;
a ``Basic`` header is treated like no credential.

The first boot creates a hardcoded ``admin``/``admin`` account if (and
only if) no user named ``admin`` exists. It is never configurable and an
existing admin row is never overwritten, so changing that password
survives restarts. While the shipped password is still in use, a
server-side first-boot gate (``_BootstrapGateMiddleware``) refuses every
authenticated operation except login, current-user info, logout and the
self-service password change. Programmatic clients use API keys, which
keep their existing per-route scope semantics unchanged (but are refused
until the bootstrap rotation completes). See ``docs/operate/upgrade.md``.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit
import os
import gzip
import shutil
import logging
from logging.handlers import RotatingFileHandler
import re
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse, Response
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from pydantic import BaseModel, Field
from typing import Literal
from fastapi.staticfiles import StaticFiles

from teledrive import uploader
from teledrive.api_keys import ApiKeyStore
from teledrive.s3.credentials import load_master_key
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.jobs import jobs as storage_job_rows
from teledrive.storage.catalog import BucketCatalog
from teledrive.stores import sessions as _session_store
from teledrive.stores import telegram_accounts as _accounts
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from teledrive.storage.user_mode import (
    UserSessionRuntime, UserSendJournal, UnifiedUserTransport, transport_mode,
)
from web.deps import (
    _same_origin, permission_registry, require_auth,
)
from web.errors import _scrub_text, _telegram_error_response
from web.routers.public import (
    _hash_share_password, _serve_static_page, _share_rate, _site_path, index,
)
from web.routers.config import health
# Settings machinery and scheduler loops live in their own modules; every
# name below is re-exported because the routers resolve app-owned state
# through their late-bound ``_webapp()`` lookups and the tests through
# ``monkeypatch.setattr(web.app, ...)``. The moved code reaches this
# module's attributes the same way (see ``_app()`` in each module), so
# the split changes where the functions are defined, not how state is
# read or patched.
from web.settings_runtime import (  # noqa: F401 (re-exports)
    _create_default_admin, _drop_retired_auth_settings, _persist_settings_document,
    _read_config_file, _redact_tree, _redacted_config, _reload_service_settings,
    _restore_secrets, _restore_tree, _secure_mkdir, _secure_write,
    _seed_settings_document, _settings_store, default_config,
    effective_config, ensure_config, read_raw_config, settings_bind_address,
    settings_s3_port, settings_web_port, validate_and_write_config,
)
from web.schedulers import (  # noqa: F401 (re-exports)
    _SCHEDULER_IDLE_NOTICE, _storage_job_root, folder_watch_loop,
    folder_watch_scan, lifecycle_scheduler_loop, notification_scheduler_loop,
    report_scheduler_loop, tiering_scheduler_loop, upload_job_scheduler_loop,
)
mtproto_storage_runtime = UserSessionRuntime()

CONFIG_PATH = Path(os.environ.get("TELEDRIVE_CONFIG", "config/config.yaml"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
REDACTED = "__REDACTED__"

# Service settings come ONLY from config/config.yaml (owner policy); the
# TELEDRIVE_CONFIG env var just points at the file. Tests override the
# module attributes below directly. The /data roots derive from the data
# dir (paths.data_dir / TELEDRIVE_DATA_DIR, default /data) so non-Docker
# deployments can point the app at a writable tree; with the default the
# values are byte-identical to the previous literals.
DATA_DIR = os.environ.get("TELEDRIVE_DATA_DIR", "/data")
MAX_REQUEST_BYTES = 32 * 1024 * 1024
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]
AUTH_DIR = Path(os.path.join(DATA_DIR, "auth"))
STORAGE_SCRATCH_DIR = os.path.join(DATA_DIR, "tmp")
REST_MAX_UPLOAD_BYTES = 2 * 1024**3
JOB_SOURCE_ROOT = "/uploads"
JOB_AUTO_RUN = True
ALLOWED_SQLITE_ROOTS = (DATA_DIR,)
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
        except Exception as exc:
            # Best-effort enrichment only: the audit record still lands
            # with a generic actor when this fails.
            _module_logger.debug(
                "session token actor lookup failed: %s", exc)
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
        except Exception as exc:
            # Same contract as the session-token lookup above: the audit
            # record degrades to the generic "api-key" actor.
            _module_logger.debug("api key actor lookup failed: %s", exc)
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
    except Exception as exc:
        # The request itself must survive an audit failure, but a lost
        # audit record is a governance event: without this line the loss
        # is invisible and the trail silently has holes.
        _module_logger.warning(
            "audit record for action %r could not be persisted: %s",
            action, exc)


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
        # Deliberately the one silent site left in this module: the file
        # handler itself is broken here, so routing the complaint through
        # logging would recurse into the same failure. Nothing else in the
        # app swallows an exception without a trace.
        pass

_FILE_LOG_HANDLER = None


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


def db_connect():
    cfg = effective_config()
    uploader.validate_storage_paths(cfg)
    return uploader.connect_db(cfg.db_path)


# The settings-document cache lives here (not in web.settings_runtime)
# because tests replace it wholesale with
# ``monkeypatch.setattr(web.app, "_CONFIG_CACHE", ...)`` and
# ``effective_config`` resolves it through this module at call time.
_CONFIG_CACHE: dict = {"mtime": None, "config": None}


@asynccontextmanager
async def lifespan(_: FastAPI):
    global upload_job_scheduler_task, lifecycle_scheduler_task
    global notification_scheduler_task
    global folder_watch_task
    global tiering_scheduler_task, report_scheduler_task
    os.umask(0o077)
    # Settings first: ensure_config() mkdirs AUTH_DIR, which must already
    # reflect the config/env override (Docker only worked by accident
    # because the image pre-creates /data/auth).
    _reload_service_settings()
    ensure_config()
    # The bootstrap INSERT names `enabled`, so the column must exist first --
    # and it does: db_connect() opens the engine, which runs the schema
    # coordinator, whose `core` step adds users.enabled. An inline ALTER here
    # would be a SECOND DDL path for the same column: it ran after the
    # coordinator had already applied it, so it was dead code that only
    # looked like the thing keeping startup working.
    _create_default_admin()
    # Probe the database at startup: a broken database must be visible
    # immediately. It does not abort startup (the health endpoint reports
    # the same failure and recovery is a config fix, not a process
    # restart), but the error is logged with its cause, not swallowed.
    try:
        db_connect().close()
    except Exception as exc:
        _module_logger.error("startup database probe failed: %s", exc)
    # Set up rotating compressed log file.
    try:
        cfg = read_raw_config()
        log_path = (cfg.get("logging") or {}).get("log_path",
                                                  os.path.join(DATA_DIR,
                                                               "teledrive.log"))
        log_dir = os.path.dirname(log_path) or DATA_DIR
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
        install_db_extra_packages(DB_EXTRA_PACKAGES,
                                  os.path.join(DATA_DIR, "site-packages"))
    # Permit a new unconfigured installation to serve health/configuration;
    # writes fail closed until a USER session connects.
    try:
        await mtproto_storage_runtime.start()
    except Exception as exc:
        _log(_scrub_text(f"user session warning: {exc}"), "storage")
    global _main_event_loop
    _main_event_loop = asyncio.get_running_loop()
    conn = None
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
    except Exception as exc:
        _log(_scrub_text(f"startup database warning: {exc}"), "startup")
    finally:
        # A failing ensure_* must not leak the connection; startup has no
        # pool to return it to.
        if conn is not None:
            conn.close()
    upload_job_scheduler_task = asyncio.create_task(upload_job_scheduler_loop())
    lifecycle_scheduler_task = asyncio.create_task(lifecycle_scheduler_loop())
    tiering_scheduler_task = asyncio.create_task(tiering_scheduler_loop())
    notification_scheduler_task = asyncio.create_task(notification_scheduler_loop())
    report_scheduler_task = asyncio.create_task(report_scheduler_loop())
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
    if report_scheduler_task:
        report_scheduler_task.cancel()
        await asyncio.gather(report_scheduler_task, return_exceptions=True)
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
_SHARE_TOKEN_PATH = re.compile(
    r"(?P<prefix>/share/|/api/v1/admin/storage/shares/)"
    r"(?P<token>[A-Za-z0-9_-]{16,64})(?P<rest>/?$)")


class _BootstrapGateMiddleware:
    """The first-boot gate, enforced server side.

    While the seeded ``admin`` account still authenticates with the
    shipped default password, the deployment is still in bootstrap:
    every AUTHENTICATED operation is refused with a 403 that names the
    required action, except the exact flow that completes setup --
    login, current-user info, logout, the self-service password change
    -- plus the health/static/certificate surfaces a browser needs to
    reach them. The condition is ACCOUNT STATE (a cached PBKDF2 probe
    of the stored hash; see ``web.routers.auth._bootstrap_gate_active``),
    never a trustable browser flag, and it fails closed on probe errors.

    Bearer API keys are refused outright while the gate is up: on a
    legitimate first boot none can exist yet (minting is itself gated),
    so any key that still answers was issued under the default-password
    admin -- exactly the delegated authority this lock exists to contain
    (see ``docs/start/first-upload.md``). The S3 data plane applies the
    same rule to SigV4 credentials in ``web.s3``.

    Pure ASGI rather than ``@app.middleware("http")`` so the WebSocket
    log stream is gated too: a gated session's subscription is closed
    with 4403 before the handler accepts it. Registered FIRST, which
    makes it the innermost layer: the host check, the body limiter and
    the audit logger have already run when the gate decides, so its
    denials land in the audit trail like any other.
    """

    # (method, path) pairs the gate lets through while active. HEAD is
    # normalised to GET before matching; /static/* is prefix-allowed.
    ALLOWED = frozenset({
        ("POST", "/api/v1/auth/login"), ("POST", "/api/auth/login"),
        ("GET", "/api/v1/auth/me"), ("GET", "/api/auth/me"),
        ("POST", "/api/v1/auth/logout"), ("POST", "/api/auth/logout"),
        ("POST", "/api/v1/auth/password"), ("POST", "/api/auth/password"),
        ("GET", "/api/health"), ("GET", "/__health"),
        # The page that hosts the change form and its assets.
        ("GET", "/login"),
        # Public certificates: a client must be able to trust the
        # deployment's TLS before it can safely complete the flow.
        ("GET", "/server.cer"), ("GET", "/server.crt"),
        ("GET", "/api/v1/certificate.cer"), ("GET", "/api/v1/certificate.pem"),
    })

    DENIED_DETAIL = (
        "TeleDrive is completing first-boot setup: the seeded administrator "
        "account still uses the default password. Sign in as admin and "
        "change it (POST /api/v1/auth/password) before using the API.")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            await self._http(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _allowed(self, method: str, path: str) -> bool:
        if method.upper() == "HEAD":
            method = "GET"
        return ((method.upper(), path) in self.ALLOWED
                or path.startswith("/static/"))

    async def _http(self, scope, receive, send):
        from starlette.requests import Request
        from web.routers.auth import _bootstrap_gate_active, _get_current_user
        request = Request(scope, receive=receive)
        if self._allowed(request.method, request.url.path):
            await self.app(scope, receive, send)
            return
        # No credential: nothing to gate -- the handler's own 401 is the
        # right answer, and anonymous traffic must not pay the probe.
        auth = request.headers.get("authorization", "")
        token = None
        if auth.lower().startswith("bearer "):
            if auth[7:].strip().startswith("td_live_"):
                token = "__api_key__"
            else:
                token = auth[7:].strip()
        elif request.cookies.get("teledrive_session"):
            token = request.cookies.get("teledrive_session")
        if token is None:
            await self.app(scope, receive, send)
            return
        if not _bootstrap_gate_active():
            await self.app(scope, receive, send)
            return
        if token != "__api_key__":
            # A session token only trips the gate when it actually
            # resolves: a revoked or expired session is unauthenticated
            # and must keep answering 401, not 403.
            if _get_current_user(request) is None:
                await self.app(scope, receive, send)
                return
        response = JSONResponse(status_code=403, content={
            "detail": self.DENIED_DETAIL,
            "code": "bootstrap_password_change_required"})
        await response(scope, receive, send)

    async def _websocket(self, scope, receive, send):
        from starlette.requests import HTTPConnection
        from web.routers.auth import _bootstrap_gate_active, _get_current_user
        # HTTPConnection, not Request: it reads headers/cookies from any
        # scope type, and Request asserts scope["type"] == "http".
        request = HTTPConnection(scope)
        token = request.cookies.get("teledrive_session")
        if (token and _bootstrap_gate_active()
                and _get_current_user(request) is not None):
            # Same close code the handler uses for authorization denials;
            # the REST twin carries the human-readable reason.
            await send({"type": "websocket.close", "code": 4403})
            return
        await self.app(scope, receive, send)


# Registered BEFORE the decorator middlewares below: Starlette wraps in
# reverse registration order, so the first registration is the innermost
# layer and the gate decides after the host check, body limiter and
# audit logger have already run.
app.add_middleware(_BootstrapGateMiddleware)


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


# Registered LAST: Starlette wraps the stack in reverse registration order,
# so the most recently registered middleware is outermost. The host check
# must run before the audit logger (which opens a database connection) and
# before the security middleware buffers a 32MB request body.
@app.middleware("http")
async def _trusted_host_middleware(request: Request, call_next):
    # ALLOWED_HOSTS reloads from config.yaml at runtime; resolve it per
    # request instead of capturing the import-time default.
    #
    # The host must be parsed properly: a bracketed IPv6 literal
    # (``Host: [::1]:8080``) has colons inside the brackets, so splitting on
    # the first colon produced "[" and the documented default allowlist
    # entry ``[::1]`` could never match. ``urlsplit`` handles both shapes.
    raw_host = request.headers.get("host") or ""
    try:
        host = urlsplit(f"//{raw_host}").hostname or ""
    except ValueError:
        return JSONResponse(status_code=400,
                            content={"detail": "Invalid host header"})
    # Keep the bracketed form for IPv6 so it compares with the allowlist
    # entries as an operator writes them.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if host and host not in ALLOWED_HOSTS:
        return JSONResponse(status_code=400, content={"detail": "Invalid host header"})
    return await call_next(request)


class StartRequest(BaseModel):
    mode: Literal["run-once", "scan-only", "connect"] = Field(
        default="run-once", description="Run upload batch, scan only, or connect accounts."
    )


class TelegramAuthRequest(BaseModel):
    account: str = Field(min_length=1, max_length=64, examples=["primary"])
    kind: Literal["code", "password"]
    value: str = Field(min_length=1, max_length=1024, description="Telegram code or 2FA password; never logged.")


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


def _prom_escape(value: str) -> str:
    return (str(value).replace("\\", "\\\\")
            .replace('"', '\\"').replace("\n", "\\n"))


@app.get("/api/v1/metrics", tags=["Observability"],
         summary="Prometheus metrics: jobs, quotas, Telegram sessions, floods")
def prometheus_metrics(_: None = Depends(require_auth)):
    """Text exposition format 0.0.4; scrape with HTTP auth like any API route."""
    # Raw by design: a scrape endpoint issues cross-table read-only
    # aggregates (counts and sums for the exposition format). No store owns
    # them because nothing mutates here and no other caller needs the shape.
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

        # Session health and soft quotas go through the typed store: the
        # web layer does not scan the telegram_sessions table directly.
        # Sorted by id so the exposition stays byte-identical to the
        # previous un-ordered scan (SQLite served it in rowid = id order).
        sessions = sorted(_accounts.list_sessions(conn),
                          key=lambda row: row["id"])
        if sessions:
            lines += [
                "# HELP teledrive_telegram_session_authorized "
                "1 = authorized, 0 = expired/revoked.",
                "# TYPE teledrive_telegram_session_authorized gauge",
            ]
        for row in sessions:
            account, authorized = row["account"], row["authorized"]
            label = 'account="%s"' % _prom_escape(account)
            if authorized is not None:
                lines.append("teledrive_telegram_session_authorized{%s} %d"
                             % (label, int(authorized)))
        quotas = [(row["account"], row["soft_quota_bytes"])
                  for row in sessions]
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
        except Exception as exc:
            # Metrics degrade by omitting the series; a scrape that is
            # quietly missing series is worth a trace for the operator.
            _module_logger.debug(
                "flood observation metrics unavailable: %s", exc)
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
        except Exception as exc:
            _module_logger.debug(
                "flood cooldown metrics unavailable: %s", exc)
    finally:
        conn.close()
    return Response(content="\n".join(lines) + "\n",
                    media_type="text/plain; charset=utf-8")


from web.routers import (auth_router, buckets_router, config_router,
                        public_router, rest_router, s3admin_router,
                        telegram_router,
                        users_router)  # noqa: E402  (router import, no app logic)
from web.routers.auth import (  # noqa: E402  (re-exports used via web.app)
    AUTH_FAILURES, _get_current_user, _hash_password,
    _invalidate_default_admin_cache, _session_token_digest, _verify_password,
)
from web.routers.telegram import (  # noqa: E402  (re-exports used via web.app)
    _MAX_VERIFY_ATTEMPTS, _record_flood_wait, telegram_session_health_loop,
)
from web.routers.buckets import _public_s3_origin  # noqa: E402
from web.routers.rest import _stream_object_upload  # noqa: E402
from web import s3_governance_api  # noqa: E402  (router import, no app logic)

_module_logger = logging.getLogger(__name__)
# FastAPI 0.142 keeps an included router lazy behind an ``_IncludedRouter``
# placeholder instead of copying its routes into ``app.routes``. Every
# consumer that reasons about "the routes" -- the permission registry and the
# frozen surface snapshot -- therefore reads them through
# ``web.permissions.route_views()``, which flattens both shapes. That is ONE
# mechanism for all three routers, and it inherits the framework's own
# include semantics instead of mutating ``app.router.routes`` by hand.
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(telegram_router)
app.include_router(config_router)
app.include_router(buckets_router)
app.include_router(s3admin_router)
app.include_router(public_router)
app.include_router(rest_router)
app.include_router(s3_governance_api.router)
