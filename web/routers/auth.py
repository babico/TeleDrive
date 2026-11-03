"""Authentication: login, logout, the current user and password change.

Paths are absolute: ``APIRouter`` has no prefix because ``web.permissions``
matches the full route path.
"""
from __future__ import annotations

import logging

import hashlib
import hmac
import secrets
import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from teledrive.stores import sessions as _session_store
from teledrive.stores import users as _user_store
from web.deps import _same_origin, client_identity, require_auth

_module_logger = logging.getLogger(__name__)

router = APIRouter()


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


AUTH_FAILURES: dict[str, deque[float]] = {}

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
            valid = hmac.compare_digest(
                digest, hashlib.sha256((salt + password).encode()).hexdigest())
            # Run the PBKDF2 work a modern hash would do. Without it, a
            # legacy row answers measurably faster and the timing reveals
            # both the hash format and that the username exists.
            hashlib.pbkdf2_hmac(
                "sha256", password.encode(), b"teledrive-legacy-timing",
                _PBKDF2_ITERATIONS)
            return valid
    except Exception as exc:
        # Fail closed (a broken hash must never log anyone in), but say so:
        # without this log a crypto/DB failure is indistinguishable from a
        # wrong password.
        _module_logger.warning("password verification failed: %s", exc)
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


# Keyed by the STORED HASH (None = no such account row), never by username:
# a password change writes a new hash, which misses the cache and forces a
# recompute, so no invalidation hook can be forgotten. The PBKDF2 comparison
# is the expensive part; the row read is deliberately repeated per probe.
_DEFAULT_ADMIN_PW_CACHE: dict[str | None, bool] = {}


def _probe_default_admin(username: str,
                         db_connect=None) -> tuple[str | None, bool]:
    """Read the account row and test it against the shipped default.

    Returns ``(stored_hash, default_password_verifies)``. ``db_connect``
    lets a caller that owns its own database binding (the S3 gateway
    module) probe through it instead of the web app's.
    """
    connect = db_connect or _webapp().db_connect
    conn = connect()
    try:
        record = _user_store.get_by_username(conn, username)
    finally:
        conn.close()
    if record is None:
        return None, False
    return record["password_hash"], _verify_password(
        "admin", record["password_hash"])


def _cached_default_admin_probe(username: str, *, fail_closed: bool,
                                db_connect=None) -> bool:
    """The shared account-state probe behind the UI nudge and the gate.

    ``fail_closed`` selects the error direction when the probe cannot
    read the database: the UI nudge treats that as "already changed"
    (a DB blip must not loop the warning), while the first-boot GATE
    treats it as "still in bootstrap" -- in that state no request has a
    trustworthy credential anyway (sessions, API keys and S3 credentials
    all live in the same database), so a transient read failure must not
    be the thing that disarms the lock. Failed probes are never cached.
    """
    try:
        stored_hash, in_use = _probe_default_admin(username, db_connect)
    except Exception as exc:
        _module_logger.warning(
            "%s admin password probe failed: %s",
            "bootstrap gate" if fail_closed else "default-admin", exc)
        return fail_closed
    cached = _DEFAULT_ADMIN_PW_CACHE.get(stored_hash)
    if cached is None:
        cached = in_use
        if len(_DEFAULT_ADMIN_PW_CACHE) >= 64:
            # Unbounded growth would need unbounded distinct hashes; cap
            # it anyway so a pathological writer cannot balloon memory.
            _DEFAULT_ADMIN_PW_CACHE.clear()
        _DEFAULT_ADMIN_PW_CACHE[stored_hash] = cached
    return cached


def _default_admin_password_in_use(username: str = "admin") -> bool:
    """True while the seeded account still uses the shipped 'admin' password."""
    return _cached_default_admin_probe(username, fail_closed=False)


def _bootstrap_gate_active(db_connect=None) -> bool:
    """True while the deployment must finish first-boot setup.

    This is the GATE condition (see ``web.app._BootstrapGateMiddleware``):
    the seeded ``admin`` account still authenticates with the shipped
    default password. It is ACCOUNT STATE read from the database, never
    a trustable browser flag, and it fails closed on probe errors.
    """
    return _cached_default_admin_probe("admin", fail_closed=True,
                                       db_connect=db_connect)


def _invalidate_default_admin_cache() -> None:
    _DEFAULT_ADMIN_PW_CACHE.clear()


def _auth_throttle_blocked(key: str) -> bool:
    """True while a client has exhausted its authentication failures."""
    now = time.time()
    window = max(1, int(_webapp().AUTH_FAILURE_WINDOW_SECONDS))
    limit = max(1, int(_webapp().AUTH_FAILURE_LIMIT))
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
    conn = _webapp().db_connect()
    try:
        return _session_store.resolve(conn, digest, int(time.time()))
    except Exception as exc:
        # Fail closed: an unreadable session store must not authenticate.
        # Logged because a DB blip otherwise looks exactly like an expired
        # session and sends operators chasing ghosts.
        _module_logger.warning("session resolution failed: %s", exc)
        return None
    finally:
        conn.close()


@router.post("/api/v1/auth/login", tags=["Authentication"], summary="Login with username and password")
@router.post("/api/auth/login", tags=["Authentication"], include_in_schema=False)
def login(payload: dict, request: Request):
    _same_origin(request)
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    if not username or not password:
        raise HTTPException(400, "username and password are required")
    # Throttle key: the real client when a trusted proxy fronts the
    # deployment (see web.deps.client_identity), never the shared proxy
    # address -- otherwise one attacker blocks every login behind it.
    client = client_identity(request)
    throttle_key = f"login:{username}:{client}"
    _auth_throttle_check(throttle_key)
    conn = _webapp().db_connect()
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
        conn = _webapp().db_connect()
        try:
            _user_store.set_password(
                conn, record["id"], _hash_password(password), int(time.time()))
        finally:
            conn.close()
    AUTH_FAILURES.pop(throttle_key, None)
    token = "td_sess_" + secrets.token_urlsafe(32)
    now = int(time.time())
    expires = now + 7 * 86400  # 7 days
    conn = _webapp().db_connect()
    try:
        # Same transaction: sessions.create commits once, after both writes.
        _user_store.set_last_login(conn, record["id"], now, commit=False)
        _session_store.create(
            conn, token=_session_token_digest(token), user_id=record["id"],
            created_at=now, expires_at=expires)
    finally:
        conn.close()
    _webapp()._log(f"login: username={username}", "auth")
    resp = JSONResponse(content={"token": token, "user": {"id": record["id"], "username": record["username"], "role": record["role"]},
                                  "expires_at": expires,
                                  # Same account-state probe as /auth/me:
                                  # lets a first-boot client learn it must
                                  # complete the rotation before anything else.
                                  "must_change_password": bool(
                                      username == "admin"
                                      and _default_admin_password_in_use("admin"))})
    # Behind a TLS-terminating reverse proxy the cookie must still be
    # Secure when the client connection is https (X-Forwarded-Proto).
    forwarded_https = (_webapp().TRUSTED_PROXY and request.headers.get(
        "x-forwarded-proto", "").lower() == "https")
    resp.set_cookie(key="teledrive_session", value=token, httponly=True,
                    max_age=7 * 86400, samesite="lax", path="/",
                    secure=bool(_webapp().SSL_CERTFILE) or forwarded_https)
    return resp


@router.post("/api/v1/auth/logout", tags=["Authentication"], summary="Logout and revoke session")
@router.post("/api/auth/logout", tags=["Authentication"], include_in_schema=False)
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
        conn = _webapp().db_connect()
        try:
            _session_store.delete_token(conn, _session_token_digest(token))
        finally:
            conn.close()
    _webapp()._log(f"logout: user={user['username'] if user else 'unknown'}", "auth")
    resp = JSONResponse(content={"ok": True})
    resp.delete_cookie(key="teledrive_session", path="/")
    return resp


@router.get("/api/v1/auth/me", tags=["Authentication"], summary="Get current user")
@router.get("/api/auth/me", tags=["Authentication"], include_in_schema=False)
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


def _validate_new_password(new_pw: str, current_pw: str) -> None:
    """The self-service rotation minimums (400 on breach).

    The shipped default is public knowledge, so the new password must be
    a strong secret that is neither the old one nor ``admin`` in any
    casing. Letters mixed with digits/symbols keeps the rotation from
    landing on another dictionary word.
    """
    if new_pw.casefold() == "admin":
        raise HTTPException(
            400, "the new password must differ from the shipped default")
    if len(new_pw) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if new_pw == current_pw:
        raise HTTPException(
            400, "the new password must differ from the current one")
    if not (any(c.isalpha() for c in new_pw)
            and any(not c.isalpha() for c in new_pw)):
        raise HTTPException(
            400, "password must mix letters with digits or symbols")


@router.post("/api/v1/auth/password", tags=["Authentication"],
             summary="Change the caller's own password")
@router.post("/api/auth/password", tags=["Authentication"], include_in_schema=False)
def change_own_password(request: Request, payload: dict):
    """Self-service password change for the authenticated account.

    This is one of the few operations the first-boot gate leaves open
    while the seeded ``admin`` account still uses the shipped default
    password, so the bootstrap rotation can always complete. Only the
    caller's OWN account can be changed: the current password must be
    presented, the new one must clear :func:`_validate_new_password`,
    and the request is CSRF/same-origin fenced like every state change.
    On success every session for the account is revoked and one fresh
    session is issued (rotation), so the browser stays signed in while
    any older or stolen token dies immediately.
    """
    _same_origin(request)
    # An API key is not the account: letting one rotate (or probe) the
    # password of the principal that minted it would hand a bearer token
    # a takeover primitive. Checked before session resolution so a key
    # gets the specific error, not a generic 401.
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer td_live_"):
        raise HTTPException(
            403, "Password changes need an interactive session, not an API key")
    user = _get_current_user(request)
    if user is None:
        raise HTTPException(401, "Not authenticated")
    request.state.user = user
    current_pw = str(payload.get("current_password", ""))
    new_pw = str(payload.get("new_password", ""))
    _validate_new_password(new_pw, current_pw)
    conn = _webapp().db_connect()
    try:
        # Re-read the row: the session says who calls, the row says what
        # the password currently is (it may have changed since login).
        record = _user_store.get_by_username(conn, user["username"])
        if record is None:
            raise HTTPException(404, "account not found")
        if not _verify_password(current_pw, record["password_hash"]):
            _webapp()._log(f"self password change denied: wrong current "
                           f"password user={user['username']}", "auth")
            raise HTTPException(403, "Current password is incorrect")
        token = "td_sess_" + secrets.token_urlsafe(32)
        now = int(time.time())
        expires = now + 7 * 86400  # 7 days
        # One transaction: the new hash, the revocation of EVERY session
        # for this account and the replacement session land together
        # (sessions.create commits once, after all three writes).
        _user_store.set_password(
            conn, record["id"], _hash_password(new_pw), now, commit=False)
        _session_store.delete_for_user(conn, record["id"], commit=False)
        _session_store.create(
            conn, token=_session_token_digest(token), user_id=record["id"],
            created_at=now, expires_at=expires)
        _invalidate_default_admin_cache()
        _webapp()._log(f"self password change: user={user['username']}",
                       "auth")
        _webapp()._audit(request, "auth.password.self_change",
                         target=user["username"])
    finally:
        conn.close()
    resp = JSONResponse(content={
        "ok": True, "token": token,
        "user": {"id": record["id"], "username": record["username"],
                 "role": record["role"]},
        "expires_at": expires})
    # Same cookie contract as login: Secure behind TLS or a trusted
    # https proxy, httpOnly, lax, 7 days.
    forwarded_https = (_webapp().TRUSTED_PROXY and request.headers.get(
        "x-forwarded-proto", "").lower() == "https")
    resp.set_cookie(key="teledrive_session", value=token, httponly=True,
                    max_age=7 * 86400, samesite="lax", path="/",
                    secure=bool(_webapp().SSL_CERTFILE) or forwarded_https)
    return resp


@router.put("/api/v1/admin/users/{user_id}/password", tags=["Users"],
        summary="Change a user's password")
def change_user_password(user_id: int, request: Request, payload: dict,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    new_pw = str(payload.get("password", ""))
    if len(new_pw) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    pw_hash = _hash_password(new_pw)
    now = int(time.time())
    conn = _webapp().db_connect()
    try:
        if _user_store.get_by_id(conn, user_id) is None:
            raise HTTPException(404, "user not found")
        # Revoke all sessions for this user (force re-login) in the same
        # transaction as the password change.
        _user_store.set_password(conn, user_id, pw_hash, now, commit=False)
        _session_store.delete_for_user(conn, user_id, commit=False)
        conn.commit()
        _invalidate_default_admin_cache()
        _webapp()._log(f"change password: user_id={user_id}", "users")
    finally:
        conn.close()
    return {"ok": True}
