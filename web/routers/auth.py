"""Authentication: login, logout, the current user and password change.

Paths are absolute: ``APIRouter`` has no prefix because ``web.permissions``
matches the full route path.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from teledrive.stores import sessions as _session_store
from teledrive.stores import users as _user_store
from web.deps import _same_origin, require_auth

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
            conn = _webapp().db_connect()
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
    except Exception:
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
    client = request.client.host if request.client else "-"
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
                                  "expires_at": expires})
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
