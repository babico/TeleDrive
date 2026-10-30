"""WebUI user administration: CRUD, roles, sessions and the audit trail.

Paths are absolute: ``APIRouter`` has no prefix because ``web.permissions``
matches the full route path.

App-owned state is read through ``_webapp()`` at call time so the existing
monkeypatch-based tests (``webapp.db_connect``, ``webapp._log``) still take
effect, and because importing ``web.app`` at module scope would be a cycle:
``web.app`` imports this module at the end of its own body.
"""
from __future__ import annotations

import re
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from teledrive.stores import sessions as _session_store
from teledrive.stores import users as _user_store
from web.deps import _same_origin, permission_registry, require_auth

router = APIRouter()


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


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


@router.put("/api/v1/admin/users/{user_id}/role", tags=["Users"],
        summary="Change a user's role")
def change_user_role(user_id: int, request: Request, payload: dict,
                     _: None = Depends(require_auth)):
    _same_origin(request)
    role = str(payload.get("role", "")).strip()
    if role not in ("admin", "operator", "viewer"):
        raise HTTPException(400, "role must be admin, operator or viewer")
    conn = _webapp().db_connect()
    try:
        record = _user_store.get_by_id(conn, user_id)
        if record is None:
            raise HTTPException(404, "user not found")
        _assert_not_last_admin(conn, record["role"], role)
        _user_store.set_role(conn, user_id, role, int(time.time()))
        _webapp()._log(f"change role: user_id={user_id} {record['role']} -> {role}", "users")
    finally:
        conn.close()
    return {"ok": True}


# --- Detailed user management & role control --------------------------------

@router.get("/api/v1/admin/users/{user_id}", tags=["Users"],
         summary="Get user detail")
def get_user_detail(user_id: int, _: None = Depends(require_auth)):
    conn = _webapp().db_connect()
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


@router.put("/api/v1/admin/users/{user_id}", tags=["Users"],
         summary="Update user (username, role, enabled)")
def update_user(user_id: int, request: Request, payload: dict,
                _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
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
        _webapp()._log(f"update user: id={user_id} username={username} role={role} enabled={enabled}", "users")
        _webapp()._audit(request, "user.update", target=str(user_id),
               detail={"username": username, "role": role,
                       "enabled": enabled})
    finally:
        conn.close()
    return {"ok": True}


@router.delete("/api/v1/admin/users/{user_id}/sessions", tags=["Users"],
            summary="Revoke all sessions for a user")
def revoke_user_sessions(user_id: int, request: Request,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        revoked = _session_store.delete_for_user(conn, user_id)
        _webapp()._log(f"revoke sessions: user_id={user_id} count={revoked}", "users")
    finally:
        conn.close()
    return {"ok": True, "revoked": revoked}


@router.get("/api/v1/admin/roles", tags=["Users"], summary="List available roles and permissions")
def list_roles(_: None = Depends(require_auth)):
    """The canonical role -> permission map, resolved against the live routes.

    Reporting from the registry (rather than a hand-written list) is what
    keeps this endpoint honest: it shows the groups each role actually
    holds after the admin-only surfaces are excluded.
    """
    return {"roles": permission_registry().role_map()}


# --- User management (multi-user WebUI) ------------------------------------

@router.get("/api/v1/admin/users", tags=["Users"], summary="List WebUI users")
def list_users(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        return {"users": _user_store.list(conn)}
    finally:
        conn.close()


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


@router.post("/api/v1/admin/users", tags=["Users"], status_code=201,
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
    pw_hash = _webapp()._hash_password(payload.password)
    now = int(time.time())
    conn = _webapp().db_connect()
    try:
        try:
            record = _user_store.create(
                conn, username=payload.username, password_hash=pw_hash,
                role=payload.role, now=now)
        except Exception as exc:
            raise HTTPException(409, "username already exists") from exc
    finally:
        conn.close()
    _webapp()._log(f"create user: username={payload.username} role={payload.role}", "users")
    _webapp()._audit(request, "user.create", target=payload.username,
           detail={"role": payload.role})
    return {"id": record["id"], "username": payload.username, "role": payload.role}


@router.delete("/api/v1/admin/users/{user_id}", tags=["Users"],
            summary="Delete a WebUI user")
def delete_user(user_id: int, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
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
        _webapp()._log(f"delete user: id={user_id} username={record['username']}", "users")
        _webapp()._audit(request, "user.delete", target=str(user_id),
               detail={"username": record["username"]})
    finally:
        conn.close()
    return {"ok": True}


@router.get("/api/v1/admin/audit", tags=["Users"],
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
    conn = _webapp().db_connect()
    try:
        return {"events": _audit_store.recent(
            conn, limit=limit, action=action, actor=actor)}
    finally:
        conn.close()
