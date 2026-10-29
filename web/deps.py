"""Shared request dependencies: authentication, role policy and CSRF.

Moved verbatim out of :mod:`web.app` so the routers can depend on one module
instead of importing the application module. ``web.app`` re-exports every
name here during the transition, so both import paths resolve to the same
objects.

Import direction is ``web.app`` -> ``web.deps``. Anything this module needs
from ``web.app`` (``_log``, ``db_connect``, ``_get_current_user``,
``_enforce_user_permission`` and the ``app`` instance) is therefore imported
inside the function that uses it. That also keeps the lookup live, so tests
that monkeypatch ``webapp.db_connect`` or ``webapp._log`` still take effect.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from teledrive.api_keys import ApiKeyStore
from web.permissions import READ_METHODS, is_admin_only

bearer_auth = HTTPBearer(auto_error=False)


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
        from web.app import _log
        _log(f"denied: user={user.get('username')} role={user.get('role')} "
             f"{request.method} {request.url.path}", "auth")
        raise HTTPException(403, "Insufficient permissions for this action")


_permission_registry_cache: "PermissionRegistry | None" = None
_route_provider_installed = False


def permission_registry() -> "PermissionRegistry":
    """The per-endpoint permission catalog, built from the live route
    table (lazily: routes are declared while this module loads)."""
    global _permission_registry_cache, _route_provider_installed
    if _permission_registry_cache is None:
        from web.permissions import PermissionRegistry
        from web import app as _application
        _permission_registry_cache = PermissionRegistry(_application.app.routes)
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
    from web.app import _enforce_user_permission, _get_current_user, db_connect
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
        from web.app import _log
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


def require_api_scope(required: str):
    """HTTP bearer authorization, independent of the browser session/CSRF flow."""
    def check(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth)) -> None:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, "API Bearer token required",
                                headers={"WWW-Authenticate": "Bearer"})
        from web.app import db_connect
        conn = db_connect()
        try:
            authorized = ApiKeyStore(conn).authorize(credentials.credentials, required)
        finally:
            conn.close()
        if not authorized:
            raise HTTPException(403, "API token is invalid, expired or lacks permission")
    return check


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
        from web.app import _log
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
        from web.app import _log
        _log("denied: api-key attempted to mint a key outliving itself",
             "auth")
        raise HTTPException(
            403,
            "An API key can only delegate authority that expires no later "
            "than its own",
        )


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
        from web.app import _log
        _log(f"denied: api-key attempted to {what} an S3 credential",
             "security")
        raise HTTPException(
            403,
            "S3 credentials can only be managed from an interactive "
            "session, never with an API key",
        )
    return (getattr(request.state, "user", None) or {}).get("username") \
        or "unknown"
