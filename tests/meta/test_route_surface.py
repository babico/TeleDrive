"""The authorization surface, frozen.

A refactor may move a handler from one module to another. It must not change
which (method, path) pairs exist, what permission each one requires, or
whether it is admin-only -- a moved route that loses its `Depends(...)` is an
unauthenticated route, and only an assertion on the surface catches that.

This file is generated ONCE from the tree before the `web/app.py` split
(`docs/handoffs/02-split-web-app.md` step 0) and is expected to stay
byte-identical through it. When a route is deliberately added, removed or
re-gated, update this table in the same commit and say so in the message.
"""
from __future__ import annotations

import pytest

import web.app as webapp
from web.permissions import PermissionRegistry, is_admin_only

# (method, path, permission, admin_only)
EXPECTED_SURFACE = {
    ("DELETE", "/api/v1/admin/keys/{identifier}", 'delete:/api/v1/admin/keys/{identifier}', True),
    ("DELETE", "/api/v1/admin/s3-credentials/{identifier}", 'delete:/api/v1/admin/s3-credentials/{identifier}', True),
    ("DELETE", "/api/v1/admin/s3-governance/{bucket}/ownership", 'delete:/api/v1/admin/s3-governance/{bucket}/ownership', False),
    ("DELETE", "/api/v1/admin/s3-governance/{bucket}/policy", 'delete:/api/v1/admin/s3-governance/{bucket}/policy', False),
    ("DELETE", "/api/v1/admin/s3-governance/{bucket}/replication", 'delete:/api/v1/admin/s3-governance/{bucket}/replication', False),
    ("DELETE", "/api/v1/admin/s3-governance/{bucket}/reports/{kind}/{config_id}", 'delete:/api/v1/admin/s3-governance/{bucket}/reports/{kind}/{config_id}', False),
    ("DELETE", "/api/v1/admin/s3-governance/{bucket}/tiering/{config_id}", 'delete:/api/v1/admin/s3-governance/{bucket}/tiering/{config_id}', False),
    ("DELETE", "/api/v1/admin/s3-governance/{bucket}/website", 'delete:/api/v1/admin/s3-governance/{bucket}/website', False),
    ("DELETE", "/api/v1/admin/s3/credentials/{identifier}", 'delete:/api/v1/admin/s3/credentials/{identifier}', True),
    ("DELETE", "/api/v1/admin/storage/buckets/{bucket}", 'delete:/api/v1/admin/storage/buckets/{bucket}', False),
    ("DELETE", "/api/v1/admin/storage/buckets/{bucket}/objects", 'delete:/api/v1/admin/storage/buckets/{bucket}/objects', False),
    ("DELETE", "/api/v1/admin/storage/buckets/{bucket}/pin", 'delete:/api/v1/admin/storage/buckets/{bucket}/pin', False),
    ("DELETE", "/api/v1/admin/storage/channels/{channel_id}", 'delete:/api/v1/admin/storage/channels/{channel_id}', False),
    ("DELETE", "/api/v1/admin/storage/shares/{token}", 'delete:/api/v1/admin/storage/shares/{token}', True),
    ("DELETE", "/api/v1/admin/storage/telegram-session", 'delete:/api/v1/admin/storage/telegram-session', True),
    ("DELETE", "/api/v1/admin/storage/telegram-sessions/{account}", 'delete:/api/v1/admin/storage/telegram-sessions/{account}', False),
    ("DELETE", "/api/v1/admin/users/{user_id}", 'delete:/api/v1/admin/users/{user_id}', True),
    ("DELETE", "/api/v1/admin/users/{user_id}/sessions", 'delete:/api/v1/admin/users/{user_id}/sessions', True),
    ("DELETE", "/api/v1/buckets/{bucket}", 'rest:buckets:delete', False),
    ("DELETE", "/api/v1/buckets/{bucket}/objects", 'rest:objects:delete', False),
    ("GET", "/", None, False),
    ("GET", "/api/auth/me", 'get:/api/auth/me', False),
    ("GET", "/api/config", 'get:/api/config', False),
    ("GET", "/api/health", None, False),
    ("GET", "/api/logs", 'get:/api/logs', True),
    ("GET", "/api/v1/admin/audit", 'get:/api/v1/admin/audit', True),
    ("GET", "/api/v1/admin/keys", 'get:/api/v1/admin/keys', True),
    ("GET", "/api/v1/admin/keys/permissions", 'get:/api/v1/admin/keys/permissions', True),
    ("GET", "/api/v1/admin/roles", 'get:/api/v1/admin/roles', False),
    ("GET", "/api/v1/admin/s3-credentials", 'get:/api/v1/admin/s3-credentials', True),
    ("GET", "/api/v1/admin/s3-credentials/{identifier}/secret", 'get:/api/v1/admin/s3-credentials/{identifier}/secret', True),
    ("GET", "/api/v1/admin/s3-governance/signing-credentials", 'get:/api/v1/admin/s3-governance/signing-credentials', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/notifications", 'get:/api/v1/admin/s3-governance/{bucket}/notifications', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/object-lock", 'get:/api/v1/admin/s3-governance/{bucket}/object-lock', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/ownership", 'get:/api/v1/admin/s3-governance/{bucket}/ownership', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/policy", 'get:/api/v1/admin/s3-governance/{bucket}/policy', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/public-access-block", 'get:/api/v1/admin/s3-governance/{bucket}/public-access-block', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/replication", 'get:/api/v1/admin/s3-governance/{bucket}/replication', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/reports", 'get:/api/v1/admin/s3-governance/{bucket}/reports', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/tiering", 'get:/api/v1/admin/s3-governance/{bucket}/tiering', False),
    ("GET", "/api/v1/admin/s3-governance/{bucket}/website", 'get:/api/v1/admin/s3-governance/{bucket}/website', False),
    ("GET", "/api/v1/admin/s3-multipart/stale", 'get:/api/v1/admin/s3-multipart/stale', False),
    ("GET", "/api/v1/admin/s3/credentials", 'get:/api/v1/admin/s3/credentials', True),
    ("GET", "/api/v1/admin/s3/credentials/{identifier}/secret", 'get:/api/v1/admin/s3/credentials/{identifier}/secret', True),
    ("GET", "/api/v1/admin/storage/active-channel", 'get:/api/v1/admin/storage/active-channel', False),
    ("GET", "/api/v1/admin/storage/buckets", 'get:/api/v1/admin/storage/buckets', False),
    ("GET", "/api/v1/admin/storage/buckets/{bucket}/content", 'get:/api/v1/admin/storage/buckets/{bucket}/content', False),
    ("GET", "/api/v1/admin/storage/buckets/{bucket}/cors", 'get:/api/v1/admin/storage/buckets/{bucket}/cors', False),
    ("GET", "/api/v1/admin/storage/buckets/{bucket}/objects", 'get:/api/v1/admin/storage/buckets/{bucket}/objects', False),
    ("GET", "/api/v1/admin/storage/buckets/{bucket}/pin", 'get:/api/v1/admin/storage/buckets/{bucket}/pin', False),
    ("GET", "/api/v1/admin/storage/buckets/{bucket}/quota", 'get:/api/v1/admin/storage/buckets/{bucket}/quota', True),
    ("GET", "/api/v1/admin/storage/buckets/{bucket}/website", 'get:/api/v1/admin/storage/buckets/{bucket}/website', True),
    ("GET", "/api/v1/admin/storage/channel-history", 'get:/api/v1/admin/storage/channel-history', False),
    ("GET", "/api/v1/admin/storage/channels", 'get:/api/v1/admin/storage/channels', False),
    ("GET", "/api/v1/admin/storage/gc", 'get:/api/v1/admin/storage/gc', True),
    ("GET", "/api/v1/admin/storage/gc-audit", 'get:/api/v1/admin/storage/gc-audit', True),
    ("GET", "/api/v1/admin/storage/gc-candidates", 'get:/api/v1/admin/storage/gc-candidates', True),
    ("GET", "/api/v1/admin/storage/health", 'get:/api/v1/admin/storage/health', False),
    ("GET", "/api/v1/admin/storage/jobs", 'get:/api/v1/admin/storage/jobs', False),
    ("GET", "/api/v1/admin/storage/mtproto-unresolved", 'get:/api/v1/admin/storage/mtproto-unresolved', False),
    ("GET", "/api/v1/admin/storage/pending-stale", 'get:/api/v1/admin/storage/pending-stale', False),
    ("GET", "/api/v1/admin/storage/replication", 'get:/api/v1/admin/storage/replication', False),
    ("GET", "/api/v1/admin/storage/search", 'get:/api/v1/admin/storage/search', False),
    ("GET", "/api/v1/admin/storage/shares", 'get:/api/v1/admin/storage/shares', True),
    ("GET", "/api/v1/admin/storage/telegram-session", 'get:/api/v1/admin/storage/telegram-session', False),
    ("GET", "/api/v1/admin/storage/telegram-session/floodwait", 'get:/api/v1/admin/storage/telegram-session/floodwait', False),
    ("GET", "/api/v1/admin/storage/telegram-sessions", 'get:/api/v1/admin/storage/telegram-sessions', False),
    ("GET", "/api/v1/admin/storage/usage", 'get:/api/v1/admin/storage/usage', False),
    ("GET", "/api/v1/admin/storage/version-history", 'get:/api/v1/admin/storage/version-history', False),
    ("GET", "/api/v1/admin/storage/versions", 'get:/api/v1/admin/storage/versions', False),
    ("GET", "/api/v1/admin/users", 'get:/api/v1/admin/users', True),
    ("GET", "/api/v1/admin/users/{user_id}", 'get:/api/v1/admin/users/{user_id}', True),
    ("GET", "/api/v1/auth/me", 'get:/api/v1/auth/me', False),
    ("GET", "/api/v1/buckets", 'rest:buckets:list', False),
    ("GET", "/api/v1/buckets/{bucket}/content", 'rest:objects:get', False),
    ("GET", "/api/v1/buckets/{bucket}/objects", 'rest:objects:list', False),
    ("GET", "/api/v1/buckets/{bucket}/versions", 'rest:objects:list-versions', False),
    ("GET", "/api/v1/certificate.cer", 'get:/api/v1/certificate.cer', False),
    ("GET", "/api/v1/certificate.pem", 'get:/api/v1/certificate.pem', False),
    ("GET", "/api/v1/config", 'get:/api/v1/config', False),
    ("GET", "/api/v1/logs", 'get:/api/v1/logs', True),
    ("GET", "/api/v1/metrics", 'get:/api/v1/metrics', False),
    ("GET", "/docs", None, False),
    ("GET", "/login", None, False),
    ("GET", "/openapi.json", None, False),
    ("GET", "/redoc", None, False),
    ("GET", "/s3", None, False),
    ("GET", "/s3/buckets", None, False),
    ("GET", "/s3/credentials", None, False),
    ("GET", "/s3/governance", None, False),
    ("GET", "/server.cer", None, False),
    ("GET", "/server.crt", None, False),
    ("GET", "/settings", None, False),
    ("GET", "/settings/general", None, False),
    ("GET", "/settings/telegram", None, False),
    ("GET", "/share/{token}", None, False),
    ("GET", "/site/{bucket}", None, False),
    ("GET", "/site/{bucket}/{path:path}", None, False),
    ("GET", "/storage", None, False),
    ("GET", "/{page_name}", None, False),
    ("GET", "/{page_name}.html", None, False),
    ("POST", "/api/auth/login", 'post:/api/auth/login', False),
    ("POST", "/api/auth/logout", 'post:/api/auth/logout', False),
    ("POST", "/api/v1/admin/keys", 'post:/api/v1/admin/keys', True),
    ("POST", "/api/v1/admin/keys/{identifier}/rotate", 'post:/api/v1/admin/keys/{identifier}/rotate', True),
    ("POST", "/api/v1/admin/s3-credentials", 'post:/api/v1/admin/s3-credentials', True),
    ("POST", "/api/v1/admin/s3-multipart/{upload_id}/recover", 'post:/api/v1/admin/s3-multipart/{upload_id}/recover', False),
    ("POST", "/api/v1/admin/s3/credentials", 'post:/api/v1/admin/s3/credentials', True),
    ("POST", "/api/v1/admin/storage/buckets", 'post:/api/v1/admin/storage/buckets', False),
    ("POST", "/api/v1/admin/storage/buckets/{bucket}/objects/copy", 'post:/api/v1/admin/storage/buckets/{bucket}/objects/copy', False),
    ("POST", "/api/v1/admin/storage/buckets/{bucket}/presign", 'post:/api/v1/admin/storage/buckets/{bucket}/presign', False),
    ("POST", "/api/v1/admin/storage/buckets/{bucket}/shares", 'post:/api/v1/admin/storage/buckets/{bucket}/shares', False),
    ("POST", "/api/v1/admin/storage/channels", 'post:/api/v1/admin/storage/channels', False),
    ("POST", "/api/v1/admin/storage/channels/{channel_id}/activate", 'post:/api/v1/admin/storage/channels/{channel_id}/activate', False),
    ("POST", "/api/v1/admin/storage/gc/collect", 'post:/api/v1/admin/storage/gc/collect', True),
    ("POST", "/api/v1/admin/storage/jobs", 'post:/api/v1/admin/storage/jobs', False),
    ("POST", "/api/v1/admin/storage/jobs/import-legacy", 'post:/api/v1/admin/storage/jobs/import-legacy', False),
    ("POST", "/api/v1/admin/storage/jobs/run-next", 'post:/api/v1/admin/storage/jobs/run-next', False),
    ("POST", "/api/v1/admin/storage/jobs/{job_id}/cancel", 'post:/api/v1/admin/storage/jobs/{job_id}/cancel', False),
    ("POST", "/api/v1/admin/storage/jobs/{job_id}/retry", 'post:/api/v1/admin/storage/jobs/{job_id}/retry', False),
    ("POST", "/api/v1/admin/storage/pending-stale/{object_id}/abandon", 'post:/api/v1/admin/storage/pending-stale/{object_id}/abandon', False),
    ("POST", "/api/v1/admin/storage/replication/repair", 'post:/api/v1/admin/storage/replication/repair', False),
    ("POST", "/api/v1/admin/storage/search/reindex", 'post:/api/v1/admin/storage/search/reindex', False),
    ("POST", "/api/v1/admin/storage/telegram-session/request-code", 'post:/api/v1/admin/storage/telegram-session/request-code', True),
    ("POST", "/api/v1/admin/storage/telegram-session/verify-code", 'post:/api/v1/admin/storage/telegram-session/verify-code', True),
    ("POST", "/api/v1/admin/storage/telegram-sessions/{account}/health-check", 'post:/api/v1/admin/storage/telegram-sessions/{account}/health-check', False),
    ("POST", "/api/v1/admin/storage/versions/index-current", 'post:/api/v1/admin/storage/versions/index-current', False),
    ("POST", "/api/v1/admin/storage/versions/{version_id}/restore", 'post:/api/v1/admin/storage/versions/{version_id}/restore', False),
    ("POST", "/api/v1/admin/users", 'post:/api/v1/admin/users', True),
    ("POST", "/api/v1/auth/login", 'post:/api/v1/auth/login', False),
    ("POST", "/api/v1/auth/logout", 'post:/api/v1/auth/logout', False),
    ("POST", "/api/v1/buckets", 'rest:buckets:create', False),
    ("POST", "/share/{token}", None, False),
    ("PUT", "/api/config", 'put:/api/config', True),
    ("PUT", "/api/v1/admin/s3-credentials/{identifier}", 'put:/api/v1/admin/s3-credentials/{identifier}', True),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/notifications", 'put:/api/v1/admin/s3-governance/{bucket}/notifications', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/object-lock", 'put:/api/v1/admin/s3-governance/{bucket}/object-lock', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/ownership", 'put:/api/v1/admin/s3-governance/{bucket}/ownership', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/policy", 'put:/api/v1/admin/s3-governance/{bucket}/policy', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/public-access-block", 'put:/api/v1/admin/s3-governance/{bucket}/public-access-block', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/replication", 'put:/api/v1/admin/s3-governance/{bucket}/replication', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/reports/{kind}/{config_id}", 'put:/api/v1/admin/s3-governance/{bucket}/reports/{kind}/{config_id}', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/tiering/{config_id}", 'put:/api/v1/admin/s3-governance/{bucket}/tiering/{config_id}', False),
    ("PUT", "/api/v1/admin/s3-governance/{bucket}/website", 'put:/api/v1/admin/s3-governance/{bucket}/website', False),
    ("PUT", "/api/v1/admin/s3/credentials/{identifier}", 'put:/api/v1/admin/s3/credentials/{identifier}', True),
    ("PUT", "/api/v1/admin/storage/buckets/{bucket}/content", 'put:/api/v1/admin/storage/buckets/{bucket}/content', False),
    ("PUT", "/api/v1/admin/storage/buckets/{bucket}/cors", 'put:/api/v1/admin/storage/buckets/{bucket}/cors', False),
    ("PUT", "/api/v1/admin/storage/buckets/{bucket}/pin", 'put:/api/v1/admin/storage/buckets/{bucket}/pin', False),
    ("PUT", "/api/v1/admin/storage/buckets/{bucket}/quota", 'put:/api/v1/admin/storage/buckets/{bucket}/quota', True),
    ("PUT", "/api/v1/admin/storage/buckets/{bucket}/website", 'put:/api/v1/admin/storage/buckets/{bucket}/website', True),
    ("PUT", "/api/v1/admin/storage/gc", 'put:/api/v1/admin/storage/gc', True),
    ("PUT", "/api/v1/admin/storage/replication", 'put:/api/v1/admin/storage/replication', False),
    ("PUT", "/api/v1/admin/storage/strategy", 'put:/api/v1/admin/storage/strategy', False),
    ("PUT", "/api/v1/admin/storage/telegram-sessions/{account}/quota", 'put:/api/v1/admin/storage/telegram-sessions/{account}/quota', False),
    ("PUT", "/api/v1/admin/users/{user_id}", 'put:/api/v1/admin/users/{user_id}', True),
    ("PUT", "/api/v1/admin/users/{user_id}/password", 'put:/api/v1/admin/users/{user_id}/password', True),
    ("PUT", "/api/v1/admin/users/{user_id}/role", 'put:/api/v1/admin/users/{user_id}/role', True),
    ("PUT", "/api/v1/buckets/{bucket}/content", 'rest:objects:put', False),
    ("PUT", "/api/v1/config", 'put:/api/v1/config', True),
}


def _surface():
    # route_views, not app.routes: FastAPI 0.142 keeps an included router
    # lazy, so app.routes alone omits every endpoint that lives in
    # web/routers/*. A snapshot built the naive way would pass while those
    # routes silently fell out of the authorization map.
    from web.permissions import route_views

    registry = PermissionRegistry(route_views(webapp.app))
    found = set()
    for route in route_views(webapp.app):
        for method in route.methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            found.add((method, route.path,
                       registry.permission_for(method, route.path),
                       is_admin_only(method, route.path)))
    return found


def test_the_authorization_surface_is_unchanged():
    found = _surface()
    missing = EXPECTED_SURFACE - found
    added = found - EXPECTED_SURFACE
    assert not missing, f"routes disappeared from the surface: {sorted(missing)}"
    assert not added, f"new routes appear without review: {sorted(added)}"


def test_every_non_public_route_has_a_permission():
    """A permission-less route must be DELIBERATELY public.

    ``permission_for`` returns ``None`` for routes outside the registry.
    That is legitimate only for the public surface the app defines in
    ``web.permissions._is_public`` (the login page, health, the certificate,
    share links, the website). A non-public route with no permission would be
    an authorization gap rather than a style issue, so this pins the exact
    boundary: every ``None`` is on the public list.
    """
    from web.permissions import _is_public

    # The HTML page shells authenticate INSIDE the handler and redirect an
    # unauthenticated visitor to /login, so they intentionally carry no route
    # permission (`permissions.py` lets a session read them). The data behind
    # them is permissioned. Listing them explicitly keeps this test honest:
    # a NEW unpermissioned page is a failure, not an implicit pass.
    in_handler_auth_pages = {
        ("GET", "/settings/general"), ("GET", "/settings/telegram"),
        ("GET", "/settings"), ("GET", "/s3/credentials"),
        ("GET", "/s3/buckets"), ("GET", "/s3"),
        ("GET", "/storage"), ("GET", "/{page_name}.html"),
        ("GET", "/{page_name}"), ("GET", "/site/{bucket}"),
        ("GET", "/site/{bucket}/{path:path}"), ("GET", "/s3/governance"),
    }

    from web.permissions import route_views

    registry = PermissionRegistry(route_views(webapp.app))
    offenders = []
    for route in route_views(webapp.app):
        path = route.path
        for method in route.methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            if registry.permission_for(method, path) is not None:
                continue
            if _is_public(path) or (method, path) in in_handler_auth_pages:
                continue
            offenders.append((method, path))
    assert offenders == [], (
        f"non-public routes without a permission: {offenders}")
