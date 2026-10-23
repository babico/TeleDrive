"""Unified per-endpoint permission registry.

Every /api/v1 route carries exactly one permission, derived from its
method + path template so the catalog can NEVER drift from the routes:
the registry is built from the live FastAPI route table. The nine REST
bearer endpoints keep their curated short names (issued keys depend on
them); every other route gets a canonical "method:path" name.

Both authorization paths check this registry:
- browser sessions (require_auth) — role policy, behavior unchanged
- bearer API keys — granted endpoint permissions, ANY route

A key with a permission for one route gains nothing on any other route;
there are no groups left to over-grant.
"""
from __future__ import annotations

import re

# Curated short names for the original REST bearer surface (backward
# compatibility with issued keys and the S3 credential docs).
CURATED_PERMISSIONS = {
    ("GET", "/api/v1/buckets"): "rest:buckets:list",
    ("POST", "/api/v1/buckets"): "rest:buckets:create",
    ("DELETE", "/api/v1/buckets/{bucket}"): "rest:buckets:delete",
    ("GET", "/api/v1/buckets/{bucket}/versions"): "rest:objects:list-versions",
    ("GET", "/api/v1/buckets/{bucket}/objects"): "rest:objects:list",
    ("DELETE", "/api/v1/buckets/{bucket}/objects"): "rest:objects:delete",
    ("PUT", "/api/v1/buckets/{bucket}/content"): "rest:objects:put",
    ("HEAD", "/api/v1/buckets/{bucket}/content"): "rest:objects:head",
    ("GET", "/api/v1/buckets/{bucket}/content"): "rest:objects:get",
}

# Short human descriptions for permission groups (path with {params}
# folded to '*', trailing '/*' dropped — the same rule the UI uses).
GROUP_DESCRIPTIONS = {
    "/api/auth/login": "Authenticate with username/password; sets the session cookie.",
    "/api/auth/logout": "Destroy the current session.",
    "/api/auth/me": "The current session's user profile.",
    "/api/v1/auth/login": "Authenticate with username/password; sets the session cookie.",
    "/api/v1/auth/logout": "Destroy the current session.",
    "/api/v1/auth/me": "The current session's user profile.",
    "/api/config": "Deployment configuration (read/redacted, save).",
    "/api/logs": "Audit and application log streaming.",
    "/api/v1/admin/storage/jobs/import-legacy": "Import legacy Bot-era upload jobs.",
    "/api/v1/admin/storage/jobs/run-next": "Manually trigger the next queued upload job.",
    "/api/v1/admin/storage/telegram-session/floodwait": "Report a FloodWait observation for an account.",
    "/api/v1/admin/storage/telegram-session/request-code": "Start adding a Telegram session: request the login code.",
    "/api/v1/admin/storage/telegram-session/verify-code": "Complete adding a Telegram session: verify the login code.",
    "/api/v1/admin/storage/telegram-session": "Add a Telegram user session (code/verify/floodwait).",
    "/api/v1/admin/storage/jobs": "Upload job queue: list, import, trigger.",
    "/api/v1/auth": "Session login/logout and the current user's profile (v1).",
    "/api/v1/config": "Deployment configuration (read/redacted, save) (v1).",
    "/api/v1/logs": "Audit and application log streaming (v1).",
    "/api/v1/metrics": "Prometheus-style metrics export.",
    "/api/v1/admin/keys": "REST API key management: list, issue, revoke.",
    "/api/v1/admin/keys/permissions": "The per-endpoint permission catalog itself.",
    "/api/v1/admin/keys/*/rotate": "Rotate one API key; new secret shown once.",
    "/api/v1/admin/roles": "Role definitions used by user management.",
    "/api/v1/admin/users": "Dashboard users: list, create, update, delete.",
    "/api/v1/admin/users/*/password": "Force-change another user's password.",
    "/api/v1/admin/users/*/role": "Change another user's role.",
    "/api/v1/admin/users/*/sessions": "Revoke another user's active sessions.",
    "/api/v1/admin/s3-credentials": "S3 SigV4 credentials: list, issue, update, revoke (legacy alias).",
    "/api/v1/admin/s3-credentials/*/secret": "Reveal one S3 credential's secret (audited).",
    "/api/v1/admin/s3/credentials": "S3 SigV4 credentials: list, issue, update, revoke.",
    "/api/v1/admin/s3/credentials/*/secret": "Reveal one S3 credential's secret (audited).",
    "/api/v1/admin/s3-multipart/stale": "List stale multipart upload sessions.",
    "/api/v1/admin/s3-multipart/*/recover": "Recover a stale multipart session's parts.",
    "/api/v1/buckets": "Programmatic bucket surface for bearer keys.",
    "/api/v1/buckets/*/content": "Object byte upload/download over REST.",
    "/api/v1/buckets/*/objects": "Current object listing and logical delete.",
    "/api/v1/buckets/*/versions": "A key's published immutable versions.",
    "/api/v1/admin/storage/active-channel": "Which Telegram channel currently receives uploads.",
    "/api/v1/admin/storage/buckets": "Bucket catalog with usage and quota (WebUI).",
    "/api/v1/admin/storage/buckets/*/content": "WebUI object browsing and byte transfer.",
    "/api/v1/admin/storage/buckets/*/cors": "Bucket CORS configuration.",
    "/api/v1/admin/storage/buckets/*/objects": "WebUI object listing and deletion.",
    "/api/v1/admin/storage/buckets/*/objects/copy": "Server-side object copy.",
    "/api/v1/admin/storage/buckets/*/pin": "Pin a bucket's uploads to one Telegram account.",
    "/api/v1/admin/storage/buckets/*/presign": "Issue a presigned share URL for an object.",
    "/api/v1/admin/storage/buckets/*/quota": "Per-bucket size/object quotas.",
    "/api/v1/admin/storage/buckets/*/shares": "Manage public share links for a bucket's objects.",
    "/api/v1/admin/storage/channel-history": "Telegram channel message history inventory.",
    "/api/v1/admin/storage/channels": "Telegram storage channels and activation.",
    "/api/v1/admin/storage/channels/*/activate": "Make a channel the active upload target.",
    "/api/v1/admin/storage/gc": "Physical GC state, metrics and the owner toggle.",
    "/api/v1/admin/storage/gc/collect": "Dry-run or execute physical collection of retained media.",
    "/api/v1/admin/storage/gc-audit": "GC decision audit trail.",
    "/api/v1/admin/storage/gc-candidates": "Failed-object GC candidates (preview only).",
    "/api/v1/admin/storage/health": "Storage engine health and job state summary.",
    "/api/v1/admin/storage/jobs": "Upload job queue: list, import, trigger.",
    "/api/v1/admin/storage/jobs/*/cancel": "Cancel a queued/running upload job.",
    "/api/v1/admin/storage/jobs/*/retry": "Retry a failed upload job.",
    "/api/v1/admin/storage/mtproto-unresolved": "Unresolved MTProto send intents (crash forensics).",
    "/api/v1/admin/storage/pending-stale": "Stale pending objects from interrupted uploads.",
    "/api/v1/admin/storage/pending-stale/*/abandon": "Abandon one stale pending object.",
    "/api/v1/admin/storage/replication": "Cross-account replication status and configuration.",
    "/api/v1/admin/storage/replication/repair": "Digest-verify and re-send missing replicas.",
    "/api/v1/admin/storage/search": "Full-text content search across object bytes.",
    "/api/v1/admin/storage/search/reindex": "Rebuild the content search index.",
    "/api/v1/admin/storage/shares": "List/revoke public share links.",
    "/api/v1/admin/storage/strategy": "Upload account-selection strategy.",
    "/api/v1/admin/storage/telegram-session": "Add a Telegram user session (code/verify/floodwait).",
    "/api/v1/admin/storage/telegram-sessions": "Telegram accounts with usage, cooldowns, quotas.",
    "/api/v1/admin/storage/telegram-sessions/*/health-check": "Probe one account's session health.",
    "/api/v1/admin/storage/telegram-sessions/*/quota": "Per-account soft quota in bytes.",
    "/api/v1/admin/storage/usage": "Daily upload volume series for the dashboard chart.",
    "/api/v1/admin/storage/version-history": "Cross-bucket version and delete-marker history.",
    "/api/v1/admin/storage/versions": "A key's published versions (restore source).",
    "/api/v1/admin/storage/versions/*/restore": "Restore a published version without re-upload.",
    "/api/v1/admin/storage/versions/index-current": "Index current objects for version navigation.",
}


def group_for(path: str) -> str:
    """The permission group of a route path: {params} fold to '*', a
    trailing '/*' is dropped ('/x/{id}' groups under '/x')."""
    group = re.sub(r"\{[^}]+\}", "*", path)
    if group.endswith("/*"):
        group = group[:-2]
    return group

# Routes that must never require a permission: public surface and the
# auth bootstrap itself.
_PUBLIC_PREFIXES = (
    "/api/health", "/__health", "/static/", "/login", "/logout",
    "/share/", "/docs", "/redoc", "/openapi.json",
)
_PUBLIC_EXACT = {"/", "/login", "/logout", "/favicon.ico"}


def canonical_permission(method: str, template: str) -> str:
    if (method, template) in CURATED_PERMISSIONS:
        return CURATED_PERMISSIONS[(method, template)]
    return f"{method.lower()}:{template}"


def _is_public(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)


def _template_pattern(template: str) -> re.Pattern:
    parts = template.split("{")
    pieces = []
    for index, part in enumerate(parts):
        if index == 0:
            pieces.append(re.escape(part))
            continue
        name, _, rest = part.partition("}")
        pieces.append("[^/]+")
        pieces.append(re.escape(rest))
    return re.compile("^" + "".join(pieces) + "$")


class PermissionRegistry:
    """Method+template -> permission, with concrete-request matching."""

    def __init__(self, routes):
        self._entries: list[tuple[str, str, str, re.Pattern, str]] = []
        self._by_key: dict[tuple[str, str], str] = {}
        for route in routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None) or set()
            # Only the JSON API surface carries permissions; HTML pages
            # are session-cookie views and public endpoints (health)
            # have no gate to permission.
            if (not path or not path.startswith("/api/")
                    or _is_public(path)):
                continue
            summary = (getattr(route, "summary", None)
                       or (getattr(route.endpoint, "__doc__", "") or ""
                           ).strip().split("\n")[0][:140])
            for method in sorted(methods - {"OPTIONS"}):
                permission = canonical_permission(method, path)
                self._entries.append(
                    (method, path, permission, _template_pattern(path),
                     summary))
                self._by_key.setdefault((method, path), permission)
        # The curated names must all correspond to real routes.
        for (method, path), name in CURATED_PERMISSIONS.items():
            assert (method, path) in self._by_key, (method, path)

    def permission_for(self, method: str, concrete_path: str) -> str | None:
        for entry_method, _template, permission, pattern, _summary \
                in self._entries:
            if entry_method == method and pattern.match(concrete_path):
                return permission
        return None

    def catalog(self) -> list[dict]:
        return [
            {"name": permission, "method": method, "path": template,
             "summary": summary}
            for method, template, permission, _, summary in sorted(
                self._entries, key=lambda e: (e[1], e[0]))]

    def groups(self) -> list[dict]:
        """Routes grouped by permission group with descriptions."""
        grouped: dict[str, list[dict]] = {}
        for entry in self.catalog():
            grouped.setdefault(group_for(entry["path"]), []).append(entry)
        return [
            {"name": name,
             "description": GROUP_DESCRIPTIONS.get(
                 name, "API endpoints under " + name),
             "routes": routes}
            for name, routes in sorted(grouped.items())]
