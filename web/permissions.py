"""Unified per-endpoint permission registry and role model.

Every /api/v1 route carries exactly one permission, derived from its
method + path template so the catalog can NEVER drift from the routes:
the registry is built from the live FastAPI route table. The nine REST
bearer endpoints keep their curated short names (issued keys depend on
them); every other route gets a canonical "method:path" name.

There is ONE permission model for authenticated users. A browser session
cookie resolves to a local `users` row, and that row's role grants a set
of endpoint permissions derived here:

- admin     every permission in the registry (superset by construction)
- operator  every permission except the admin-only surfaces below
- viewer    only read permissions (GET/HEAD, or a curated read name)
            outside the admin-only surfaces

The admin-only surfaces are listed in ``_ADMIN_ONLY_PREFIXES`` and the
storage owner-decision routes in ``_ADMIN_ONLY_BUCKETS_SUFFIXES``. They
are excluded from operator and viewer even though those roles can never
reach them: the path gate in ``web.app._required_roles`` already blocks
them, so the role map is defence in depth rather than the only gate.

Bearer API keys are deliberately NOT mapped through a role. A key's
permissions are exactly the scope names it was issued with (plus the
legacy expansions), so existing keys keep working unchanged. A key with
one route's permission gains nothing on any other route.
"""
from __future__ import annotations

import re

READ_METHODS = frozenset({"GET", "HEAD"})

# ---------------------------------------------------------------------------
# The canonical role -> permission map. THIS is the only place a session
# principal gets authority from; there is no "any GET is fine" rule. Read
# each row as an audit statement:
#
#   admin     every API permission in the live registry, including routes
#             added after this file was written
#   operator  every permission EXCEPT the admin-only surfaces listed below:
#             users, roles/API keys, S3 credentials, physical GC, bucket
#             quota, website publishing and deployment-config writes
#   viewer    read-only: GET/HEAD routes and the curated REST read names,
#             again excluding every admin-only surface
#
# A role not listed here grants NOTHING (fail closed).
# ---------------------------------------------------------------------------
ROLE_PERMISSION_RULES: dict[str, dict] = {
    "admin": {
        "description": "Full access: every API permission in the registry.",
        "read_only": False,
        "deny_admin_only": False,
    },
    "operator": {
        "description": (
            "All data and storage permissions. No user, API-key, S3-credential, "
            "physical-GC, quota, website-publish or deployment-config "
            "administration."),
        "read_only": False,
        "deny_admin_only": True,
    },
    "viewer": {
        "description": (
            "Read-only: GET/HEAD routes and curated REST read names, outside "
            "the admin-only surfaces."),
        "read_only": True,
        "deny_admin_only": True,
    },
}

# Surfaces only the admin role may attempt, for every method. Config is
# admin-only for writes (viewers may read the redacted document), so it
# is handled separately below.
_ADMIN_ONLY_PREFIXES = (
    "/api/v1/admin/users",
    "/api/v1/admin/keys",
    "/api/v1/admin/s3/credentials",
    "/api/v1/admin/s3-credentials",
    "/api/v1/admin/storage/gc",
    # The log buffer is an audit trail: it contains object keys, request
    # paths and failure detail. Every role could read it, which is how a
    # share token and a credential id ended up readable by a viewer. Logs are
    # an operator/admin surface, not a read-only one.
    "/api/v1/logs",
    "/api/logs",
    # Durable security trail: names users, buckets, keys and objects.
    "/api/v1/admin/audit",
    # A share token IS the credential: the anonymous URL needs nothing else.
    # A read-only viewer who can list them becomes an anonymous publisher
    # that outlives their own account, so listing and revoking are admin.
    "/api/v1/admin/storage/shares",
)

# Binding a Telegram account is a storage-wide act: the bound account becomes
# the identity every future upload is sent as, and completing a login
# deactivates the other channels. An operator who can do this owns the
# backend, so the MUTATING side is an admin (owner) decision.
#
# Deliberately enumerated rather than prefix-matched: "/telegram-session" is a
# prefix of "/telegram-sessions" (the read-only account listing operators
# need), and the status/floodwait GETs are harmless reads that every role may
# perform.
_ADMIN_ONLY_TELEGRAM_SESSION_MUTATIONS = frozenset({
    "/api/v1/admin/storage/telegram-session",
    "/api/v1/admin/storage/telegram-session/request-code",
    "/api/v1/admin/storage/telegram-session/verify-code",
})
# Bucket quota and website publishing are owner decisions: quota changes
# can reject uploads, and public_read publishes objects anonymously.
_ADMIN_ONLY_BUCKETS_PREFIX = "/api/v1/admin/storage/buckets"
_ADMIN_ONLY_BUCKETS_SUFFIXES = ("/quota", "/website")
# Only writes to the deployment configuration are administrative.
_ADMIN_ONLY_WRITE_EXACT = frozenset({"/api/v1/config"})

# The curated REST names that are read-only even though they do not carry
# a "get:"/"head:" prefix.
_CURATED_READ_PERMISSIONS = frozenset({
    "rest:buckets:list",
    "rest:objects:list",
    "rest:objects:list-versions",
    "rest:objects:get",
    "rest:objects:head",
})


def canonical_path(path: str) -> str:
    """Fold the legacy /api/* aliases onto /api/v1/* before matching."""
    if (path.startswith("/api/")
            and not path.startswith("/api/v1/")
            and not path.startswith("/api/health")):
        return "/api/v1/" + path[len("/api/"):]
    return path


def is_admin_only(method: str, path: str) -> bool:
    """True when only the admin role may attempt this route."""
    path = canonical_path(path)
    if any(path.startswith(prefix) for prefix in _ADMIN_ONLY_PREFIXES):
        return True
    if (str(method).upper() not in READ_METHODS
            and path in _ADMIN_ONLY_TELEGRAM_SESSION_MUTATIONS):
        return True
    if (path.startswith(_ADMIN_ONLY_BUCKETS_PREFIX)
            and path.endswith(_ADMIN_ONLY_BUCKETS_SUFFIXES)):
        return True
    if (str(method).upper() not in READ_METHODS
            and path in _ADMIN_ONLY_WRITE_EXACT):
        return True
    return False


def _is_read_permission(permission: str) -> bool:
    return (permission.startswith(("get:", "head:"))
            or permission in _CURATED_READ_PERMISSIONS)

# Curated short names for the original REST bearer surface (backward
# compatibility with issued keys and the S3 credential docs).
# The curated route -> permission mapping has ONE definition, in
# teledrive/api_keys.py, because keys and the permission registry must agree
# on the same names. This used to be a literal copy of the same nine pairs;
# two sources for one fact would eventually drift.
from teledrive.api_keys import CURATED_ROUTES as CURATED_PERMISSIONS

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
# The public certificate must be fetchable before any client trusts the
# deployment's TLS, so it cannot require a login (bootstrap deadlock).
_PUBLIC_EXACT = {"/", "/login", "/logout", "/favicon.ico",
                 "/server.cer", "/server.crt"}


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
        self._by_permission: dict[str, tuple[str, str]] = {}
        self._role_permissions: dict[str, frozenset[str]] = {}
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
                self._by_permission.setdefault(permission, (method, path))
        # The curated names must all correspond to real routes.
        for (method, path), name in CURATED_PERMISSIONS.items():
            assert (method, path) in self._by_key, (method, path)

    def permission_for(self, method: str, concrete_path: str) -> str | None:
        for entry_method, _template, permission, pattern, _summary \
                in self._entries:
            if entry_method == method and pattern.match(concrete_path):
                return permission
        return None

    def permissions_for_role(self, role: str | None) -> frozenset[str]:
        """The effective endpoint permissions granted by a user's role.

        The rule comes from ``ROLE_PERMISSION_RULES``; unknown/absent roles
        grant nothing. The sets are resolved against the live route table
        once per registry instance, so a new route is automatically
        admin-visible and can never silently appear in a lower role.
        """
        key = role or ""
        cached = self._role_permissions.get(key)
        if cached is not None:
            return cached
        rule = ROLE_PERMISSION_RULES.get(key)
        if rule is None:
            granted = frozenset()
        else:
            selected: set[str] = set()
            for permission, (method, template) in self._by_permission.items():
                if rule["deny_admin_only"] and is_admin_only(method, template):
                    continue
                if rule["read_only"] and not _is_read_permission(permission):
                    continue
                selected.add(permission)
            granted = frozenset(selected)
        self._role_permissions[key] = granted
        return granted

    def role_allows(self, role: str | None, permission: str) -> bool:
        return permission in self.permissions_for_role(role)

    def role_map(self) -> list[dict]:
        """The auditable role map: description, mode and granted groups."""
        rows = []
        for role, rule in sorted(ROLE_PERMISSION_RULES.items()):
            granted = self.permissions_for_role(role)
            groups = sorted({
                group_for(template)
                for permission in granted
                for (_method, template) in [self._by_permission[permission]]
            })
            rows.append({
                "name": role,
                "description": rule["description"],
                "read_only": rule["read_only"],
                "permission_count": len(granted),
                "groups": groups,
            })
        return rows

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
