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
        self._entries: list[tuple[str, str, str, re.Pattern]] = []
        self._by_key: dict[tuple[str, str], str] = {}
        seen = set()
        for route in routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None) or set()
            if not path or _is_public(path):
                continue
            for method in sorted(methods - {"OPTIONS"}):
                permission = canonical_permission(method, path)
                self._entries.append(
                    (method, path, permission, _template_pattern(path)))
                self._by_key.setdefault((method, path), permission)
                seen.add(permission)
        # The curated names must all correspond to real routes.
        for (method, path), name in CURATED_PERMISSIONS.items():
            assert (method, path) in self._by_key, (method, path)

    def permission_for(self, method: str, concrete_path: str) -> str | None:
        for entry_method, _template, permission, pattern in self._entries:
            if entry_method == method and pattern.match(concrete_path):
                return permission
        return None

    def catalog(self) -> list[dict]:
        return [
            {"name": permission, "method": method, "path": template}
            for method, template, permission, _ in sorted(
                self._entries, key=lambda e: (e[1], e[0]))]
