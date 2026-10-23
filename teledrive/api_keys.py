"""High-entropy REST API keys with SQL-backed scopes and atomic revocation.

No plaintext secrets are stored. The token appears exactly once on creation
or rotation; only its SHA-256 digest and non-secret prefix are persisted.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from sqlalchemy import BigInteger, Boolean, Column, MetaData, String, Table, Text, delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from teledrive.db import Database

_metadata = MetaData()
api_keys = Table(
    "api_credentials", _metadata,
    Column("id", String(36), primary_key=True),
    Column("digest", String(64), nullable=False, unique=True),
    Column("prefix", String(24), nullable=False),
    Column("name", String(120), nullable=False),
    Column("scopes", Text, nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("expires_at", BigInteger),
    Column("last_used_at", BigInteger),
    Column("revoked", Boolean, nullable=False),
)
# Per-endpoint permissions: every REST bearer endpoint is individually
# permissionable. The description doubles as the UI label.
ENDPOINT_PERMISSIONS = {
    "rest:buckets:list": "GET /api/v1/buckets — list buckets",
    "rest:buckets:create": "POST /api/v1/buckets — create a bucket",
    "rest:buckets:delete": "DELETE /api/v1/buckets/{bucket} — remove an empty bucket",
    "rest:objects:list": "GET /api/v1/buckets/{bucket}/objects — list current objects",
    "rest:objects:list-versions": "GET /api/v1/buckets/{bucket}/versions — list a key's published versions",
    "rest:objects:get": "GET /api/v1/buckets/{bucket}/content — stream object bytes (Range)",
    "rest:objects:head": "HEAD /api/v1/buckets/{bucket}/content — object headers",
    "rest:objects:put": "PUT /api/v1/buckets/{bucket}/content — upload object bytes",
    "rest:objects:delete": "DELETE /api/v1/buckets/{bucket}/objects — unlink a current object",
}

# Legacy grouped scopes stay valid and expand to endpoint sets, so keys
# issued before per-endpoint permissions keep working unchanged.
# Scopes with an empty expansion gate no REST endpoint today.
LEGACY_SCOPE_EXPANSION = {
    "buckets:read": ("rest:buckets:list",),
    "buckets:manage": ("rest:buckets:create", "rest:buckets:delete"),
    "objects:read": ("rest:objects:list", "rest:objects:list-versions",
                     "rest:objects:get", "rest:objects:head"),
    "objects:write": ("rest:objects:put",),
    "objects:delete": ("rest:objects:delete",),
    "jobs:read": (), "jobs:manage": (),
    "accounts:read": (), "accounts:manage": (),
    "settings:read": (), "settings:manage": (),
    "keys:manage": (),
    "admin:*": tuple(ENDPOINT_PERMISSIONS),
}
ALLOWED_SCOPES = frozenset(ENDPOINT_PERMISSIONS) | frozenset(LEGACY_SCOPE_EXPANSION)


def expand_scopes(scopes) -> frozenset[str]:
    """Resolve a key's scopes (legacy groups and/or per-endpoint names)
    into the concrete set of endpoint permissions they grant."""
    granted: set[str] = set()
    for scope in scopes or ():
        if scope in ENDPOINT_PERMISSIONS:
            granted.add(scope)
        else:
            granted.update(LEGACY_SCOPE_EXPANSION.get(scope, ()))
    return frozenset(granted)


@dataclass(frozen=True)
class IssuedKey:
    id: str
    value: str
    prefix: str
    scopes: tuple[str, ...]


class ApiKeyStore:
    def __init__(self, db: Database):
        self.db = db
        _metadata.create_all(db.engine)

    @staticmethod
    def _check_scopes(scopes: list[str]) -> tuple[str, ...]:
        if not isinstance(scopes, list) or not scopes or any(
            not isinstance(s, str) or s not in ALLOWED_SCOPES for s in scopes
        ):
            raise ValueError("Unknown or empty permission scope")
        normalized = tuple(sorted(set(scopes)))
        if "admin:*" in normalized and len(normalized) != 1:
            raise ValueError("admin:* cannot be combined with other scopes")
        return normalized

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, name: str, scopes: list[str], *, expires_at: int | None = None,
               now: int | None = None) -> IssuedKey:
        now = int(time.time()) if now is None else now
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 120):
            raise ValueError("Invalid API key name")
        permissions = self._check_scopes(scopes)
        if expires_at is not None and (expires_at <= now or expires_at > now + 10 * 365 * 86400):
            raise ValueError("API key expiration must be in the future (max 10 years)")
        identifier = secrets.token_hex(16)
        token = "td_live_" + secrets.token_urlsafe(32)
        prefix = token[:16]
        self.db.connection.execute(insert(api_keys).values(
            id=identifier, digest=self._digest(token), prefix=prefix,
            name=name.strip(), scopes=json.dumps(permissions),
            created_at=now, expires_at=expires_at, last_used_at=None, revoked=False,
        ))
        self.db.commit()
        return IssuedKey(identifier, token, prefix, permissions)

    def list(self) -> list[dict]:
        rows = self.db.connection.execute(
            select(api_keys.c.id, api_keys.c.prefix, api_keys.c.name,
                   api_keys.c.scopes, api_keys.c.created_at, api_keys.c.expires_at,
                   api_keys.c.last_used_at, api_keys.c.revoked)
            .order_by(api_keys.c.revoked.asc(), api_keys.c.created_at.desc(), api_keys.c.id)
        ).mappings().all()
        return [{**dict(row), "scopes": json.loads(row["scopes"])} for row in rows]

    def authorize(self, token: str, scope: str, *, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        if (not isinstance(token, str) or len(token) > 200
                or not token.startswith("td_live_")):
            return False
        result = self.db.connection.execute(
            select(api_keys.c.id, api_keys.c.scopes, api_keys.c.revoked, api_keys.c.expires_at)
            .where(api_keys.c.digest == self._digest(token))
        ).first()
        if not result or result[2] or (result[3] is not None and result[3] <= now):
            return False
        if scope not in expand_scopes(json.loads(result[1])):
            return False
        self.db.connection.execute(
            update(api_keys).where(api_keys.c.id == result[0]).values(last_used_at=now)
        )
        self.db.commit()
        return True

    def name_for_token(self, token: str) -> str | None:
        """Return the name of the API key for a given token, or None."""
        if (not isinstance(token, str) or len(token) > 200
                or not token.startswith("td_live_")):
            return None
        result = self.db.connection.execute(
            select(api_keys.c.name)
            .where(api_keys.c.digest == self._digest(token))
        ).first()
        if result is None:
            return None
        return result[0]

    def revoke(self, identifier: str) -> bool:
        changed = self.db.connection.execute(
            update(api_keys).where(api_keys.c.id == identifier, api_keys.c.revoked.is_(False))
            .values(revoked=True)
        )
        self.db.commit()
        return changed.rowcount == 1

    def rotate(self, identifier: str, *, now: int | None = None) -> IssuedKey:
        now = int(time.time()) if now is None else now
        old = self.db.connection.execute(
            select(api_keys.c.name, api_keys.c.scopes, api_keys.c.expires_at)
            .where(api_keys.c.id == identifier, api_keys.c.revoked.is_(False))
        ).first()
        if old is None:
            raise FileNotFoundError("API key not found or revoked")
        if old[2] is not None and old[2] <= now:
            raise ValueError("Cannot rotate expired key")
        permissions = json.loads(old[1])
        # Keep creation+revoke in one transaction, so no partial rotation.
        token = "td_live_" + secrets.token_urlsafe(32)
        new_id = secrets.token_hex(16)
        changed = self.db.connection.execute(update(api_keys).where(
            api_keys.c.id == identifier, api_keys.c.revoked.is_(False)
        ).values(revoked=True))
        if changed.rowcount != 1:
            self.db.connection.rollback()
            raise ValueError("Concurrent key revocation")
        self.db.connection.execute(insert(api_keys).values(
            id=new_id, digest=self._digest(token), prefix=token[:16],
            name=old[0], scopes=old[1], created_at=now,
            expires_at=old[2], last_used_at=None, revoked=False,
        ))
        self.db.commit()
        return IssuedKey(new_id, token, token[:16], tuple(permissions))
