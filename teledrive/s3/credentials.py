"""Encrypted, independently revocable S3 access credentials.

A dedicated Fernet master key is mandatory. DB backups alone never reveal
AWS secret keys. Losing the master key makes existing keys unusable.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import BigInteger, Boolean, Column, MetaData, String, Table, Text, insert, select, update

from teledrive.db import Database

_meta = MetaData()
credentials = Table(
    "storage_s3_credentials", _meta,
    Column("id", String(36), primary_key=True),
    Column("name", String(120), nullable=False),
    Column("access_key", String(64), nullable=False, unique=True),
    Column("encrypted_secret", Text, nullable=False),
    Column("permissions", Text, nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("expires_at", BigInteger),
    Column("revoked", Boolean, nullable=False),
)
PERMISSIONS = frozenset({
    "s3:ListAllMyBuckets", "s3:CreateBucket", "s3:DeleteBucket",
    "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetObject", "s3:GetObjectAttributes", "s3:PutObject", "s3:DeleteObject",
    "s3:GetObjectTagging", "s3:PutObjectTagging", "s3:DeleteObjectTagging",
    "s3:GetBucketTagging", "s3:PutBucketTagging", "s3:DeleteBucketTagging",
    "s3:GetBucketCORS", "s3:PutBucketCORS",
    "s3:GetBucketVersioning", "s3:PutBucketVersioning",
    "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock",
    "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration",
    "s3:GetBucketPolicyStatus",
    # Read-only AWS compatibility probes (no configuration permissions).
    "s3:GetBucketAcl", "s3:GetObjectAcl",
    "s3:GetOwnershipControls", "s3:GetBucketPolicy",
    "s3:GetBucketReplication", "s3:GetBucketWebsite",
    "s3:GetBucketNotification", "s3:GetBucketLogging",
    # Website configuration (Phase I). The public read gate itself is an
    # admin API decision, never an S3 credential permission.
    "s3:PutBucketWebsite", "s3:DeleteBucketWebsite",
    # Notification webhooks and access-logging configuration (Phase F).
    "s3:PutBucketNotification", "s3:PutBucketLogging",
    "s3:GetBucketRequestPayment", "s3:GetAccelerateConfiguration",
    "s3:GetEncryptionConfiguration", "s3:GetBucketObjectLockConfiguration",
    "s3:GetObjectRetention", "s3:GetObjectLegalHold",
    # Object Lock configuration (Phase C of the metadata parity plan).
    "s3:PutBucketObjectLockConfiguration", "s3:PutObjectRetention",
    "s3:PutObjectLegalHold",
    # ACL grants (Phase D): write paths for the intersection model.
    "s3:PutBucketAcl", "s3:PutObjectAcl",
    # Bucket replication (Phase G): the S3 surface over the existing
    # cross-account replica engine. No AWS IAM or cross-region semantics.
    "s3:PutBucketReplication", "s3:DeleteBucketReplication",
})
DEFAULT_PERMISSIONS = tuple(sorted(PERMISSIONS))


def load_master_key() -> bytes:
    secret_file = os.environ.get("TELEDRIVE_S3_MASTER_KEY_FILE", "").strip()
    if secret_file:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(secret_file, flags)
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(256).strip()
    else:
        data = os.environ.get("TELEDRIVE_S3_MASTER_KEY", "").encode("ascii").strip()
    try:
        Fernet(data)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Set a valid 32-byte Fernet TELEDRIVE_S3_MASTER_KEY") from exc
    return data


@dataclass(frozen=True)
class IssuedS3Credential:
    id: str
    access_key: str
    secret_key: str
    permissions: tuple[str, ...]


class S3CredentialStore:
    def __init__(self, database: Database, master_key: bytes):
        self.db = database
        self.cipher = Fernet(master_key)
        _meta.create_all(database.engine)

    def create(self, name: str, permissions: list[str], *,
               expires_at: int | None = None, now: int | None = None) -> IssuedS3Credential:
        now = int(time.time()) if now is None else now
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 120):
            raise ValueError("S3 credential requires a name (1–120 characters)")
        if not isinstance(permissions, list) or not permissions or any(
                p not in PERMISSIONS for p in permissions):
            raise ValueError("Unknown or empty S3 permission")
        if expires_at is not None and (expires_at <= now or expires_at > now + 10 * 365 * 86400):
            raise ValueError("Expiration must be in the future (up to 10 years)")
        from uuid import uuid4
        identifier = str(uuid4())
        access = "TD" + secrets.token_hex(12).upper()
        secret = secrets.token_urlsafe(40)
        perms = tuple(sorted(set(permissions)))
        self.db.connection.execute(insert(credentials).values(
            id=identifier, name=name.strip(), access_key=access,
            encrypted_secret=self.cipher.encrypt(secret.encode()).decode(),
            permissions=json.dumps(perms), created_at=now, expires_at=expires_at,
            revoked=False,
        ))
        self.db.commit()
        return IssuedS3Credential(identifier, access, secret, perms)

    def list(self) -> list[dict]:
        rows = self.db.connection.execute(select(
            credentials.c.id, credentials.c.name, credentials.c.access_key,
            credentials.c.permissions, credentials.c.created_at,
            credentials.c.expires_at, credentials.c.revoked,
        ).order_by(credentials.c.created_at.desc(), credentials.c.id)).mappings().all()
        return [{**dict(row), "permissions": json.loads(row["permissions"])} for row in rows]

    def resolve(self, access_key: str, permission: str, *,
                now: int | None = None) -> str | None:
        now = int(time.time()) if now is None else now
        if not isinstance(access_key, str) or len(access_key) > 64 or permission not in PERMISSIONS:
            return None
        row = self.db.connection.execute(select(
            credentials.c.encrypted_secret, credentials.c.permissions,
            credentials.c.revoked, credentials.c.expires_at,
        ).where(credentials.c.access_key == access_key)).first()
        if not row or row[2] or (row[3] is not None and row[3] <= now):
            return None
        if permission not in json.loads(row[1]):
            return None
        try:
            return self.cipher.decrypt(row[0].encode()).decode()
        except (InvalidToken, ValueError, UnicodeError):
            return None

    def is_active(self, access_key: str, *, now: int | None = None) -> bool:
        """Does this access key belong to an active, unexpired credential?

        ACL grantees are validated against this so an unknown or revoked
        CanonicalUser ID is rejected at write time instead of silently
        never matching.
        """
        now = int(time.time()) if now is None else now
        if not isinstance(access_key, str) or len(access_key) > 64:
            return False
        row = self.db.connection.execute(select(
            credentials.c.revoked, credentials.c.expires_at,
        ).where(credentials.c.access_key == access_key)).first()
        return bool(row) and not row[0] and (row[1] is None or row[1] > now)

    def reveal(self, identifier: str) -> dict:
        """Decrypt and return an ACTIVE credential's secret (admin only).

        Secrets are encrypted at rest and shown on demand; every reveal
        must be audit-logged by the caller.
        """
        row = self.db.connection.execute(select(
            credentials.c.id, credentials.c.access_key,
            credentials.c.encrypted_secret, credentials.c.revoked,
            credentials.c.expires_at, credentials.c.permissions,
        ).where((credentials.c.id == identifier)
                | (credentials.c.access_key == identifier))).first()
        if not row:
            raise ValueError("Unknown credential")
        if row[3]:
            raise ValueError("Revoked credentials have no active secret")
        # An EXPIRED credential cannot authenticate, so its secret must
        # not be handed out either: revealing it would be misleading and
        # extend the secret's useful life past the operator's intent.
        if row[4] is not None and int(row[4]) <= int(time.time()):
            raise ValueError("Expired credentials have no active secret")
        try:
            secret = self.cipher.decrypt(row[2].encode()).decode()
        except (InvalidToken, ValueError, UnicodeError):
            raise ValueError("Credential secret cannot be decrypted "
                             "(master key changed?)") from None
        return {"id": row[0], "access_key": row[1], "secret_key": secret,
                "permissions": json.loads(row[5])}

    def update(self, identifier: str, *, name: str | None = None,
               permissions: list[str] | None = None,
               expires_at: int | None = None,
               clear_expiry: bool = False) -> dict:
        """Edit an ACTIVE credential's name, permissions and expiry.

        The access key and secret never change: rotating the secret means
        issuing a new credential, which keeps the audit trail honest.
        """
        row = self.db.connection.execute(select(
            credentials.c.id, credentials.c.revoked,
        ).where((credentials.c.id == identifier)
                | (credentials.c.access_key == identifier))).first()
        if not row:
            raise ValueError("Unknown credential")
        if row[1]:
            raise ValueError("Revoked credentials cannot be edited")
        values: dict = {}
        if name is not None:
            name = str(name).strip()
            if not name or len(name) > 128:
                raise ValueError("Invalid credential name")
            values["name"] = name
        if permissions is not None:
            if (not isinstance(permissions, list)
                    or not permissions
                    or any(p not in PERMISSIONS for p in permissions)):
                raise ValueError("Invalid permission set")
            values["permissions"] = json.dumps(sorted(set(permissions)))
        if expires_at is not None:
            values["expires_at"] = int(expires_at)
        elif clear_expiry:
            values["expires_at"] = None
        if not values:
            raise ValueError("Nothing to update")
        self.db.connection.execute(update(credentials).where(
            credentials.c.id == row[0]).values(**values))
        self.db.commit()
        updated = [c for c in self.list() if c["id"] == row[0]]
        return updated[0]

    def revoke(self, identifier: str) -> bool:
        changed = self.db.connection.execute(update(credentials).where(
            credentials.c.id == identifier, credentials.c.revoked.is_(False)
        ).values(revoked=True))
        self.db.commit()
        return changed.rowcount == 1
