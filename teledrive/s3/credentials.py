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
    # Phase L4 ABAC: principal tags.  TEXT (nullable) is safe on MySQL
    # where a DEFAULT on TEXT is rejected; None means an empty tag set.
    Column("tags", Text),
)
PERMISSIONS = frozenset({
    "s3:ListAllMyBuckets", "s3:CreateBucket", "s3:DeleteBucket",
    # S3 Express One Zone surfaces. TeleDrive has no directory buckets, so
    # ListDirectoryBuckets is a real always-empty listing and CreateSession
    # always answers NoSuchBucket, but both still authenticate and authorize.
    "s3:ListDirectoryBuckets", "s3:CreateSession",
    "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetObject", "s3:GetObjectAttributes", "s3:PutObject", "s3:DeleteObject",
    "s3:GetObjectTagging", "s3:PutObjectTagging", "s3:DeleteObjectTagging",
    # Object annotations (Phase O2): a separate store from tags; the four
    # permissions are independently grantable.
    "s3:GetObjectAnnotation", "s3:PutObjectAnnotation",
    "s3:DeleteObjectAnnotation", "s3:ListObjectAnnotations",
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
    # Phase O6: the single real state is writable (BucketOwner / Suspended).
    "s3:PutBucketRequestPayment", "s3:PutBucketAccelerateConfiguration",
    "s3:GetEncryptionConfiguration", "s3:GetBucketObjectLockConfiguration",
    # SSE-C (client-supplied keys). There is deliberately no SSE-S3/KMS
    # scope: no server-side key exists to grant access to.
    "s3:GetBucketEncryption", "s3:PutBucketEncryption",
    "s3:DeleteBucketEncryption", "s3:PutObjectEncryption",
    "s3:GetObjectRetention", "s3:GetObjectLegalHold",
    # Object Lock configuration (Phase C of the metadata parity plan).
    "s3:PutBucketObjectLockConfiguration", "s3:PutObjectRetention",
    "s3:PutObjectLegalHold",
    # ACL grants (Phase D): write paths for the intersection model.
    "s3:PutBucketAcl", "s3:PutObjectAcl",
    # Bucket policy engine (Phase L).
    "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
    "s3:PutBucketOwnershipControls", "s3:DeleteBucketOwnershipControls",
    "s3:PutBucketAbac", "s3:GetBucketAbac",
    # Bucket replication (Phase G): the S3 surface over the existing
    # cross-account replica engine. No AWS IAM or cross-region semantics.
    "s3:PutBucketReplication", "s3:DeleteBucketReplication",
    # Phase O: real atomic rename, real Select and honest RestoreObject.
    "s3:RenameObject", "s3:SelectObjectContent", "s3:RestoreObject",
    # Storage reports (Phase N): analytics, inventory and metrics
    # configuration CRUD. GET and DELETE have their own scope names so an
    # operator can grant read-only report visibility without write access.
    "s3:GetBucketAnalyticsConfiguration", "s3:PutBucketAnalyticsConfiguration",
    "s3:DeleteBucketAnalyticsConfiguration",
    "s3:GetBucketInventoryConfiguration", "s3:PutBucketInventoryConfiguration",
    "s3:DeleteBucketInventoryConfiguration",
    "s3:GetBucketMetricsConfiguration", "s3:PutBucketMetricsConfiguration",
    "s3:DeleteBucketMetricsConfiguration",
    # Intelligent-Tiering (Phase N5 + O1): real configuration CRUD plus the
    # catalog access gate and RestoreObject window.
    "s3:GetBucketIntelligentTieringConfiguration",
    "s3:PutBucketIntelligentTieringConfiguration",
    "s3:DeleteBucketIntelligentTieringConfiguration",
    "s3:ListBucketIntelligentTieringConfigurations",
    # S3 Metadata configuration (Phase O3). AWS uses the SAME IAM action for
    # the V1 and V2 create/get/delete operations, so only one scope exists
    # for each of those verbs. The three update operations have their own
    # action names in the AWS API reference.
    "s3:CreateBucketMetadataTableConfiguration",
    "s3:GetBucketMetadataTableConfiguration",
    "s3:DeleteBucketMetadataTableConfiguration",
    "s3:UpdateBucketMetadataJournalTableConfiguration",
    "s3:UpdateBucketMetadataInventoryTableConfiguration",
    "s3:UpdateBucketMetadataAnnotationTableConfiguration",
})
DEFAULT_PERMISSIONS = tuple(sorted(PERMISSIONS))
MAX_CREDENTIAL_TAGS = 50


def _validated_tags(tags) -> dict[str, str]:
    if tags is None:
        return {}
    if not isinstance(tags, dict) or len(tags) > MAX_CREDENTIAL_TAGS:
        raise ValueError("Credential tags must be a dict of at most 50 entries")
    clean: dict[str, str] = {}
    for key, value in tags.items():
        if (not isinstance(key, str) or not key or len(key) > 128
                or not isinstance(value, str) or len(value) > 256):
            raise ValueError("Invalid credential tag")
        clean[key] = value
    return clean


_tags_column_ensured = False


def ensure_credential_tags_column(db) -> None:
    """Add storage_s3_credentials.tags on deployments predating Phase L.

    The ALTER runs in ``teledrive.storage.schema``; this wrapper keeps the
    historical entry point and its process-wide "already checked" fast path.
    """
    global _tags_column_ensured
    if _tags_column_ensured:
        return
    from teledrive.storage.schema import ensure_schema
    ensure_schema(db.engine)
    _tags_column_ensured = True



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
    def __init__(self, database: Database, master_key: bytes, *,
                 ensure: bool = True):
        self.db = database
        self.cipher = Fernet(master_key)
        # ``ensure=False`` is for the pre-authentication path: the S3 gateway
        # must not run schema DDL for an unauthenticated request, or anyone
        # who can reach the port can trigger a migration. Signature
        # verification only needs a read, and a missing table reads as "no
        # such credential" -- which fails closed. Every write path keeps the
        # default.
        if ensure:
            from teledrive.storage.schema import ensure_schema
            ensure_schema(database.engine)

    def create(self, name: str, permissions: list[str], *,
               expires_at: int | None = None, now: int | None = None,
               tags: dict[str, str] | None = None) -> IssuedS3Credential:
        now = int(time.time()) if now is None else now
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 120):
            raise ValueError("S3 credential requires a name (1–120 characters)")
        if not isinstance(permissions, list) or not permissions or any(
                p not in PERMISSIONS for p in permissions):
            raise ValueError("Unknown or empty S3 permission")
        if expires_at is not None and (expires_at <= now or expires_at > now + 10 * 365 * 86400):
            raise ValueError("Expiration must be in the future (up to 10 years)")
        clean_tags = _validated_tags(tags)
        from uuid import uuid4
        identifier = str(uuid4())
        access = "TD" + secrets.token_hex(12).upper()
        secret = secrets.token_urlsafe(40)
        perms = tuple(sorted(set(permissions)))
        self.db.connection.execute(insert(credentials).values(
            id=identifier, name=name.strip(), access_key=access,
            encrypted_secret=self.cipher.encrypt(secret.encode()).decode(),
            permissions=json.dumps(perms), created_at=now, expires_at=expires_at,
            revoked=False, tags=json.dumps(clean_tags, sort_keys=True),
        ))
        self.db.commit()
        return IssuedS3Credential(identifier, access, secret, perms)

    def _resolve(self, identifier) -> str:
        """The credential's canonical id, from an id OR an access key.

        All four operations (reveal, update, rotate-by-reissue, revoke) used
        to interpret ``identifier`` differently -- reveal/update matched
        ``id OR access_key`` while revoke matched the id only, so the same
        string addressed a credential on one endpoint and 404'd on another.
        One resolver, with a bounded input, keeps them consistent.
        """
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 200:
            raise ValueError("Invalid credential identifier")
        row = self.db.connection.execute(select(credentials.c.id).where(
            (credentials.c.id == identifier)
            | (credentials.c.access_key == identifier)).limit(1)).first()
        if row is None:
            raise ValueError("Unknown credential")
        return row[0]

    def list(self) -> list[dict]:
        rows = self.db.connection.execute(select(
            credentials.c.id, credentials.c.name, credentials.c.access_key,
            credentials.c.permissions, credentials.c.created_at,
            credentials.c.expires_at, credentials.c.revoked,
            credentials.c.tags,
        ).order_by(credentials.c.created_at.desc(), credentials.c.id)).mappings().all()
        return [{**dict(row), "permissions": json.loads(row["permissions"]),
                 "tags": json.loads(row["tags"] or "{}")} for row in rows]

    def principal_tags(self, access_key: str) -> dict[str, str]:
        """Tags used by ABAC ``aws:PrincipalTag/*`` conditions."""
        if not isinstance(access_key, str) or len(access_key) > 64:
            return {}
        raw = self.db.connection.execute(select(credentials.c.tags).where(
            credentials.c.access_key == access_key)).scalar_one_or_none()
        try:
            parsed = json.loads(raw or "{}")
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

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
        resolved = self._resolve(identifier)
        row = self.db.connection.execute(select(
            credentials.c.id, credentials.c.access_key,
            credentials.c.encrypted_secret, credentials.c.revoked,
            credentials.c.expires_at, credentials.c.permissions,
        ).where(credentials.c.id == resolved)).first()
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
               clear_expiry: bool = False,
               tags: dict[str, str] | None = None) -> dict:
        """Edit an ACTIVE credential's name, permissions and expiry.

        The access key and secret never change: rotating the secret means
        issuing a new credential, which keeps the audit trail honest.
        """
        resolved = self._resolve(identifier)
        row = self.db.connection.execute(select(
            credentials.c.id, credentials.c.revoked,
        ).where(credentials.c.id == resolved)).first()
        if not row:
            raise ValueError("Unknown credential")
        if row[1]:
            raise ValueError("Revoked credentials cannot be edited")
        # Editing an expired credential would be a revival: expiry is enforced
        # at SigV4 time, so a new future expiry restores live access. A dead
        # credential must be reissued, which leaves an honest audit trail.
        current_expiry = self.db.connection.execute(select(
            credentials.c.expires_at).where(
            credentials.c.id == row[0])).scalar_one()
        if current_expiry is not None and int(current_expiry) <= int(time.time()):
            raise ValueError("Expired credentials cannot be edited; issue a "
                             "new credential")
        values: dict = {}
        if name is not None:
            name = str(name).strip()
            # Same bound as create() -- the column is String(120), so a
            # longer name was silently truncated or rejected by the backend.
            if not name or len(name) > 120:
                raise ValueError("Invalid credential name")
            values["name"] = name
        if permissions is not None:
            if (not isinstance(permissions, list)
                    or not permissions
                    or any(p not in PERMISSIONS for p in permissions)):
                raise ValueError("Invalid permission set")
            values["permissions"] = json.dumps(sorted(set(permissions)))
        if expires_at is not None:
            # An edit must obey the same expiry bounds as create(), or it can
            # revive an already-expired credential (or set a past date) and
            # thereby grant real access at signature-verification time.
            expires_at = int(expires_at)
            now = int(time.time())
            if (expires_at <= now
                    or expires_at > now + 10 * 365 * 86400):
                raise ValueError(
                    "Expiration must be in the future (up to 10 years)")
            values["expires_at"] = expires_at
        elif clear_expiry:
            values["expires_at"] = None
        if tags is not None:
            values["tags"] = json.dumps(_validated_tags(tags), sort_keys=True)
        if not values:
            raise ValueError("Nothing to update")
        self.db.connection.execute(update(credentials).where(
            credentials.c.id == row[0]).values(**values))
        self.db.commit()
        updated = [c for c in self.list() if c["id"] == row[0]]
        return updated[0]

    def revoke(self, identifier: str) -> bool:
        resolved = self._resolve(identifier)
        changed = self.db.connection.execute(update(credentials).where(
            credentials.c.id == resolved, credentials.c.revoked.is_(False)
        ).values(revoked=True))
        self.db.commit()
        return changed.rowcount == 1
