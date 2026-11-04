"""S3 Express One Zone directory buckets and CreateSession sessions.

TeleDrive is a single-process, Telegram-backed, single-region store. It has
no AWS Availability Zones, no S3 Express One Zone hardware and no One Zone
durability/throughput contract. What this module implements is the *functional
directory-bucket protocol* on top of the existing SQL catalog and Telegram
manifests:

* ``bucket_type = general | directory`` on the shared ``storage_buckets``
  table. A directory bucket name is immutable and AWS-shaped:
  ``base--zone-id--x-s3``. The ``zone_id`` is a **logical compatibility
  zone** configured per deployment (``TELEDRIVE_S3_DIRECTORY_ZONE_ID``);
  it never claims to be an AWS Availability Zone, and no One Zone
  durability or latency is implied or provided.
* ``ListDirectoryBuckets`` enumerates the real directory rows with
  keyset pagination and opaque, HMAC-scoped continuation tokens. It never
  returns general-purpose buckets (and ``ListBuckets`` never returns
  directory buckets).
* ``CreateSession`` issues cryptographically random, short-lived
  ``AccessKeyId`` / ``SecretAccessKey`` / ``SessionToken`` / ``Expiration``
  bound to ONE directory bucket, a mode (``ReadOnly`` / ``ReadWrite``), the
  signer's long-lived access key and the logical zone. The default lifetime
  is 5 minutes, matching AWS. The session token is stored only as a SHA-256
  hash; the secret is Fernet-encrypted with the S3 master key. Sessions are
  revoked when the bucket is deleted or the owning credential is revoked.
* Zonal (object-data-plane) requests on a directory bucket must be signed
  with the ``s3express`` SigV4 scope AND carry the exact
  ``x-amz-s3session-token`` header matching the session's stored hash.
  Control-plane operations (CreateSession, CreateBucket, DeleteBucket,
  HeadBucket) keep using long-lived credentials, exactly like AWS's split
  between zonal and regional endpoints.

Fail-closed rules live in :func:`classify_directory_operation`: a request
that names a directory bucket but asks for a general-purpose-only operation
(a bucket policy, versioning, V1 listings, browser form uploads, batch
deletes, server-side copies, object versioning selectors) is rejected with
``400 InvalidRequest`` rather than silently degraded, and vice versa a
general-purpose bucket never accepts ``s3express`` signing or session
credentials.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import (
    BigInteger, Boolean, Column, Index, MetaData, String, Table, Text,
    delete, insert, select, update,
)
from sqlalchemy.exc import SQLAlchemyError

from teledrive.db import Database

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_DIRECTORY_BUCKETS = 1000
MAX_DIRECTORY_TOKEN_LENGTH = 1024
SESSION_MODES = frozenset({"ReadOnly", "ReadWrite"})
SESSION_TOKEN_HEADER = "x-amz-s3session-token"
DIRECTORY_SUFFIX = "--x-s3"

# Default 5 minutes, exactly like AWS S3 Express sessions. The environment
# override exists for operators and tests; anything outside the bounds is
# clamped so a typo can neither mint 10-year sessions nor zero-second ones.
DEFAULT_SESSION_LIFETIME_SECONDS = 300
MIN_SESSION_LIFETIME_SECONDS = 30
MAX_SESSION_LIFETIME_SECONDS = 3600

# A zonal session may authenticate exactly these SigV4 actions. The set is
# the union of the ReadOnly and ReadWrite modes; the mode check happens in
# S3ExpressSessionStore.resolve.
READ_ONLY_ACTIONS = frozenset({
    "s3:GetObject", "s3:ListBucket", "s3:GetObjectAttributes",
})
ZONAL_ACTIONS = READ_ONLY_ACTIONS | frozenset({
    "s3:PutObject", "s3:DeleteObject", "s3:RenameObject",
})
# Control-plane operations on directory buckets keep long-lived
# credentials, mirroring AWS's regional s3express-control endpoint.
CONTROL_ACTIONS = frozenset({
    "s3:CreateSession", "s3:CreateBucket", "s3:DeleteBucket",
})

_DIRECTORY_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
_ZONE_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
# Continuation tokens are valid for 15 minutes; a page cursor older than
# that is stale and fails closed instead of paginating ancient state.
DIRECTORY_TOKEN_MAX_AGE_SECONDS = 900


class DirectoryBucketError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


# ---------------------------------------------------------------------------
# Names and the logical compatibility zone
# ---------------------------------------------------------------------------

def is_directory_bucket_name(name: str) -> bool:
    """Does this bucket name belong to the directory namespace by shape?

    The AWS wire format is ``base--zone-id--x-s3``; the suffix alone selects
    the namespace, exactly like botocore's own ``is_s3express_bucket``.
    """
    return isinstance(name, str) and name.endswith(DIRECTORY_SUFFIX)


def configured_zone() -> str:
    """The deployment's LOGICAL compatibility zone id.

    This is a compatibility label required by the immutable AWS name
    format. It is NOT an AWS Availability Zone: TeleDrive has no zonal
    infrastructure, no One Zone durability and no Express throughput class.
    """
    zone = os.environ.get("TELEDRIVE_S3_DIRECTORY_ZONE_ID", "").strip()
    return zone or "use1-az1"


def parse_directory_bucket_name(name: str) -> tuple[str, str]:
    """Split ``base--zone-id--x-s3`` into ``(base, zone_id)``.

    Raises :class:`DirectoryBucketError` with ``InvalidBucketName`` for
    every name that is not a well-formed, immutable directory-bucket name:
    the base must be 3+ lowercase alphanumeric/hyphen characters (dots are
    not allowed in directory names), the zone must be a non-empty lowercase
    label, and the whole name must fit the 63-byte S3 bucket limit.
    """
    if not is_directory_bucket_name(name):
        raise DirectoryBucketError(
            "InvalidBucketName",
            "Directory bucket names must end with --zone-id--x-s3",
        )
    stem = name[: -len(DIRECTORY_SUFFIX)]
    base, separator, zone = stem.rpartition("--")
    if not separator or not base or not zone:
        raise DirectoryBucketError(
            "InvalidBucketName",
            "Directory bucket names must be base--zone-id--x-s3",
        )
    if (".." in name or not 3 <= len(base) <= 63 or len(name) > 63
            or "--" in base
            or not _DIRECTORY_NAME_RE.fullmatch(base)
            or not _ZONE_RE.fullmatch(zone)):
        raise DirectoryBucketError(
            "InvalidBucketName",
            "The specified directory bucket name is not valid",
        )
    return base, zone


# ---------------------------------------------------------------------------
# Operation classification (the fail-closed gate)
# ---------------------------------------------------------------------------

def classify_directory_operation(method: str, object_path: bool, params,
                                 action: str | None, *, form_upload: bool,
                                 multi_delete: bool,
                                 copy_source: bool) -> str:
    """Route a request that names a directory bucket to its only valid class.

    Returns ``"zonal"`` (object data plane; S3 Express session credentials
    required) or ``"control"`` (long-lived credentials). Anything a
    directory bucket cannot serve raises ``InvalidRequest`` so the request
    fails closed instead of silently degrading into a general-purpose
    operation.
    """
    real = {key for key in params
            if not key.startswith("X-Amz-") and key != "x-id"}
    if form_upload:
        raise DirectoryBucketError(
            "InvalidRequest",
            "Browser POST policy uploads are not supported on directory "
            "buckets",
        )
    if multi_delete:
        raise DirectoryBucketError(
            "InvalidRequest",
            "DeleteObjects is not supported on directory buckets",
        )
    if copy_source:
        raise DirectoryBucketError(
            "InvalidRequest",
            "Server-side copies are not supported on directory buckets "
            "here; PUT the bytes instead",
        )
    if "versionId" in real or "versions" in real:
        raise DirectoryBucketError(
            "InvalidRequest",
            "Directory buckets are not versioned; version selectors are "
            "not supported",
        )
    if (not object_path and method == "GET"
            and not ({"list-type", "session", "uploads"} & real)):
        raise DirectoryBucketError(
            "InvalidRequest",
            "ListObjects (V1) is not supported on directory buckets; use "
            "ListObjectsV2",
        )
    if method == "HEAD" and not object_path:
        # HeadBucket is a control-plane existence probe (AWS also exempts
        # it from session credentials).
        return "control"
    if action in CONTROL_ACTIONS:
        return "control"
    if action in ZONAL_ACTIONS and (object_path or method == "GET"):
        return "zonal"
    raise DirectoryBucketError(
        "InvalidRequest",
        "This S3 operation is not supported on directory buckets",
    )


# ---------------------------------------------------------------------------
# Catalog rows (the shared storage_buckets table, typed)
# ---------------------------------------------------------------------------

def bucket_type_of(db: Database, name: str) -> str | None:
    """``"general"``, ``"directory"`` or ``None`` when the bucket is absent."""
    from teledrive.storage.catalog_tables import buckets
    row = db.connection.execute(select(buckets.c.bucket_type).where(
        buckets.c.name == name)).scalar_one_or_none()
    return row


def create_directory_bucket(db: Database, name: str, now: int, *,
                            location_name: str | None = None) -> None:
    """Insert a typed directory row into the shared bucket catalog.

    The name is immutable (it embeds the zone), so creation validates the
    full ``base--zone-id--x-s3`` shape and requires the zone to equal the
    deployment's configured logical zone. ``location_name`` is the optional
    ``CreateBucketConfiguration/Location/Name`` value from the request
    body; when present it must agree with the name.
    """
    from sqlalchemy.exc import IntegrityError
    from teledrive.storage.catalog_tables import buckets

    base, zone = parse_directory_bucket_name(name)
    configured = configured_zone()
    if zone != configured:
        raise DirectoryBucketError(
            "InvalidLocationConstraint",
            f"Directory buckets here use the logical zone {configured!r}; "
            f"the requested zone {zone!r} is not configured on this "
            "deployment",
        )
    if location_name is not None and location_name != zone:
        raise DirectoryBucketError(
            "InvalidLocationConstraint",
            "CreateBucketConfiguration Location does not match the bucket "
            "name zone",
        )
    try:
        with db.connection.begin_nested():
            db.connection.execute(insert(buckets).values(
                name=name, created_at=now, bucket_type="directory"))
    except IntegrityError:
        # Same idempotency contract as general-purpose CreateBucket: the
        # name is immutable, so an existing row IS this bucket.
        pass
    db.commit()


def list_directory_bucket_records(db: Database, *, after: str = "",
                                  limit: int = MAX_DIRECTORY_BUCKETS,
                                  ) -> tuple[list[tuple[str, int]], bool]:
    """One keyset page of directory rows; ``has_more`` drives the token."""
    from teledrive.storage.catalog_tables import buckets

    if not 1 <= limit <= MAX_DIRECTORY_BUCKETS:
        raise DirectoryBucketError("InvalidArgument", "Invalid page limit")
    statement = select(buckets.c.name, buckets.c.created_at).where(
        buckets.c.bucket_type == "directory")
    if after:
        statement = statement.where(buckets.c.name > after)
    rows = db.connection.execute(
        statement.order_by(buckets.c.name).limit(limit + 1)).all()
    return [(str(r[0]), int(r[1])) for r in rows[:limit]], len(rows) > limit


# ---------------------------------------------------------------------------
# Opaque, scoped ListDirectoryBuckets continuation tokens
# ---------------------------------------------------------------------------

def encode_directory_token(master: bytes, after: str, *,
                           now: int | None = None) -> str:
    issued = int(time.time()) if now is None else now
    payload = json.dumps(
        {"a": after, "t": issued}, separators=(",", ":"),
        sort_keys=True).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    mac = hmac.new(master, b"teledrive:list-directory-buckets:v1:"
                   + encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{mac}"


def decode_directory_token(master: bytes, token: str, *,
                           now: int | None = None) -> str:
    """Verify an opaque continuation token and return its high-water mark.

    The token is HMAC-scoped to this deployment's master key and expires
    after 15 minutes: a stale or foreign cursor fails closed with
    ``InvalidArgument`` instead of paginating state it never described.
    """
    from teledrive.s3.sigv4 import SigV4Error

    current = int(time.time()) if now is None else now
    try:
        if not token or len(token) > MAX_DIRECTORY_TOKEN_LENGTH:
            raise ValueError("Bad token length")
        encoded, mac = token.split(".")
        if len(mac) != 64:
            raise ValueError("Bad token MAC")
        computed = hmac.new(
            master, b"teledrive:list-directory-buckets:v1:"
            + encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed, mac):
            raise ValueError("Bad token signature")
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_",
            validate=True)
        decoded = json.loads(payload)
        if (not isinstance(decoded, dict) or set(decoded) != {"a", "t"}
                or not isinstance(decoded["a"], str)
                or not 0 < len(decoded["a"]) <= 63
                or type(decoded["t"]) is not int
                or not 0 <= current - decoded["t"]
                <= DIRECTORY_TOKEN_MAX_AGE_SECONDS):
            raise ValueError("Token does not match this listing")
        return decoded["a"]
    except (ValueError, TypeError, UnicodeError, KeyError,
            binascii.Error) as exc:
        raise SigV4Error(
            "InvalidArgument",
            "Invalid or stale ListDirectoryBuckets continuation token",
        ) from exc


def list_directory_buckets_xml(page: list[tuple[str, int]],
                               continuation_token: str | None) -> bytes:
    """AWS-shaped ListDirectoryBucketsResult for one real page."""
    root = ET.Element("ListDirectoryBucketsResult", xmlns=NAMESPACE)
    if page:
        buckets_tag = ET.SubElement(root, "Buckets")
        for name, created_at in page:
            entry = ET.SubElement(buckets_tag, "Bucket")
            ET.SubElement(entry, "Name").text = name
            ET.SubElement(entry, "CreationDate").text = time.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(created_at))
            ET.SubElement(entry, "BucketRegion").text = "us-east-1"
    if continuation_token is not None:
        ET.SubElement(root, "ContinuationToken").text = continuation_token
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


# ---------------------------------------------------------------------------
# CreateSession: short-lived S3 Express session credentials
# ---------------------------------------------------------------------------

sessions_metadata = MetaData()
s3_sessions = Table(
    "storage_s3_sessions", sessions_metadata,
    Column("id", String(36), primary_key=True),
    Column("access_key", String(64), nullable=False, unique=True),
    # SHA-256 of the session token: the token itself is never stored.
    Column("token_hash", String(64), nullable=False),
    # Fernet(master key) of the session secret; a database backup alone
    # never reveals it.
    Column("encrypted_secret", Text, nullable=False),
    Column("bucket", String(63), nullable=False),
    Column("mode", String(16), nullable=False),
    Column("zone_id", String(64), nullable=False),
    # The long-lived access key that signed the CreateSession request.
    Column("owner", String(64), nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("expires_at", BigInteger, nullable=False),
    Column("revoked", Boolean, nullable=False),
)
Index("ix_storage_s3_sessions_bucket", s3_sessions.c.bucket)


@dataclass(frozen=True)
class IssuedSession:
    access_key: str
    secret_key: str
    session_token: str
    bucket: str
    mode: str
    zone_id: str
    owner: str
    expires_at: int


def session_lifetime_seconds() -> int:
    raw = os.environ.get("TELEDRIVE_S3_SESSION_LIFETIME_SECONDS", "").strip()
    try:
        requested = int(raw) if raw else DEFAULT_SESSION_LIFETIME_SECONDS
    except ValueError:
        requested = DEFAULT_SESSION_LIFETIME_SECONDS
    return max(MIN_SESSION_LIFETIME_SECONDS,
               min(MAX_SESSION_LIFETIME_SECONDS, requested))


class S3ExpressSessionStore:
    """Issue and validate short-lived directory-bucket sessions.

    Sessions are bound to ONE bucket, one mode, the signer's long-lived
    access key and the bucket's logical zone. Revocation is a durable SQL
    row flag, so it is immediately visible to every worker and connection
    that resolves the session (there is no in-process credential cache).
    """

    def __init__(self, database: Database, master_key: bytes):
        self.db = database
        self.cipher = Fernet(master_key)

    def issue(self, bucket: str, mode: str, owner: str, *,
              now: int | None = None) -> IssuedSession:
        current = int(time.time()) if now is None else now
        if mode not in SESSION_MODES:
            raise ValueError("Session mode must be ReadOnly or ReadWrite")
        if not isinstance(owner, str) or not owner:
            raise ValueError("Sessions require a signing credential")
        _, zone = parse_directory_bucket_name(bucket)
        from uuid import uuid4
        lifetime = session_lifetime_seconds()
        expires = current + lifetime
        access = "TDX" + secrets.token_hex(12).upper()
        secret = secrets.token_urlsafe(40)
        token = secrets.token_urlsafe(48)
        self.db.connection.execute(insert(s3_sessions).values(
            id=str(uuid4()), access_key=access,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            encrypted_secret=self.cipher.encrypt(secret.encode()).decode(),
            bucket=bucket, mode=mode, zone_id=zone, owner=owner,
            created_at=current, expires_at=expires, revoked=False))
        # Opportunistic purge: rows expired more than an hour ago are dead
        # weight; resolve() would refuse them anyway.
        self.db.connection.execute(delete(s3_sessions).where(
            s3_sessions.c.expires_at < current - 3600))
        self.db.commit()
        return IssuedSession(access, secret, token, bucket, mode, zone,
                             owner, expires)

    def resolve(self, access_key: str, bucket: str, permission: str,
                token: str, *, now: int | None = None) -> str | None:
        """The session's secret, or ``None`` for every refusal.

        One lookup enforces the whole custody contract: existence,
        revocation, expiry, single-bucket binding, mode scope and an
        exact, constant-time session-token match. Failures never
        distinguish which check failed, and the token itself never
        reaches an error message or log line.
        """
        current = int(time.time()) if now is None else now
        if (not isinstance(access_key, str) or len(access_key) > 64
                or not isinstance(token, str) or len(token) > 256
                or permission not in ZONAL_ACTIONS):
            return None
        try:
            row = self.db.connection.execute(select(
                s3_sessions.c.encrypted_secret, s3_sessions.c.token_hash,
                s3_sessions.c.bucket, s3_sessions.c.mode,
                s3_sessions.c.revoked, s3_sessions.c.expires_at,
            ).where(s3_sessions.c.access_key == access_key)).first()
        except SQLAlchemyError:
            # An unmigrated database (pre-handoff-07 schema) has no
            # sessions table; the pre-authentication path must not run
            # DDL, so the honest answer is "no such session" — closed.
            return None
        if row is None or row[4] or row[5] <= current or row[2] != bucket:
            return None
        allowed = (READ_ONLY_ACTIONS if row[3] == "ReadOnly"
                   else ZONAL_ACTIONS)
        if permission not in allowed:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, row[1]):
            return None
        try:
            return self.cipher.decrypt(row[0].encode()).decode()
        except (InvalidToken, ValueError, UnicodeError):
            return None

    def revoke_for_bucket(self, bucket: str) -> int:
        changed = self.db.connection.execute(update(s3_sessions).where(
            s3_sessions.c.bucket == bucket,
            s3_sessions.c.revoked.is_(False)).values(revoked=True))
        self.db.commit()
        return changed.rowcount

    def revoke_for_owner(self, owner: str) -> int:
        changed = self.db.connection.execute(update(s3_sessions).where(
            s3_sessions.c.owner == owner,
            s3_sessions.c.revoked.is_(False)).values(revoked=True))
        self.db.commit()
        return changed.rowcount


class SessionCredentialView:
    """A credential-store facade that resolves ONLY S3 Express sessions.

    Zonal handlers receive this in place of the long-lived store so the
    aws-chunked decoder and multipart paths can verify chunk signatures
    with the session secret, while every long-lived key keeps failing
    closed on the zonal plane.
    """

    def __init__(self, sessions: S3ExpressSessionStore, bucket: str,
                 token: str):
        self._sessions = sessions
        self._bucket = bucket
        self._token = token

    def resolve(self, access_key: str, permission: str) -> str | None:
        return self._sessions.resolve(
            access_key, self._bucket, permission, self._token)


def create_session_xml(session: IssuedSession) -> bytes:
    """The AWS CreateSessionResult document (botocore-parsable)."""
    root = ET.Element("CreateSessionResult", xmlns=NAMESPACE)
    credentials = ET.SubElement(root, "Credentials")
    ET.SubElement(credentials, "AccessKeyId").text = session.access_key
    ET.SubElement(credentials, "SecretAccessKey").text = session.secret_key
    ET.SubElement(credentials, "SessionToken").text = session.session_token
    ET.SubElement(credentials, "Expiration").text = datetime.fromtimestamp(
        session.expires_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def create_session_error(bucket: str, *, bucket_class: str | None,
                         session_mode: str | None) -> DirectoryBucketError | None:
    """Why no session can be issued for this bucket, or ``None`` when it can.

    ``None`` means the bucket exists as a directory bucket and a session
    may be issued. The failure taxonomy keeps the historical, truthful
    distinctions: a malformed name is ``InvalidBucketName``; an existing
    general-purpose bucket is ``InvalidRequest`` (Express sessions cannot
    be created for it); any other well-formed name is the botocore-model
    error ``NoSuchBucket``. AWS validates the session mode even when the
    call cannot succeed, so a malformed mode is a 400 rather than a
    misleading 404.
    """
    if is_directory_bucket_name(bucket):
        try:
            parse_directory_bucket_name(bucket)
        except DirectoryBucketError as exc:
            return exc
    else:
        try:
            from teledrive.storage.catalog import BucketCatalog
            BucketCatalog.validate_bucket(bucket)
        except ValueError:
            return DirectoryBucketError(
                "InvalidBucketName",
                "The specified bucket name is not valid for S3",
            )
    if session_mode is not None and session_mode not in SESSION_MODES:
        return DirectoryBucketError(
            "InvalidArgument",
            "SessionMode must be ReadOnly or ReadWrite",
        )
    if bucket_class == "directory":
        return None
    if bucket_class == "general":
        return DirectoryBucketError(
            "InvalidRequest",
            "CreateSession requires an S3 Express One Zone directory bucket; "
            "this TeleDrive bucket is a general-purpose bucket and no Express "
            "session can be created for it",
        )
    return DirectoryBucketError(
        "NoSuchBucket",
        "The specified bucket does not exist as an S3 Express One Zone "
        "directory bucket",
        404,
    )
