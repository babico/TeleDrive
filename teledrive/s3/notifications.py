"""Metadata-backed S3 notifications and access-logging configuration.

Notification delivery is a transactional outbox: object mutations insert an
event row in the SAME SQL transaction that publishes the catalog change, and
a retry worker POSTs it to an owner-approved HTTP(S) webhook. There is no SQS,
SNS or Lambda destination: AWS queue/topic payloads cannot honestly exist over
a private Telegram gateway, so those XML elements fail closed with 501.

Delivered event vocabulary (the subset actually emitted):

* ``s3:ObjectCreated:Put``                  PutObject / browser POST upload
* ``s3:ObjectCreated:Copy``                 CopyObject
* ``s3:ObjectCreated:CompleteMultipartUpload``
* ``s3:ObjectRemoved:Delete``               explicit VersionId revocation and
                                            multipart abort (logical removal)
* ``s3:ObjectRemoved:DeleteMarkerCreated``  DELETE without VersionId

``s3:ObjectCreated:*`` and ``s3:ObjectRemoved:*`` wildcards subscribe to every
event in the matching family. Filters support AWS-shaped ``prefix``/``suffix``
rules.

Access logging configuration is persisted and readable through the real GET
API. Delivering the audit-log stream into the target bucket is NOT implemented;
S3_SPECS.md records that gap explicitly instead of pretending logs are copied.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import logging
import threading
import weakref
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import uuid4
from xml.etree import ElementTree as ET

from cryptography.fernet import Fernet, InvalidToken
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import (BigInteger, Boolean, Column, ForeignKey, Integer,
                        MetaData, String, Table, Text, delete, insert, select,
                        update)

from teledrive.storage.catalog import BucketCatalog, buckets, catalog_metadata

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_NOTIFICATION_XML_BYTES = 16 * 1024
MAX_LOGGING_XML_BYTES = 16 * 1024
MAX_DESTINATION_LENGTH = 2048
MAX_SECRET_LENGTH = 256
MAX_ATTEMPTS = 8
BASE_BACKOFF_NS = 30 * 1_000_000_000
MAX_BACKOFF_NS = 3600 * 1_000_000_000
POST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 64 * 1024

CREATED_EVENTS = frozenset({
    "s3:ObjectCreated:Put",
    "s3:ObjectCreated:Copy",
    "s3:ObjectCreated:CompleteMultipartUpload",
    "s3:ObjectCreated:Post",
})
REMOVED_EVENTS = frozenset({
    "s3:ObjectRemoved:Delete",
    "s3:ObjectRemoved:DeleteMarkerCreated",
})
SUPPORTED_EVENTS = frozenset(
    CREATED_EVENTS | REMOVED_EVENTS
    | {"s3:ObjectCreated:*", "s3:ObjectRemoved:*"}
)

_LOGGER = logging.getLogger("teledrive.s3.notifications")

notification_configs = Table(
    "storage_notification_configs", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    Column("events", Text, nullable=False),
    Column("destination", Text, nullable=False),
    Column("encrypted_secret", Text),
    Column("filter_prefix", String(1024), nullable=False, default=""),
    Column("filter_suffix", String(1024), nullable=False, default=""),
    Column("enabled", Boolean, nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)

# The outbox is deliberately independent of the bucket foreign key: an event
# must survive until delivery even if its bucket is deleted.
outbox_metadata = MetaData()
event_outbox = Table(
    "storage_event_outbox", outbox_metadata,
    Column("id", String(36), primary_key=True),
    Column("event_type", String(64), nullable=False),
    Column("bucket", String(63), nullable=False),
    Column("object_key", String(1024), nullable=False),
    Column("version_id", String(80)),
    Column("payload", Text, nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("next_retry_ns", BigInteger, nullable=False),
    Column("created_ns", BigInteger, nullable=False),
    Column("delivered_ns", BigInteger),
    Column("last_error", Text),
)

logging_configs = Table(
    "storage_logging_configs", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    Column("target_bucket", String(63), nullable=False),
    Column("target_prefix", String(1024), nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("created_at", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)

_CONFIG_TABLES = (notification_configs, logging_configs)
_ALL_TABLES = (notification_configs, event_outbox, logging_configs)
_ENSURED_ENGINES: "weakref.WeakSet" = weakref.WeakSet()
_ENSURED_LOCK = threading.Lock()


class NotificationError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def _name(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid_namespace(node) -> bool:
    name = _name(node)
    return node.tag in {name, f"{{{NS}}}{name}"}


def _scalar(node, label: str, *, maximum: int) -> str:
    if (not _valid_namespace(node) or node.attrib or len(node)
            or _name(node) != label):
        raise NotificationError("MalformedXML", "Unexpected notification field")
    value = node.text or ""
    if len(value.encode("utf-8")) > maximum:
        raise NotificationError("InvalidArgument", f"{label} is too long")
    return value


def _webhook_destination(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_DESTINATION_LENGTH:
        raise NotificationError("InvalidArgument", "Invalid webhook endpoint")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise NotificationError("InvalidArgument", "Invalid webhook endpoint")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment):
        raise NotificationError(
            "InvalidArgument", "Webhook endpoints must be plain HTTP(S) URLs")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise NotificationError("InvalidArgument", "Invalid webhook port")
    if any(char in parsed.hostname for char in " \t\r\n"):
        raise NotificationError("InvalidArgument", "Invalid webhook host")
    return value


def _event_name(value: str) -> str:
    if value not in SUPPORTED_EVENTS:
        raise NotificationError(
            "InvalidArgument",
            "Unsupported S3 event; HTTP(S) webhook delivery covers "
            "ObjectCreated and ObjectRemoved events only",
        )
    return value


def _filter_rules(node) -> tuple[str, str]:
    if (not _valid_namespace(node) or node.attrib or _name(node) != "Filter"
            or len(node) != 1):
        raise NotificationError("MalformedXML", "Invalid notification filter")
    s3_key = node[0]
    if (not _valid_namespace(s3_key) or s3_key.attrib
            or _name(s3_key) != "S3Key" or not 1 <= len(s3_key) <= 2):
        raise NotificationError("MalformedXML", "Invalid S3Key filter")
    prefix = suffix = ""
    seen = set()
    for rule in s3_key:
        if (not _valid_namespace(rule) or rule.attrib
                or _name(rule) != "FilterRule" or len(rule) != 2):
            raise NotificationError("MalformedXML", "Invalid FilterRule")
        fields = {_name(child): child for child in rule}
        if (set(fields) != {"Name", "Value"}
                or any(child.attrib or len(child) for child in rule)):
            raise NotificationError("MalformedXML", "Invalid FilterRule fields")
        name = _scalar(fields["Name"], "Name", maximum=16)
        value = _scalar(fields["Value"], "Value", maximum=1024)
        if name not in {"prefix", "suffix"} or name in seen:
            raise NotificationError(
                "InvalidArgument", "Filter supports one prefix and one suffix")
        seen.add(name)
        if name == "prefix":
            prefix = value
        else:
            suffix = value
    return prefix, suffix


def parse_notification_xml(payload: bytes) -> dict | None:
    """Parse a strict NotificationConfiguration; None disables notifications."""
    if len(payload) > MAX_NOTIFICATION_XML_BYTES:
        raise NotificationError(
            "MalformedXML", "Notification XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise NotificationError(
            "MalformedXML", "Invalid notification XML") from exc
    if (not _valid_namespace(root) or root.attrib
            or _name(root) != "NotificationConfiguration" or len(root) > 1):
        raise NotificationError(
            "MalformedXML", "Unexpected NotificationConfiguration document")
    if not len(root):
        return None
    node = root[0]
    label = _name(node)
    if label in {"TopicConfiguration", "QueueConfiguration",
                 "CloudFunctionConfiguration"}:
        raise NotificationError(
            "NotImplemented",
            "SNS, SQS and Lambda notification destinations are not supported; "
            "TeleDrive delivers HTTP(S) webhooks only", 501)
    if (not _valid_namespace(node) or node.attrib
            or label != "WebhookConfiguration"):
        raise NotificationError(
            "MalformedXML",
            "Only one WebhookConfiguration element is supported")
    fields: dict = {
        "Id": [], "Endpoint": [], "Event": [], "Filter": [], "Secret": [],
    }
    for child in node:
        name = _name(child)
        if name not in fields:
            raise NotificationError(
                "MalformedXML", "Unsupported WebhookConfiguration field")
        fields[name].append(child)
    if len(fields["Endpoint"]) != 1 or len(fields["Secret"]) > 1:
        raise NotificationError(
            "InvalidArgument", "WebhookConfiguration requires one Endpoint")
    if not 1 <= len(fields["Event"]) <= 10:
        raise NotificationError(
            "InvalidArgument", "WebhookConfiguration requires 1..10 events")
    if len(fields["Filter"]) > 1:
        raise NotificationError(
            "InvalidArgument", "WebhookConfiguration allows one Filter")
    ident = (_scalar(fields["Id"][0], "Id", maximum=255)
             if fields["Id"] else "")
    if len(fields["Id"]) > 1:
        raise NotificationError("InvalidArgument", "Duplicate Id")
    destination = _webhook_destination(
        _scalar(fields["Endpoint"][0], "Endpoint",
                maximum=MAX_DESTINATION_LENGTH))
    events = [_event_name(
        _scalar(event, "Event", maximum=64)) for event in fields["Event"]]
    if len(set(events)) != len(events):
        raise NotificationError("InvalidArgument", "Duplicate event")
    secret = None
    if fields["Secret"]:
        secret = _scalar(fields["Secret"][0], "Secret",
                         maximum=MAX_SECRET_LENGTH)
        if not 16 <= len(secret) <= MAX_SECRET_LENGTH:
            raise NotificationError(
                "InvalidArgument", "Webhook secret must be 16..256 characters")
    prefix, suffix = ("", "")
    if fields["Filter"]:
        prefix, suffix = _filter_rules(fields["Filter"][0])
    return {
        "id": ident,
        "destination": destination,
        "events": events,
        "filter_prefix": prefix,
        "filter_suffix": suffix,
        "secret": secret,
        "enabled": True,
    }


def notification_xml(config: dict | None) -> bytes:
    root = ET.Element("NotificationConfiguration", xmlns=NS)
    if config:
        node = ET.SubElement(root, "WebhookConfiguration")
        if config.get("id"):
            ET.SubElement(node, "Id").text = config["id"]
        ET.SubElement(node, "Endpoint").text = config["destination"]
        for event in config["events"]:
            ET.SubElement(node, "Event").text = event
        if config.get("filter_prefix") or config.get("filter_suffix"):
            s3_key = ET.SubElement(ET.SubElement(node, "Filter"), "S3Key")
            for name, value in (("prefix", config.get("filter_prefix", "")),
                                ("suffix", config.get("filter_suffix", ""))):
                if value:
                    rule = ET.SubElement(s3_key, "FilterRule")
                    ET.SubElement(rule, "Name").text = name
                    ET.SubElement(rule, "Value").text = value
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def parse_logging_xml(payload: bytes) -> dict | None:
    """Parse a strict BucketLoggingStatus; None disables logging."""
    if len(payload) > MAX_LOGGING_XML_BYTES:
        raise NotificationError("MalformedXML", "Logging XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise NotificationError("MalformedXML", "Invalid logging XML") from exc
    if (not _valid_namespace(root) or root.attrib
            or _name(root) != "BucketLoggingStatus" or len(root) > 1):
        raise NotificationError(
            "MalformedXML", "Unexpected BucketLoggingStatus document")
    if not len(root):
        return None
    node = root[0]
    if (not _valid_namespace(node) or node.attrib
            or _name(node) != "LoggingEnabled"):
        raise NotificationError("MalformedXML", "Expected LoggingEnabled")
    fields: dict = {"TargetBucket": [], "TargetPrefix": [], "TargetGrants": []}
    for child in node:
        name = _name(child)
        if name == "TargetGrants":
            raise NotificationError(
                "NotImplemented",
                "Logging TargetGrants are not supported", 501)
        if name not in fields:
            raise NotificationError(
                "MalformedXML", "Unsupported LoggingEnabled field")
        fields[name].append(child)
    if len(fields["TargetBucket"]) != 1 or len(fields["TargetPrefix"]) > 1:
        raise NotificationError(
            "InvalidArgument", "LoggingEnabled requires one TargetBucket")
    target = _scalar(fields["TargetBucket"][0], "TargetBucket", maximum=63)
    try:
        BucketCatalog.validate_bucket(target)
    except ValueError as exc:
        raise NotificationError(
            "InvalidArgument", "Invalid logging target bucket") from exc
    prefix = ""
    if fields["TargetPrefix"]:
        prefix = _scalar(fields["TargetPrefix"][0], "TargetPrefix",
                         maximum=1024)
        if any(ord(char) < 32 or ord(char) == 127 for char in prefix):
            raise NotificationError(
                "InvalidArgument", "Invalid logging target prefix")
    return {
        "target_bucket": target,
        "target_prefix": prefix,
        "enabled": True,
    }


def logging_xml(config: dict | None) -> bytes:
    root = ET.Element("BucketLoggingStatus", xmlns=NS)
    if config:
        node = ET.SubElement(root, "LoggingEnabled")
        ET.SubElement(node, "TargetBucket").text = config["target_bucket"]
        ET.SubElement(node, "TargetPrefix").text = config["target_prefix"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def approved_destinations(raw: str | None) -> tuple[str, ...]:
    """Parse the owner-managed comma-separated destination allowlist."""
    return tuple(
        part.strip() for part in (raw or "").split(",") if part.strip()
    )


def destination_is_approved(destination: str,
                            allowlist: tuple[str, ...]) -> bool:
    """Require an exact origin, or an allowlisted path prefix.

    An allowlist entry without a path approves the whole origin; an entry with
    a path approves that exact path and everything below it.
    """
    target = urlsplit(destination)
    for entry in allowlist:
        try:
            allowed = urlsplit(entry)
        except ValueError:
            continue
        if (allowed.scheme not in {"http", "https"} or not allowed.hostname
                or allowed.query):
            continue
        if (target.scheme != allowed.scheme
                or target.hostname != allowed.hostname
                or target.port != allowed.port):
            continue
        if not allowed.path or allowed.path == "/":
            return True
        base = allowed.path.rstrip("/")
        if target.path == base or target.path.startswith(base + "/"):
            return True
    return False


def event_matches(event_type: str, patterns) -> bool:
    for pattern in patterns:
        if pattern == event_type:
            return True
        if pattern.endswith(":*") and event_type.startswith(pattern[:-1]):
            return True
    return False


def _payload(event_type: str, bucket: str, key: str,
             version_id: str | None, now_ns: int) -> dict:
    moment = time.strftime(
        "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now_ns / 1_000_000_000))
    return {
        "eventVersion": "2.1",
        "eventSource": "aws:s3",
        "awsRegion": "us-east-1",
        "eventTime": moment,
        "eventName": event_type,
        "s3": {
            "s3SchemaVersion": "1.0",
            "configurationId": "teledrive-webhook",
            "bucket": {
                "name": bucket,
                "ownerIdentity": {"principalId": "teledrive"},
            },
            "object": {
                "key": key,
                **({"versionId": version_id} if version_id else {}),
            },
        },
    }


def ensure_notification_tables(engine) -> None:
    """Create notification tables once per engine (idempotent)."""
    with _ENSURED_LOCK:
        if engine in _ENSURED_ENGINES:
            return
        catalog_metadata.create_all(engine, tables=_CONFIG_TABLES)
        outbox_metadata.create_all(engine, tables=[event_outbox])
        _ENSURED_ENGINES.add(engine)


def enqueue_event(connection, *, event_type: str, bucket: str, object_key: str,
                  version_id: str | None = None,
                  now_ns: int | None = None) -> int:
    """Insert matching outbox rows on an EXISTING transaction.

    Returns the number of rows inserted. The caller owns commit/rollback, so a
    notification is durable exactly when the catalog mutation is durable.
    """
    if (event_type not in SUPPORTED_EVENTS
            or not isinstance(bucket, str)
            or not isinstance(object_key, str)
            or (version_id is not None and not isinstance(version_id, str))):
        return 0
    now_ns = time.time_ns() if now_ns is None else int(now_ns)
    row = connection.execute(select(
        notification_configs.c.events,
        notification_configs.c.filter_prefix,
        notification_configs.c.filter_suffix,
        notification_configs.c.enabled,
    ).where(notification_configs.c.bucket == bucket)).first()
    if row is None or not row[3]:
        return 0
    try:
        patterns = json.loads(row[0])
    except (TypeError, ValueError):
        return 0
    if not isinstance(patterns, list) or not event_matches(event_type, patterns):
        return 0
    if row[1] and not object_key.startswith(row[1]):
        return 0
    if row[2] and not object_key.endswith(row[2]):
        return 0
    payload = _payload(event_type, bucket, object_key, version_id, now_ns)
    connection.execute(insert(event_outbox).values(
        id=str(uuid4()), event_type=event_type, bucket=bucket,
        object_key=object_key, version_id=version_id,
        payload=json.dumps(payload, separators=(",", ":"), sort_keys=True),
        attempts=0, next_retry_ns=now_ns, created_ns=now_ns,
        delivered_ns=None, last_error=None,
    ))
    return 1


def enqueue_event_safely(connection, **kwargs) -> int:
    """Never let notification bookkeeping fail the catalog mutation.

    A SAVEPOINT confines any failure (missing tables, corrupt configuration)
    so the surrounding transaction stays usable. On success the outbox row
    commits with the caller's transaction.

    DDL is deliberately NOT issued here: this runs inside a caller-owned
    write transaction, and creating tables on a separate connection while
    that transaction holds the lock deadlocks on SQLite. The tables are
    created when the catalog is constructed and at application startup.
    """
    try:
        with connection.begin_nested():
            return enqueue_event(connection, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive boundary
        _LOGGER.warning("notification enqueue skipped: %s",
                        type(exc).__name__)
        return 0


class NotificationStore:
    """Read/write notification and logging configuration for one catalog."""

    def __init__(self, catalog: BucketCatalog, master_key: bytes | None = None):
        self.catalog, self.db = catalog, catalog.db
        ensure_notification_tables(self.db.engine)
        self.cipher = Fernet(master_key) if master_key is not None else None

    def _bucket_exists(self, bucket: str) -> None:
        if self.db.connection.execute(
            select(buckets.c.name).where(buckets.c.name == bucket)
        ).first() is None:
            raise FileNotFoundError("Bucket not found")

    def get_config(self, bucket: str) -> dict | None:
        self._bucket_exists(bucket)
        row = self.db.connection.execute(select(
            notification_configs.c.events,
            notification_configs.c.destination,
            notification_configs.c.filter_prefix,
            notification_configs.c.filter_suffix,
            notification_configs.c.enabled,
        ).where(notification_configs.c.bucket == bucket)).first()
        if row is None:
            return None
        try:
            events = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Corrupted notification configuration") from exc
        return {
            "id": "",
            "destination": row[1],
            "events": events,
            "filter_prefix": row[2],
            "filter_suffix": row[3],
            "enabled": bool(row[4]),
            "secret": None,
        }

    def replace_config(self, bucket: str, config: dict | None) -> None:
        self._bucket_exists(bucket)
        now = int(time.time())
        try:
            guard = self.db.connection.execute(update(buckets).where(
                buckets.c.name == bucket
            ).values(created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(notification_configs).where(
                notification_configs.c.bucket == bucket))
            if config is not None:
                secret = config.get("secret")
                encrypted = None
                if secret is not None:
                    if self.cipher is None:
                        raise NotificationError(
                            "InternalError",
                            "Notification secret encryption is unavailable", 500)
                    encrypted = self.cipher.encrypt(
                        secret.encode("utf-8")).decode("ascii")
                self.db.connection.execute(insert(notification_configs).values(
                    bucket=bucket,
                    events=json.dumps(config["events"], sort_keys=True),
                    destination=config["destination"],
                    encrypted_secret=encrypted,
                    filter_prefix=config.get("filter_prefix", ""),
                    filter_suffix=config.get("filter_suffix", ""),
                    enabled=bool(config.get("enabled", True)),
                    created_at=now, updated_at=now,
                ))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise

    def get_logging(self, bucket: str) -> dict | None:
        self._bucket_exists(bucket)
        row = self.db.connection.execute(select(
            logging_configs.c.target_bucket,
            logging_configs.c.target_prefix,
            logging_configs.c.enabled,
        ).where(logging_configs.c.bucket == bucket)).first()
        if row is None:
            return None
        return {
            "target_bucket": row[0],
            "target_prefix": row[1],
            "enabled": bool(row[2]),
        }

    def replace_logging(self, bucket: str, config: dict | None) -> None:
        self._bucket_exists(bucket)
        now = int(time.time())
        try:
            guard = self.db.connection.execute(update(buckets).where(
                buckets.c.name == bucket
            ).values(created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(logging_configs).where(
                logging_configs.c.bucket == bucket))
            if config is not None:
                self.db.connection.execute(insert(logging_configs).values(
                    bucket=bucket,
                    target_bucket=config["target_bucket"],
                    target_prefix=config["target_prefix"],
                    enabled=bool(config.get("enabled", True)),
                    created_at=now, updated_at=now,
                ))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise

    def outbox_rows(self, bucket: str | None = None) -> list[dict]:
        query = select(event_outbox)
        if bucket is not None:
            query = query.where(event_outbox.c.bucket == bucket)
        rows = self.db.connection.execute(
            query.order_by(event_outbox.c.created_ns,
                           event_outbox.c.id)).mappings().all()
        return [dict(row) for row in rows]


@dataclass(frozen=True)
class DeliveryResult:
    claimed: int
    delivered: int
    retried: int
    abandoned: int


class HttpWebhookSender:
    """Minimal bounded POST sender; no redirects, no proxy handling."""

    def __init__(self, timeout: float = POST_TIMEOUT_SECONDS):
        self.timeout = timeout

    def send(self, destination: str, body: bytes,
             headers: dict[str, str]) -> None:
        parsed = urlsplit(destination)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Unsupported webhook destination")
        connection_class = (http.client.HTTPSConnection if parsed.scheme == "https"
                            else http.client.HTTPConnection)
        connection = connection_class(
            parsed.hostname, parsed.port, timeout=self.timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response.read(MAX_RESPONSE_BYTES)
            if not 200 <= response.status < 300:
                raise RuntimeError(f"webhook returned HTTP {response.status}")
        finally:
            connection.close()


class NotificationDelivery:
    """Bounded exponential-backoff outbox retry state machine."""

    def __init__(self, catalog: BucketCatalog, *, master_key: bytes | None = None,
                 sender=None):
        self.catalog, self.db = catalog, catalog.db
        ensure_notification_tables(self.db.engine)
        self.cipher = Fernet(master_key) if master_key is not None else None
        self.sender = sender or HttpWebhookSender()

    def _mark(self, row_id: str, *, attempts: int, next_retry_ns: int,
              delivered_ns: int | None, error: str | None) -> None:
        self.db.connection.execute(update(event_outbox).where(
            event_outbox.c.id == row_id,
        ).values(attempts=attempts, next_retry_ns=next_retry_ns,
                 delivered_ns=delivered_ns, last_error=error))

    def deliver_due(self, *, limit: int = 100, now_ns: int | None = None) -> DeliveryResult:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid delivery batch size")
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        rows = self.db.connection.execute(select(
            event_outbox.c.id, event_outbox.c.event_type,
            event_outbox.c.bucket, event_outbox.c.payload,
            event_outbox.c.attempts, event_outbox.c.next_retry_ns,
        ).where(
            event_outbox.c.delivered_ns.is_(None),
            event_outbox.c.next_retry_ns <= now_ns,
            event_outbox.c.attempts < MAX_ATTEMPTS,
        ).order_by(event_outbox.c.next_retry_ns,
                   event_outbox.c.created_ns).limit(limit)).all()
        delivered = retried = abandoned = 0
        try:
            for row_id, event_type, bucket, payload, attempts, _ in rows:
                config = self.db.connection.execute(select(
                    notification_configs.c.destination,
                    notification_configs.c.encrypted_secret,
                    notification_configs.c.enabled,
                ).where(notification_configs.c.bucket == bucket)).first()
                if config is None or not config[2]:
                    self._mark(row_id, attempts=attempts + 1,
                               next_retry_ns=now_ns, delivered_ns=now_ns,
                               error="notification configuration removed")
                    abandoned += 1
                    continue
                body = payload.encode("utf-8")
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "TeleDrive-Webhook/1.0",
                    "X-TeleDrive-Event": event_type,
                    "X-TeleDrive-Event-Id": row_id,
                }
                secret = None
                if config[1]:
                    if self.cipher is None:
                        raise RuntimeError(
                            "Notification secret cannot be decrypted")
                    try:
                        secret = self.cipher.decrypt(
                            config[1].encode("ascii")).decode("utf-8")
                    except (InvalidToken, UnicodeError, ValueError):
                        secret = None
                if secret:
                    timestamp = str(now_ns // 1_000_000_000)
                    signature = hmac.new(
                        secret.encode("utf-8"),
                        timestamp.encode("ascii") + b"." + body,
                        hashlib.sha256,
                    ).hexdigest()
                    headers["X-TeleDrive-Timestamp"] = timestamp
                    headers["X-TeleDrive-Signature"] = "sha256=" + signature
                try:
                    self.sender.send(config[0], body, headers)
                except Exception as exc:
                    attempts += 1
                    if attempts >= MAX_ATTEMPTS:
                        self._mark(row_id, attempts=attempts,
                                   next_retry_ns=now_ns,
                                   delivered_ns=now_ns,
                                   error=("delivery abandoned after "
                                          f"{MAX_ATTEMPTS} attempts: "
                                          f"{type(exc).__name__}"))
                        abandoned += 1
                    else:
                        delay = min(BASE_BACKOFF_NS * (2 ** (attempts - 1)),
                                    MAX_BACKOFF_NS)
                        self._mark(row_id, attempts=attempts,
                                   next_retry_ns=now_ns + delay,
                                   delivered_ns=None,
                                   error=type(exc).__name__)
                        retried += 1
                else:
                    self._mark(row_id, attempts=attempts + 1,
                               next_retry_ns=now_ns,
                               delivered_ns=now_ns, error=None)
                    delivered += 1
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        return DeliveryResult(len(rows), delivered, retried, abandoned)
