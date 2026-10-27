"""Bucket-level encryption configuration (SSE-C only).

SSE-C keys are supplied per request and never retained, so there is no
bucket-level default key to store.  The only honest bucket configuration is
therefore the explicit *absence* of a server-side default.  AWS-shaped
documents that ask for default encryption are refused:

* ``SSEAlgorithm=AES256``  -> 501 (that is SSE-S3, which needs a server key)
* ``SSEAlgorithm=aws:kms`` -> 501 (no KMS backing)

Storing either would silently weaken the promise that "encrypted" means the
client holds the key.  ``GetBucketEncryption`` returns the real stored
document (an empty rule set) or an honest 404.
"""
from __future__ import annotations

import json
import time

from sqlalchemy import (
    BigInteger, Column, ForeignKey, String, Table, delete, insert, select,
)

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from xml.etree import ElementTree as ET

from teledrive.db import Database
from teledrive.storage.catalog import catalog_metadata

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_ENCRYPTION_XML_BYTES = 16 * 1024

bucket_encryption = Table(
    "storage_bucket_encryption", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    # AWS-shaped rule list.  Only the empty list is accepted today.
    Column("rules", String(4096), nullable=False),
    Column("updated_at", BigInteger, nullable=False),
    Column("updated_by", String(64), nullable=False),
)


class BucketEncryptionError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def _local(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid_namespace(node) -> bool:
    name = _local(node)
    return node.tag in {name, f"{{{NS}}}{name}"}


def _algorithm(node) -> str | None:
    for child in node:
        if _local(child) == "SSEAlgorithm":
            return (child.text or "").strip()
    return None


def parse_encryption_xml(payload: bytes) -> list[dict]:
    """Strict parse; only an empty rule set is honest for SSE-C."""
    if not payload:
        raise BucketEncryptionError("MalformedXML",
                                    "Server-side encryption XML is empty")
    if len(payload) > MAX_ENCRYPTION_XML_BYTES:
        raise BucketEncryptionError("MalformedXML",
                                    "Encryption XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise BucketEncryptionError("MalformedXML",
                                    "Invalid server-side encryption XML") from exc
    if not _valid_namespace(root) or _local(root) != "ServerSideEncryptionConfiguration":
        raise BucketEncryptionError(
            "MalformedXML", "Unexpected server-side encryption document")
    for child in root:
        if not _valid_namespace(child) or _local(child) != "Rule":
            raise BucketEncryptionError(
                "MalformedXML", "Only Rule elements are accepted")
        for element in child:
            if not _valid_namespace(element):
                raise BucketEncryptionError(
                    "MalformedXML", "Unexpected encryption rule element")
            name = _local(element)
            if name == "ApplyServerSideEncryptionByDefault":
                algorithm = _algorithm(element)
                if algorithm == "AES256":
                    raise BucketEncryptionError(
                        "NotImplemented",
                        "Bucket default encryption with AES256 (SSE-S3) is "
                        "not supported: TeleDrive holds no server-side key "
                        "for objects the client did not encrypt. Use SSE-C "
                        "headers on each request instead",
                        501,
                    )
                if algorithm in {"aws:kms", "aws:kms:dsse"}:
                    raise BucketEncryptionError(
                        "NotImplemented",
                        "Bucket default encryption with aws:kms is not "
                        "supported: there is no KMS backing",
                        501,
                    )
                raise BucketEncryptionError(
                    "InvalidArgument",
                    "SSE-C has no bucket-level default algorithm; supply the "
                    "customer key on each request")
            if name == "BucketKeyEnabled":
                raise BucketEncryptionError(
                    "NotImplemented",
                    "Bucket keys require SSE-KMS, which has no backing here",
                    501,
                )
            raise BucketEncryptionError(
                "MalformedXML", "Unknown server-side encryption rule element")
    return []


def encryption_xml(rules: list[dict]) -> bytes:
    """Render the stored configuration (currently always an empty rule set)."""
    root = ET.Element("ServerSideEncryptionConfiguration", xmlns=NS)
    # Only the empty list is storable; guard against future silent shapes.
    if rules:
        raise BucketEncryptionError("InternalError",
                                    "Unsupported stored encryption rules", 500)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class BucketEncryptionStore:
    def __init__(self, database: Database):
        self.db = database
        catalog_metadata.create_all(database.engine, tables=[bucket_encryption])

    def get(self, bucket: str) -> list[dict] | None:
        raw = self.db.connection.execute(select(bucket_encryption.c.rules).where(
            bucket_encryption.c.bucket == bucket)).scalar_one_or_none()
        if raw is None:
            return None
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise BucketEncryptionError(
                "InternalError", "Stored encryption configuration is corrupt",
                500) from exc
        return parsed if isinstance(parsed, list) else []

    def replace(self, bucket: str, rules: list[dict], actor: str) -> None:
        if rules:
            raise BucketEncryptionError("InternalError",
                                        "Unsupported encryption rules", 500)
        now = int(time.time())
        existing = self.db.connection.execute(select(
            bucket_encryption.c.bucket).where(
                bucket_encryption.c.bucket == bucket)).scalar_one_or_none()
        payload = json.dumps(rules, sort_keys=True, separators=(",", ":"))
        if existing is None:
            self.db.connection.execute(insert(bucket_encryption).values(
                bucket=bucket, rules=payload, updated_at=now,
                updated_by=(actor or "-")[:64],
            ))
        else:
            from sqlalchemy import update
            self.db.connection.execute(update(bucket_encryption).where(
                bucket_encryption.c.bucket == bucket).values(
                    rules=payload, updated_at=now,
                    updated_by=(actor or "-")[:64]))
        self.db.commit()

    def delete(self, bucket: str) -> None:
        self.db.connection.execute(delete(bucket_encryption).where(
            bucket_encryption.c.bucket == bucket))
        self.db.commit()
