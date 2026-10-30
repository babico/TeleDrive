"""Bucket-level encryption configuration.

Two modes exist, and the bucket document says which one:

* **SSE-C** — the client supplies the key per request and nothing is stored.
  The bucket default is then the explicit *absence* of a server-side default,
  which is an empty rule set.
* **SSE-S3 / envelope** — the server holds the key. ``SSEAlgorithm=AES256``
  is accepted **only when the deployment has set ``storage.encryption:
  envelope``**, because that is what makes the claim true: TeleDrive then
  generates one data key per object and wraps it with a KEK derived from the
  S3 master key. A deployment that has not enabled it answers 501 naming the
  setting, rather than storing a rule it cannot honour.

``aws:kms`` stays 501 in both modes: there is no AWS KMS here, and claiming
KMS while using a local key would be a lie. ``AES256`` is the honest name for
"this deployment encrypts for you".
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
    # AWS-shaped rule list: empty (SSE-C) or one AES256 default (envelope).
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


def parse_encryption_xml(payload: bytes, *,
                         envelope_enabled: bool = False) -> list[dict]:
    """Strict parse.

    An empty rule set is valid always (it means "no server-side default").
    ``AES256`` is valid only when envelope encryption is enabled; ``aws:kms``
    is never valid here.
    """
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
    rules: list[dict] = []
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
                    if not envelope_enabled:
                        raise BucketEncryptionError(
                            "NotImplemented",
                            "Bucket default encryption with AES256 (SSE-S3) "
                            "requires storage.encryption: envelope in "
                            "config.yaml. Without it TeleDrive holds no "
                            "server-side key; use SSE-C headers per request "
                            "instead",
                            501,
                        )
                    rules.append({
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "AES256",
                        },
                    })
                    continue
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
    return rules


def encryption_xml(rules: list[dict]) -> bytes:
    """Render the stored configuration."""
    root = ET.Element("ServerSideEncryptionConfiguration", xmlns=NS)
    for rule in rules:
        node = ET.SubElement(root, "Rule")
        default = ET.SubElement(node, "ApplyServerSideEncryptionByDefault")
        ET.SubElement(default, "SSEAlgorithm").text = (
            rule["apply_server_side_encryption_by_default"]["sse_algorithm"])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class BucketEncryptionStore:
    def __init__(self, database: Database):
        self.db = database
        from teledrive.storage.schema import ensure_schema
        ensure_schema(database.engine)
        database.release_setup_snapshot()

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
        for rule in rules:
            if (set(rule) != {"apply_server_side_encryption_by_default"}
                    or rule["apply_server_side_encryption_by_default"].get(
                        "sse_algorithm") != "AES256"):
                raise BucketEncryptionError(
                    "InternalError", "Unsupported encryption rules", 500)
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
