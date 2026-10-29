"""Metadata-backed S3 website configuration (Phase I).

A website configuration is real SQL state: the bucket's index document and
optional error document live in ``storage_website_configs``. The configuration
alone does NOT make a bucket readable — the per-bucket ``public_read`` flag in
``storage_buckets`` is a separate, explicit owner decision (admin role, audit
logged) and defaults to FALSE.

The public ``/site/{bucket}/...`` route serves ONLY the current, ready object
version (never staging, deleted markers or version history). ``public_read``
turning on publishes every current object in the bucket anonymously to anyone
who can reach the app origin.

``RedirectAllRequestsTo`` and ``RoutingRules`` are valid AWS website XML but
have no honest backing here (there are no extra hostnames or rewrite engine),
so they are rejected with 501 rather than accepted and silently ignored.
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import (Boolean, Column, ForeignKey, String, Table, delete,
                        insert, select, update)

from teledrive.storage.catalog import BucketCatalog, buckets, catalog_metadata

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_WEBSITE_XML_BYTES = 16 * 1024
MAX_DOCUMENT_NAME_BYTES = 255

website_configs = Table(
    "storage_website_configs", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"),
           primary_key=True),
    Column("index_document", String(MAX_DOCUMENT_NAME_BYTES), nullable=False),
    Column("error_document", String(MAX_DOCUMENT_NAME_BYTES)),
    Column("enabled", Boolean, nullable=False, default=True),
)

_UNSAFE_DOCUMENT = re.compile(r"[\x00-\x1f\x7f\\?#%]")


class WebsiteError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def _name(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid_namespace(node) -> bool:
    name = _name(node)
    return node.tag in {name, f"{{{NS}}}{name}"}


def validate_document_name(value, label: str) -> str:
    """A website document is a relative object key, never a filesystem path.

    Rejecting ``..``/``.`` path segments, absolute paths, backslashes and URL
    delimiters keeps the configured document name from escaping the served
    bucket key space or changing the request's query/fragment.
    """
    if not isinstance(value, str):
        raise WebsiteError("InvalidArgument", f"{label} must be a string")
    raw = value.strip()
    if not raw or len(raw.encode("utf-8")) > MAX_DOCUMENT_NAME_BYTES:
        raise WebsiteError("InvalidArgument", f"{label} is invalid")
    if _UNSAFE_DOCUMENT.search(raw):
        raise WebsiteError("InvalidArgument", f"{label} is invalid")
    if raw.startswith("/") or raw.startswith("~"):
        raise WebsiteError("InvalidArgument", f"{label} must be relative")
    if any(segment in {"", ".", ".."} for segment in raw.split("/")):
        raise WebsiteError("InvalidArgument", f"{label} is invalid")
    if raw.endswith("/"):
        raise WebsiteError("InvalidArgument", f"{label} must name a document")
    return raw


def _document(root, label: str, child_name: str) -> str:
    matches = [node for node in root if _name(node) == label]
    if len(matches) != 1:
        raise WebsiteError("MalformedXML", f"Exactly one {label} is required")
    node = matches[0]
    if not _valid_namespace(node) or node.attrib or len(node) != 1:
        raise WebsiteError("MalformedXML", f"Invalid {label}")
    value = node[0]
    if (not _valid_namespace(value) or value.attrib or len(value)
            or _name(value) != child_name):
        raise WebsiteError("MalformedXML", f"Invalid {label}")
    return validate_document_name(value.text or "", label)


def parse_website_xml(payload: bytes) -> dict:
    """Parse a strict, bounded WebsiteConfiguration document."""
    if len(payload) > MAX_WEBSITE_XML_BYTES:
        raise WebsiteError("MalformedXML", "Website XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise WebsiteError("MalformedXML", "Invalid website XML") from exc
    if (not _valid_namespace(root) or root.attrib
            or _name(root) != "WebsiteConfiguration"):
        raise WebsiteError("MalformedXML", "Unexpected website document")
    # Unsupported AWS website features are rejected honestly instead of
    # being accepted and ignored (no extra hostnames / rewrite engine here).
    for node in root:
        if _name(node) in {"RedirectAllRequestsTo", "RoutingRules"}:
            raise WebsiteError(
                "NotImplemented",
                "RedirectAllRequestsTo and RoutingRules are not supported", 501)
    allowed = {"IndexDocument", "ErrorDocument"}
    if len(root) == 0 or any(_name(node) not in allowed for node in root):
        raise WebsiteError("MalformedXML", "Unexpected website configuration field")
    index_document = _document(root, "IndexDocument", "Suffix")
    error_nodes = [node for node in root if _name(node) == "ErrorDocument"]
    error_document = None
    if error_nodes:
        error_document = _document(root, "ErrorDocument", "Key")
    return {
        "index_document": index_document,
        "error_document": error_document,
        "enabled": True,
    }


def website_xml(config: dict) -> bytes:
    root = ET.Element("WebsiteConfiguration", xmlns=NS)
    index_node = ET.SubElement(root, "IndexDocument")
    ET.SubElement(index_node, "Suffix").text = config["index_document"]
    if config.get("error_document"):
        error_node = ET.SubElement(root, "ErrorDocument")
        ET.SubElement(error_node, "Key").text = config["error_document"]
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class WebsiteConfigStore:
    """The bucket website configuration + its public_read gate.

    ``public_read`` lives in ``storage_buckets`` because it is a bucket policy
    decision, not a property of the XML document. It defaults to FALSE and is
    only written by the explicit admin API (or cleared by DeleteBucketWebsite
    and bucket deletion).
    """

    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)

    def _bucket_exists(self, name: str) -> None:
        if self.db.connection.execute(
            select(buckets.c.name).where(buckets.c.name == name)
        ).first() is None:
            raise FileNotFoundError("Bucket not found")

    def get(self, name: str) -> dict | None:
        self._bucket_exists(name)
        row = self.db.connection.execute(select(
            website_configs.c.index_document,
            website_configs.c.error_document,
            website_configs.c.enabled,
        ).where(website_configs.c.bucket == name)).first()
        if row is None:
            return None
        return {
            "index_document": row[0],
            "error_document": row[1],
            "enabled": bool(row[2]),
        }

    def replace(self, name: str, config: dict, *,
                public_read: bool | None = None) -> None:
        """Write the config, optionally setting the public_read gate.

        The conditional bucket UPDATE fences a concurrent bucket deletion.
        S3 PutBucketWebsite passes ``public_read=None`` so a configuration
        write never turns public exposure on by itself.
        """
        try:
            guard = self.db.connection.execute(update(buckets).where(
                buckets.c.name == name
            ).values(created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(website_configs).where(
                website_configs.c.bucket == name))
            self.db.connection.execute(insert(website_configs).values(
                bucket=name,
                index_document=config["index_document"],
                error_document=config.get("error_document"),
                enabled=bool(config.get("enabled", True)),
            ))
            if public_read is not None:
                self.db.connection.execute(update(buckets).where(
                    buckets.c.name == name
                ).values(public_read=bool(public_read)))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise

    def delete(self, name: str) -> None:
        """Remove the website config AND revoke public read in one transaction.

        Deleting the site must never leave a public bucket behind.
        """
        try:
            guard = self.db.connection.execute(update(buckets).where(
                buckets.c.name == name
            ).values(created_at=buckets.c.created_at))
            if guard.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(website_configs).where(
                website_configs.c.bucket == name))
            self.db.connection.execute(update(buckets).where(
                buckets.c.name == name).values(public_read=False))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
