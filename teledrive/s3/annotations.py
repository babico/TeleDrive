"""Per-object S3 annotations with a separate, bounded metadata store.

An annotation is a named UTF-8 payload attached to one object. It is NOT an
object tag: annotations live in their own table, are never returned by
GetObjectTagging, are never folded into object metadata, and cannot influence
ACL or policy evaluation. Keeping the stores separate means a caller with only
``s3:GetObjectTagging`` never sees annotation payloads and vice versa.

Contract implemented here (deliberately tighter than AWS so the SQL store
stays bounded and index-friendly):

* name: 1..128 UTF-8 *bytes*, charset ``[A-Za-z0-9._/-]``. AWS allows 512
  bytes and a wider Unicode set; the narrower set keeps names deterministic
  across SQLite/MySQL/PostgreSQL collations.
* value: at most 1024 UTF-8 bytes (AWS allows 1 MiB). Annotation payloads are
  inline SQL text here; 1 KiB keeps a full object's annotations inside one
  row-page and makes the 50-annotation cap genuinely small.
* at most 50 annotations per object. AWS permits 1,000; 50 is the chosen
  bound (documented in docs/S3_FULL_COVERAGE_PLAN.md O2) and is enforced
  inside the write transaction with ``AnnotationLimitExceeded``.

The AWS wire shape is authoritative:

* single annotation:  ``?annotation&annotationName=<name>`` (GET/PUT/DELETE)
* listing:            ``?annotation&annotation-prefix=...&max-annotation-results=...&continuation-token=...`` (GET)

AWS deliberately reuses the ``annotation`` subresource for both the singular
and list forms; ``?annotations`` is not an AWS selector. The list form is
selected by the ABSENCE of ``annotationName`` and the presence of list
parameters. Only the current object is addressable: a ``versionId`` selector
is rejected by the query guard (annotations are not independently versioned).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
import time
from email.utils import formatdate
from xml.etree import ElementTree as ET

from sqlalchemy import (BigInteger, Column, ForeignKey, String, Table, Text,
                        delete, func, insert, select, update)

from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import metadata as annotation_metadata

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_ANNOTATION_NAME_BYTES = 128
MAX_ANNOTATION_VALUE_BYTES = 1024
MAX_ANNOTATIONS_PER_OBJECT = 50
MAX_ANNOTATION_RESULTS = 1000
# A continuation token is opaque to clients; cap it so a hostile token cannot
# grow the guard's work before signature verification completes.
MAX_CONTINUATION_TOKEN_BYTES = 4096

_NAME_RE = re.compile(r"[A-Za-z0-9._/-]+\Z")

annotations = Table(
    "storage_object_annotations", annotation_metadata,
    Column("object_id", String(36), ForeignKey("storage_objects.id"),
           primary_key=True),
    Column("name", String(MAX_ANNOTATION_NAME_BYTES), primary_key=True),
    # Text, not String: no server default is needed (the writer always
    # supplies it), so MySQL's DEFAULT-on-TEXT restriction does not apply.
    Column("value", Text, nullable=False),
    Column("created_ns", BigInteger, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
)

_ENSURED_LOCK = threading.Lock()
_ENSURED_ENGINES: set[int] = set()


def ensure_annotation_tables(engine) -> None:
    """Create the annotation table once per engine (idempotent).

    Called from the application startup (outside any request transaction) and
    from ``AnnotationStore.__init__``. It is NEVER called from a catalog
    mutation: Phase J proved that DDL inside a write transaction deadlocks
    SQLite against the caller's lock.
    """
    key = id(engine)
    with _ENSURED_LOCK:
        if key in _ENSURED_ENGINES:
            return
        annotation_metadata.create_all(engine, tables=[annotations])
        _ENSURED_ENGINES.add(key)


class AnnotationError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def validate_annotation_name(value) -> str:
    if not isinstance(value, str):
        raise AnnotationError("InvalidAnnotationName",
                              "Annotation name must be a string")
    raw = value
    if not raw or len(raw.encode("utf-8")) > MAX_ANNOTATION_NAME_BYTES:
        raise AnnotationError(
            "AnnotationNameTooLong" if raw else "InvalidAnnotationName",
            f"Annotation name must be 1..{MAX_ANNOTATION_NAME_BYTES} bytes",
        )
    if not _NAME_RE.fullmatch(raw):
        raise AnnotationError(
            "InvalidAnnotationName",
            "Annotation names may contain only letters, digits, '.', '_', "
            "'-' and '/'",
        )
    return raw


def validate_annotation_prefix(value) -> str:
    """A prefix is validated with the same safe alphabet as a name."""
    if value == "":
        return ""
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_ANNOTATION_NAME_BYTES:
        raise AnnotationError("InvalidPrefix", "Annotation prefix is invalid")
    if not _NAME_RE.fullmatch(value):
        raise AnnotationError("InvalidPrefix", "Annotation prefix is invalid")
    return value


def validate_annotation_value(payload: bytes) -> str:
    """Annotations are UTF-8 text; binary payloads get AWS's 415."""
    if not isinstance(payload, (bytes, bytearray)):
        raise AnnotationError("InvalidRequest", "Annotation payload is invalid")
    if len(payload) > MAX_ANNOTATION_VALUE_BYTES:
        raise AnnotationError(
            "InvalidRequest",
            f"Annotation payload exceeds {MAX_ANNOTATION_VALUE_BYTES} bytes",
        )
    try:
        return bytes(payload).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnnotationError(
            "UnsupportedMediaType",
            "The annotation payload is not valid UTF-8 encoded text", 415,
        ) from exc


def annotation_etag(value: str) -> str:
    """The ETag of the annotation payload (quoted MD5, like an S3 object)."""
    return '"' + hashlib.md5(value.encode("utf-8"),
                             usedforsecurity=False).hexdigest() + '"'


def annotation_http_date(updated_ns: int) -> str:
    return formatdate(updated_ns / 1_000_000_000, usegmt=True)


def continuation_token(master: bytes, bucket: str, key: str, after: str) -> str:
    """Signed opaque cursor bound to one (bucket, key) annotation listing."""
    payload = json.dumps(
        {"b": bucket, "k": key, "a": after},
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(master, body.encode("ascii"),
                         hashlib.sha256).hexdigest()[:32]
    return f"{body}.{signature}"


def parse_continuation_token(master: bytes, bucket: str, key: str,
                             token: str) -> str:
    if (not isinstance(token, str) or not token
            or len(token.encode("ascii", "ignore")) > MAX_CONTINUATION_TOKEN_BYTES):
        raise AnnotationError("InvalidArgument", "Invalid continuation token")
    body, _, signature = token.rpartition(".")
    expected = hmac.new(master, body.encode("ascii", "ignore"),
                        hashlib.sha256).hexdigest()[:32]
    if not body or not hmac.compare_digest(signature, expected):
        raise AnnotationError("InvalidArgument", "Invalid continuation token")
    try:
        padded = body + "=" * (-len(body) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError) as exc:
        raise AnnotationError("InvalidArgument",
                              "Invalid continuation token") from exc
    if (not isinstance(decoded, dict)
            or decoded.get("b") != bucket or decoded.get("k") != key
            or not isinstance(decoded.get("a"), str)):
        raise AnnotationError("InvalidArgument", "Invalid continuation token")
    return decoded["a"]


def annotations_xml(bucket: str, key: str, prefix: str, max_results: int,
                    entries: list[dict], *, next_token: str | None = None) -> bytes:
    root = ET.Element("ListObjectAnnotationsOutput", xmlns=NS)
    listing = ET.SubElement(root, "Annotations")
    for entry in entries:
        node = ET.SubElement(listing, "AnnotationEntry")
        ET.SubElement(node, "AnnotationName").text = entry["name"]
        ET.SubElement(node, "ETag").text = annotation_etag(entry["value"])
        ET.SubElement(node, "LastModified").text = annotation_http_date(
            entry["updated_ns"])
        ET.SubElement(node, "Size").text = str(
            len(entry["value"].encode("utf-8")))
    ET.SubElement(root, "Bucket").text = bucket
    ET.SubElement(root, "Key").text = key
    ET.SubElement(root, "AnnotationPrefix").text = prefix
    ET.SubElement(root, "MaxAnnotationResults").text = str(max_results)
    ET.SubElement(root, "AnnotationCount").text = str(len(entries))
    if next_token is not None:
        ET.SubElement(root, "NextContinuationToken").text = next_token
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def put_annotation_xml(key: str, name: str) -> bytes:
    root = ET.Element("PutObjectAnnotationOutput", xmlns=NS)
    ET.SubElement(root, "Key").text = key
    ET.SubElement(root, "AnnotationName").text = name
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class AnnotationStore:
    """CRUD for ``storage_object_annotations`` keyed by object ID."""

    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        ensure_annotation_tables(self.db.engine)

    def count(self, object_id: str) -> int:
        return int(self.db.connection.execute(
            select(func.count()).select_from(annotations).where(
                annotations.c.object_id == object_id)
        ).scalar_one())

    def get(self, object_id: str, name: str) -> dict | None:
        row = self.db.connection.execute(select(
            annotations.c.name, annotations.c.value,
            annotations.c.created_ns, annotations.c.updated_ns,
        ).where(
            annotations.c.object_id == object_id,
            annotations.c.name == name,
        )).first()
        if row is None:
            return None
        return {"name": row[0], "value": row[1],
                "created_ns": int(row[2]), "updated_ns": int(row[3])}

    def put(self, object_id: str, name: str, value: str, *,
            now_ns: int | None = None, actor: str = "",
            bucket: str = "", object_key: str = "") -> dict:
        """Create or replace exactly one annotation in one transaction.

        The limit check and the write share a transaction; a concurrent
        writer therefore either observes the committed row or re-runs after
        the database serializes the write (SQLite) / row lock (PostgreSQL,
        MySQL). Replace preserves ``created_ns``.
        """
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        try:
            existing = self.db.connection.execute(select(
                annotations.c.created_ns,
            ).where(
                annotations.c.object_id == object_id,
                annotations.c.name == name,
            )).first()
            if existing is None:
                count = self.db.connection.execute(
                    select(func.count()).select_from(annotations).where(
                        annotations.c.object_id == object_id)
                ).scalar_one()
                if int(count) >= MAX_ANNOTATIONS_PER_OBJECT:
                    raise AnnotationError(
                        "AnnotationLimitExceeded",
                        f"An object supports at most "
                        f"{MAX_ANNOTATIONS_PER_OBJECT} annotations",
                    )
                self.db.connection.execute(insert(annotations).values(
                    object_id=object_id, name=name, value=value,
                    created_ns=now_ns, updated_ns=now_ns,
                ))
            else:
                self.db.connection.execute(update(annotations).where(
                    annotations.c.object_id == object_id,
                    annotations.c.name == name,
                ).values(value=value, updated_ns=now_ns))
            self._journal_annotation_change(
                object_id, name, bucket, object_key, actor)
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        return self.get(object_id, name)

    def delete(self, object_id: str, name: str, *, actor: str = "",
               bucket: str = "", object_key: str = "") -> bool:
        """Idempotent: an absent annotation is still a successful DELETE."""
        changed = self.db.connection.execute(delete(annotations).where(
            annotations.c.object_id == object_id,
            annotations.c.name == name,
        ))
        if changed.rowcount:
            self._journal_annotation_change(
                object_id, name, bucket, object_key, actor)
        self.db.commit()
        return changed.rowcount > 0

    def _journal_annotation_change(self, object_id: str, name: str,
                                   bucket: str, object_key: str,
                                   actor: str) -> None:
        """Record the annotation change on the CURRENT transaction.

        The caller may omit bucket/key (older call sites); journaling is then
        skipped rather than guessed. A SAVEPOINT isolates any failure.
        """
        if not bucket or not object_key:
            return
        try:
            from teledrive.s3.metadata_journal import journal_event_safely
            journal_event_safely(
                self.db.connection, event="annotation_changed", bucket=bucket,
                object_key=object_key, version_id=object_id, actor=actor,
                detail={"annotation": name},
            )
        except Exception:
            pass

    def list(self, object_id: str, *, prefix: str = "",
             after: str | None = None, limit: int = MAX_ANNOTATION_RESULTS
             ) -> tuple[list[dict], str | None]:
        """One page ordered by name; ``after`` is the exclusive cursor."""
        if not 1 <= limit <= MAX_ANNOTATION_RESULTS:
            raise AnnotationError("InvalidArgument",
                                  "max-annotation-results is out of range")
        stmt = select(
            annotations.c.name, annotations.c.value,
            annotations.c.created_ns, annotations.c.updated_ns,
        ).where(annotations.c.object_id == object_id)
        if prefix:
            stmt = stmt.where(annotations.c.name.startswith(prefix, autoescape=True))
        if after is not None:
            stmt = stmt.where(annotations.c.name > after)
        rows = self.db.connection.execute(
            stmt.order_by(annotations.c.name).limit(limit + 1)
        ).all()
        more = len(rows) > limit
        page = rows[:limit]
        entries = [{"name": row[0], "value": row[1],
                    "created_ns": int(row[2]), "updated_ns": int(row[3])}
                   for row in page]
        next_after = entries[-1]["name"] if more and entries else None
        return entries, next_after

    def delete_object(self, object_id: str) -> None:
        self.db.connection.execute(delete(annotations).where(
            annotations.c.object_id == object_id))
        self.db.commit()
