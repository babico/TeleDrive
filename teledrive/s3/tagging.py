"""S3 object tags stored per immutable Telegram object version.

Object body bytes always live in Telegram. Tags are small SQL metadata only.
Writing tags on one version never mutates an older version or a CopyObject
source. An object head is locked before current-version tag mutation.
"""
from __future__ import annotations

import json
import time

from sqlalchemy import (
    BigInteger, Column, ForeignKey, String, Table, Text, delete, insert,
    select, update,
)

from teledrive.storage.catalog import (
    BucketCatalog, heads, published_versions, removed_versions,
    catalog_metadata,
)
from teledrive.storage.manifest import metadata as _meta, objects
object_tags = Table(
    "storage_object_tags", _meta,
    Column("object_id", String(36), ForeignKey("storage_objects.id"), primary_key=True),
    Column("tag_key", String(512), primary_key=True),
    Column("tag_value", String(1024), nullable=False),
)
# Phase J: tagging writes against a READY-but-unpublished version are
# journaled here and applied in the SAME transaction as the head move.
# A pending row is never observable through GetObjectTagging.
pending_tags = Table(
    "storage_pending_tags", _meta,
    Column("object_id", String(36), ForeignKey("storage_objects.id"), primary_key=True),
    Column("tags", Text, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
    Column("actor", String(255), nullable=False),
)


bucket_tags = Table(
    "storage_bucket_tags", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"), primary_key=True),
    Column("tag_key", String(512), primary_key=True),
    Column("tag_value", String(1024), nullable=False),
)


class TaggingError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def validate_tags(tags: list[tuple[str, str]], *, max_tags: int = 10) -> list[tuple[str, str]]:
    if not isinstance(tags, list) or len(tags) > max_tags:
        raise TaggingError("InvalidTag", f"Resource supports at most {max_tags} tags")
    seen = set()
    result = []
    for key, value in tags:
        if not isinstance(key, str) or not isinstance(value, str):
            raise TaggingError("InvalidTag", "Tag keys and values must be strings")
        # AWS counts tag lengths in UTF-16 code units, not UTF-8 bytes.
        try:
            key_units = len(key.encode("utf-16-le")) // 2
            val_units = len(value.encode("utf-16-le")) // 2
        except UnicodeError as exc:
            raise TaggingError("InvalidTag", "Invalid Unicode in tag") from exc
        if (not 1 <= key_units <= 128 or val_units > 256
                or key.lower().startswith("aws:")):
            raise TaggingError("InvalidTag", "Invalid key/value length or reserved aws: prefix")
        if key in seen:
            raise TaggingError("InvalidTag", "Duplicate tag key")
        seen.add(key)
        result.append((key, value))
    return result


def _decode_pending_tags(raw: str) -> list[tuple[str, str]]:
    return [(str(key), str(value)) for key, value in json.loads(raw)]


def journal_pending_tags_uncommitted(connection, object_id: str,
                                     tags: list[tuple[str, str]],
                                     actor: str) -> None:
    """Stage validated tags in the caller's transaction; never commit.

    The journal is keyed by one object version and is applied exactly once
    inside ``BucketCatalog.publish``. An empty tag set removes the row.
    """
    connection.execute(delete(pending_tags).where(
        pending_tags.c.object_id == object_id))
    if tags:
        connection.execute(insert(pending_tags).values(
            object_id=object_id,
            tags=json.dumps(tags, ensure_ascii=False),
            updated_ns=time.time_ns(),
            actor=(actor or "")[:255],
        ))


def apply_pending_tags_uncommitted(connection, object_id: str) -> bool:
    """Apply a journaled tag set in the publish transaction.

    Returns True when a journal row existed. The row is deleted only in
    the same transaction that installs the real version tags, so a failed
    publish leaves neither visible tags nor a half-applied journal.
    """
    raw = connection.execute(
        select(pending_tags.c.tags).where(
            pending_tags.c.object_id == object_id)
    ).scalar_one_or_none()
    if raw is None:
        return False
    tags = validate_tags(_decode_pending_tags(raw))
    connection.execute(delete(object_tags).where(
        object_tags.c.object_id == object_id))
    for tag_key, tag_value in tags:
        connection.execute(insert(object_tags).values(
            object_id=object_id, tag_key=tag_key, tag_value=tag_value,
        ))
    connection.execute(delete(pending_tags).where(
        pending_tags.c.object_id == object_id))
    return True


def delete_pending_tags_uncommitted(connection, object_id: str) -> None:
    """Reclaim a journal row in the caller's revision/GC transaction."""
    connection.execute(delete(pending_tags).where(
        pending_tags.c.object_id == object_id))


def ensure_pending_tag_table(engine) -> None:
    """Create the Phase J journal table (idempotent).

    publish() applies the journal inside its head-move transaction, so the
    table must exist before any publish — including on a database where no
    ObjectTagStore has been constructed yet.
    """
    _meta.create_all(engine, tables=[pending_tags])


class ObjectTagStore:
    def __init__(self, catalog: BucketCatalog):
        self.catalog = catalog
        self.db = catalog.db
        _meta.create_all(self.db.engine, tables=[object_tags, pending_tags])
        self.db.release_setup_snapshot()

    def get(self, object_id: str) -> list[tuple[str, str]]:
        return list(self.db.connection.execute(
            select(object_tags.c.tag_key, object_tags.c.tag_value)
            .where(object_tags.c.object_id == object_id)
            .order_by(object_tags.c.tag_key)
        ).all())

    def get_pending(self, object_id: str) -> list[tuple[str, str]] | None:
        """Inspection helper; never used by a public GET response."""
        raw = self.db.connection.execute(
            select(pending_tags.c.tags).where(
                pending_tags.c.object_id == object_id)
        ).scalar_one_or_none()
        return None if raw is None else _decode_pending_tags(raw)

    def replace_current(self, bucket: str, key: str,
                        tags: list[tuple[str, str]], *,
                        actor: str = "") -> str:
        tags = validate_tags(tags)
        # Lock the current head row while replacing its version-scoped tags.
        # On PostgreSQL/MySQL this UPDATE serializes concurrent head changes.
        digest = self.catalog._keyhash(key)
        try:
            current = self.catalog.get(bucket, key)
            guard = self.db.connection.execute(update(heads).where(
                heads.c.bucket == bucket, heads.c.key_hash == digest,
                heads.c.object_id == current.item.id,
                heads.c.generation == current.generation,
            ).values(updated_at=int(time.time())))
            if guard.rowcount != 1:
                raise TaggingError("OperationAborted", "Object replaced during tagging", 409)
            self.db.connection.execute(delete(object_tags).where(
                object_tags.c.object_id == current.item.id
            ))
            for tag_key, tag_value in tags:
                self.db.connection.execute(insert(object_tags).values(
                    object_id=current.item.id, tag_key=tag_key, tag_value=tag_value
                ))
            self._journal_tag_change(bucket, key, current.item.id, tags, actor)
            self.db.commit()
            return current.item.id
        except BaseException:
            self.db.connection.rollback()
            raise

    def _journal_tag_change(self, bucket: str, key: str, object_id: str,
                            tags: list[tuple[str, str]], actor: str) -> None:
        """Append a metadata-journal tag event on the CURRENT transaction."""
        try:
            from teledrive.s3.metadata_journal import journal_event_safely
            journal_event_safely(
                self.db.connection, event="tagged", bucket=bucket,
                object_key=key, version_id=object_id, actor=actor,
                detail={"tag_count": len(tags)},
            )
        except Exception:
            pass

    def replace_published(self, bucket: str, key: str, identifier: str,
                          tags: list[tuple[str, str]]) -> None:
        """Mutate tags on only a proven published immutable version.

        Unknown/unpublished READY staging is never writable through VersionId.
        SQL row lock fences concurrent physical metadata modifications while
        the actual Telegram payload remains immutable.
        """
        tags = validate_tags(tags)
        try:
            # Acquire the writer lock FIRST, before any consistent SELECT.
            # MySQL REPEATABLE READ would otherwise pin a stale snapshot
            # while waiting on a concurrent VersionId DELETE's object lock.
            locked = self.db.connection.execute(
                update(objects).where(
                    objects.c.id == identifier,
                    objects.c.bucket == bucket,
                    objects.c.object_key == key,
                    objects.c.status == "ready",
                ).values(updated_at=objects.c.updated_at)
            )
            if locked.rowcount != 1:
                raise TaggingError("NoSuchVersion", "Object version unavailable", 404)
            revoked = self.db.connection.execute(
                select(removed_versions.c.object_id).where(
                    removed_versions.c.object_id == identifier
                ).with_for_update()
            ).scalar_one_or_none()
            if revoked is not None or not self.catalog.is_visible_version(
                bucket, key, identifier
            ):
                raise TaggingError("NoSuchVersion", "Object version revoked or unpublished", 404)
            self.db.connection.execute(
                delete(object_tags).where(object_tags.c.object_id == identifier)
            )
            for tag_key, tag_value in tags:
                self.db.connection.execute(insert(object_tags).values(
                    object_id=identifier, tag_key=tag_key, tag_value=tag_value,
                ))
            self._journal_tag_change(bucket, key, identifier, tags, "")
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise

    def replace_version(self, bucket: str, key: str, identifier: str,
                        tags: list[tuple[str, str]], *,
                        actor: str = "") -> str:
        """Tag a published version, or journal a READY-but-unpublished one.

        The object row lock serializes this decision with ``publish``: if a
        concurrent publish commits first this writes the real version tags;
        otherwise it stages the journal that publish applies atomically.
        Returns ``"published"`` or ``"pending"``.
        """
        tags = validate_tags(tags)
        try:
            locked = self.db.connection.execute(
                update(objects).where(
                    objects.c.id == identifier,
                    objects.c.bucket == bucket,
                    objects.c.object_key == key,
                    objects.c.status == "ready",
                ).values(updated_at=objects.c.updated_at)
            )
            if locked.rowcount != 1:
                raise TaggingError("NoSuchVersion", "Object version unavailable", 404)
            revoked = self.db.connection.execute(
                select(removed_versions.c.object_id).where(
                    removed_versions.c.object_id == identifier
                ).with_for_update()
            ).scalar_one_or_none()
            if revoked is not None:
                raise TaggingError("NoSuchVersion", "Object version revoked", 404)
            published = self.db.connection.execute(
                select(published_versions.c.object_id).where(
                    published_versions.c.object_id == identifier)
            ).scalar_one_or_none()
            if published is not None:
                if not self.catalog.is_visible_version(bucket, key, identifier):
                    raise TaggingError(
                        "NoSuchVersion", "Object version unavailable", 404)
                self.db.connection.execute(
                    delete(object_tags).where(
                        object_tags.c.object_id == identifier)
                )
                for tag_key, tag_value in tags:
                    self.db.connection.execute(insert(object_tags).values(
                        object_id=identifier, tag_key=tag_key,
                        tag_value=tag_value,
                    ))
                delete_pending_tags_uncommitted(self.db.connection, identifier)
                self._journal_tag_change(bucket, key, identifier, tags, actor)
                mode = "published"
            else:
                journal_pending_tags_uncommitted(
                    self.db.connection, identifier, tags, actor)
                mode = "pending"
            self.db.commit()
            return mode
        except BaseException:
            self.db.connection.rollback()
            raise

    def attach_uncommitted(self, object_id: str,
                           tags: list[tuple[str, str]]) -> None:
        """Set initial tags before publishing head; caller commits both atomically."""
        for tag_key, tag_value in validate_tags(tags):
            self.db.connection.execute(insert(object_tags).values(
                object_id=object_id, tag_key=tag_key, tag_value=tag_value
            ))

    def copy_tags(self, source_id: str, destination_id: str) -> None:
        """Copy in the caller's transaction; never issue a separate commit."""
        for tag_key, tag_value in self.get(source_id):
            self.db.connection.execute(insert(object_tags).values(
                object_id=destination_id, tag_key=tag_key, tag_value=tag_value
            ))


class BucketTagStore:
    """Bucket tags are distinct metadata from object version tags."""

    def __init__(self, catalog: BucketCatalog):
        self.catalog = catalog
        self.db = catalog.db
        catalog_metadata.create_all(self.db.engine, tables=[bucket_tags])
        self.db.release_setup_snapshot()

    def _ensure_bucket(self, bucket: str) -> None:
        from teledrive.storage.catalog import buckets
        present = self.db.connection.execute(
            select(buckets.c.name).where(buckets.c.name == bucket)
        ).first()
        if present is None:
            raise FileNotFoundError("Bucket not found")

    def get(self, bucket: str) -> list[tuple[str, str]]:
        self._ensure_bucket(bucket)
        return list(self.db.connection.execute(
            select(bucket_tags.c.tag_key, bucket_tags.c.tag_value)
            .where(bucket_tags.c.bucket == bucket)
            .order_by(bucket_tags.c.tag_key)
        ).all())

    def replace(self, bucket: str, tags: list[tuple[str, str]]) -> None:
        from teledrive.storage.catalog import buckets
        tags = validate_tags(tags, max_tags=50)
        try:
            # Serialize concurrent bucket deletion/tag mutation.
            guarded = self.db.connection.execute(update(buckets).where(
                buckets.c.name == bucket
            ).values(created_at=buckets.c.created_at))
            if guarded.rowcount != 1:
                raise FileNotFoundError("Bucket not found")
            self.db.connection.execute(delete(bucket_tags).where(
                bucket_tags.c.bucket == bucket
            ))
            for key, value in tags:
                self.db.connection.execute(insert(bucket_tags).values(
                    bucket=bucket, tag_key=key, tag_value=value
                ))
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
