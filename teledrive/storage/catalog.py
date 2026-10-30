"""Bucket and current-object catalog shared by future REST and S3 gateways.

Telegram is the only payload backend. This module stores names, pointers and
immutable object IDs, never object body bytes. Previous object manifests
remain available after replacement/removal until explicit safe GC.
"""
from __future__ import annotations

import hashlib
import re

from sqlalchemy import inspect, text

from .catalog_acl import BucketAclMixin
from .catalog_buckets import BucketAdminMixin
from .catalog_lock import BucketLockMixin
from .catalog_tables import (
    ObjectHead, bucket_acl_grants, buckets, catalog_metadata, heads,
    object_acl_grants, published_versions, removed_versions,
)
from .catalog_versions import BucketVersionMixin
from .manifest import ManifestStore, StoredObject, objects

# Re-exported for the existing import sites (``web/s3_gateway/*``, copy.py,
# gc_collect.py, multipart.py and the tests all import these names from
# ``teledrive.storage.catalog``).  Declarations live in catalog_tables.py.
__all__ = [
    "BucketCatalog", "ObjectHead", "bucket_acl_grants", "buckets",
    "catalog_metadata", "heads", "object_acl_grants", "published_versions",
    "removed_versions",
]

_BUCKET_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?\Z")


def ensure_versioning_column(db) -> None:
    """Ensure the bucket/object versioning, lock and tiering columns exist.

    The defensive ALTERs moved into ``teledrive.storage.schema`` so they run
    exactly once per schema under the cross-process migration lock instead of
    racing between worker processes.  This wrapper keeps the old entry point.
    """
    from .schema import ensure_schema

    ensure_schema(db.engine)


class BucketCatalog(
        BucketAdminMixin, BucketLockMixin, BucketAclMixin, BucketVersionMixin):
    """Manage bucket names and a single current pointer per logical object key.

    The underlying manifest remains immutable. A newer version simply moves
    the head pointer atomically; old Telegram chunks are not deleted.
    """

    def __init__(self, manifests: ManifestStore):
        self.manifests = manifests
        self.db = manifests.db
        # The single serialized migration creates the catalog tables, the
        # Phase J pending-tag journal and the metadata-journal tables.  On a
        # warm schema this is a pure in-process no-op, so constructors stay
        # cheap and never issue DDL of their own.
        from .schema import ensure_schema
        ensure_schema(self.db.engine)
        self.db.release_setup_snapshot()

    @staticmethod
    def validate_bucket(name: str) -> None:
        if (not isinstance(name, str) or len(name) < 3 or len(name) > 63
                or not _BUCKET_RE.fullmatch(name) or ".." in name
                or ".-" in name or "-." in name
                or all(part.isdigit() for part in name.split("."))):
            raise ValueError("Invalid S3-compatible bucket name")

    @staticmethod
    def _keyhash(key: str) -> str:
        if not isinstance(key, str) or not (1 <= len(key.encode("utf-8")) <= 1024):
            raise ValueError("Object key must contain 1..1024 UTF-8 bytes")
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _enqueue_notification(self, event_type: str, bucket: str, key: str, *,
                              version_id: str | None = None) -> None:
        """Record an event on the CURRENT transaction; never fail the write."""
        try:
            from teledrive.s3.notifications import enqueue_event_safely
            enqueue_event_safely(
                self.db.connection, event_type=event_type, bucket=bucket,
                object_key=key, version_id=version_id,
            )
        except Exception:
            # The notification module already isolates its own failures.
            pass

    def _journal_metadata(self, event: str, bucket: str, key: str, *,
                          version_id: str | None = None,
                          detail: dict | None = None) -> None:
        """Append an S3 Metadata journal row on the CURRENT transaction.

        Only buckets with a metadata configuration are journaled. The write
        is confined to a SAVEPOINT by ``journal_event_safely`` so a journal
        failure can never fail the storage mutation that it describes.
        """
        try:
            from teledrive.s3.metadata_journal import journal_event_safely
            journal_event_safely(
                self.db.connection, event=event, bucket=bucket,
                object_key=key, version_id=version_id, detail=detail,
            )
        except Exception:
            # journal_event_safely already isolates its own failures.
            pass

    def _apply_pending_tags(self, identifier: str) -> None:
        """Apply a Phase J tag journal in the current publish transaction."""
        from teledrive.s3.tagging import apply_pending_tags_uncommitted
        try:
            apply_pending_tags_uncommitted(self.db.connection, identifier)
        except BaseException:
            # A malformed journal or SQL failure must not publish a version
            # without the tags its writer was promised.
            self.db.connection.rollback()
            raise

    def _delete_pending_tags(self, identifier: str) -> None:
        """Reclaim a Phase J journal row in the caller's transaction."""
        if not inspect(self.db.engine).has_table("storage_pending_tags"):
            return
        from teledrive.s3.tagging import delete_pending_tags_uncommitted
        delete_pending_tags_uncommitted(self.db.connection, identifier)

    def _delete_annotations(self, identifier: str) -> None:
        """Revoke an object version's annotations in the caller's transaction.

        Annotations are not independently versioned: revoking the version
        removes them too, exactly like its tags. The table is checked first
        because a legacy database may predate Phase O2; DDL is never issued
        here (the store/startup create it).
        """
        if not inspect(self.db.engine).has_table("storage_object_annotations"):
            return
        self.db.connection.execute(text(
            "DELETE FROM storage_object_annotations WHERE object_id = :object_id"
        ), {"object_id": identifier})

