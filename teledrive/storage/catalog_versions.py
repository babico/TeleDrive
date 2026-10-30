"""Object version mixin for the storage catalog.

Extracted verbatim from ``catalog.py`` (move-only).  This is the most
load-bearing half of the storage layer: ``publish`` is the only writer of a
head's ``generation`` and every delete path fences on the object ID.  Every
method uses the assembled ``BucketCatalog``'s ``self.db``/``self.manifests``.
"""
from __future__ import annotations

import time
from uuid import uuid4

from sqlalchemy import and_, delete, insert, or_, select, update
from sqlalchemy.exc import IntegrityError

from .catalog_tables import (
    ObjectHead, heads, object_acl_grants, published_versions, removed_versions,
)
from .manifest import StoredObject, objects


class BucketVersionMixin:
    def get(self, bucket: str, key: str) -> ObjectHead:
        digest = self._keyhash(key)
        row = self.db.connection.execute(
            select(heads.c.object_id, heads.c.generation)
            .where(heads.c.bucket == bucket, heads.c.key_hash == digest)
        ).first()
        if row is None:
            raise FileNotFoundError("Object key does not exist")
        item = self.manifests.get(row[0])
        if item.bucket != bucket or item.key != key:
            raise RuntimeError("Object key digest collision; refusing unsafe resolution")
        return ObjectHead(item, int(row[1]))

    def is_visible_version(self, bucket: str, key: str, version_id: str) -> bool:
        """Require exact published key proof AND absence of a removal record."""
        row = self.db.connection.execute(
            select(published_versions.c.object_id)
            .select_from(published_versions.join(
                objects, objects.c.id == published_versions.c.object_id,
            ).outerjoin(
                removed_versions,
                removed_versions.c.object_id == published_versions.c.object_id,
            )).where(
                published_versions.c.object_id == version_id,
                published_versions.c.bucket == bucket,
                published_versions.c.key_hash == self._keyhash(key),
                objects.c.bucket == bucket,
                objects.c.object_key == key,
                objects.c.status.in_(("ready", "delete-marker")),
                removed_versions.c.object_id.is_(None),
            )
        ).scalar_one_or_none()
        return row is not None


    def delete_marker(self, bucket: str, key: str, *,
                      expected_generation: int | None = None,
                      expected_object_id: str | None = None) -> str:
        """Publish a zero-byte logical tombstone with one atomic head CAS.

        The marker is NOT a ready payload manifest; Telegram is never touched.
        A concurrent write must not be overwritten by a stale DELETE.
        """
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        digest = self._keyhash(key)
        row = self.db.connection.execute(select(
            heads.c.object_id, heads.c.generation,
        ).where(heads.c.bucket == bucket, heads.c.key_hash == digest)).first()
        if expected_object_id is not None and (row is None or row[0] != expected_object_id):
            raise ValueError("Delete precondition object ID changed")
        if expected_generation is not None and (
            (int(row[1]) if row else 0) != expected_generation
        ):
            raise ValueError("Delete precondition generation changed")
        if self.versioning_state(bucket) == "Suspended":
            # AWS suspended semantics: DELETE removes the head and
            # retires the current version WITHOUT creating a marker
            # (unversioned-style delete). Returns None so callers omit
            # the marker headers.
            if row is None:
                return None
            # A legal hold or an open retention window forbids removing the
            # version. The explicit-version path enforces this; the suspended
            # branch did not, so on a lock-enabled bucket whose versioning was
            # set to Suspended, an ordinary DELETE hid a COMPLIANCE-retained
            # object -- recoverable bytes, but a real immutability breach.
            lock_row = self.db.connection.execute(select(
                objects.c.legal_hold, objects.c.retention_until_ns,
            ).where(objects.c.id == row[0])).first()
            if lock_row is not None:
                if bool(lock_row[0]):
                    raise PermissionError(
                        "Object is under legal hold and cannot be deleted")
                if (lock_row[1] is not None
                        and int(lock_row[1]) > time.time_ns()):
                    raise PermissionError(
                        "Object is under retention and cannot be deleted")
            changed = self.db.connection.execute(delete(heads).where(
                heads.c.bucket == bucket, heads.c.key_hash == digest,
                heads.c.object_id == row[0],
                heads.c.generation == row[1],
            ))
            if changed.rowcount != 1:
                self.db.connection.rollback()
                raise ValueError("Concurrent object deletion/write")
            self.db.connection.execute(insert(removed_versions).values(
                object_id=row[0], removed_ns=time.time_ns(),
            ))
            self._enqueue_notification(
                "s3:ObjectRemoved:Delete", bucket, key, version_id=row[0])
            self._journal_metadata(
                "deleted", bucket, key, version_id=row[0],
                detail={"reason": "suspended_version_removed"})
            self._delete_pending_tags(row[0])
            self.db.commit()
            return None
        marker = str(uuid4())
        now = int(time.time())
        try:
            self.db.connection.execute(insert(objects).values(
                id=marker, bucket=bucket, object_key=key,
                status="delete-marker", size=0, sha256=None,
                created_at=now, updated_at=now, error=None,
            ))
            if row is None:
                try:
                    with self.db.connection.begin_nested():
                        self.db.connection.execute(insert(heads).values(
                            bucket=bucket, key_hash=digest, object_id=marker,
                            generation=1, updated_at=now,
                        ))
                except IntegrityError as exc:
                    raise ValueError("Concurrent object creation") from exc
            else:
                changed = self.db.connection.execute(update(heads).where(
                    heads.c.bucket == bucket, heads.c.key_hash == digest,
                    heads.c.object_id == row[0],
                    heads.c.generation == row[1],
                ).values(object_id=marker, generation=int(row[1]) + 1, updated_at=now))
                if changed.rowcount != 1:
                    raise ValueError("Concurrent object deletion/write")
            self.db.connection.execute(insert(published_versions).values(
                object_id=marker, bucket=bucket, key_hash=digest,
                committed_ns=time.time_ns(),
            ))
            self._enqueue_notification(
                "s3:ObjectRemoved:DeleteMarkerCreated", bucket, key,
                version_id=marker)
            self._journal_metadata(
                "deleted", bucket, key, version_id=marker,
                detail={"reason": "delete_marker_created"})
            self.db.commit()
            return marker
        except BaseException:
            self.db.connection.rollback()
            raise

    def delete_version(self, bucket: str, key: str, version_id: str) -> bool:
        """Hide an exact published VersionId, retaining immutable remote data.

        If the selected version owns HEAD, advance to the latest remaining
        version (including a prior marker); this is a compare-and-swap in the
        same SQL transaction as the version revocation.
        """
        digest = self._keyhash(key)
        try:
            # Serialize revocation with version-specific tag edits on the
            # underlying object row, even for historical (non-HEAD) versions.
            # A second DELETE waits for this write lock and then observes the
            # committed logical removal rather than leaking a unique-key error.
            lock = self.db.connection.execute(
                update(objects).where(
                    objects.c.id == version_id,
                    objects.c.status.in_(("ready", "delete-marker")),
                ).values(updated_at=objects.c.updated_at)
            )
            if lock.rowcount != 1:
                self.db.connection.rollback()
                return False
            # A plain SELECT can read an obsolete REPEATABLE READ snapshot on
            # MySQL, established earlier by the S3 credential lookup. This
            # locking current-read observes another session's committed
            # revocation even if our original snapshot predates it.
            revoked = self.db.connection.execute(
                select(removed_versions.c.object_id).where(
                    removed_versions.c.object_id == version_id,
                ).with_for_update()
            ).scalar_one_or_none()
            if revoked is not None or not self.is_visible_version(
                bucket, key, version_id
            ):
                self.db.connection.rollback()
                return False
            # Object lock (Phase C): a retained or legal-held version
            # refuses explicit deletion — WORM enforced at the same
            # write lock that serializes the revocation.
            locked = self.db.connection.execute(
                select(objects.c.retention_until_ns, objects.c.legal_hold)
                .where(objects.c.id == version_id)).first()
            if locked is not None and (
                    locked[1]
                    or (locked[0] is not None
                        and int(locked[0]) > time.time_ns())):
                self.db.connection.rollback()
                raise PermissionError("Object is under retention")
            head = self.db.connection.execute(select(
                heads.c.object_id, heads.c.generation,
            ).where(heads.c.bucket == bucket, heads.c.key_hash == digest)).first()
            self.db.connection.execute(insert(removed_versions).values(
                object_id=version_id, removed_ns=time.time_ns(),
            ))
            if head is not None and head[0] == version_id:
                previous = self.db.connection.execute(
                    select(published_versions.c.object_id)
                    .select_from(published_versions.join(
                        objects, objects.c.id == published_versions.c.object_id,
                    ).outerjoin(removed_versions,
                        removed_versions.c.object_id == published_versions.c.object_id,
                    )).where(
                        published_versions.c.bucket == bucket,
                        published_versions.c.key_hash == digest,
                        objects.c.object_key == key,
                        objects.c.status.in_(("ready", "delete-marker")),
                        removed_versions.c.object_id.is_(None),
                    ).order_by(
                        published_versions.c.committed_ns.desc(),
                        published_versions.c.object_id.desc(),
                    ).limit(1)
                ).scalar_one_or_none()
                selector = (
                    heads.c.bucket == bucket, heads.c.key_hash == digest,
                    heads.c.object_id == version_id,
                    heads.c.generation == head[1],
                )
                if previous is None:
                    changed = self.db.connection.execute(delete(heads).where(*selector))
                else:
                    changed = self.db.connection.execute(update(heads).where(
                        *selector
                    ).values(object_id=previous, generation=int(head[1]) + 1,
                             updated_at=int(time.time())))
                if changed.rowcount != 1:
                    raise ValueError("Version HEAD changed concurrently")
            self._enqueue_notification(
                "s3:ObjectRemoved:Delete", bucket, key,
                version_id=version_id)
            self._journal_metadata(
                "version_revoked", bucket, key, version_id=version_id)
            self._delete_pending_tags(version_id)
            self._delete_annotations(version_id)
            self.db.commit()
            return True
        except IntegrityError:
            # An idempotent duplicate DELETE is not a server error. Keep the
            # fail-closed behavior if a different constraint is violated.
            self.db.connection.rollback()
            if not self.is_visible_version(bucket, key, version_id):
                return False
            raise
        except BaseException:
            self.db.connection.rollback()
            raise

    def current_marker(self, bucket: str, key: str) -> str | None:
        digest = self._keyhash(key)
        return self.db.connection.execute(
            select(objects.c.id).select_from(heads.join(
                objects, heads.c.object_id == objects.c.id,
            )).where(
                heads.c.bucket == bucket, heads.c.key_hash == digest,
                objects.c.bucket == bucket, objects.c.object_key == key,
                objects.c.status == "delete-marker",
            )
        ).scalar_one_or_none()

    def _record_published_uncommitted(self, item: StoredObject) -> None:
        """Append a proven head-version record in its publication transaction.

        Records never represent an incomplete upload, overwritten staged part,
        or a failed conditional write. A historical HEAD predating this index
        can be registered explicitly when an operator requests its versions.
        """
        self.db.connection.execute(insert(published_versions).values(
            object_id=item.id, bucket=item.bucket,
            key_hash=self._keyhash(item.key),
            committed_ns=time.time_ns(),
        ))

    def index_legacy_current_heads(self, *, dry_run: bool = True,
                                   limit: int = 100) -> list[str]:
        """Backfill only proven current HEADs; unknown old versions stay hidden.

        An old READY manifest can be a never-published upload and is NOT safe
        to promote. This backfill only trusts pointers already in HEADs.
        """
        if not 1 <= limit <= 1000:
            raise ValueError("Invalid history index limit")
        missing = self.db.connection.execute(
            select(heads.c.object_id, objects.c.bucket, objects.c.object_key)
            .select_from(
                heads.join(objects, heads.c.object_id == objects.c.id)
                     .outerjoin(
                         published_versions,
                         heads.c.object_id == published_versions.c.object_id,
                     )
            )
            .where(
                published_versions.c.object_id.is_(None),
                objects.c.status == "ready",
            )
            .order_by(heads.c.bucket, heads.c.key_hash).limit(limit)
        ).all()
        ids = []
        for identifier, bucket, key in missing:
            if self._keyhash(key) != self.db.connection.execute(
                select(heads.c.key_hash).where(
                    heads.c.bucket == bucket, heads.c.object_id == identifier,
                )
            ).scalar_one_or_none():
                raise RuntimeError("Legacy HEAD references inconsistent key metadata")
            ids.append(identifier)
            if not dry_run:
                self._record_published_uncommitted(
                    self.manifests.get(identifier)
                )
        if not dry_run and ids:
            self.db.commit()
        return ids

    def list_versions(self, bucket: str, key: str, *,
                      limit: int = 100) -> list[dict]:
        """Read versions proven published, not all READY/staged manifests."""
        if not 1 <= limit <= 1000:
            raise ValueError("Invalid version limit")
        digest = self._keyhash(key)
        try:
            current = self.get(bucket, key).item.id
        except FileNotFoundError:
            current = None
        rows = self.db.connection.execute(
            select(published_versions.c.object_id,
                   published_versions.c.committed_ns,
                   objects.c.size, objects.c.sha256)
            .select_from(published_versions.join(
                objects, published_versions.c.object_id == objects.c.id
            ).outerjoin(
                removed_versions,
                removed_versions.c.object_id == published_versions.c.object_id,
            ))
            .where(
                removed_versions.c.object_id.is_(None),
                published_versions.c.bucket == bucket,
                published_versions.c.key_hash == digest,
                objects.c.status == "ready",
                objects.c.bucket == bucket,
                objects.c.object_key == key,
            ).order_by(
                published_versions.c.committed_ns.desc(),
                published_versions.c.object_id.desc(),
            ).limit(limit)
        ).mappings().all()
        return [
            {
                "version_id": row["object_id"],
                "size": int(row["size"]),
                "sha256": row["sha256"],
                "committed_ns": int(row["committed_ns"]),
                "is_current": row["object_id"] == current,
            }
            for row in rows
        ]

    def list_bucket_versions(
        self, bucket: str, *, prefix: str = "", key_marker: str = "",
        version_marker: str = "", limit: int = 1000,
    ) -> tuple[list[dict], bool]:
        """Bounded, deterministic S3 listing of proven published history.

        Never include READY manifests that did not win HEAD publication.
        The pagination marker must correspond to a published version of
        exactly the supplied bucket/key; dangling or forged markers fail.
        Delete markers are modeled as SQL-only published tombstones.
        """
        if not 1 <= limit <= 1000 or len(prefix.encode("utf-8")) > 1024:
            raise ValueError("Invalid version-list pagination")
        if version_marker and not key_marker:
            raise ValueError("Version-id marker requires key marker")
        where = [
            published_versions.c.bucket == bucket,
            objects.c.bucket == bucket,
            objects.c.status.in_(("ready", "delete-marker")),
            removed_versions.c.object_id.is_(None),
        ]
        if prefix:
            where.append(objects.c.object_key.startswith(prefix, autoescape=True))
        if key_marker:
            self._keyhash(key_marker)
            if version_marker:
                selected = self.db.connection.execute(
                    select(published_versions.c.committed_ns)
                    .select_from(published_versions.join(
                        objects, published_versions.c.object_id == objects.c.id
                    ).outerjoin(
                        removed_versions,
                        removed_versions.c.object_id == published_versions.c.object_id,
                    )).where(
                        removed_versions.c.object_id.is_(None),
                        published_versions.c.bucket == bucket,
                        objects.c.object_key == key_marker,
                        published_versions.c.object_id == version_marker,
                        objects.c.status.in_(("ready", "delete-marker")),
                    )
                ).scalar_one_or_none()
                if selected is None:
                    raise ValueError("Unknown version-id marker")
                where.append(or_(
                    objects.c.object_key > key_marker,
                    and_(
                        objects.c.object_key == key_marker,
                        or_(
                            published_versions.c.committed_ns < selected,
                            and_(
                                published_versions.c.committed_ns == selected,
                                published_versions.c.object_id < version_marker,
                            ),
                        ),
                    ),
                ))
            else:
                where.append(objects.c.object_key > key_marker)
        rows = self.db.connection.execute(
            select(
                published_versions.c.object_id,
                published_versions.c.committed_ns,
                objects.c.object_key, objects.c.size, objects.c.sha256,
                objects.c.status.label("object_status"),
                heads.c.object_id.label("current_id"),
            )
            .select_from(
                published_versions.join(
                    objects, published_versions.c.object_id == objects.c.id
                ).outerjoin(
                    removed_versions,
                    removed_versions.c.object_id == published_versions.c.object_id,
                ).outerjoin(
                    heads,
                    and_(
                        heads.c.bucket == published_versions.c.bucket,
                        heads.c.key_hash == published_versions.c.key_hash,
                        heads.c.object_id == published_versions.c.object_id,
                    ),
                )
            )
            .where(*where)
            .order_by(
                objects.c.object_key,
                published_versions.c.committed_ns.desc(),
                published_versions.c.object_id.desc(),
            ).limit(limit + 1)
        ).mappings().all()
        return [
            {
                "key": row["object_key"],
                "version_id": row["object_id"],
                "committed_ns": int(row["committed_ns"]),
                "size": int(row["size"]),
                "sha256": row["sha256"],
                "is_delete_marker": row["object_status"] == "delete-marker",
                "is_current": row["current_id"] is not None,
            }
            for row in rows[:limit]
        ], len(rows) > limit

    def publish(self, identifier: str, *, now: int,
                expected_generation: int | None = None,
                expected_object_id: str | None = None,
                event_type: str = "s3:ObjectCreated:Put") -> ObjectHead:
        """Atomically update the current pointer after Telegram upload succeeds.

        expected_generation=0 is create-if-absent, and a positive value is
        optimistic concurrency control. None permits last-writer-wins.
        """
        item = self.manifests.get(identifier)
        digest = self._keyhash(item.key)
        if item.bucket not in self.list_buckets():
            raise ValueError("Bucket does not exist")
        # Phase J: serialize publication with a concurrent tagging write on
        # this exact version. That writer either journals before this lock
        # (so the journal is applied below) or observes the published row
        # after it and writes real tags instead.
        locked = self.db.connection.execute(
            update(objects).where(objects.c.id == identifier).values(
                updated_at=objects.c.updated_at)
        )
        if locked.rowcount != 1:
            self.db.connection.rollback()
            raise ValueError("Object version unavailable")
        existing = self.db.connection.execute(
            select(heads.c.object_id, heads.c.generation)
            .where(heads.c.bucket == item.bucket, heads.c.key_hash == digest)
        ).first()
        if existing is None:
            if expected_object_id is not None:
                self.db.connection.rollback()
                raise ValueError("Object changed; object ID precondition failed")
            if expected_generation not in (None, 0):
                self.db.connection.rollback()
                raise ValueError("Object changed; generation precondition failed")
            try:
                with self.db.connection.begin_nested():
                    self.db.connection.execute(insert(heads).values(
                        bucket=item.bucket, key_hash=digest, object_id=item.id,
                        generation=1, updated_at=now,
                    ))
            except IntegrityError as exc:
                self.db.connection.rollback()
                raise ValueError("Concurrent object creation; retry with generation") from exc
            self._record_published_uncommitted(item)
            self._apply_pending_tags(identifier)
            self._enqueue_notification(
                event_type, item.bucket, item.key, version_id=item.id)
            self._journal_metadata(
                "created", item.bucket, item.key, version_id=item.id,
                detail={"size": int(item.size)})
            self.db.commit()
            # Phase C: buckets with a default retention lock every new
            # version at publish time (WORM from the first byte).
            self.apply_default_lock(item.id)
            return ObjectHead(item, 1)

        old = self.db.connection.execute(select(
            objects.c.bucket, objects.c.object_key, objects.c.status,
        ).where(objects.c.id == existing[0])).one_or_none()
        if old is None or old[0] != item.bucket or old[1] != item.key:
            self.db.connection.rollback()
            raise RuntimeError("Object hash collision detected")
        if old[2] not in ("ready", "delete-marker"):
            self.db.connection.rollback()
            raise RuntimeError("Current head refers to a non-published object")
        generation = int(existing[1])
        if expected_object_id is not None and expected_object_id != existing[0]:
            self.db.connection.rollback()
            raise ValueError("Object changed; object ID precondition failed")
        if expected_generation is not None and expected_generation != generation:
            self.db.connection.rollback()
            raise ValueError("Object changed; generation precondition failed")
        changed = self.db.connection.execute(
            update(heads)
            .where(
                heads.c.bucket == item.bucket, heads.c.key_hash == digest,
                heads.c.object_id == existing[0],
                heads.c.generation == generation,
            )
            .values(object_id=item.id, generation=generation + 1, updated_at=now)
        )
        if changed.rowcount != 1:
            self.db.connection.rollback()
            raise ValueError("Concurrent object modification")
        if self.versioning_state(item.bucket) == "Suspended":
            # AWS suspended semantics: a new write replaces the current
            # version; the superseded version retires from the journal
            # in the SAME transaction (no unversioned-history growth).
            self.db.connection.execute(insert(removed_versions).values(
                object_id=existing[0], removed_ns=time.time_ns(),
            ))
        self._record_published_uncommitted(item)
        self._apply_pending_tags(identifier)
        self._enqueue_notification(
            event_type, item.bucket, item.key, version_id=item.id)
        self._journal_metadata(
            "created", item.bucket, item.key, version_id=item.id,
            detail={"size": int(item.size)})
        self.db.commit()
        self.apply_default_lock(item.id)
        return ObjectHead(item, generation + 1)

    def rename_object(self, bucket: str, source_key: str, destination_key: str,
                      *, now: int, expected_source_id: str | None = None,
                      expected_generation: int | None = None) -> ObjectHead:
        """Move the CURRENT head from one key to another in ONE transaction.

        Only the head row, the manifest's ``object_key`` and the key-scoped
        published-version/ACL digests move. Chunk rows, replica rows, Telegram
        payloads, tags, HTTP metadata and the pending-tag journal are keyed by
        object ID and therefore follow the object untouched. Callers must
        enforce source existence, lock and both ACL sides before calling.
        """
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        source_digest = self._keyhash(source_key)
        destination_digest = self._keyhash(destination_key)
        if source_digest == destination_digest:
            raise ValueError("Rename source and destination are identical")
        try:
            # Serialize the rename with delete/tag/lock mutations on the
            # exact source version, exactly like publish/delete_version.
            if expected_source_id is not None:
                candidate = expected_source_id
            else:
                candidate = self.db.connection.execute(select(
                    heads.c.object_id).where(
                        heads.c.bucket == bucket,
                        heads.c.key_hash == source_digest,
                    )).scalar_one_or_none()
                if candidate is None:
                    self.db.connection.rollback()
                    raise FileNotFoundError("Source object does not exist")
            lock = self.db.connection.execute(
                update(objects).where(
                    objects.c.id == candidate,
                    objects.c.bucket == bucket,
                    objects.c.status == "ready",
                ).values(updated_at=objects.c.updated_at)
            )
            if lock.rowcount != 1:
                self.db.connection.rollback()
                raise FileNotFoundError("Source object does not exist")
            head = self.db.connection.execute(select(
                heads.c.object_id, heads.c.generation,
            ).where(
                heads.c.bucket == bucket,
                heads.c.key_hash == source_digest,
            )).first()
            if head is None:
                self.db.connection.rollback()
                raise FileNotFoundError("Source object does not exist")
            source_id, generation = str(head[0]), int(head[1])
            if expected_source_id is not None and source_id != expected_source_id:
                self.db.connection.rollback()
                raise ValueError("Source object changed")
            if expected_generation is not None and generation != expected_generation:
                self.db.connection.rollback()
                raise ValueError("Source object changed")
            item = self.manifests.get(source_id)
            if item.bucket != bucket or item.key != source_key:
                self.db.connection.rollback()
                raise RuntimeError("Object hash collision detected")
            # Object lock blocks a rename exactly as it blocks delete: the
            # physical payload never moves, so moving the head must not let
            # a WORM-retained version escape its key/retention contract.
            if self.is_locked(source_id):
                self.db.connection.rollback()
                raise PermissionError("Object is under retention")
            # Fail closed on ANY destination claim: a current head, a
            # historical published version, an object row or a key-scoped
            # ACL. Rename never overwrites and never merges version chains.
            occupied = (
                self.db.connection.execute(select(heads.c.object_id).where(
                    heads.c.bucket == bucket,
                    heads.c.key_hash == destination_digest)).first()
                or self.db.connection.execute(select(
                    published_versions.c.object_id).where(
                        published_versions.c.bucket == bucket,
                        published_versions.c.key_hash == destination_digest,
                    )).first()
                or self.db.connection.execute(select(objects.c.id).where(
                    objects.c.bucket == bucket,
                    objects.c.object_key == destination_key,
                    objects.c.status.in_(("ready", "delete-marker")),
                )).first()
                or self.db.connection.execute(select(
                    object_acl_grants.c.grantee).where(
                        object_acl_grants.c.bucket == bucket,
                        object_acl_grants.c.key_hash == destination_digest,
                    )).first()
            )
            if occupied:
                self.db.connection.rollback()
                raise FileExistsError("Destination object already exists")
            changed = self.db.connection.execute(update(heads).where(
                heads.c.bucket == bucket,
                heads.c.key_hash == source_digest,
                heads.c.object_id == source_id,
                heads.c.generation == generation,
            ).values(
                key_hash=destination_digest,
                generation=generation + 1,
                updated_at=now,
            ))
            if changed.rowcount != 1:
                self.db.connection.rollback()
                raise ValueError("Concurrent object modification")
            self.db.connection.execute(update(objects).where(
                objects.c.id == source_id,
            ).values(object_key=destination_key))
            self.db.connection.execute(update(published_versions).where(
                published_versions.c.object_id == source_id,
            ).values(key_hash=destination_digest))
            self.db.connection.execute(update(object_acl_grants).where(
                object_acl_grants.c.bucket == bucket,
                object_acl_grants.c.key_hash == source_digest,
            ).values(key_hash=destination_digest))
            self._journal_metadata(
                "renamed", bucket, destination_key, version_id=source_id,
                detail={"source_key": source_key})
            self.db.commit()
            return ObjectHead(self.manifests.get(source_id), generation + 1)
        except BaseException:
            self.db.connection.rollback()
            raise


    def list_objects(self, bucket: str, *, prefix: str = "",
                     after: str | None = None, limit: int = 100) -> list[ObjectHead]:
        if not 1 <= limit <= 1000:
            raise ValueError("Invalid page limit")
        stmt = (
            select(heads.c.generation, objects)
            .select_from(heads.join(objects, heads.c.object_id == objects.c.id))
            .where(heads.c.bucket == bucket, objects.c.status == "ready")
        )
        if prefix:
            stmt = stmt.where(objects.c.object_key.startswith(prefix, autoescape=True))
        if after is not None:
            stmt = stmt.where(objects.c.object_key > after)
        rows = self.db.connection.execute(
            stmt.order_by(objects.c.object_key, objects.c.id).limit(limit)
        ).mappings().all()
        return [ObjectHead(
            StoredObject(
                id=row["id"], bucket=row["bucket"], key=row["object_key"],
                size=int(row["size"]), sha256=row["sha256"],
                created_at=int(row["created_at"]),
            ), int(row["generation"]),
        ) for row in rows]

    def remove_current(self, bucket: str, key: str, *,
                       expected_generation: int | None = None,
                       expected_object_id: str | None = None) -> bool:
        """Unlink a head only; Telegram data stays until separately verified GC."""
        digest = self._keyhash(key)
        try:
            current = self.get(bucket, key)
        except FileNotFoundError:
            return False
        if expected_generation is not None and current.generation != expected_generation:
            raise ValueError("Object changed; generation precondition failed")
        if expected_object_id is not None and current.item.id != expected_object_id:
            raise ValueError("Object changed; object ID precondition failed")
        # The unlink itself always fences on the OBJECT ID, even when the
        # caller only sent a generation. publish() restarts the counter at 1
        # whenever the head is absent, so A@gen1 -> unlink -> B@gen1 has the
        # SAME generation for a different object: a conditional delete by
        # generation alone destroyed the newer object (verified over HTTP).
        # The id is unique forever, so it closes the ABA window.
        condition = [
            heads.c.bucket == bucket, heads.c.key_hash == digest,
            heads.c.object_id == current.item.id,
            heads.c.generation == current.generation,
        ]
        changed = self.db.connection.execute(delete(heads).where(and_(*condition)))
        self.db.commit()
        if changed.rowcount != 1:
            # Rowcount 0 means a concurrent writer replaced the head between
            # the read and the delete. Reporting {"ok": true} made a lost
            # race look like success; the S3 path correctly returns 412.
            raise ValueError("Object changed; unlink precondition failed")
        return True

