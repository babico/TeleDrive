"""Physical GC for logically-deleted objects (owner-gated).

Logical deletes (delete markers, version revocations, head unlinks)
retain Telegram media as a recovery journal. This module turns that
backlog into reclaimable storage when the owner enables GC:

- ``metrics``: physical vs logical object/byte counts plus the
  reclaimable backlog.
- ``candidates``: fail-closed enumeration of physically-deletable
  objects — proven-published, not a current head, not a dedup alias
  source, aged past the safety interval, and (scope=revoked) explicitly
  version-revoked or (scope=deleted) belonging to a key whose live
  head is gone or a delete marker.
- ``collect``: re-verifies every candidate immediately before acting,
  deletes the Telegram messages through the transport, journals the
  result and only then drops chunk rows and hides the object from
  version history. Partial failures leave the object retryable.

The state toggle (storage_gc_state) is a loud, auditable owner
decision; nothing here ever runs automatically.
"""
from __future__ import annotations

import json
import time

from sqlalchemy import (BigInteger, Boolean, Column, Integer, String,
                        Table, Text, delete, func, insert, inspect, not_,
                        select, text, update)

from .catalog import heads, published_versions, removed_versions
from .manifest import (ChunkReference, chunks, metadata,
                       object_aliases, objects, replica_chunks)

gc_state = Table(
    "storage_gc_state", metadata,
    Column("id", Integer, primary_key=True),  # singleton row, always 1
    Column("enabled", Boolean, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
    Column("updated_by", String(255), nullable=False),
    # Added in Phase A; pre-existing deployments get it via
    # _ensure_grace_column's ALTER TABLE.
    Column("grace_seconds", Integer),
)
# Explicit physical-collection requests: version deletes, multipart
# aborts and lifecycle expirations enqueue their objects here when GC
# is enabled; the collector drains them after the grace period.
gc_queue = Table(
    "storage_gc_queue", metadata,
    Column("object_id", String(36), primary_key=True),
    Column("enqueued_ns", BigInteger, nullable=False),
    Column("reason", String(64), nullable=False),
)
gc_collected = Table(
    "storage_gc_collected", metadata,
    Column("object_id", String(36), primary_key=True),
    Column("bucket", String(63), nullable=False),
    Column("object_key", String(1024), nullable=False),
    Column("chunk_count", Integer, nullable=False),
    Column("bytes", BigInteger, nullable=False),
    Column("scope", String(16), nullable=False),
    Column("deleted_refs", Text, nullable=False),
    Column("collected_ns", BigInteger, nullable=False),
)

SCOPES = ("revoked", "deleted", "queued")
DEFAULT_MIN_AGE_SECONDS = 24 * 3600
MIN_AGE_FLOOR_SECONDS = 3600
DEFAULT_GRACE_SECONDS = 24 * 3600


def _ensure_grace_column(db):
    """storage_gc_state.grace_seconds may be missing in deployments created
    before Phase A; the ALTER now runs in the schema coordinator."""
    from .schema import ensure_schema
    ensure_schema(db.engine)


def _send_intents_table():
    from .user_mode import mtproto_send_intents
    return mtproto_send_intents


class RetainedMediaGC:
    def __init__(self, db):
        self.db = db
        from .schema import ensure_schema
        ensure_schema(db.engine)

    # -- state -----------------------------------------------------------
    def state(self) -> dict:
        row = self.db.connection.execute(
            select(gc_state.c.enabled, gc_state.c.updated_ns,
                   gc_state.c.updated_by,
                   gc_state.c.grace_seconds).where(gc_state.c.id == 1)
        ).first()
        if row is None:
            return {"enabled": False, "updated_ns": None,
                    "updated_by": None,
                    "grace_seconds": DEFAULT_GRACE_SECONDS}
        return {"enabled": bool(row[0]), "updated_ns": row[1],
                "updated_by": row[2],
                "grace_seconds": int(row[3] or DEFAULT_GRACE_SECONDS)}

    def set_enabled(self, enabled: bool, *, by: str,
                    grace_seconds: int | None = None) -> None:
        now = time.time_ns()
        if grace_seconds is not None:
            if not MIN_AGE_FLOOR_SECONDS <= grace_seconds <= 90 * 86400:
                raise ValueError("GC grace outside 1h..90d")
        values = {"enabled": bool(enabled), "updated_ns": now,
                  "updated_by": by}
        if grace_seconds is not None:
            values["grace_seconds"] = int(grace_seconds)
        changed = self.db.connection.execute(
            update(gc_state).where(gc_state.c.id == 1).values(**values))
        if changed.rowcount != 1:
            if "grace_seconds" not in values:
                values["grace_seconds"] = DEFAULT_GRACE_SECONDS
            self.db.connection.execute(
                insert(gc_state).values(id=1, **values))
        self.db.commit()

    # -- queue -----------------------------------------------------------
    def enqueue(self, object_ids, reason: str = "manual") -> int:
        """Idempotently request physical collection for objects once
        their grace period passes. No-op when the objects are unknown."""
        if not isinstance(reason, str) or not 1 <= len(reason) <= 64:
            raise ValueError("Invalid GC queue reason")
        now = time.time_ns()
        known = {row for row in self.db.connection.execute(
            select(objects.c.id).where(objects.c.id.in_(list(object_ids)))
        ).scalars()} if object_ids else set()
        already = {row for row in self.db.connection.execute(
            select(gc_queue.c.object_id).where(
                gc_queue.c.object_id.in_(list(known)))
        ).scalars()} if known else set()
        fresh = sorted(known - already)
        if fresh:
            self.db.connection.execute(insert(gc_queue), [
                {"object_id": oid, "enqueued_ns": now, "reason": reason}
                for oid in fresh])
            self.db.commit()
        return len(fresh)

    def _grace_seconds(self) -> int:
        return int(self.state().get("grace_seconds") or DEFAULT_GRACE_SECONDS)

    # -- metrics ---------------------------------------------------------
    def metrics(self) -> dict:
        db = self.db.connection
        logical = db.execute(text(
            "SELECT COUNT(DISTINCT c.object_id), COALESCE(SUM(c.size), 0) "
            "FROM storage_chunks c JOIN storage_object_heads h "
            "ON h.object_id = c.object_id")).one()
        physical = db.execute(text(
            "SELECT COUNT(DISTINCT object_id), COALESCE(SUM(size), 0) "
            "FROM storage_chunks")).one()
        # Reclaimable backlog, mirroring candidates()' fail-closed
        # filters as pure counts.
        base = ("FROM storage_objects o "
                "WHERE o.status = 'ready' "
                "AND NOT EXISTS (SELECT 1 FROM storage_object_heads h "
                "WHERE h.object_id = o.id) "
                "AND NOT EXISTS (SELECT 1 FROM storage_object_aliases a "
                "WHERE a.source_object_id = o.id) "
                "AND EXISTS (SELECT 1 FROM storage_published_versions p "
                "WHERE p.object_id = o.id)")
        # Both queries are fully static: the f-string only splices the
        # module-constant `base` fragment above; no user input flows in.
        revoked = db.execute(text(
            f"SELECT COUNT(*) {base} "
            "AND EXISTS (SELECT 1 FROM storage_removed_versions r "
            "WHERE r.object_id = o.id)")).scalar_one()  # nosec B608
        deleted = db.execute(text(
            f"SELECT COUNT(*) {base} "  # nosec B608
            "AND NOT EXISTS ("
            "SELECT 1 FROM storage_published_versions p2 "
            "JOIN storage_object_heads h2 "
            "ON h2.bucket = p2.bucket AND h2.key_hash = p2.key_hash "
            "JOIN storage_objects oh ON oh.id = h2.object_id "
            "WHERE p2.object_id = o.id AND oh.status <> 'delete-marker')"
        )).scalar_one()  # nosec B608
        collected = db.execute(text(
            "SELECT COUNT(*), COALESCE(SUM(bytes), 0) "
            "FROM storage_gc_collected")).one()
        queued = db.execute(select(func.count()).select_from(gc_queue)
                            ).scalar_one()
        return {
            "logical_objects": int(logical[0] or 0),
            "logical_bytes": int(logical[1] or 0),
            "physical_objects": int(physical[0] or 0),
            "physical_bytes": int(physical[1] or 0),
            "retained_objects": int(physical[0] or 0) - int(logical[0] or 0),
            "retained_bytes": int(physical[1] or 0) - int(logical[1] or 0),
            "reclaimable": {"revoked": int(revoked), "deleted": int(deleted)},
            "queued": int(queued or 0),
            "collected_objects": int(collected[0] or 0),
            "collected_bytes": int(collected[1] or 0),
        }

    # -- candidates ------------------------------------------------------
    def candidates(self, *, scope: str, min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
                   limit: int = 100) -> list[dict]:
        """Fail-closed enumeration; never mutates anything."""
        if scope not in SCOPES:
            raise ValueError("Invalid GC scope")
        if min_age_seconds < MIN_AGE_FLOOR_SECONDS:
            raise ValueError("GC minimum age is below the safety floor")
        if not 1 <= limit <= 1000:
            raise ValueError("Invalid GC candidate limit")
        cutoff = (time.time_ns() // 1_000_000_000) - min_age_seconds
        db = self.db.connection
        if scope == "queued":
            # Explicit collection requests (version deletes, MPU aborts,
            # lifecycle expirations): eligible once past the grace
            # period measured from ENQUEUE time, under the same
            # fail-closed safety filters as every other scope.
            grace_ns = self._grace_seconds() * 1_000_000_000
            queued = db.execute(
                select(gc_queue.c.object_id, gc_queue.c.reason,
                       gc_queue.c.enqueued_ns)
                .where(gc_queue.c.enqueued_ns <= time.time_ns() - grace_ns)
                .order_by(gc_queue.c.enqueued_ns).limit(limit)
            ).mappings().all()
            result = []
            for entry in queued:
                row = db.execute(
                    select(objects.c.id, objects.c.bucket,
                           objects.c.object_key, objects.c.updated_at)
                    .where(
                        objects.c.id == entry["object_id"],
                        objects.c.status == "ready",
                        not_(exists(heads.c.object_id, objects.c.id)),
                        not_(exists_source_alias(objects.c.id)),
                        exists(published_versions.c.object_id, objects.c.id),
                    )
                ).mappings().first()
                if row is None:
                    continue
                size, chunk_count = db.execute(text(
                    "SELECT COALESCE(SUM(size), 0), COUNT(*) "
                    "FROM storage_chunks WHERE object_id = :oid"),
                    {"oid": row["id"]}).one()
                result.append({
                    "object_id": row["id"], "bucket": row["bucket"],
                    "key": row["object_key"],
                    "updated_at": row["updated_at"],
                    "reason": entry["reason"],
                    "enqueued_ns": entry["enqueued_ns"],
                    "chunk_count": int(chunk_count), "bytes": int(size),
                })
            return result
        rows = db.execute(
            select(objects.c.id, objects.c.bucket, objects.c.object_key,
                   objects.c.updated_at)
            .where(
                objects.c.status == "ready",
                objects.c.updated_at < cutoff,
                # Not a current head anywhere.
                not_(exists(heads.c.object_id, objects.c.id)),
                # Never delete media a dedup alias still points at.
                not_(exists_source_alias(objects.c.id)),
                # Only proven-published payloads (no staged/failed).
                exists(published_versions.c.object_id, objects.c.id),
            ).order_by(objects.c.updated_at).limit(limit)
        ).mappings().all()
        result = []
        for row in rows:
            if scope == "revoked":
                revoked = db.execute(
                    select(removed_versions.c.object_id).where(
                        removed_versions.c.object_id == row["id"])
                ).first() is not None
                if not revoked:
                    continue
            else:
                # scope == "deleted": also include every published
                # version of a key whose live head is gone or is a
                # delete marker. Historical versions of LIVE keys stay.
                live = db.execute(text(
                    "SELECT 1 FROM storage_published_versions p "
                    "JOIN storage_object_heads h "
                    "ON h.bucket = p.bucket AND h.key_hash = p.key_hash "
                    "JOIN storage_objects oh ON oh.id = h.object_id "
                    "WHERE p.object_id = :oid AND oh.status <> 'delete-marker' "
                    "LIMIT 1"), {"oid": row["id"]}
                ).first() is not None
                if live:
                    continue
            size, chunk_count = db.execute(text(
                "SELECT COALESCE(SUM(size), 0), COUNT(*) FROM storage_chunks "
                "WHERE object_id = :oid"), {"oid": row["id"]}
            ).one()
            result.append({
                "object_id": row["id"], "bucket": row["bucket"],
                "key": row["object_key"], "updated_at": row["updated_at"],
                "chunk_count": int(chunk_count), "bytes": int(size),
            })
        return result

    # -- execution -------------------------------------------------------
    async def collect(self, transport, *, scope: str,
                      min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
                      limit: int = 50, chunk_refs=None) -> dict:
        """Physically delete retained media for the given candidates.

        chunk_refs optionally carries a precomputed candidate list (the
        endpoint's dry-run preview reuses it); otherwise candidates()
        is called with the same fail-closed filters.
        """
        if self.state().get("enabled") is not True:
            raise PermissionError("Physical GC is disabled (owner gate)")
        pending = chunk_refs if chunk_refs is not None else self.candidates(
            scope=scope, min_age_seconds=min_age_seconds, limit=limit)
        report = {"collected": [], "skipped": [], "failed": []}
        for candidate in pending:
            object_id = candidate["object_id"]
            try:
                outcome = await self._collect_object(transport, object_id,
                                                     scope)
            except Exception as exc:  # per-object isolation
                report["failed"].append({
                    "object_id": object_id, "reason": str(exc)[:200]})
                continue
            if scope == "queued" and outcome in ("collected", "skipped"):
                # Drain the request: collected means done, skipped means
                # the object no longer qualifies (restored, aliased or
                # already gone) — keep only failures for retry.
                self.db.connection.execute(delete(gc_queue).where(
                    gc_queue.c.object_id == object_id))
                self.db.commit()
            report[outcome].append({
                "object_id": object_id, "bucket": candidate.get("bucket"),
                "key": candidate.get("key"),
                "reason": candidate.get("reason"),
                "chunk_count": candidate.get("chunk_count", 0)
                if outcome == "collected" else 0,
                "bytes": candidate.get("bytes", 0)
                if outcome == "collected" else 0,
            })
        return report

    async def _collect_object(self, transport, object_id: str,
                              scope: str) -> str:
        db = self.db.connection
        # Fail-closed re-verification immediately before any deletion.
        row = db.execute(
            select(objects.c.status, objects.c.bucket, objects.c.object_key)
            .where(objects.c.id == object_id)).first()
        if row is None or row[0] != "ready":
            return "skipped"
        if db.execute(select(heads.c.object_id).where(
                heads.c.object_id == object_id)).first() is not None:
            return "skipped"
        if db.execute(select(object_aliases.c.object_id).where(
                object_aliases.c.source_object_id == object_id)
                ).first() is not None:
            return "skipped"
        # Object lock (Phase C): retained or legal-held media is never
        # physically collected, even when queued.
        lock_state = db.execute(
            select(objects.c.retention_until_ns, objects.c.legal_hold)
            .where(objects.c.id == object_id)).first()
        if lock_state is not None and (
                lock_state[1]
                or (lock_state[0] is not None
                    and int(lock_state[0]) > time.time_ns())):
            return "skipped"
        try:
            intents = _send_intents_table()
            if db.execute(select(intents.c.object_id).where(
                    intents.c.object_id == object_id,
                    intents.c.message_id.is_(None))).first() is not None:
                return "skipped"
        except Exception:
            pass  # journal table absent in this deployment
        chunk_rows = db.execute(
            select(chunks.c.ordinal, chunks.c.offset, chunks.c.size,
                   chunks.c.sha256, chunks.c.account, chunks.c.chat_id,
                   chunks.c.message_id)
            .where(chunks.c.object_id == object_id)
            .order_by(chunks.c.ordinal)).all()
        if not chunk_rows:
            return "skipped"
        from .manifest import ChunkReference
        deleted_ordinals, deleted_refs, total_bytes = [], [], 0
        for ordinal, offset, size, sha256, account, chat_id, message_id \
                in chunk_rows:
            reference = ChunkReference(
                ordinal=ordinal, offset=offset, size=size, sha256=sha256,
                account=account, chat_id=chat_id, message_id=message_id)
            await transport.delete(reference)
            deleted_ordinals.append(ordinal)
            deleted_refs.append({"account": account, "chat_id": chat_id,
                                 "message_id": message_id, "size": size})
            total_bytes += int(size)
        # Telegram media is gone for these chunks; commit the SQL side.
        db.execute(delete(chunks).where(
            chunks.c.object_id == object_id,
            chunks.c.ordinal.in_(deleted_ordinals)))
        db.execute(delete(replica_chunks).where(
            replica_chunks.c.object_id == object_id))
        remaining = db.execute(text(
            "SELECT COUNT(*) FROM storage_chunks WHERE object_id = :oid"),
            {"oid": object_id}).scalar_one()
        db.execute(insert(gc_collected).values(
            object_id=object_id, bucket=row[1], object_key=row[2],
            chunk_count=len(deleted_ordinals), bytes=total_bytes,
            scope=scope, deleted_refs=json.dumps(deleted_refs),
            collected_ns=time.time_ns()))
        if not remaining:
            # Hide the physically-gone object from version history and
            # future dedup; the GC journal keeps the audit trail.
            db.execute(insert(removed_versions).values(
                object_id=object_id, removed_ns=time.time_ns()))
            db.execute(update(objects).where(
                objects.c.id == object_id).values(
                status="gc-collected"))
            # Phase J: a deferred tag journal for this version can never
            # be applied once its payload is physically gone.
            if inspect(db.engine).has_table("storage_pending_tags"):
                from teledrive.s3.tagging import (
                    delete_pending_tags_uncommitted,
                )
                delete_pending_tags_uncommitted(db, object_id)
        self.db.commit()
        return "collected"


def exists(column, value):
    from sqlalchemy import exists as _exists
    return _exists(select(column).where(column == value))


def exists_source_alias(object_id):
    from sqlalchemy import exists as _exists
    return _exists(select(object_aliases.c.object_id).where(
        object_aliases.c.source_object_id == object_id))
