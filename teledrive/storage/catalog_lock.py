"""Object lock, retention, legal hold and access counters for the catalog.

``BucketLockMixin`` is mixed into ``BucketCatalog``; it relies on ``self.db``
and ``self.manifests`` and never creates a table of its own (the schema
coordinator owns all DDL).
"""
from __future__ import annotations

import time

from sqlalchemy import select, update

from .catalog_tables import buckets
from .manifest import objects


class BucketLockMixin:
    # -- object lock (Phase C) -------------------------------------------
    def object_lock_config(self, bucket: str) -> dict | None:
        """(enabled, default_mode, default_days) or None when unset."""
        row = self.db.connection.execute(
            select(buckets.c.object_lock_enabled,
                   buckets.c.object_lock_default_mode,
                   buckets.c.object_lock_default_days)
            .where(buckets.c.name == bucket)).first()
        if row is None:
            raise FileNotFoundError("Bucket does not exist")
        if not row[0]:
            return None
        return {"default_mode": row[1], "default_days": row[2]}

    def set_object_lock_config(self, bucket: str, *, mode: str,
                               days: int | None) -> None:
        """One-way enable (AWS): once enabled, object lock cannot be
        disabled; the default retention may only be tightened."""
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("Invalid object lock mode")
        if days is not None and not 1 <= days <= 3650:
            raise ValueError("Default retention days outside 1..3650")
        current = self.db.connection.execute(
            select(buckets.c.object_lock_enabled,
                   buckets.c.object_lock_default_days)
            .where(buckets.c.name == bucket)).first()
        if current is None:
            raise FileNotFoundError("Bucket does not exist")
        if current[0] and days is not None and current[1] is not None \
                and days < int(current[1]):
            raise ValueError(
                "Object lock default retention can only be extended")
        self.db.connection.execute(
            update(buckets).where(buckets.c.name == bucket).values(
                object_lock_enabled=True,
                object_lock_default_mode=mode,
                object_lock_default_days=days))
        self.db.commit()

    def object_lock_state(self, object_id: str) -> dict:
        row = self.db.connection.execute(
            select(objects.c.retention_mode, objects.c.retention_until_ns,
                   objects.c.legal_hold)
            .where(objects.c.id == object_id)).first()
        if row is None:
            raise FileNotFoundError("Object does not exist")
        return {"mode": row[0], "retain_until_ns": row[1],
                "legal_hold": bool(row[2])}

    def is_locked(self, object_id: str) -> bool:
        state = self.object_lock_state(object_id)
        now_ns = time.time_ns()
        return (state["legal_hold"]
                or (state["retain_until_ns"] is not None
                    and int(state["retain_until_ns"]) > now_ns))

    # -- access tracking + Intelligent-Tiering gate (Phase N5) -----------
    def object_read_state(self, object_id: str, *, now_ns: int | None = None) -> dict:
        """Return the access gate for one immutable object version.

        ``archived`` is true for ARCHIVE_ACCESS/DEEP_ARCHIVE_ACCESS unless a
        RestoreObject window is still open. The Telegram chunks always exist;
        this is a catalog-level read gate, never a different storage medium.
        """
        row = self.db.connection.execute(
            select(objects.c.storage_class, objects.c.restore_until_ns,
                   objects.c.access_count, objects.c.last_accessed_ns)
            .where(objects.c.id == object_id)).first()
        if row is None:
            raise FileNotFoundError("Object does not exist")
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        storage_class = row[0] or "STANDARD"
        restore_until = None if row[1] is None else int(row[1])
        archived = storage_class in ("ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS")
        return {
            "storage_class": storage_class,
            "restore_until_ns": restore_until,
            "restored": bool(archived and restore_until is not None
                             and restore_until > now_ns),
            "archived": bool(archived and not (
                restore_until is not None and restore_until > now_ns)),
            "access_count": int(row[2] or 0),
            "last_accessed_ns": (None if row[3] is None else int(row[3])),
        }

    def record_object_access(self, object_id: str, *,
                             now_ns: int | None = None) -> None:
        """Atomically count a successful GetObject/HeadObject.

        One UPDATE computes both fields from the stored row, so concurrent
        readers never lose a count or resurrect an older timestamp.
        """
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        self.db.connection.execute(
            update(objects).where(objects.c.id == object_id).values(
                access_count=objects.c.access_count + 1,
                last_accessed_ns=now_ns))
        self.db.commit()

    def object_access_stats(self, bucket: str, *, limit: int = 100,
                            offset: int = 0) -> list[dict]:
        """Small operator accessor for the Phase N5 counters."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid access statistics limit")
        if type(offset) is not int or offset < 0:
            raise ValueError("Invalid access statistics offset")
        rows = self.db.connection.execute(
            select(objects.c.id, objects.c.object_key, objects.c.storage_class,
                   objects.c.access_count, objects.c.last_accessed_ns,
                   objects.c.restore_until_ns)
            .where(objects.c.bucket == bucket, objects.c.status == "ready")
            .order_by(objects.c.object_key, objects.c.id)
            .limit(limit).offset(offset)).mappings().all()
        return [{
            "object_id": row["id"], "key": row["object_key"],
            "storage_class": row["storage_class"] or "STANDARD",
            "access_count": int(row["access_count"] or 0),
            "last_accessed_ns": (None if row["last_accessed_ns"] is None
                                 else int(row["last_accessed_ns"])),
            "restore_until_ns": (None if row["restore_until_ns"] is None
                                 else int(row["restore_until_ns"])),
        } for row in rows]

    def set_retention(self, object_id: str, *, mode: str,
                      until_ns: int) -> None:
        """COMPLIANCE retention is extend-only (AWS immutability)."""
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("Invalid retention mode")
        current = self.object_lock_state(object_id)
        if (current["mode"] == "COMPLIANCE"
                and current["retain_until_ns"] is not None
                and int(until_ns) < int(current["retain_until_ns"])):
            raise ValueError(
                "COMPLIANCE retention can only be extended")
        self.db.connection.execute(
            update(objects).where(objects.c.id == object_id).values(
                retention_mode=mode, retention_until_ns=until_ns))
        self.db.commit()

    def clear_retention(self, object_id: str) -> None:
        current = self.object_lock_state(object_id)
        if current["mode"] == "COMPLIANCE" and current["retain_until_ns"] \
                and int(current["retain_until_ns"]) > time.time_ns():
            raise ValueError(
                "Active COMPLIANCE retention cannot be removed")
        self.db.connection.execute(
            update(objects).where(objects.c.id == object_id).values(
                retention_mode=None, retention_until_ns=None))
        self.db.commit()

    def set_legal_hold(self, object_id: str, held: bool) -> None:
        self.db.connection.execute(
            update(objects).where(objects.c.id == object_id).values(
                legal_hold=bool(held)))
        self.db.commit()

    def apply_default_lock(self, object_id: str) -> None:
        """At publish time: apply the bucket's default retention."""
        item = self.manifests.get(object_id)
        config = self.object_lock_config(item.bucket)
        if config and config.get("default_days"):
            self.db.connection.execute(
                update(objects).where(objects.c.id == object_id).values(
                    retention_mode=config["default_mode"],
                    retention_until_ns=time.time_ns()
                    + int(config["default_days"]) * 86400 * 1_000_000_000))
            self.db.commit()
