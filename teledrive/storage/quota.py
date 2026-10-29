"""Per-bucket quota enforcement (TeleDrive-level; S3 has no native quota).

Quotas must be enforced by EVERY path that can add bytes to a bucket, not
just the two REST/S3 handlers that happened to call it. The API review found
that ``POST /api/v1/admin/storage/jobs`` bypassed the quota entirely: a bucket
configured for 10 bytes and 1 object accepted a 5000-byte job and published
it, so an operator or a single-scope key could make an admin-only control
ineffective.

This module is the single implementation. The web layer maps its
:class:`QuotaExceeded` to HTTP 413 and the job worker records it as a failed
job.
"""
from __future__ import annotations

import hashlib

from sqlalchemy import text


class QuotaExceeded(ValueError):
    """The upload would breach a configured bucket quota."""


def bucket_quota(conn, bucket: str) -> tuple[int | None, int | None]:
    """Return ``(max_size_bytes, max_objects)``; ``(None, None)`` when unset."""
    row = conn.connection.execute(text(
        "SELECT max_size_bytes, max_objects FROM bucket_quotas "
        "WHERE bucket = :b"), {"b": bucket}).fetchone()
    return (row[0], row[1]) if row else (None, None)


def bucket_current_usage(conn, bucket: str) -> tuple[int, int]:
    """``(object_count, total_size)`` of a bucket's CURRENT objects."""
    row = conn.connection.execute(text(
        "SELECT COUNT(o.id), COALESCE(SUM(o.size), 0) "
        "FROM storage_object_heads h "
        "JOIN storage_objects o ON o.id = h.object_id "
        "WHERE h.bucket = :b"), {"b": bucket}).fetchone()
    return (int(row[0]) if row else 0, int(row[1]) if row else 0)


def has_current_key(conn, bucket: str, key: str) -> bool:
    """True when ``key`` already has a head (an overwrite is not a new object)."""
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    row = conn.connection.execute(text(
        "SELECT COUNT(*) FROM storage_object_heads "
        "WHERE bucket = :b AND key_hash = :kh"),
        {"b": bucket, "kh": key_hash}).scalar()
    return bool(row)


def enforce_bucket_quota(conn, bucket: str, key: str,
                         incoming_size: int) -> None:
    """Raise :class:`QuotaExceeded` when the upload would breach the quota.

    Overwriting an existing key does not count against the object limit
    (the object already exists), but it does count against the size limit
    through the head replacement performed later.
    """
    max_size, max_objects = bucket_quota(conn, bucket)
    if max_size is None and max_objects is None:
        return
    if max_size is not None:
        _count, current_size = bucket_current_usage(conn, bucket)
        if current_size + incoming_size > max_size:
            raise QuotaExceeded("Upload exceeds bucket quota (max size)")
    if max_objects is not None:
        count, _size = bucket_current_usage(conn, bucket)
        if not has_current_key(conn, bucket, key) and count >= max_objects:
            raise QuotaExceeded("Upload exceeds bucket quota (max objects)")
