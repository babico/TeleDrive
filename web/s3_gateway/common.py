"""Shared S3 gateway helpers.

Move-only extraction from ``web/s3.py`` (handoff 01, step 4).
"""
from __future__ import annotations

from fastapi.responses import Response

from web.app import _enforce_bucket_quota
from web.s3_gateway.xml import _error


def storage_transport(db):
    """Resolve the transport through ``web.s3``.

    ``tests/s3`` monkeypatches ``gateway.storage_transport`` (the attribute on
    the ``web.s3`` module).  Extracted handlers must keep resolving that name
    at call time, exactly like the original free-global lookup did.
    """
    from web import s3

    return s3.storage_transport(db)


def _quota_guard(db, bucket: str, key: str, size: int) -> Response | None:
    """Enforce TeleDrive per-bucket quotas on S3-path uploads.

    Returns an S3-style 413 error response when the upload would exceed the
    configured quota, or None when the upload may proceed. The REST upload
    path enforces the same policy inside web.app.
    """
    from fastapi import HTTPException as _HTTPException
    try:
        _enforce_bucket_quota(db, bucket, key, size)
    except _HTTPException as exc:
        return _error("EntityTooLarge", str(exc.detail), 413)
    return None
