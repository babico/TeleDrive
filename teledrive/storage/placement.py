"""Bucket→account placement context.

The transport's account selection runs deep below the engine call that
knows the bucket. Threading the bucket through every transport signature
would break the transport interface for every implementation and test
double, so the engine publishes the current upload bucket in a
ContextVar instead: isolated per asyncio task, set for the duration of
one object's upload, read by the routing preference.
"""
from __future__ import annotations

import contextvars

_current_bucket: contextvars.ContextVar[str | None] = (
    contextvars.ContextVar("teledrive_upload_bucket", default=None))


def set_upload_bucket(bucket: str):
    """Publish the bucket being uploaded; returns the reset token."""
    return _current_bucket.set(bucket)


def reset_upload_bucket(token) -> None:
    _current_bucket.reset(token)


def current_upload_bucket() -> str | None:
    return _current_bucket.get()
