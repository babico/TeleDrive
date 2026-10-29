"""Shared per-request state for the S3 verb-family handlers.

Move-only extraction from ``web/s3.py`` (handoff 01, step 1).  The
construction site stays in ``web/s3._handle`` because it is interleaved with
routing-flag computation.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from teledrive.db import Database
from teledrive.s3.credentials import S3CredentialStore
from teledrive.storage.catalog import BucketCatalog


@dataclass
class _S3RequestContext:
    """Shared per-request state for the extracted S3 verb-family handlers.

    ``_handle`` computes routing flags, authentication and the shared
    stores once, then delegates to a focused handler with this context.
    Handlers raise the same exceptions and return the same responses as
    the original inline code; ``_handle`` maps exceptions to S3 errors.
    """
    request: Request
    db: Database
    store: S3CredentialStore
    master: bytes
    bucket: str
    key: str
    owner: str = ""
    catalog: BucketCatalog | None = None
    inline_tags: list[tuple[str, str]] | None = None
    checksum_mode: str | None = None
    retain: bool = False
    # Routing flags, computed by _handle before delegation:
    multi_delete: bool = False
    mpu_bucket_list: bool = False
    mpu_start: bool = False
    mpu_id: str | None = None
    mpu_part: bool = False
    mpu_complete: bool = False
    mpu_abort: bool = False
    mpu_list: bool = False
    is_version_read: bool = False
    is_version_delete: bool = False
    is_version_listing: bool = False
    is_object_attributes: bool = False
    is_object_tagging: bool = False
    is_version_tagging: bool = False
    is_object_annotation: bool = False
    is_bucket_tagging: bool = False
    is_bucket_cors: bool = False
    is_bucket_versioning: bool = False
    is_public_access_block: bool = False
    is_bucket_lifecycle: bool = False
    is_bucket_policy_status: bool = False
    is_bucket_policy: bool = False
    is_bucket_ownership: bool = False
    is_bucket_abac: bool = False
    is_bucket_replication: bool = False
    is_bucket_website: bool = False
    is_bucket_notification: bool = False
    is_bucket_logging: bool = False
    is_bucket_encryption: bool = False
    is_object_encryption: bool = False
    report_kind: str | None = None
    is_bucket_tiering: bool = False
    metadata_selector: str | None = None
