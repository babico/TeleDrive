"""Table declarations for the bucket and current-object catalog.

These are pure declarations. The schema coordinator in
``teledrive.storage.schema`` is the only creator of these tables; no mixin or
store constructor may issue DDL for them.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import (
    BigInteger, Boolean, Column, ForeignKey, Integer, MetaData, String,
    Table, Index, false,
)

from .manifest import StoredObject

catalog_metadata = MetaData()
buckets = Table(
    "storage_buckets", catalog_metadata,
    Column("name", String(63), primary_key=True),
    Column("created_at", BigInteger, nullable=False),
    # Phase B of the metadata parity plan: AWS-shaped bucket versioning
    # states. Pre-existing deployments get the column via a defensive
    # ALTER (see ensure_versioning_column).
    Column("versioning_state", String(16), nullable=False,
           server_default="Enabled"),
    # Phase C: object lock. One-way enable (AWS semantics): once a
    # bucket has object lock enabled it cannot be disabled.
    Column("object_lock_enabled", Boolean, nullable=False,
           server_default=false()),
    Column("object_lock_default_mode", String(16)),
    Column("object_lock_default_days", Integer),
    # Phase E: public access block (four booleans stored as JSON,
    # default all-true like AWS) and the persisted object ownership
    # model (BucketOwnerEnforced — the one real model here).
    # VARCHAR rather than TEXT: MySQL rejects DEFAULT on TEXT/BLOB
    # columns, and this column carries a real server default. The JSON
    # payload is ~120 characters, so 512 is ample.
    Column("public_access_block", String(512), nullable=False,
           server_default='{"BlockPublicAcls": true, '
           '"IgnorePublicAcls": true, "BlockPublicPolicy": true, '
           '"RestrictPublicBuckets": true}'),
    Column("object_ownership", String(32), nullable=False,
           server_default="BucketOwnerEnforced"),
    # Phase I: website hosting is public only after an explicit, audited
    # admin decision. It defaults to FALSE and is never implied by a
    # stored website configuration.
    Column("public_read", Boolean, nullable=False,
           server_default=false()),
)
object_acl_grants = Table(
    "storage_object_acl_grants", catalog_metadata,
    Column("bucket", String(63), primary_key=True),
    Column("key_hash", String(64), primary_key=True),
    Column("grantee", String(64), primary_key=True),
    Column("permission", String(16), primary_key=True),
    Column("owner", String(64), nullable=False),
)
bucket_acl_grants = Table(
    "storage_bucket_acl_grants", catalog_metadata,
    Column("bucket", String(63), primary_key=True),
    Column("grantee", String(64), primary_key=True),
    Column("permission", String(16), primary_key=True),
    Column("owner", String(64), nullable=False),
)
heads = Table(
    "storage_object_heads", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"), primary_key=True),
    Column("key_hash", String(64), primary_key=True),
    Column("object_id", String(36), nullable=False),
    Column("generation", BigInteger, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
)
published_versions = Table(
    "storage_published_versions", catalog_metadata,
    Column("object_id", String(36), primary_key=True),
    Column("bucket", String(63), nullable=False),
    Column("key_hash", String(64), nullable=False),
    Column("committed_ns", BigInteger, nullable=False),
)
# Logical S3 VersionId deletion revokes visibility but NEVER removes Telegram
# media, manifests or aliases. Existing deployments receive an additive table.
removed_versions = Table(
    "storage_removed_versions", catalog_metadata,
    Column("object_id", String(36), primary_key=True),
    Column("removed_ns", BigInteger, nullable=False),
)
# Physical GC asks "is this object a head anywhere?" for every candidate,
# via EXISTS(heads.object_id == objects.id). The heads primary key is
# (bucket, key_hash), so that probe scanned the whole table.
Index("ix_storage_object_heads_object", heads.c.object_id)
Index("ix_storage_published_versions_key",
      published_versions.c.bucket, published_versions.c.key_hash,
      published_versions.c.committed_ns)


@dataclass(frozen=True)
class ObjectHead:
    item: StoredObject
    generation: int
