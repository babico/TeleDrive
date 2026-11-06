"""Bucket administration mixin for the storage catalog.

Extracted verbatim from ``catalog.py`` (move-only).  Every method still uses
the assembled ``BucketCatalog``'s ``self.db``; nothing here creates tables or
opens its own connection.
"""
from __future__ import annotations

import json

from sqlalchemy import delete, insert, inspect, select, text, update
from sqlalchemy.exc import IntegrityError

from .catalog_tables import buckets
from .manifest import objects


class BucketAdminMixin:
    def create_bucket(self, name: str, now: int) -> None:
        self.validate_bucket(name)
        try:
            with self.db.connection.begin_nested():
                self.db.connection.execute(insert(buckets).values(name=name, created_at=now))
        except IntegrityError as exc:
            raise ValueError("Bucket already exists") from exc
        self.db.commit()

    # -- versioning state (Phase B) --------------------------------------
    def versioning_state(self, bucket: str) -> str:
        """'Enabled' (default, versioned-by-default store) or 'Suspended'."""
        state = self.db.connection.execute(
            select(buckets.c.versioning_state).where(
                buckets.c.name == bucket)).scalar_one_or_none()
        return state or "Enabled"

    def set_versioning(self, bucket: str, state: str) -> None:
        if state not in ("Enabled", "Suspended"):
            raise ValueError("Invalid versioning state")
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        changed = self.db.connection.execute(
            update(buckets).where(buckets.c.name == bucket)
            .values(versioning_state=state))
        if changed.rowcount != 1:
            raise FileNotFoundError("Bucket does not exist")
        self.db.commit()

    # -- public access block & ownership (Phase E) ----------------------
    PAB_FIELDS = ("BlockPublicAcls", "IgnorePublicAcls",
                  "BlockPublicPolicy", "RestrictPublicBuckets")

    def public_access_block(self, bucket: str) -> dict:
        """The bucket's persisted four-flag PAB (default all-true)."""
        raw = self.db.connection.execute(
            select(buckets.c.public_access_block)
            .where(buckets.c.name == bucket)).scalar_one_or_none()
        if raw is None:
            raise FileNotFoundError("Bucket does not exist")
        try:
            flags = json.loads(raw)
        except (TypeError, ValueError):
            flags = {}
        return {field: bool(flags.get(field, True))
                for field in self.PAB_FIELDS}

    def set_public_access_block(self, bucket: str, flags: dict) -> None:
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        clean = {}
        for field in self.PAB_FIELDS:
            value = flags.get(field)
            if not isinstance(value, bool):
                raise ValueError(f"PAB field {field} must be a boolean")
            clean[field] = value
        self.db.connection.execute(
            update(buckets).where(buckets.c.name == bucket).values(
                public_access_block=json.dumps(clean)))
        self.db.commit()

    def object_ownership(self, bucket: str) -> str:
        """The persisted object ownership model.  BucketOwnerEnforced
        ignores object ACL grants; ObjectWriter and BucketOwnerPreferred
        apply them (the latter also auto-grants the owner on
        ``bucket-owner-full-control`` uploads)."""
        value = self.db.connection.execute(
            select(buckets.c.object_ownership)
            .where(buckets.c.name == bucket)).scalar_one_or_none()
        if value is None:
            raise FileNotFoundError("Bucket does not exist")
        return value or "BucketOwnerEnforced"

    def set_object_ownership(self, bucket: str, model: str) -> None:
        if model not in ("BucketOwnerEnforced", "ObjectWriter",
                         "BucketOwnerPreferred"):
            raise ValueError("Invalid object ownership model")
        changed = self.db.connection.execute(
            update(buckets).where(buckets.c.name == bucket)
            .values(object_ownership=model))
        if changed.rowcount != 1:
            raise FileNotFoundError("Bucket does not exist")
        self.db.commit()

    def clear_object_ownership(self, bucket: str) -> None:
        """DeleteBucketOwnershipControls returns to BucketOwnerEnforced."""
        self.set_object_ownership(bucket, "BucketOwnerEnforced")

    def clear_public_access_block(self, bucket: str) -> None:
        """DeletePublicAccessBlock → the all-true default.

        The Phase E schema stores the four flags as one JSON column on
        the bucket rather than a separate row; clearing it to the
        documented default is the same state a fresh bucket has.
        """
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        default = json.dumps({field: True for field in self.PAB_FIELDS})
        self.db.connection.execute(
            update(buckets).where(buckets.c.name == bucket).values(
                public_access_block=default))
        self.db.commit()

    def public_read(self, bucket: str) -> bool:
        """The website public-read gate (default FALSE)."""
        value = self.db.connection.execute(
            select(buckets.c.public_read)
            .where(buckets.c.name == bucket)).scalar_one_or_none()
        if value is None:
            raise FileNotFoundError("Bucket does not exist")
        return bool(value)

    def list_buckets(self) -> list[str]:
        return list(self.db.connection.execute(select(buckets.c.name).order_by(buckets.c.name)).scalars())

    def list_bucket_records(self, *, prefix: str = "", after: str = "",
                            limit: int = 10000,
                            bucket_type: str = "general",
                            ) -> tuple[list[tuple[str, int]], bool]:
        """SQL-only keyset page; return creation dates and a has-next marker.

        LIKE patterns are escaped to preserve literal S3 prefixes. SQL never
        materializes all matching buckets to serve a single bounded page.
        ``bucket_type`` separates the two namespaces that share this table:
        ListBuckets reads ``general`` rows only, ListDirectoryBuckets reads
        ``directory`` rows through its own store
        (teledrive.s3.directory_buckets), and neither ever leaks the other.
        """
        if not 1 <= limit <= 10000:
            raise ValueError("Invalid bucket page limit")
        # Bucket names are strictly lowercase ASCII. SQLite LIKE can compare
        # case-insensitively, so uppercase prefixes can never match.
        if prefix != prefix.lower():
            return [], False
        statement = select(buckets.c.name, buckets.c.created_at).where(
            buckets.c.bucket_type == bucket_type)
        if prefix:
            statement = statement.where(buckets.c.name.startswith(prefix, autoescape=True))
        if after:
            statement = statement.where(buckets.c.name > after)
        rows = self.db.connection.execute(
            statement.order_by(buckets.c.name).limit(limit + 1),
        ).all()
        return [(str(r[0]), int(r[1])) for r in rows[:limit]], len(rows) > limit

    def delete_bucket(self, name: str) -> None:
        """Delete an empty bucket and every configuration row it owns.

        Every bucket-name-keyed configuration table carries an
        ``ON DELETE CASCADE`` foreign key to ``storage_buckets`` (schema
        step ``bucket_fk_cascade``), so the single guarded DELETE below
        removes tags, lifecycle, CORS, website, metadata journal/config,
        bucket/object ACL grants, policy, ABAC, encryption, replication,
        tiering, report, notification, logging, quota, account-pin and
        share rows atomically.  That closes the old orphan window: a
        configuration write that passed its existence check in an earlier
        transaction can no longer commit a row after the sweep, because
        its INSERT now fails on the same foreign key instead of creating
        an orphan for a deleted bucket.
        """
        existing = self.db.connection.execute(
            select(buckets.c.name, buckets.c.created_at).where(
                buckets.c.name == name)
        ).first()
        if existing is None:
            raise FileNotFoundError("Bucket does not exist")
        # Pin the exact row this delete validated. A concurrent create of
        # the same name must never be removed by this call's stale
        # conclusion: the final DELETE below matches created_at too, so a
        # re-created bucket survives and this delete observes it is gone.
        created_at = int(existing[1])
        history = self.db.connection.execute(
            select(objects.c.id).where(objects.c.bucket == name).limit(1)
        ).first()
        # A bucket with initiated multipart uploads must not disappear, even
        # before the first part is uploaded. Retain all abort/completion
        # history until a verified lifecycle GC can safely remove it.
        if inspect(self.db.engine).has_table("storage_multipart_uploads"):
            mpu_history = self.db.connection.execute(
                text("SELECT id FROM storage_multipart_uploads WHERE bucket = :bucket LIMIT 1"),
                {"bucket": name},
            ).first()
            if mpu_history is not None:
                raise ValueError("Bucket has multipart history; safe GC required")
        if history is not None:
            raise ValueError("Bucket has object history; safe physical GC required")
        # Object-keyed rows have no bucket column and therefore no bucket
        # cascade; remove those of this bucket's objects (and any orphan
        # left by an already-reclaimed manifest) explicitly.
        if inspect(self.db.engine).has_table("storage_pending_tags"):
            self.db.connection.execute(text(
                "DELETE FROM storage_pending_tags WHERE object_id IN "
                "(SELECT id FROM storage_objects WHERE bucket = :bucket) "
                "OR object_id NOT IN (SELECT id FROM storage_objects)"
            ), {"bucket": name})
        if inspect(self.db.engine).has_table("storage_object_annotations"):
            self.db.connection.execute(text(
                "DELETE FROM storage_object_annotations WHERE object_id IN "
                "(SELECT id FROM storage_objects WHERE bucket = :bucket) "
                "OR object_id NOT IN (SELECT id FROM storage_objects)"
            ), {"bucket": name})
        # Delete the bucket row LAST, guarded by created_at: the cascade
        # removes the name-keyed configuration atomically with it, and a
        # bucket re-created between the checks above and this statement is
        # left untouched instead of being deleted by a stale conclusion.
        removed = self.db.connection.execute(delete(buckets).where(
            buckets.c.name == name, buckets.c.created_at == created_at))
        if not removed.rowcount:
            self.db.connection.rollback()
            raise FileNotFoundError("Bucket does not exist")
        self.db.commit()
