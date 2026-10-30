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
                            limit: int = 10000) -> tuple[list[tuple[str, int]], bool]:
        """SQL-only keyset page; return creation dates and a has-next marker.

        LIKE patterns are escaped to preserve literal S3 prefixes. SQL never
        materializes all matching buckets to serve a single bounded page.
        """
        if not 1 <= limit <= 10000:
            raise ValueError("Invalid bucket page limit")
        # Bucket names are strictly lowercase ASCII. SQLite LIKE can compare
        # case-insensitively, so uppercase prefixes can never match.
        if prefix != prefix.lower():
            return [], False
        statement = select(buckets.c.name, buckets.c.created_at)
        if prefix:
            statement = statement.where(buckets.c.name.startswith(prefix, autoescape=True))
        if after:
            statement = statement.where(buckets.c.name > after)
        rows = self.db.connection.execute(
            statement.order_by(buckets.c.name).limit(limit + 1),
        ).all()
        return [(str(r[0]), int(r[1])) for r in rows[:limit]], len(rows) > limit

    def delete_bucket(self, name: str) -> None:
        """Refuse buckets with any current or historical manifests."""
        existing = self.db.connection.execute(
            select(buckets.c.name).where(buckets.c.name == name)
        ).first()
        if existing is None:
            raise FileNotFoundError("Bucket does not exist")
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
        # A physically empty bucket can be deleted even if its tag set is
        # nonempty; do not leave dangling metadata across SQL backends.
        if inspect(self.db.engine).has_table("storage_bucket_tags"):
            self.db.connection.execute(
                text("DELETE FROM storage_bucket_tags WHERE bucket = :bucket"),
                {"bucket": name},
            )
        if inspect(self.db.engine).has_table("storage_bucket_lifecycle"):
            self.db.connection.execute(
                text("DELETE FROM storage_bucket_lifecycle WHERE bucket = :bucket"),
                {"bucket": name},
            )
        if inspect(self.db.engine).has_table("storage_bucket_cors"):
            self.db.connection.execute(
                text("DELETE FROM storage_bucket_cors WHERE bucket = :bucket"),
                {"bucket": name},
            )
        # Phase J: never leave a deferred tag journal behind. Rows owned by
        # this bucket are removed explicitly; orphan rows (their manifest is
        # already gone) are equally unreclaimable and removed as well.
        if inspect(self.db.engine).has_table("storage_pending_tags"):
            self.db.connection.execute(text(
                "DELETE FROM storage_pending_tags WHERE object_id IN "
                "(SELECT id FROM storage_objects WHERE bucket = :bucket) "
                "OR object_id NOT IN (SELECT id FROM storage_objects)"
            ), {"bucket": name})
        # Phase I: deleting a bucket must not leave website state or a
        # public_read gate behind. The bucket row is removed below, but
        # clear both explicitly so the intent is local and testable.
        if inspect(self.db.engine).has_table("storage_website_configs"):
            self.db.connection.execute(
                text("DELETE FROM storage_website_configs WHERE bucket = :bucket"),
                {"bucket": name},
            )
        # Phase O2: object annotations are per-object rows with no bucket
        # column; remove rows for this bucket's objects and any orphan left
        # by an already-reclaimed manifest.
        if inspect(self.db.engine).has_table("storage_object_annotations"):
            self.db.connection.execute(text(
                "DELETE FROM storage_object_annotations WHERE object_id IN "
                "(SELECT id FROM storage_objects WHERE bucket = :bucket) "
                "OR object_id NOT IN (SELECT id FROM storage_objects)"
            ), {"bucket": name})
        # Phase O3: a deleted bucket must not leave a metadata configuration
        # or journal rows behind (the journal is the bucket's local table).
        if inspect(self.db.engine).has_table("storage_metadata_journal"):
            self.db.connection.execute(text(
                "DELETE FROM storage_metadata_journal WHERE bucket = :bucket"
            ), {"bucket": name})
        if inspect(self.db.engine).has_table("storage_metadata_configs"):
            self.db.connection.execute(text(
                "DELETE FROM storage_metadata_configs WHERE bucket = :bucket"
            ), {"bucket": name})
        # Every remaining governance surface keyed by the bucket NAME must
        # be cleared too, or re-creating a bucket with the same name silently
        # revives the previous one's rights and settings: an old bucket
        # policy (including a Deny), ABAC gates, an SSE default, replication
        # rules, tiering rules (which make new objects answer 403 until
        # restored), webhook/logging targets and report schedules. Quotas,
        # account pins and public share links have the same problem -- a
        # stale share URL would keep working against the new bucket's keys.
        # Object-keyed rows (ACL grants) are cleared here as well.
        for table, column in (
            ("storage_bucket_acl_grants", "bucket"),
            ("storage_bucket_policy", "bucket"),
            ("storage_bucket_abac", "bucket"),
            ("storage_bucket_encryption", "bucket"),
            ("storage_replication_configs", "bucket"),
            ("storage_tiering_configs", "bucket"),
            ("storage_report_configs", "bucket"),
            ("storage_notification_configs", "bucket"),
            ("storage_logging_configs", "bucket"),
            ("bucket_quotas", "bucket"),
            ("bucket_account_pins", "bucket"),
            ("share_links", "bucket"),
        ):
            if inspect(self.db.engine).has_table(table):
                # table/column come from the hardcoded tuple above, never
                # request input; the value stays a bound parameter.
                self.db.connection.execute(text(
                    f"DELETE FROM {table} WHERE {column} = :bucket"  # nosec B608
                ), {"bucket": name})
        # Object-keyed ACL grants have no bucket column of their own.
        if inspect(self.db.engine).has_table("storage_object_acl_grants"):
            self.db.connection.execute(text(
                "DELETE FROM storage_object_acl_grants WHERE bucket = :bucket"
            ), {"bucket": name})
        self.db.connection.execute(
            update(buckets).where(buckets.c.name == name).values(public_read=False))
        self.db.connection.execute(delete(buckets).where(buckets.c.name == name))
        self.db.commit()
