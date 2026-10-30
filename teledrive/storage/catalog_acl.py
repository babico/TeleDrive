"""Bucket and object ACL grants for the catalog.

``BucketAclMixin`` is mixed into ``BucketCatalog``; it relies on ``self.db``
and on the class's ``_keyhash``/``list_buckets`` helpers, and never creates a
table of its own (the schema coordinator owns all DDL).
"""
from __future__ import annotations

from sqlalchemy import delete, insert, select

from .catalog_tables import bucket_acl_grants, object_acl_grants


class BucketAclMixin:
    # -- ACL grants (Phase D) --------------------------------------------
    def bucket_acl(self, bucket: str) -> tuple[str | None, list[tuple[str, str]]]:
        """Stored (owner access key, grants). ([], None owner) when the
        bucket has never had an ACL written — the unrestricted baseline."""
        rows = self.db.connection.execute(
            select(bucket_acl_grants.c.grantee,
                   bucket_acl_grants.c.permission,
                   bucket_acl_grants.c.owner)
            .where(bucket_acl_grants.c.bucket == bucket)
            .order_by(bucket_acl_grants.c.grantee,
                      bucket_acl_grants.c.permission)).all()
        if not rows:
            return None, []
        return rows[0][2], [(row[0], row[1]) for row in rows]

    def set_bucket_acl(self, bucket: str, owner: str,
                       grants: list[tuple[str, str]]) -> None:
        """Replace the bucket ACL. The owner always retains an implicit
        FULL_CONTROL row (AWS semantics); grant rows are deduplicated."""
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        combined = set(grants)
        combined.add((owner, "FULL_CONTROL"))
        with self.db.connection.begin_nested():
            self.db.connection.execute(
                delete(bucket_acl_grants).where(
                    bucket_acl_grants.c.bucket == bucket))
            self.db.connection.execute(insert(bucket_acl_grants), [
                {"bucket": bucket, "grantee": grantee, "permission": perm,
                 "owner": owner}
                for grantee, perm in sorted(combined)
            ])
        self.db.commit()

    def object_acl(self, bucket: str, key: str) -> tuple[str | None, list[tuple[str, str]]]:
        digest = self._keyhash(key)
        rows = self.db.connection.execute(
            select(object_acl_grants.c.grantee,
                   object_acl_grants.c.permission,
                   object_acl_grants.c.owner)
            .where(object_acl_grants.c.bucket == bucket,
                   object_acl_grants.c.key_hash == digest)
            .order_by(object_acl_grants.c.grantee,
                      object_acl_grants.c.permission)).all()
        if not rows:
            return None, []
        return rows[0][2], [(row[0], row[1]) for row in rows]

    def set_object_acl(self, bucket: str, key: str, owner: str,
                       grants: list[tuple[str, str]]) -> None:
        """Replace the ACL of one exact object key. Grants on this key
        only ever affect this key — never siblings, never the bucket."""
        if bucket not in self.list_buckets():
            raise FileNotFoundError("Bucket does not exist")
        digest = self._keyhash(key)
        combined = set(grants)
        combined.add((owner, "FULL_CONTROL"))
        with self.db.connection.begin_nested():
            self.db.connection.execute(
                delete(object_acl_grants).where(
                    object_acl_grants.c.bucket == bucket,
                    object_acl_grants.c.key_hash == digest))
            self.db.connection.execute(insert(object_acl_grants), [
                {"bucket": bucket, "key_hash": digest, "grantee": grantee,
                 "permission": perm, "owner": owner}
                for grantee, perm in sorted(combined)
            ])
        self.db.commit()

    def acl_grants_for(self, bucket: str, key: str | None) -> tuple[list, list]:
        """(bucket_rows, object_rows) for the ACL intersection gate:
        every stored row (any grantee) for the bucket, and for the
        exact object key when given. Object rows are looked up by the
        key digest — grants only ever match their exact key."""
        bucket_rows = self.db.connection.execute(
            select(bucket_acl_grants.c.grantee,
                   bucket_acl_grants.c.permission)
            .where(bucket_acl_grants.c.bucket == bucket)).all()
        object_rows: list = []
        if key is not None:
            object_rows = self.db.connection.execute(
                select(object_acl_grants.c.grantee,
                       object_acl_grants.c.permission)
                .where(object_acl_grants.c.bucket == bucket,
                       object_acl_grants.c.key_hash == self._keyhash(key))
            ).all()
        return list(bucket_rows), object_rows
