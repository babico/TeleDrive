# 05a — catalog mixins, part 1 (steps 1–3)

Read `05-split-catalog.md` first. This handoff covers only the first three
steps of that plan. The remaining two mixins are for the next agent.

## State on arrival

The working tree was clean and there was **no** stray
`teledrive/storage/catalog_lock.py`. Steps 1 and 2 had already landed on
`main` before this session, as move-only commits:

- `4de96c1 refactor(storage): move catalog table declarations to catalog_tables.py`
- `bf058d7 refactor(storage): extract BucketAclMixin from BucketCatalog`

They were re-verified here, not rewritten. Step 3 is the new commit:

- `9421426 refactor(storage): extract BucketLockMixin from BucketCatalog`

All three are move-only: no test, call site or SQL changed.

## What moved

### `teledrive/storage/catalog_tables.py` (step 1, already landed)

Every `Table`/`Index` declaration from the old `catalog.py`, verbatim:

- `catalog_metadata`, `buckets`, `object_acl_grants`, `bucket_acl_grants`,
  `heads`, `published_versions`, `removed_versions`
- `Index("ix_storage_object_heads_object", ...)`,
  `Index("ix_storage_published_versions_key", ...)`
- the frozen `ObjectHead` dataclass

No DDL was added. `teledrive/storage/schema.py` remains the only creator.

### `teledrive/storage/catalog_acl.py` (step 2, already landed)

`BucketAclMixin`, containing verbatim:

`bucket_acl`, `set_bucket_acl`, `object_acl`, `set_object_acl`,
`acl_grants_for`.

### `teledrive/storage/catalog_lock.py` (step 3, this session)

`BucketLockMixin`, containing verbatim, in the original order:

`object_lock_config`, `set_object_lock_config`, `object_lock_state`,
`is_locked`, `object_read_state`, `record_object_access`,
`object_access_stats`, `set_retention`, `clear_retention`, `set_legal_hold`,
`apply_default_lock` (the whole old `# -- object lock (Phase C)` and
`# -- access tracking + Intelligent-Tiering gate (Phase N5)` block).

Imports are exactly what the block uses: `time`, SQLAlchemy `select`/`update`,
`catalog_tables.buckets`, `manifest.objects`. The mixin creates no table.

`BucketCatalog` is now:

```python
class BucketCatalog(BucketAclMixin, BucketLockMixin):
```

`_keyhash` and `validate_bucket` remain staticmethods on `BucketCatalog`, as
required by `copy.py`, `multipart.py` and the ACL mixin.

## Exact re-export block in `catalog.py`

```python
from .catalog_acl import BucketAclMixin
from .catalog_lock import BucketLockMixin
from .catalog_tables import (
    ObjectHead, bucket_acl_grants, buckets, catalog_metadata, heads,
    object_acl_grants, published_versions, removed_versions,
)
from .manifest import ManifestStore, StoredObject, objects

# Re-exported for the existing import sites (``web/s3_gateway/*``, copy.py,
# gc_collect.py, multipart.py and the tests all import these names from
# ``teledrive.storage.catalog``).  Declarations live in catalog_tables.py.
__all__ = [
    "BucketCatalog", "ObjectHead", "bucket_acl_grants", "buckets",
    "catalog_metadata", "heads", "object_acl_grants", "published_versions",
    "removed_versions",
]
```

Every table name and `ObjectHead` is therefore still importable from
`teledrive.storage.catalog`. `catalog_metadata` is included because existing
call sites import it too.

## Line counts

| File | Lines |
|---|---|
| `teledrive/storage/catalog.py` | 1136 |
| `teledrive/storage/catalog_lock.py` | 184 |
| `teledrive/storage/catalog_acl.py` | 101 |
| `teledrive/storage/catalog_tables.py` | 101 |

`catalog.py` is still far above the ~250-line target because steps 4 and 5
have not run.

## What remains (next agent)

`catalog.py` still holds `__init__`, `_keyhash`, `validate_bucket` and:

- **Step 4 — `catalog_buckets.py`, `BucketAdminMixin`:**
  `create_bucket`, `versioning_state`, `set_versioning`,
  `public_access_block`, `set_public_access_block`, `object_ownership`,
  `set_object_ownership`, `clear_object_ownership`,
  `clear_public_access_block`, `public_read`, `list_buckets`,
  `list_bucket_records`, `delete_bucket`.
  (The plan's wording for this mixin is "create/list/delete bucket,
  versioning state, public_read, PAB, ownership"; `list_bucket_records` sits
  with that admin surface.)
- **Step 5 — `catalog_versions.py`, `BucketVersionMixin`, last because it
  contains `publish`:**
  `get`, `is_visible_version`, `_enqueue_notification`, `_journal_metadata`,
  `delete_marker`, `delete_version`, `current_marker`,
  `_record_published_uncommitted`, `index_legacy_current_heads`,
  `list_versions`, `list_bucket_versions`, `publish`, `rename_object`,
  `_apply_pending_tags`, `_delete_pending_tags`, `_delete_annotations`,
  `list_objects`, `remove_current`.

Order matters: do step 4 first, then step 5, verifying each separately. Keep
`publish`'s exact CAS (`generation` fence and `expected_object_id`),
`delete_marker`'s legal-hold/retention refusal, and `remove_current`'s
object-id fence byte-for-byte.

Shared leftovers (`__init__`, `_keyhash`, `validate_bucket`) stay on
`BucketCatalog`; `_keyhash` must stay reachable as `catalog._keyhash(...)`.
The mixin inheritance order in the plan is
`BucketAdminMixin, BucketLockMixin, BucketAclMixin, BucketVersionMixin`; no
method name currently collides, so any order preserves behaviour, but match
the plan.

## Verification (this session)

Run from the repo root with the project venv (plain `bandit` is not on
`PATH`; use `.venv/bin/bandit`):

```
python -m compileall -q teledrive web
.venv/bin/bandit -q -r teledrive web -ll
.venv/bin/pytest tests/storage -q -n 4
.venv/bin/pytest tests/s3 -q -n 4
.venv/bin/pytest tests/ -q -n 4
.venv/bin/python scripts/ops/sync_s3_inventory.py --check
```

Results after step 3:

- compileall: clean (no output)
- bandit: exit 0, only the pre-existing `nosec` warnings
- `tests/storage`: **328 passed, 2 skipped**
- `tests/s3`: **1289 passed, 46 skipped**
- full `tests/`: **2018 passed, 109 skipped**
- inventory: `in sync: 114 supported, 0 partial (0 by code, 0 by design),
  2 unsupported`

No test file was modified. `tests/storage/test_storage_catalog.py` passed
unchanged.

## Landmines for the next agent

- `catalog.py` still imports `time`, `objects`, `buckets`, `update` for the
  remaining versions/admin code; do not prune imports until the final file is
  assembled, then remove only what is genuinely unused.
- Do not add `create_all` or any DDL to a mixin.
- The lock/ACL mixins use `self.db`, `self.manifests`, `self._keyhash` and
  `self.list_buckets`; keep those on the assembled class.
- `apply_default_lock` is called from `publish`, so keeping `publish` last
  avoids transient import cycles and makes review of the CAS trivial.
