# 05 — splitting `teledrive/storage/catalog.py`

Read `00-baseline.md` first. This one is different from the `web/s3.py` split:
the file is a single class, not a module of functions.

## Why a mixin split, not a module split

`BucketCatalog` is imported by name in ~30 places (`from
teledrive.storage.catalog import BucketCatalog`) and its methods are called as
`catalog.get(...)`, `catalog.publish(...)`. Extracting free functions would
rewrite every call site and is not a refactor.

Extracting **mixins** keeps `BucketCatalog` as one class with the same
surface, and the only change at an import site is nothing at all.

```
teledrive/storage/catalog_tables.py   buckets, heads, published_versions,
                                      removed_versions, ACL grant tables,
                                      and their Index declarations
teledrive/storage/catalog_buckets.py  BucketAdminMixin: create/list/delete
                                      bucket, versioning state, public_read,
                                      PAB, ownership
teledrive/storage/catalog_lock.py     BucketLockMixin: object_lock_config,
                                      set_object_lock_config, retention,
                                      legal hold, apply_default_lock,
                                      object_read_state, access counters
teledrive/storage/catalog_acl.py      BucketAclMixin: bucket/object ACL
                                      grants, acl_grants_for
teledrive/storage/catalog_versions.py BucketVersionMixin: get, publish,
                                      delete_marker, delete_version,
                                      remove_current, rename_object,
                                      list_versions, list_bucket_versions,
                                      list_objects, index_legacy_current_heads
teledrive/storage/catalog.py          BucketCatalog(BucketAdminMixin,
                                      BucketLockMixin, BucketAclMixin,
                                      BucketVersionMixin) + __init__ +
                                      the small shared helpers
```

`catalog.py` must keep re-exporting every table name and `ObjectHead`, because
`web/s3_gateway/*`, `teledrive/storage/copy.py`, `gc_collect.py`,
`multipart.py` and the tests import them from there.

## Invariants that must survive

1. **One DDL path.** Tables are declared in `catalog_tables.py`; the schema
   coordinator creates them. A mixin must not create anything.
2. **`_keyhash` and `validate_bucket` stay staticmethods on the class.**
   `copy.py` and `multipart.py` call `catalog._keyhash(...)` directly.
3. **`publish` is the only writer of a head's `generation`,** and it must keep
   the exact CAS semantics (including the `expected_object_id` fence).
4. **`delete_marker` keeps the suspended-branch lock check** — a legal hold or
   an open retention window must refuse the delete.
5. **`remove_current` always fences on object id**, and answers
   409-equivalent (a raised `ValueError`) on a lost race.
6. Every method keeps its `self.db` / `self.manifests` usage; no mixin may
   introduce its own connection or commit differently.

## Order of work (each step green)

1. `catalog_tables.py` — pure declarations, plus `ObjectHead`. Re-export from
   `catalog.py`.
2. `catalog_acl.py` — smallest, no CAS logic.
3. `catalog_lock.py`.
4. `catalog_buckets.py`.
5. `catalog_versions.py` — last: it holds `publish`, the most load-bearing
   method in the storage layer.

## Verification

```
python -m compileall -q teledrive web
bandit -q -r teledrive web -ll
pytest tests/storage -q -n 4
pytest tests/s3 -q -n 4
pytest tests/web tests/meta -q -n 4
python scripts/ops/sync_s3_inventory.py --check
```

`tests/storage/test_storage_catalog.py` is the contract for this file; it must
pass **unchanged**. If it needs an edit, the move was not move-only.

## Definition of done

- `wc -l teledrive/storage/catalog.py` under ~250 (class assembly + shared
  helpers + re-exports).
- Every table name still importable from `teledrive.storage.catalog`.
- No behaviour change, no test edit, and a handoff listing what stayed and
  why.
