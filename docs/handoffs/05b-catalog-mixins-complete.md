# 05b — catalog mixins, complete (steps 4–5)

Read `05-split-catalog.md` and `05a-catalog-mixins-part1.md` first. This
handoff covers the last two steps and closes the plan: `catalog.py` is now the
class assembly plus re-exports.

State on arrival: HEAD `55d66c5`, working tree clean, `catalog.py` at 1136
lines with `BucketCatalog(BucketAclMixin, BucketLockMixin)`.

## Commits

- `a787ec0 refactor(storage): extract BucketAdminMixin from BucketCatalog`
- `60d4c18 refactor(storage): extract BucketVersionMixin from BucketCatalog`

Both are move-only. No test, call site, SQL or DDL changed.

## Final module map

| File | Lines | Contents |
|---|---|---|
| `teledrive/storage/catalog.py` | 144 | docstring, imports, `__all__`, `_BUCKET_RE`, `ensure_versioning_column`, `BucketCatalog` (`__init__`, `validate_bucket`, `_keyhash`, `_enqueue_notification`, `_journal_metadata`, `_apply_pending_tags`, `_delete_pending_tags`, `_delete_annotations`) |
| `teledrive/storage/catalog_tables.py` | 101 | table/index declarations, `ObjectHead` (step 1) |
| `teledrive/storage/catalog_acl.py` | 101 | `BucketAclMixin` (step 2) |
| `teledrive/storage/catalog_lock.py` | 184 | `BucketLockMixin` (step 3) |
| `teledrive/storage/catalog_buckets.py` | 269 | `BucketAdminMixin` (step 4) |
| `teledrive/storage/catalog_versions.py` | 762 | `BucketVersionMixin` (step 5) |

Assembly line:

```python
class BucketCatalog(
        BucketAdminMixin, BucketLockMixin, BucketAclMixin, BucketVersionMixin):
```

The plan's order (`Admin, Lock, Acl, Version`) is used. No method name
collides across the four mixins, so MRO order is behaviour-neutral today; it
was chosen to match the plan, not to resolve a conflict.

## Step 4 — `BucketAdminMixin`

Verbatim, in the original order: `create_bucket`, the whole
`# -- versioning state (Phase B)` block (`versioning_state`, `set_versioning`),
the whole `# -- public access block & ownership (Phase E)` block
(`PAB_FIELDS`, `public_access_block`, `set_public_access_block`,
`object_ownership`, `set_object_ownership`, `clear_object_ownership`,
`clear_public_access_block`, `public_read`), `list_buckets`,
`list_bucket_records`, and `delete_bucket`.

Imports used: `json`, `sqlalchemy` `delete/insert/inspect/select/text/update`,
`IntegrityError`, `catalog_tables.buckets`, `manifest.objects`.

Invariants preserved:

- `delete_bucket` still refuses on object history and on
  `storage_multipart_uploads` history, then clears, in one transaction:
  bucket tags, lifecycle, CORS, pending tags (owned + orphan), website configs,
  object annotations (owned + orphan), metadata journal, metadata configs, the
  twelve-name governance loop (`catalog_acl_grants` … `share_links`), object
  ACL grants, resets `public_read`, and finally deletes the bucket row. The
  `# nosec B608` marker moved with the code, so bandit stays clean.
- `create_bucket` still wraps the insert in `begin_nested()` and maps
  `IntegrityError` to `ValueError("Bucket already exists")`.
- `list_bucket_records` still returns `([], False)` for an uppercase prefix and
  still escapes LIKE metacharacters via `startswith(..., autoescape=True)`.

## Step 5 — `BucketVersionMixin`

Verbatim, in the original order: `get`, `is_visible_version`, `delete_marker`,
`delete_version`, `current_marker`, `_record_published_uncommitted`,
`index_legacy_current_heads`, `list_versions`, `list_bucket_versions`,
`publish`, `rename_object`, `list_objects`, `remove_current`.

Imports used: `time`, `uuid4`, `sqlalchemy`
`and_/delete/insert/or_/select/update`, `IntegrityError`,
`catalog_tables` (`ObjectHead`, `heads`, `object_acl_grants`,
`published_versions`, `removed_versions`), `manifest.StoredObject`, `objects`.

Invariants preserved, byte-for-byte:

- `publish` is still the only writer of a head's `generation`; the update
  still carries `object_id == existing[0] AND generation == previous`, still
  honours `expected_object_id` / `expected_generation` (with `0` meaning
  create-if-absent), still calls `_apply_pending_tags(identifier)` inside the
  transaction and `apply_default_lock(item.id)` after commit.
- `delete_marker`'s Suspended branch still reads
  `objects.legal_hold`/`retention_until_ns` and raises `PermissionError` for a
  hold or an open window before deleting the head.
- `delete_version` still raises `PermissionError("Object is under retention")`
  for a retained or held version, and still advances HEAD by CAS.
- `remove_current` still fences on `heads.c.object_id == current.item.id`
  *and* the generation (the ABA fix) and still raises
  `ValueError("Object changed; unlink precondition failed")` on `rowcount != 1`.

Move verification: an AST comparison of every method body against
`git show 55d66c5:teledrive/storage/catalog.py` reports 34 old / 34 new method
names, identical name set, and **zero** differing source segments.

## What deliberately stayed in `catalog.py`, and why

- `__init__`, `validate_bucket`, `_keyhash` — shared by every mixin and
  called directly from outside (`copy.py` and `multipart.py` use
  `catalog._keyhash`, the ACL lock mixins call `self._keyhash`). The plan
  requires them to stay staticmethods on the assembled class; keeping them
  here means the mixins have no base class to import.
- `_enqueue_notification`, `_journal_metadata` — called by both
  `delete_marker`/`delete_version` (versions) and the lock/ACL paths, and they
  are pure transaction-scoped shims over `teledrive.s3.*`. They belong to the
  class, not to one mixin.
- `_apply_pending_tags`, `_delete_pending_tags`, `_delete_annotations` —
  cross-cutting transaction helpers: `publish` uses the first, both delete
  paths use the second, `delete_version` uses both of the latter.
- `ensure_versioning_column` — a compatibility wrapper around
  `schema.ensure_schema`; it is a module-level function, not a method.
- All imports, `_BUCKET_RE` and the `__all__` block — the re-export contract
  is unchanged from 05a; every table name, `ObjectHead` and `BucketCatalog`
  still import from `teledrive.storage.catalog` exactly as before.

## Verification (exact output)

Run in a clean worktree at `60d4c18` (so the in-progress `web/` auth-router
edit in the main checkout could not contaminate the result):

```
python -m compileall -q teledrive web        # clean, exit 0
.venv/bin/bandit -q -r teledrive web -ll     # exit 0, only pre-existing nosec warnings
.venv/bin/pytest tests/storage -q -n 4       # 328 passed, 2 skipped
.venv/bin/pytest tests/s3 -q -n 4            # 1289 passed, 46 skipped
.venv/bin/pytest tests/web -q -n 4           # 249 passed
.venv/bin/pytest tests/ -q -n 4              # 3 failed, 2015 passed, 109 skipped
python scripts/ops/sync_s3_inventory.py --check
# inventory in sync: 114 supported, 0 partial (0 by code, 0 by design), 2 unsupported
```

The three full-suite failures are load-induced subprocess timeouts, not
regressions, and they reproduce only under `-n 4`:

```
FAILED tests/storage/test_storage_sigkill.py::test_real_sigkill_recovers_only_missing_remote_chunks
FAILED tests/storage/test_storage_sigkill.py::test_actual_sigkill_after_remote_user_acceptance_never_blindly_retries
FAILED tests/web/test_e2e_crypto.py::test_teledrive_crypto_round_trip
```

`subprocess.TimeoutExpired` after 30 s / 120 s. Run serially they pass:

```
.venv/bin/pytest tests/storage/test_storage_sigkill.py tests/web/test_e2e_crypto.py -q
# 3 passed in 7.53s
```

Neither touches the catalog. Steps 4 and 5 were each also verified
individually before committing: storage/s3/web all green as listed above.

## Definition of done

- `wc -l teledrive/storage/catalog.py` → **144** (target "under ~250": met).
- Every table name and `ObjectHead` still importable from
  `teledrive.storage.catalog`; `__all__` unchanged.
- `tests/storage/test_storage_catalog.py` passed unchanged; no test file was
  touched.
- No `create_all`, no new DDL; `schema.py` remains the only creator.

## Notes for the next agent

- The multi-worker `-n 4` full-suite run has three known timing flakes
  (`test_storage_sigkill.py` ×2, `test_e2e_crypto.py`) that pass serially.
  Do not chase them as regressions.
- If a fifth mixin is ever added, keep `_keyhash`/`validate_bucket` on
  `BucketCatalog`: `copy.py` and `multipart.py` call them as attributes of the
  concrete class.
- `catalog.py` still imports `StoredObject` and `objects` for import-site
  compatibility even though nothing in the file uses them; removing them
  would be a behaviour-adjacent change for downstream importers, so they were
  left alone.
