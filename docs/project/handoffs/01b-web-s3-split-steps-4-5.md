# 01b — `web/s3.py` split, steps 4–5

Move-only extraction. No handler logic, XML shape, authorization precedence or
checksum order changed. Two commits, one per planned step:

| Commit | Step | New modules |
|---|---|---|
| `3ddd746` | 4 | `web/s3_gateway/multipart.py`, `web/s3_gateway/common.py` |
| `dcd3b5e` | 5 | `web/s3_gateway/objects.py`, `web/s3_gateway/buckets.py` (extends `common.py`) |

`web/s3.py` remains the public import path and still re-exports every moved
name. `web/unified.py` (`from web.s3 import app`), `gateway._page` and every
other module-attribute access in `tests/` keep resolving.

## What moved where

### Step 4 — `multipart.py`, `common.py`

`web/s3_gateway/multipart.py` (700 lines at extraction, 706 after step 5):

- `_handle_multipart`
- `_mpu_initiate`
- `_mpu_list_parts`
- `_mpu_complete`
- `_mpu_upload_part`
- `_mpu_upload_part_copy`
- `_list_multipart_uploads` (it sits in the bucket section of `s3.py`, but
  `_handle_bucket_route` dispatches to it, so it belongs with the MPU family)

`web/s3_gateway/common.py` was created for the one helper the moved module
needed but that stays shared:

- `_quota_guard` (used by MPU complete, form upload and object PUT)

### Step 5 — `objects.py`, `buckets.py`, `common.py`

`web/s3_gateway/objects.py` (751 lines), in original order:

- `_read_verified_body`
- `_handle_version_delete`
- `_handle_copy_object`
- `_handle_object_delete`
- `_handle_object_put`
- `_object_attributes` (helper of object read)
- `_handle_object_read`
- `_headers` (helper of object read; not named in the plan but a strict
  dependency, so it moved rather than forcing a back-import)

`web/s3_gateway/buckets.py` (1 251 lines), in original order:

- `_replication_destinations`
- `_handle_form_upload`
- `_handle_batch_delete`
- `_handle_bucket_metadata_configuration`
- `_handle_bucket_encryption`
- `_handle_bucket_controls`
- `_list_bucket_versions`
- `_list_objects`
- `_handle_bucket_route`

`_handle_bucket_metadata_configuration` and `_handle_bucket_encryption` were
planned for `metadata_ops.py` (step 6), but `_handle_bucket_controls` calls both
directly. Leaving them in `web/s3.py` would have made `buckets.py` import back
into `web.s3`; they moved with their only caller instead. Step 6 may relocate
them, but `_handle_bucket_controls` must then import them from
`metadata_ops`. `_notification_allowlist` was also a caller-only helper, but it
**did not move** (see traps).

`common.py` gained the remaining shared helpers and the compat tables:

- `_reject_unimplemented_write_options`
- `_initial_tags`
- `_parse_initial_tags`
- `_tag_request_tags`
- `_COMPAT_BUCKET_READS`
- `_COMPAT_OBJECT_READS` (still read by the dispatcher in `web/s3.py`)

The AWS read-compatibility comment moved with `_COMPAT_*`.

`NAMESPACE` is now imported from `web/s3_gateway/xml.py` by the extracted
modules; `web/s3.py` keeps its own identical constant because the remaining
handlers and the dispatcher use it.

## Traps hit

1. **The test suite monkeypatches module attributes on `web.s3`, not on the
   extracted modules.** The first full `tests/s3` run after step 4 had 38
   failures with `503 Authorized Telethon USER session is required`; after
   step 5 the same class of failure hit SSE-C chunking and the notification
   allowlist. The fixture does:
   `monkeypatch.setattr(gateway, "storage_transport", ...)`,
   `monkeypatch.setattr(gateway, "RECOMMENDED_CHUNK_SIZE", ...)` and
   `monkeypatch.setattr(gateway, "_notification_allowlist", ...)`.
   A normal `from web.app import storage_transport` in a new module binds the
   original object and bypasses the patch.
   - `common.storage_transport(db)` resolves `web.s3.storage_transport` at call
     time. All moved object/bucket/MPU handlers use it.
   - `common._chunk_size()` resolves `web.s3.RECOMMENDED_CHUNK_SIZE` at call
     time. Seven call sites were mechanically changed from
     `RECOMMENDED_CHUNK_SIZE` to `_chunk_size()`; those seven expressions are
     the **only** body changes in either step. They are AST-identical after
     normalising the call back to the constant.
   - `_notification_allowlist` itself **stayed in `web/s3.py`**. Buckets imports
     `common._notification_allowlist`, which delegates to
     `web.s3._notification_allowlist` at call time. Moving the implementation
     into `buckets.py` and re-exporting it would have made the delegating proxy
     recurse into itself.
   No test file was edited.
2. **Nested scopes hide global names from a top-level symtable scan.**
   `MAX_METADATA_XML_BYTES` is used inside a nested `read_body()` in
   `_handle_bucket_metadata_configuration`; `parsedate_to_datetime` and
   `quote` are used inside lambdas/nested helpers. A first-pass free-variable
   scan only looked at the function's own symtable and missed them, producing
   `NameError` at request time. Recheck with a recursive walk of child
   symtables (see the checker snippet below), not just the top table.
3. **`@dataclass` / decorator trap from step 1 does not apply here:** every
   moved symbol in steps 4–5 is a plain `def`, `async def` or (for step 6)
   an undecorated class. Still use `node.decorator_list[0].lineno` if a future
   extraction includes a decorated class.
4. **Extraction order.** `_read_verified_body` (line ~2220) originally precedes
   the object handlers that come much later; the new module keeps original
   order, not call order. Python does not care, but it keeps the diff and future
   `git blame` honest.
5. **Leftover imports.** `web/s3.py` still imports many names only the extracted
   modules now use (`base64`, `hashlib`, `zlib`, the metadata stores, etc.).
   They were deliberately not pruned so the steps stay move-only. Step 6 should
   drop them while trimming.
6. **Latent undefined global `db`.** `_handle_batch_delete` (now
   `buckets.py`) and `_handle_version_delete` (now `objects.py`) call
   `RetainedMediaGC(db)` although neither function binds or receives `db`.
   This is pre-existing; both calls are inside `try/except Exception: pass`, so
   a `NameError` is silently swallowed and the GC branch is skipped. Moved
   verbatim, not fixed. Recorded here so it is not lost.

## What is left for step 6

`web/s3.py` is now **1 913 lines / 24 top-level defs+classes** (from 4 562 /
52 at the start of this scope; 3 884 after step 4).

Still in `web/s3.py`, by natural seam:

### `metadata_ops.py` (the planned step-6 module)

Object/bucket metadata configuration:

- `ObjectLockError`
- `_iso8601_ns`, `_parse_iso8601_ns` (only the object-lock handlers use them)
- `_read_acl_body`, `_validated_acl`
- `_read_verified_xml_body` (used by select/restore, so it can go with either
  `metadata_ops.py` or `objects.py`; keep it next to its callers)
- `_handle_bucket_acl`
- `_handle_object_acl`
- `_handle_bucket_object_lock`
- `_handle_object_lock_controls`
- `_handle_object_annotations` (the remaining caller of `_read_verified_body`,
  now imported from `objects.py`)
- `_handle_object_tagging` (the remaining caller of `_tag_request_tags`, now
  imported from `common.py`)
- `_handle_object_encryption`

### `objects.py` (extend it; these were not in the step-5 boundary)

- `_handle_object_rename`
- `_handle_select_object_content`
- `_perform_restore`
- `_handle_restore_object`

If these move, take `_read_verified_xml_body` with them (or leave it in
`metadata_ops.py` and import it).

### Stays in `web/s3.py` permanently

- `app`, `NAMESPACE`, the `_handle` dispatcher, `_s3_audit_log_middleware`,
  `_route_encoded_control_keys`, `health`, `root`, `path_route`
- `_notification_allowlist` — keep the real implementation here (or in a module
  that is not the one re-exported under the same name) so the `common` proxy
  keeps honouring the test monkeypatch.

Step 6's job is therefore: extract the two groups above, re-export every name,
then drop the now-unused imports and leave `web/s3.py` as dispatcher +
middleware + `app` + re-exports. The definition-of-done target from handoff 01
is still under ~500 lines / <15 defs.

## Useful checker before running the suite

Recursive free-global scan for a new module (catches nested-scope misses):

```python
import symtable, builtins
src = open(path).read()
st = symtable.symtable(src, path, "exec")
module_names = {s.get_name() for s in st.get_symbols()}
globs = set()
def walk(t):
    for c in t.get_children():
        for s in c.get_symbols():
            if s.is_global() and not s.is_assigned():
                globs.add(s.get_name())
        walk(c)
walk(st)
print(sorted(globs - module_names - set(dir(builtins))))
```

## Verification evidence

No test file, `web/app.py`, `teledrive/` or schema code was touched.

### After step 4 (`3ddd746`)

```
python -m compileall -q teledrive web      # clean
bandit -q -r teledrive web -ll             # rc=0 (pre-existing nosec warnings only)
pytest tests/s3 -q -n 4                    # 1239 passed, 46 skipped, 4 warnings in 176.69s
pytest tests/meta/test_route_surface.py -q # 2 passed
python scripts/ops/sync_s3_inventory.py --check
# inventory in sync: 114 supported, 0 partial (0 by code, 0 by design), 2 unsupported
```

### After step 5 (`dcd3b5e`)

```
python -m compileall -q teledrive web      # clean
bandit -q -r teledrive web -ll             # rc=0 (pre-existing nosec warnings only)
pytest tests/s3 -q -n 4                    # 1239 passed, 46 skipped, 4 warnings in 94.37s
pytest tests/meta/test_route_surface.py -q # 2 passed
python scripts/ops/sync_s3_inventory.py --check
# inventory in sync: 114 supported, 0 partial (0 by code, 0 by design), 2 unsupported
```

### Final broader run

```
pytest tests/s3 tests/web tests/storage tests/meta -q -n 4
# 1936 passed, 48 skipped, 5 warnings in 154.04s
```

The unrelated commits that landed during this work (`e360a91`, `10a91fb`,
`4484322` store extractions and the audit-doc commits) explain the higher
totals than the 1812 in handoff 01a.

## Line counts

| File | Lines |
|---|---|
| `web/s3.py` | 1 913 |
| `web/s3_gateway/multipart.py` | 706 |
| `web/s3_gateway/objects.py` | 751 |
| `web/s3_gateway/buckets.py` | 1 251 |
| `web/s3_gateway/common.py` | 210 |

AST equivalence was checked symbol-by-symbol against `git show HEAD:web/s3.py`
before each commit: **zero mismatches** for all moved functions, except the
seven intentional `RECOMMENDED_CHUNK_SIZE` → `_chunk_size()` call expressions,
which are equivalent after normalisation.
