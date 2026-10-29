# 01c — `web/s3.py` split, step 6 (complete)

Move-only extraction. No handler logic, XML shape, authorization precedence,
checksum order or dispatch order changed. One code commit:

| Commit | Step | New modules |
|---|---|---|
| `96bb1cb` | 6 | `web/s3_gateway/metadata_ops.py`, `web/s3_gateway/dispatch.py`; extends `objects.py`, `common.py` |

`web/s3.py` remains the public import path and still re-exports every moved
name. `web/unified.py` (`from web.s3 import app`), `from web.s3 import _page`,
and the module attributes the tests monkeypatch all keep resolving.

## Final counts

| File | Lines | Top-level defs/classes |
|---|---|---|
| `web/s3.py` | **225** | **6** |
| `web/s3_gateway/dispatch.py` | 867 | 1 |
| `web/s3_gateway/metadata_ops.py` | 612 | 12 |
| `web/s3_gateway/objects.py` | 984 | 18 |
| `web/s3_gateway/common.py` | 231 | 11 |
| `web/s3_gateway/buckets.py` | 1 252 | 9 |
| `web/s3_gateway/multipart.py` | 706 | 8 |
| `web/s3_gateway/authorization.py` | 172 | 6 |
| `web/s3_gateway/ranges.py` | 140 | 5 |
| `web/s3_gateway/checksums.py` | 136 | 4 |
| `web/s3_gateway/xml.py` | 196 | 10 |
| `web/s3_gateway/context.py` | 71 | 1 |

From 1 913 lines / 24 defs at the start of this scope; from 5 106 / 81 at the
baseline.

## Module map

### `web/s3_gateway/metadata_ops.py`
- `ObjectLockError`, `_iso8601_ns`, `_parse_iso8601_ns`
- `_read_acl_body`, `_validated_acl`
- `_handle_bucket_acl`, `_handle_object_acl`
- `_handle_bucket_object_lock`, `_handle_object_lock_controls`
- `_handle_object_annotations`
- `_handle_object_tagging`
- `_handle_object_encryption`

### `web/s3_gateway/objects.py` (extended)
- `_read_verified_xml_body` (needed by both select and restore)
- `_handle_object_rename`
- `_handle_select_object_content`
- `_perform_restore`
- `_handle_restore_object`

### `web/s3_gateway/dispatch.py`
- `_handle` — the ASGI dispatcher, moved verbatim (see "Deviation" below).

### `web/s3_gateway/common.py` (extended)
- `db_connect()` / `load_master_key()` — call-time proxies to `web.s3`, for the
  `_handle` path.
- `_select_scan_limit()` — call-time proxy for `MAX_SELECT_SCAN_BYTES`, which
  `tests/s3/test_s3_select.py` monkeypatches on `web.s3`.

### Stays in `web/s3.py`
- `app`, `NAMESPACE`, `_notification_allowlist`
- `_s3_audit_log_middleware`, `_route_encoded_control_keys`
- `health`, `root`, `path_route`
- The full re-export block.

`_notification_allowlist` must stay: `common._notification_allowlist()` calls
`web.s3._notification_allowlist()`, so moving the implementation into the module
that is also re-exported under that name would recurse. The dispatcher moved to
`dispatch.py` but is re-exported, so `web.s3._handle` still exists.

## Deviation from the written scope: the dispatcher

The scope said "keep the ASGI dispatcher (`_handle`) in `web/s3.py`", but the
definition of done also said `wc -l web/s3.py` under ~500. Both cannot hold:
`_handle` alone is **795 lines**, and with the middleware and re-exports the
file is 1 051 lines if it stays.

Two ways to reconcile them:

1. Refactor the dispatcher's ~550-line route-classification block into a
   `routing.py` helper. That changes code structure, is not verbatim, and the
   classification block shares dozens of locals with the execution half.
2. Move `_handle` verbatim to `dispatch.py` and re-export it.

Option 2 was chosen because it is the only move-only option and the handoff's
own target architecture already calls `web/s3.py` "a thin compatibility module
that re-exports the handler". `ast.dump` of `_handle` against
`git show HEAD:web/s3.py` is identical. `web.s3._handle`, `web.s3.app` and every
other module attribute still resolve. If a future reviewer prefers the
dispatcher in `web/s3.py`, reverting just this one hunk is mechanical; the
result is the 1 051-line version, which still passes every test.

Because the dispatcher moved, `db_connect` and `load_master_key` are resolved
through `common.py` proxies at call time. Tests do
`monkeypatch.setattr(gateway, "db_connect", ...)` and
`monkeypatch.setattr(gateway, "load_master_key", ...)` on `web.s3`.

## Traps hit

1. **`_handle_bucket_acl` is not in `buckets.py`.** The dispatcher's import list
   initially grouped it with the bucket handlers; it now lives in
   `metadata_ops.py`. This failed at import time, not test time.
2. **Two expression-only body changes, both in the documented monkeypatch
   class.** `_handle_object_encryption` and `_handle_select_object_content`
   used `RECOMMENDED_CHUNK_SIZE` directly; they now call `common._chunk_size()`.
   The select handler used `MAX_SELECT_SCAN_BYTES` twice (comparison and error
   string); both now call `common._select_scan_limit()`. Every other moved
   expression is byte-identical. An AST comparison that normalises those calls
   back to the module globals reports zero mismatches for all 17 moved symbols
   and for `_handle`.
3. **`_read_verified_xml_body` sits between the two groups.** It is used by
   select and restore only, so it moved to `objects.py`; `metadata_ops.py`
   imports it from there in the other direction. No cycle: `metadata_ops`
   imports `objects`, never the reverse, and neither imports `web.s3` at module
   level.
4. **`_select_scan_limit()` is called twice instead of reading the global
   twice.** Semantically identical (the original also read the module global at
   each expression), and it keeps the monkeypatch effective for both the bound
   check and the message.
5. **`web/s3.py` still imports four names it does not use** —
   `load_master_key`, `storage_transport`, `MAX_SELECT_SCAN_BYTES`,
   `RECOMMENDED_CHUNK_SIZE`. They are the monkeypatch anchors (`web.s3` must
   expose them) and the targets of the `common.py` proxies. Do not "clean" them
   away.
6. **The `@dataclass` trap from step 1 did not apply**: every symbol moved here
   is a plain `def`/`async def`/class with no decorator.

## Deliberately left alone

- `_handle_bucket_metadata_configuration` and `_handle_bucket_encryption` still
  live in `buckets.py`. Handoff 01b allowed relocating them into
  `metadata_ops.py`; it was not done because `_handle_bucket_controls` is their
  only caller and the move would add an import for no line-count benefit in
  `web/s3.py`. They are metadata handlers in a bucket-control module, not a
  behavioural issue.
- The pre-existing `Request` annotation in `common.py` without a `Request`
  import is harmless under `from __future__ import annotations`; it predates
  this step and was not touched.
- No test, `web/app.py`, `teledrive/` or schema file was edited. No DDL was
  added.

## Verification evidence

Run after the final state (`96bb1cb`), in this order:

```
$ .venv/bin/python -m compileall -q teledrive web
(clean, exit 0)

$ .venv/bin/bandit -q -r teledrive web -ll
bandit rc=0   # pre-existing nosec warnings only

$ .venv/bin/python -m pytest tests/s3 -q -n 4
1261 passed, 46 skipped, 4 warnings in 182.13s (0:03:02)

$ .venv/bin/python -m pytest tests/meta/test_route_surface.py -q
2 passed in 5.66s

$ .venv/bin/python scripts/ops/sync_s3_inventory.py --check
inventory in sync: 114 supported, 0 partial (0 by code, 0 by design), 2 unsupported

$ wc -l web/s3.py
225 web/s3.py

$ grep -c "^def \|^async def \|^class " web/s3.py
6
```

Broader run per `docs/handoffs/README.md`:

```
$ .venv/bin/python -m pytest tests/s3 tests/web tests/storage tests/meta -q -n 4
1966 passed, 48 skipped, 5 warnings in 186.70s (0:03:06)
```

Two unrelated store commits (`be697e4`, `d42f1e9`) landed while this step ran and
touched `web/app.py`/`teledrive/stores/`. The same broad command was re-run on
the merged tree after they landed:

```
$ .venv/bin/python -m pytest tests/s3 tests/web tests/storage tests/meta -q -n 4
1968 passed, 48 skipped, 5 warnings in 189.22s (0:03:09)
```

No test file was edited. `python scripts/ops/sync_s3_inventory.py --check`
remains the only writer of the inventory files.
