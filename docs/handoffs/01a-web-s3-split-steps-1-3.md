# 01a — `web/s3.py` split, steps 1–3

Move-only extraction. No behaviour, XML-shape, authorization-precedence or
checksum-order change. Three commits, one per planned step:

| Commit | Step | New modules |
|---|---|---|
| `0d8972c` | 1 | `web/s3_gateway/xml.py`, `web/s3_gateway/context.py` |
| `309df2f` | 2 | `web/s3_gateway/authorization.py` |
| `0678f4a` | 3 | `web/s3_gateway/checksums.py`, `web/s3_gateway/ranges.py` |

## Why a new package instead of `web/s3/`

`web/s3.py` is imported as a module (`import web.s3 as gateway`,
`from web.s3 import app as s3_app`, `from web.s3 import _page` in
`tests/s3/test_s3_gateway.py`). Turning the file into a package in the same
commit would change import semantics and is explicitly out of scope for these
steps. The extraction therefore lands in a **staging package**,
`web/s3_gateway/`, and `web/s3.py` re-imports every moved name. Existing
references keep resolving, including module attributes tests reach:

```python
from web.s3_gateway.context import _S3RequestContext
from web.s3_gateway.xml import (
    _canned_private_acl_xml, _compat_bucket_read_response,
    _compat_object_read_response, _error, _list_xml, _parse_tag_xml,
    _tag_xml, _xml, _xml_ok,
)
from web.s3_gateway.authorization import (
    _ABAC_CONTROL_EXEMPT, _LIST_DEFAULTS, _acl_allows,
    _apply_bucket_owner_preferred, _authorize_resource, _ownership_model,
    _policy_context, _require_source_acl,
)
from web.s3_gateway.checksums import (
    _effective_object_etag, _ssec_response_headers,
    _verify_bucket_control_payload, _verify_upload_sha256,
)
from web.s3_gateway.ranges import (
    _cursor_decode, _cursor_encode, _page, _range, _virtual_host_bucket,
)
```

## What moved where

### Step 1 — `xml.py`, `context.py`

`web/s3_gateway/xml.py` (`NAMESPACE` redefined there): `_xml`, `_error`,
`_xml_ok`, `_list_xml`, `_tag_xml`, `_parse_tag_xml`,
`_canned_private_acl_xml`, `_compat_bucket_read_response`,
`_compat_object_read_response`.

`web/s3_gateway/context.py`: the `_S3RequestContext` dataclass, verbatim
(fields, defaults and order unchanged).

**Deliberately left in `web/s3.py`:** the construction site at
`web/s3._handle` (currently around line 4206). It is interleaved with the
routing-flag computation, signature setup and the `ensure=False` credential
store; pulling it out would have meant either moving `_handle` or passing ~30
locals through a factory. That is step 6 work, not a move. The dataclass moved,
the `ctx = _S3RequestContext(...)` call did not.

### Step 2 — `authorization.py`

`_policy_context`, `_acl_allows`, `_authorize_resource`, `_ownership_model`,
`_require_source_acl`, `_apply_bucket_owner_preferred`.

The two constants that only those functions use moved with them:
`_LIST_DEFAULTS` and `_ABAC_CONTROL_EXEMPT`. Leaving them in `web/s3.py`
would have forced a circular import (`authorization.py` importing `web.s3`).
Their explanatory comments moved into the module docstring / next to the
definitions.

Precedence is byte-for-byte the same logic: policy explicit Deny → policy
explicit Allow → ACL intersection, with the ABAC gate between policy and ACL.
No condition key, default, exemption or reason string changed.

### Step 3 — `checksums.py`, `ranges.py`

`web/s3_gateway/checksums.py`: `_verify_upload_sha256`,
`_verify_bucket_control_payload`, `_effective_object_etag`,
`_ssec_response_headers`.

`web/s3_gateway/ranges.py`: `_range`, `_cursor_encode`, `_cursor_decode`,
`_page`, `_virtual_host_bucket`.

Checksum verification order, `hmac.compare_digest` use, cursor payload/HMAC
format, pagination loop and the virtual-host suffix validation are unchanged.

## Traps hit

1. **AST extraction drops decorators.** `ClassDef.lineno` points at `class`,
   not `@dataclass`. The first extraction of `_S3RequestContext` lost its
   decorator, which made every gateway request fail with
   `TypeError: _S3RequestContext() takes no arguments` (882 failed / 116
   errors). Fixed by restoring `@dataclass` in `context.py`; no other moved
   symbol has a decorator. Future extractions should use
   `node.decorator_list[0].lineno` as the start line.
2. **Orphan comments.** Deleting `_LIST_DEFAULTS` left its long ListBucket
   comment stranded in `web/s3.py`. It was removed there (and preserved in
   `authorization.py`) rather than left dangling.
3. **Extra blank lines** at each deletion site were collapsed; no code lines
   were re-wrapped.
4. **Unused import left behind:** `from dataclasses import dataclass` in
   `web/s3.py` is now unused. It was not removed so the step stays move-only;
   the final trim (step 6) can drop it along with the other imports that only
   the extracted modules still need.
5. The working tree received two unrelated commits from other agents
   (`558453a test(meta): freeze the authorization surface`, `c3b64bc
   docs(handoff): record step 0 of the web/app.py split`) while this ran.
   Nothing here touches `web/app.py`, `teledrive/` or tests, and the three
   commits are self-contained.

## Verification evidence

After each step, in this order:

```
python -m compileall -q teledrive web
bandit -q -r teledrive web -ll
pytest tests/s3 -q -n 4
python scripts/ops/sync_s3_inventory.py --check
```

Results (identical for steps 1, 2 and 3):

- `compileall`: clean.
- `bandit`: clean (`-ll`, only pre-existing `nosec` warnings).
- `pytest tests/s3 -q -n 4`: **1124 passed, 46 skipped** each time. No test
  file was edited.
- `sync_s3_inventory.py --check`: `inventory in sync: 114 supported, 0 partial
  (0 by code, 0 by design), 2 unsupported`.

Final broader run per `docs/handoffs/README.md`:

```
pytest tests/s3 tests/web tests/storage tests/meta -q -n 4
```

**1812 passed, 48 skipped** (the two unrelated commits above added tests, so
this is higher than the 1790 baseline).

An AST equivalence check (`ast.dump` of each moved top-level node, original
`web/s3.py` vs new module) reported **zero mismatches** for all 27 moved
symbols.

## What steps 4–6 must know

- `web/s3.py` is now **4562 lines / 52 top-level defs** (from 5150). The
  definition-of-done target is still ~500 lines / <15 defs, so steps 4–6 have
  the bulk left: multipart, objects/buckets, metadata_ops, then the dispatcher
  trim.
- Keep `web/s3_gateway` as the extraction target until the final step. Do not
  rename it to `web/s3/` until every `import web.s3` consumer can be updated
  atomically; `web/unified.py` imports `from web.s3 import app`.
- Still in `web/s3.py` and intentionally not moved:
  `_quota_guard`, `_headers`, `_reject_unimplemented_write_options`,
  `_initial_tags`, `_parse_initial_tags`, `_tag_request_tags`,
  `_replication_destinations`, `_COMPAT_BUCKET_READS`,
  `_COMPAT_OBJECT_READS`, `NAMESPACE` (duplicated in `xml.py`), the ASGI
  `app` and its mounting, `_handle` and the middleware functions.
  `_COMPAT_*` dicts feed `_handle`'s compat-probe routing; if `_compat_*`
  response helpers move further, keep the dicts where the dispatcher reads
  them or import them explicitly.
- `_S3RequestContext` construction remains in `_handle`; if step 6 extracts a
  context factory, keep all keyword names and defaults identical — handlers
  read `ctx.<field>` and some call sites pass by keyword.
- `authorization.py` imports `object_tags` and queries `catalog.db.connection`
  directly on purpose (constructing `ObjectTagStore` would run DDL inside the
  authorization path). Do not "tidy" that into a store constructor.
- `xml._error` is the exact XML `tests/s3` asserts on. Any future formatting
  of that module must not reorder elements or change whitespace.
- Verification is unchanged: `pytest tests/s3 -q -n 4` must stay green with no
  test edits; if a test needs to change, the move was not move-only.
