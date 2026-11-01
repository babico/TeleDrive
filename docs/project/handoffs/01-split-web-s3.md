# 01 — splitting `web/s3.py` (do this one first)

Owner order: "codebase'in kocaman kısımlarını düzelt". `web/s3.py` is the
better first target than `web/app.py`: it has **one** entry point, no
decorators, and a request-context object that already threads state, so a
move-only split is mechanically safe.

Read `00-baseline.md` first.

## The shape today

`web/s3.py` is 5 106 lines with 81 module-level functions. Everything is
reached through one ASGI handler that builds `_S3RequestContext` and
dispatches. There is exactly **one** public symbol the rest of the codebase
imports: whatever `web/s3.py` exposes to `web/app.py`'s `include_router` /
mount. Verify with:

```
grep -rn "from web.s3 import\|import web.s3\|web\.s3\." --include=*.py . | grep -v test
```

## Target modules (move-only, no logic changes)

| New module | Move these (current line numbers are a hint, not a contract) |
|---|---|
| `web/s3/xml.py` | `_xml`, `_error`, `_xml_ok`, `_list_xml`, `_tag_xml`, `_parse_tag_xml`, `_canned_private_acl_xml`, `_compat_*_response` |
| `web/s3/signing.py` | SigV4 parsing/verification, the `s3express` scope handling, `_reject_unimplemented_write_options` |
| `web/s3/authorization.py` | `_policy_context`, `_acl_allows`, `_authorize_resource`, `_ownership_model`, `_require_source_acl`, `_apply_bucket_owner_preferred` |
| `web/s3/checksums.py` | `_verify_upload_sha256`, `_verify_bucket_control_payload`, `_effective_object_etag`, `_ssec_response_headers` |
| `web/s3/ranges.py` | `_range`, `_cursor_encode`, `_cursor_decode`, `_page`, `_virtual_host_bucket` |
| `web/s3/objects.py` | object GET/PUT/HEAD/DELETE/COPY routes and `_read_verified_body` |
| `web/s3/buckets.py` | `_handle_bucket_route`, `_handle_bucket_controls`, `_list_objects`, `_list_bucket_versions`, form upload, batch delete |
| `web/s3/multipart.py` | `_handle_multipart` and every `_mpu_*` |
| `web/s3/metadata_ops.py` | encryption, tagging, ACL, object-lock, annotations, notifications, logging, replication, tiering, reports, website, policy routes |
| `web/s3/context.py` | `_S3RequestContext` and its construction |

Keep `web/s3.py` as a thin compatibility module that re-exports the handler,
because the rest of the tree imports it by that path:

```
web/unified.py:6            from web.s3 import app as s3_app
tests/storage/...user_mode   import web.s3 as gateway
tests/web/test_unified_service.py:20
tests/web/test_s3_governance_ui.py:23
tests/s3/test_s3_directory_buckets.py:174
```

A re-export is cheaper and safer than rewriting every import in the same
commit -- but note the tests reach **module attributes** (`gateway.something`),
so the re-export must cover every name the tests touch, not just `app`.

## Order of work (each step ends with a green suite)

1. `context.py` + `xml.py` — no decision logic, lowest risk.
2. `authorization.py` — highest value: one file that answers "may this
   credential do this?" is worth more than any other split.
3. `checksums.py`, `ranges.py`.
4. `multipart.py` (self-contained, ~700 lines).
5. `objects.py`, `buckets.py`.
6. `metadata_ops.py`, then trim `web/s3.py` to the dispatcher + re-exports.

## Traps specific to this file

- **Do not change authorization while moving it.** `_authorize_resource`
  returns `(allowed, reason)` and the precedence is documented in its
  docstring: policy Deny → policy Allow → ACL. A "cleanup" here is a security
  change and needs its own commit and tests.
- **`_S3RequestContext` is passed by keyword in some call sites.** Grep for
  `ctx\\.` before renaming a field.
- The gateway is mounted, not routed, in `web/app.py`; its internal path
  handling (virtual-host bucketing via `_virtual_host_bucket`) must not move
  behind a router prefix.
- `_error` shapes every S3 error document. Tests assert on exact XML; a
  whitespace change will fail `tests/s3` in a way that looks like a logic bug.
- Several handlers assume the table-creation work already happened through
  `ensure_schema`; do not add a `create_all` anywhere.

## Definition of done

- `wc -l web/s3.py` under ~500 (dispatcher + re-exports).
- `grep -c "^def \|^async def " web/s3.py` under ~15.
- `pytest tests/s3 -q -n 4` green with **no test edits**. If a test had to
  change, the move was not move-only — say so explicitly in the handoff.
- `python scripts/ops/sync_s3_inventory.py --check` still passes (the
  manifest is keyed by operation name, not by module, so it should).
