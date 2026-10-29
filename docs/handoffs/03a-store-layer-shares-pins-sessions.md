# 03a — store layer, part 1: shares, pins/quotas, sessions

Status: **done**. The first three stores of `docs/handoffs/03-store-layer.md`
are extracted and wired. Behaviour is unchanged; the regression tests named in
the plan pass unmodified.

## What moved

New package `teledrive/stores/` (docstring only in `__init__.py`):

| Module | Functions |
|---|---|
| `shares.py` | `create`, `list`, `resolve_token`, `claim_download`, `revoke`, `delete_for_bucket` |
| `pins.py` | `set`, `get`, `delete` |
| `sessions.py` | `create`, `resolve`, `username_for_token`, `list_for_user`, `delete_token`, `delete_for_user`, `delete_all`, `purge_expired` |

`teledrive/storage/quota.py` was **extended**, not duplicated:

- `set_bucket_quota(conn, bucket, max_size_bytes, max_objects, now)` — the
  portable UPDATE-then-INSERT upsert that used to live in the quota handler.
- `all_bucket_quotas(conn)` — the metrics exposition read, now ordered by
  `bucket` instead of relying on storage order.

All functions take `teledrive.db.Database`, return dicts / ints / `None`
(never a SQLAlchemy `Row`), use bound parameters and SQLAlchemy Core against
the tables in `teledrive/db.py`, and commit once per logical operation. The
only exception is `sessions.delete_for_user(..., commit=False)`, explained
below.

## Call sites rewired in `web/app.py`

Shares (`share_links`):

- `create_bucket_share` — `_share_store.create` (object version still resolved
  from the catalog first and stored as `object_id`).
- `admin_list_shares` — `_share_store.list`; status computation stayed in the
  handler.
- `admin_revoke_share` — `_share_store.revoke`.
- `_load_active_share` — `_share_store.resolve_token`.
- `_stream_share` — dict access instead of tuple indexes;
  `_share_store.claim_download` still runs **after** the manifest resolves and
  the bucket/key binding check, so a 404 cannot burn a slot.

Pins and quota (`bucket_account_pins`, `bucket_quotas`):

- `admin_get_bucket_pin` — `_pin_store.get`.
- `admin_put_bucket_pin` — the `telegram_sessions` existence check stays in the
  handler; `_pin_store.set` does the upsert.
- `admin_delete_bucket_pin` — `_pin_store.delete`.
- `admin_set_quota` — `quota.set_bucket_quota`.
- `prometheus_metrics` — `quota.all_bucket_quotas`.

Sessions (`user_sessions`):

- `_extract_user` — `_session_store.username_for_token` (best-effort audit
  identity; deliberately still ignores expiry/enabled, as before).
- `_get_current_user` — `_session_store.resolve`; disabled user and expired
  token cleanup moved into the store, identical side effects.
- `login` — `_session_store.create`. `users.last_login` is updated *before*
  the call so both writes still commit in one transaction.
- `logout` — `_session_store.delete_token`.
- `change_user_password` — `delete_for_user(..., commit=False)` before the
  handler's single commit.
- `get_user_detail` — `_session_store.list_for_user`.
- `update_user` (disable path) — `delete_for_user(..., commit=False)` before
  the handler's commit.
- `revoke_user_sessions` — `delete_for_user` (default commit) and its return
  value is the response's `revoked` count.
- `delete_user` — `delete_for_user(..., commit=False)` followed by the `users`
  DELETE and one commit, preserving the rowid-reuse invariant.

`grep -n "user_sessions\|share_links\|bucket_account_pins" web/app.py` now
matches only the `revoke_user_sessions` function name and a comment. No raw SQL
for those three tables remains.

## Remaining `text()` in `web/app.py`

`grep -c "text as _text" web/app.py` = **40** (was 51). Next targets from the
plan: `users.py`, `telegram_pending.py`, `content_index.py`.

## Deliberate deviations / semantics worth knowing

1. **`sessions.delete_for_user(commit=False)`.** The plan says commit once per
   logical operation, but `delete_user` must delete sessions and the user in
   one transaction. The store therefore takes an explicit `commit` flag; the
   caller that owns the larger transaction commits. Everything else commits
   inside the store.
2. **`sessions.resolve` does not commit on success.** It only writes when it
   removes an expired token or a disabled user's sessions; that write commits.
   A successful read leaves the transaction open exactly like the old handler
   (the caller closes the connection).
3. **`shares.list` now orders `created_at DESC, token ASC`.** The old query
   had no tie-break; the extra key only makes equal timestamps deterministic.
4. **`quota.all_bucket_quotas` now orders by `bucket`.** The old metrics query
   was unordered. Values are unchanged.
5. **`shares.delete_for_bucket` is implemented but not wired.** The only
   bucket-delete purge lives in `teledrive/storage/catalog.py` and still uses
   its hardcoded `(table, column)` tuple. That is outside this scope; the next
   agent can replace the `("share_links", "bucket")` entry with this function.
6. **`purge_expired` is unused by the app.** Implemented as
   `expires_at < now` (strictly past). It is available for a future cleanup
   job; no existing behaviour depended on it.
7. **`pins.set` preserves the old broad `except Exception`** on the INSERT
   race, including the rollback-then-UPDATE path. Narrowing it to
   `IntegrityError` would be a behaviour change, so it was left alone.

Tests added: `tests/storage/test_stores.py` covers share object binding,
expiry/exhaustion/revocation, pin upsert, quota upsert/list, session resolve
(including disabled user and expired token), scoped deletes and purge. It is
listed in `quality-security.yml` and `integration-storage.yml` so the
"every test file is scheduled" meta test stays green.

## Evidence

```
python -m compileall -q teledrive web          # clean
bandit -q -r teledrive web -ll                 # clean (exit 0)
pytest tests/web tests/s3 tests/meta -q -n 4   # 1630 passed, 46 skipped
pytest tests/storage -q -n 4                   # 306 passed, 2 skipped
python scripts/ops/sync_s3_inventory.py --check
# inventory in sync: 114 supported, 0 partial, 2 unsupported
```

The named contract suites (`test_rest_transfer.py`, `test_user_admin_safety.py`,
`test_auth_rbac.py`, `test_auth_single_model.py`) pass unchanged.

Two combined runs produced transient failures in unrelated, socket-heavy S3
tests (`test_s3_recovery`, `test_s3_sse_c`, `test_s3_batch_delete`); each
failed file passes in isolation and the immediately repeated full runs were
green. Treat those as parallel-load flakes, not regressions from this move.
