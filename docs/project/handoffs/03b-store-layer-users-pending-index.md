# 03b — store layer, part 2: users, pending Telegram logins, content index

Status: **done**. The three remaining stores from
`docs/handoffs/03-store-layer.md` are extracted and wired. Behaviour is
unchanged; the regression tests named in the plan pass unmodified.

Read `00-baseline.md` and `03a-store-layer-shares-pins-sessions.md` first.
This document only covers what changed after part 1.

## Commits

| Commit | Scope |
|---|---|
| `c1bf2c5` | `teledrive/stores/users.py` + user call sites |
| `be697e4` | `teledrive/stores/telegram_pending.py` + request/verify call sites |
| `d42f1e9` | `teledrive/stores/content_index.py` + search/reindex call sites |

The working tree at the start already contained unrelated, uncommitted
`web/s3.py` / `web/s3_gateway/` changes from another agent. They were left
untouched; each commit stages only the store module, `web/app.py` and
`tests/storage/test_stores.py`.

## New modules

| Module | Functions |
|---|---|
| `users.py` | `get_by_id`, `get_by_username`, `list`, `create`, `set_password`, `set_role`, `set_enabled`, `set_last_login`, `rename`, `delete`, `count_enabled_admins` |
| `telegram_pending.py` | `create`, `get`, `bump_attempts`, `consume`, `purge_older_than` |
| `content_index.py` | `get`, `ensure_row`, `search`, `delete_for_object` |

All take `teledrive.db.Database`, return dicts / lists / ints / bools (never a
SQLAlchemy `Row`), use SQLAlchemy Core with bound parameters, and commit once
per logical operation unless the caller owns a larger transaction.

### `users.py`

- **Validation stays in `web.app._validate_username`.** It is deliberately
  not duplicated in the store: it is a request-shape check that raises HTTP
  400, and two copies would drift. The store persists already-validated
  values.
- `get_by_id` returns the public profile **without** `password_hash`;
  `get_by_username` **includes** it because login needs it. `list` orders by
  `id` (the old listing's order). All three are equality lookups on a unique
  key (`id` / UNIQUE `username`), so no `ORDER BY`/`LIMIT` is required.
- `create` inserts, commits, then reads the id back by username
  (`RETURNING` is not portable). A duplicate username raises
  `IntegrityError`; the handler still maps it to 409.
- `set_last_login` was added beyond the plan's list: login's `last_login`
  update was one of the `users` statements that had to leave `web/app.py`.
  Login passes `commit=False`, then `sessions.create` commits both writes —
  the original single transaction.
- `rename`, `set_password`, `set_role`, `set_enabled` and `delete` accept
  `commit=False` for the handlers that also write `user_sessions`.
  `update_user` uses one transaction for rename + role + enabled, exactly as
  before (a failed role validation still rolls the rename back when the
  connection closes).
- `count_enabled_admins` is the read-only guard query: `role = 'admin' AND
  enabled = 1`.

### `telegram_pending.py`

- `create` sets `attempts = 0` explicitly and commits.
- `bump_attempts` is a bound-parameter `attempts = attempts + 1` update;
  `_record_verify_attempt` still swallows every exception, as before.
- `consume` deletes the row on success, on expiry, on a burned code hash and
  when the attempt cap is reached. The order of those checks in
  `verify_telegram_session_code` is unchanged.
- `purge_older_than` is strictly `created_at < cutoff`; `request-code` passes
  `commit=False` so the purge and the new request still commit together.

### `content_index.py`

- Table metadata comes from `teledrive.storage.manifest.content_index`; the
  FTS5/tsvector structures stay in `teledrive.storage.content_index`.
- `ensure_row` keeps the portable SELECT-then-INSERT (never
  `INSERT OR IGNORE`), commits once, and rolls back a lost insert race.
  Like the old handler it commits even when the row already exists.
- `search` **delegates** to `storage.content_index.search_content`, so there
  is exactly one FTS/snippet implementation. It returns the existing
  `[(object_id, snippet)]` tuples; the handler already unpacks tuples, so a
  dict projection would only add noise.
- `delete_for_object` also deletes the SQLite FTS mirror row so a deleted
  index row cannot keep matching. **It is implemented but not wired**: the
  app has no delete-content-index call site today. The old code never
  deleted these rows, so this is new, correct behaviour for a future caller,
  not a change to an existing path.

## Call sites rewired in `web/app.py`

Users (`users`):

- `_default_admin_password_in_use` — `_user_store.get_by_username`.
- `_create_default_admin` — `get_by_username` presence check then
  `create`; an existing `admin` row is still only read, never written.
- `_assert_not_last_admin` — `count_enabled_admins`; still fires on role
  change, disable and delete.
- `login` — `get_by_username`; the legacy-hash upgrade uses
  `set_password`; `last_login` uses `set_last_login(commit=False)` before
  `sessions.create`.
- `change_user_password` — `get_by_id` for the 404, `set_password(...,
  commit=False)` then `delete_for_user(..., commit=False)` and one commit.
- `change_user_role` — `get_by_id` + `set_role`.
- `get_user_detail` — `get_by_id`.
- `update_user` — `get_by_id`; `rename`, `set_role`, `set_enabled` all with
  `commit=False`; disabling still deletes sessions and one commit ends the
  operation. The 409-on-duplicate-username mapping is unchanged.
- `list_users` — `_user_store.list`.
- `create_user` — `_user_store.create`; same 409.
- `delete_user` — `get_by_id`, then `delete_for_user(commit=False)`,
  `users.delete(commit=False)`, one commit. The rowid-reuse invariant is
  preserved.

Pending Telegram logins (`telegram_session_pending`):

- `_record_verify_attempt` — `bump_attempts` (exception still swallowed).
- `_consume_pending_session_token` — `consume`; all four call sites now go
  through the store.
- `request_telegram_session_code` — `purge_older_than(commit=False)` +
  `create`.
- `verify_telegram_session_code` — `get`; the attempt cap, 300 s expiry and
  missing-request-session destruction paths are byte-for-byte equivalent.

Content index (`object_content_index`):

- `admin_search_objects` (mode=content) — `_content_store.search`.
- `reindex_object_contents` non-text branch — `_content_store.ensure_row`.
  The candidate query itself still joins `storage_objects` /
  `storage_object_heads` and is **not** part of this store.

## Remaining `text as _text` in `web/app.py`

`grep -c "text as _text" web/app.py` = **23** (was 40 before part 2; 51 in
the plan's baseline).

By table:

| Table(s) | Remaining statements |
|---|---|
| `users` | 1: the `ALTER TABLE users ADD COLUMN enabled` in `_migrate_users_enabled_column` |
| `telegram_sessions` | ~10: health write/probe/list/delete/quota, active-session read, metrics, pin account-existence check, replication account |
| `telegram_channels` | ~5: activate/read/create/delete, `request-code` channel fallback |
| `flood_waits` | 2: insert and latest-status read |
| storage catalog aggregates | 3 import sites: reindex candidate query, Prometheus metrics, `storage_usage_series` |

### Why these remain

The plan's store table never assigned modules to `telegram_sessions`,
`telegram_channels` or `flood_waits`, so those are **not** justified
read-only aggregates — they are simply out of scope for this handoff and are
the obvious next step (`stores/telegram_sessions.py` would cover most of
them). Two things are genuinely justified:

- `prometheus_metrics` — read-only aggregates (`telegram_sessions` gauges,
  `storage_mtproto_flood_observations`, `storage_mtproto_chat_cooldowns`).
  It degrades quietly when those catalog tables are absent; a store would
  have to reimplement that tolerance. It should get a comment saying so when
  the telegram store is added.
- `storage_usage_series` — one read-only aggregate over
  `storage_published_versions`/`storage_objects`; aggregation happens in
  Python for dialect portability. No mutation, no ambiguity.

`_migrate_users_enabled_column` is a pre-existing **landmine**, not a
justified query: DDL outside `teledrive/storage/schema.py`. It should become
an appended schema step in a separate change; moving it was out of scope and
would have changed migration ordering.

## Queries / semantics I was unsure about

1. **`users.create` selects after commit.** The old handler did
   INSERT → commit → SELECT id in the same connection; the store does the
   same, but the SELECT now re-reads the profile (one extra column set).
   On MySQL REPEATABLE READ this is a new transaction; the row was committed
   by the same connection, so it is visible. If a future caller passes
   `commit=False`-style semantics, revisit.
2. **`create_user`'s 409 covers the whole store call.** Before, only the
   INSERT was inside `try/except → 409`. Now a failure in the post-insert
   SELECT would also report "username already exists". The SELECT cannot
   fail for a committed row, but the mapping is technically broader.
3. **`telegram_pending.create` returns a dict that nothing uses.** Kept for
   symmetry with the other stores; it is the row as inserted, not a re-read.
4. **`get_by_username` returns `password_hash` to every caller.** Login and
   the default-password check need it; no handler serialises the dict
   directly. `get_by_id` deliberately omits it.
5. **`content_index.delete_for_object` FTS deletion** is new behaviour for a
   currently unwired function (see above). If a future caller deletes the
   SQLite index row outside this store, the mirror can still go stale.
6. **Two transactions in `update_user`? No.** All three updates plus the
   session delete share one commit. But `rename` is attempted before the
   role value is validated, exactly like the original; an invalid role still
   rolls the rename back on connection close.

## Tests added

`tests/storage/test_stores.py` now also covers:

- users: create/lookup/list, hash visibility split, duplicate username,
  each mutation, `commit=False` delete, enabled-admin count;
- pending logins: create/get/consume, attempt bump, strict purge, and
  `commit=False` purge;
- content index: `ensure_row` idempotence, `get`, search delegation and
  `delete_for_object` clearing both the row and the FTS mirror.

No new test file was needed, so the "every test file is scheduled" meta test
is unaffected.

## Evidence

After each of the three commits:

```
python -m compileall -q teledrive web
# clean

bandit -q -r teledrive web -ll
# exit 0

pytest tests/web tests/s3 tests/meta -q -n 4
# 1652 passed, 46 skipped   (each run:
#   c1bf2c5 234 s, be697e4 150 s, d42f1e9 228 s)
```

Final storage run:

```
pytest tests/storage -q -n 4
# 314 passed, 2 skipped
```

Contract suites run unchanged and green at every step:
`tests/web/test_user_admin_safety.py`, `tests/web/test_auth_rbac.py`,
`tests/web/test_auth_single_model.py`, `tests/web/test_telegram_session_auth.py`,
`tests/web/test_config_secrets.py`, plus `tests/storage/test_content_index.py`
and `tests/storage/test_stores.py`.

`scripts/ops/sync_s3_inventory.py --check` was not run: none of these commits
touch `teledrive/s3/operation_manifest.json`, and the unrelated working-tree
S3 changes were not staged or modified.
