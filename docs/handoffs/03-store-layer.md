# 03 — the raw-SQL layer in `web/app.py` (#13)

Read `00-baseline.md` first. Do this **after** 02, or in parallel with it only
if you stay inside `teledrive/` — 02 moves the handlers that contain the SQL.

## The problem

`web/app.py` issues ~85 statements through `conn.connection.execute(text(...))`
built at 51 call sites, each importing `text` locally as `_text`. The tables
involved: `users`, `user_sessions`, `bucket_quotas`, `bucket_account_pins`,
`share_links`, `object_content_index`, `telegram_session_pending`,
`telegram_sessions`, `bucket_account_pins`, `s3_credentials`.

Three defects came directly from this shape, all fixed one at a time:

1. an upsert written as `ON CONFLICT` that only worked on PostgreSQL/SQLite,
2. an `INSERT OR IGNORE` that only worked on SQLite,
3. a handler that read a row, derived a permission from it, and acted on a
   different row because the identifier matched `id OR prefix`.

The fix is not "wrap everything in SQLAlchemy Core". It is a **small set of
typed store functions** for the tables that handlers actually mutate, so that
(a) dialect differences live in one place, (b) validation happens next to the
schema, and (c) a handler cannot invent a query.

## Target: `teledrive/stores/`

| Module | Functions | Replaces |
|---|---|---|
| `users.py` | `get_by_id`, `get_by_username`, `create`, `set_password`, `set_role`, `set_enabled`, `rename`, `delete`, `count_enabled_admins` | the `users` text() calls |
| `sessions.py` | `create`, `resolve`, `delete_for_user`, `delete_all`, `purge_expired` | `user_sessions` |
| `quotas.py` | already exists as `teledrive/storage/quota.py` — extend, do not duplicate | `bucket_quotas` |
| `pins.py` | `set`, `get`, `delete` | `bucket_account_pins` |
| `shares.py` | `create`, `list`, `resolve_token`, `claim_download`, `revoke`, `delete_for_bucket` | `share_links` |
| `content_index.py` | `ensure_row`, `get`, `search`, `delete_for_object` | `object_content_index` |
| `telegram_pending.py` | `create`, `get`, `bump_attempts`, `consume`, `purge_older_than` | `telegram_session_pending` |

Rules for every function:

- Takes the `Database` wrapper (`teledrive/db.py`), not a raw connection.
- Returns plain dicts or small dataclasses, never SQLAlchemy `Row`.
- Commits explicitly, and only once at the end of a logical operation.
- Never builds SQL by string concatenation. If a table or column name must be
  dynamic (e.g. the bucket-delete purge), the identifier comes from a
  hardcoded literal tuple and the value is a bound parameter.
- Portable by construction: UPDATE-then-INSERT instead of `ON CONFLICT`;
  a SELECT-then-INSERT instead of `INSERT OR IGNORE`; no `RETURNING`.
- A `WHERE` that can match several rows needs a `LIMIT 1` **and** a
  deterministic `ORDER BY`, or must be an equality on a unique key. The
  prefix-ambiguity bug was exactly a missing `ORDER BY`.

## Move in this order (each step green)

1. `shares.py` — smallest, and the token logic is security-sensitive, so it
   benefits most from being isolated and unit-testable.
2. `pins.py` + extend `quotas.py`.
3. `sessions.py` — this one carries the rowid-reuse lesson; the delete path
   must remove sessions with the user in the same transaction.
4. `users.py` — the biggest win: validation (`_validate_username`), the
   last-enabled-admin guard and the bootstrap interplay all live together.
5. `telegram_pending.py` — carries the attempt cap.
6. `content_index.py`.

Do not change behaviour. The regression tests already exist for each of the
three bugs above; they must keep passing unchanged.

## Definition of done

- `grep -c "text as _text" web/app.py` drops from 51 to a handful, and every
  remaining one is a read-only aggregate (counts, health probes) with a
  comment saying why it stays.
- Each new store has unit tests that run on SQLite **and** are exercised by
  `tests/e2e/test_database_live.py` on PostgreSQL and MySQL when those URLs
  are set.
- A handoff listing any query whose semantics you were unsure about, rather
  than guessing.
