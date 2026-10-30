# 02c — `web/routers/auth.py`, `users.py`, `telegram.py` (steps 4–5, first three routers)

Move-only. Three commits, one per router. No test edited, no snapshot change,
no behaviour change. `web/app.py` went **4943 → 3757** lines.

## Base and where the commits landed

Work started at `55d66c5`; the tree was being edited concurrently (storage
mixins, then the `app.js` split in `5998590`/`b8db71b`). The three commits were
built and verified in a throwaway worktree checked out at `dc54233` and
cherry-picked onto the moving `main`, so their SHAs on `main` are:

| Commit | Router | Contents |
|---|---|---|
| `1e1a7f4` | `auth.py` | `web/routers/auth.py`, `web/app.py`, `web/routers/__init__.py` |
| `242d19b` | `users.py` | `web/routers/users.py`, `web/app.py`, `web/routers/__init__.py` |
| `39a205d` | `telegram.py` | `web/routers/telegram.py`, `web/app.py`, `web/routers/__init__.py` |

`auth.py` was committed directly on the main tree at `1e1a7f4`; `users.py` and
`telegram.py` are cherry-picks of `dd91466` and `81ebf9c` from the worktree.

## `web/routers/auth.py` (270 lines)

| Method | Path | Tags / schema | Gate |
|---|---|---|---|
| POST | `/api/v1/auth/login` | `Authentication`, summary kept | public handler; `_same_origin` + throttle |
| POST | `/api/auth/login` | `Authentication`, `include_in_schema=False` | same |
| POST | `/api/v1/auth/logout` | `Authentication`, summary kept | in-handler session; `_same_origin` |
| POST | `/api/auth/logout` | `Authentication`, `include_in_schema=False` | same |
| GET | `/api/v1/auth/me` | `Authentication`, summary kept | in-handler `_get_current_user`, 401 |
| GET | `/api/auth/me` | `Authentication`, `include_in_schema=False` | same |
| PUT | `/api/v1/admin/users/{user_id}/password` | `Users`, summary kept | `Depends(require_auth)` + `_same_origin` |

Helpers moved with their only consumers, into this module and nowhere else:
`_hash_password`, `_verify_password`, `_dummy_password_hash`,
`_session_token_digest`, `_default_admin_password_in_use`,
`_invalidate_default_admin_cache`, `_auth_throttle_blocked`,
`_auth_throttle_check`, `_auth_failure_record`, `_get_current_user`, and the
module-level state `AUTH_FAILURES`, `_PBKDF2_ITERATIONS`,
`_DUMMY_PASSWORD_HASH`, `_DEFAULT_ADMIN_PW_CACHE`.

Two app-owned settings are read through `_webapp()` at call time rather than
copied: `AUTH_FAILURE_WINDOW_SECONDS`/`AUTH_FAILURE_LIMIT` (rebound by
`_reload_service_settings`) and `TRUSTED_PROXY`/`SSL_CERTFILE` (read by the
cookie `secure=` decision). Copying them would freeze startup values and
silently break `test_public_s3_origin`-style monkeypatching of
`webapp.TRUSTED_PROXY`.

## `web/routers/users.py` (287 lines)

| Method | Path | Tags / schema | Gate |
|---|---|---|---|
| PUT | `/api/v1/admin/users/{user_id}/role` | `Users`, summary kept | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/users/{user_id}` | `Users`, summary kept | `require_auth` |
| PUT | `/api/v1/admin/users/{user_id}` | `Users`, summary kept | `require_auth` + `_same_origin` |
| DELETE | `/api/v1/admin/users/{user_id}/sessions` | `Users`, summary kept | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/roles` | `Users`, summary kept | `require_auth` |
| GET | `/api/v1/admin/users` | `Users`, summary kept | `require_auth` |
| POST | `/api/v1/admin/users` | `Users`, 201, summary kept | `require_auth` + `_same_origin` |
| DELETE | `/api/v1/admin/users/{user_id}` | `Users`, summary kept | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/audit` | `Users`, summary kept | `require_auth` |

Helpers/state moved with them: `_USERNAME_RE`, `_validate_username`,
`_assert_not_last_admin`, `UserCreateRequest`. `list_roles` keeps calling
`permission_registry()` imported from `web.deps` (the cached registry), not a
local copy.

The audit route belongs here, not with the storage sections: it is the tail of
the "Users" surface and was registered between `users` and `storage/usage` in
the old file. Its position in the file no longer matters for the registry (the
registry keys on method+path), but keeping it here preserves the audience
grouping.

## `web/routers/telegram.py` (984 lines)

Session management:

| Method | Path | Gate |
|---|---|---|
| PUT | `/api/v1/admin/storage/telegram-sessions/{account}/quota` | `require_auth` + `_same_origin` |
| POST | `/api/v1/admin/storage/telegram-sessions/{account}/health-check` | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/storage/telegram-sessions` | `require_auth` |
| DELETE | `/api/v1/admin/storage/telegram-sessions/{account}` | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/storage/telegram-session` | `require_auth` |
| GET | `/api/v1/admin/storage/telegram-session/floodwait` | `require_auth` |
| POST | `/api/v1/admin/storage/telegram-session/request-code` | `require_auth` + `_same_origin` |
| POST | `/api/v1/admin/storage/telegram-session/verify-code` | `require_auth` + `_same_origin` |
| DELETE | `/api/v1/admin/storage/telegram-session` | `require_auth` + `_same_origin` |

Channel management:

| Method | Path | Gate |
|---|---|---|
| GET | `/api/v1/admin/storage/channels` | `require_auth` |
| POST | `/api/v1/admin/storage/channels` | `require_auth` + `_same_origin` |
| DELETE | `/api/v1/admin/storage/channels/{channel_id}` | `require_auth` + `_same_origin` |
| PUT | `/api/v1/admin/storage/strategy` | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/storage/replication` | `require_auth` |
| PUT | `/api/v1/admin/storage/replication` | `require_auth` + `_same_origin` |
| POST | `/api/v1/admin/storage/replication/repair` | `require_auth` + `_same_origin` |
| POST | `/api/v1/admin/storage/channels/{channel_id}/activate` | `require_auth` + `_same_origin` |
| GET | `/api/v1/admin/storage/active-channel` | `require_auth` |

Helpers moved with their consumers: `_mask_phone`, `_probe_telegram_session`,
`_store_session_health`, `_probe_account_now`, `telegram_session_health_loop`,
`_MAX_VERIFY_ATTEMPTS`, `_record_verify_attempt`,
`_consume_pending_session_token`, `_record_flood_wait`, `_flood_wait_status`,
and the payload models `TelegramSessionRequestCode`,
`TelegramSessionVerifyCode`, `TelegramChannelCreate`.

**`telegram_session_health_loop` is re-exported from `web.app`** and must stay
so: `lifespan` in `web/app.py` calls
`asyncio.create_task(telegram_session_health_loop())` at startup. If a future
step deletes the re-exports without fixing that call site, the app fails to
start — the tests do not start the lifespan often enough to catch it quickly.

The strategy/replication handlers write `config.yaml` directly with
`_secure_write` + `os.replace` and then `_reload_service_settings()`; they read
`CONFIG_PATH`, `AUTH_DIR`, `mtproto_storage_runtime`, `storage_transport`,
`BucketCatalog`, `ManifestStore`, `TelegramObjectStorage` and
`RECOMMENDED_CHUNK_SIZE` from `_webapp()`. Do not turn those into module-level
imports: tests monkeypatch `webapp.CONFIG_PATH`, `webapp.storage_transport` and
`webapp.mtproto_storage_runtime`.

## Includes

`web/routers/__init__.py` now exports `auth_router`, `config_router`,
`public_router`, `telegram_router`, `users_router`. `web/app.py` includes all
five at the bottom, after the last `@app.*` route and before anything can call
`permission_registry()`:

```python
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(telegram_router)
app.include_router(config_router)
app.include_router(public_router)
app.include_router(s3_governance_api.router)
```

Plain `include_router`, no hand mutation of `app.router.routes`. FastAPI 0.142
keeps each included router lazy behind `_IncludedRouter`; `web.permissions.route_views()`
flattens both shapes for the registry and the frozen surface test, so no eager
include helper is needed any more.

Registration **order between these five does not affect the surface** (each has
absolute paths and none overlaps another router's path), but `public.py` must
stay after them: it owns `/{page_name}` and `/{page_name}.html`, which would
otherwise shadow later routes.

## App-owned names still read through `_webapp()`

`db_connect`, `_log`, `_audit`, `_hash_password`, `read_raw_config`,
`_secure_mkdir`, `_secure_write`, `_schedule_storage_runtime_reload`,
`_reload_service_settings`, `storage_transport`, `mtproto_storage_runtime`,
`AUTH_DIR`, `CONFIG_PATH`, `TRUSTED_PROXY`, `SSL_CERTFILE`,
`AUTH_FAILURE_WINDOW_SECONDS`, `AUTH_FAILURE_LIMIT`, `BucketCatalog`,
`ManifestStore`, `TelegramObjectStorage`, `RECOMMENDED_CHUNK_SIZE`.

This is deliberate throughout: tests monkeypatch `webapp.db_connect`,
`webapp._log`, `webapp.CONFIG_PATH`, `webapp.storage_transport`,
`webapp.mtproto_storage_runtime`, `webapp.TRUSTED_PROXY`. A module-level
`from web.app import db_connect` would bind the pre-patch object.

## Line counts

| File | Before this step | After |
|---|---|---|
| `web/app.py` | 4943 | **3757** |
| `web/routers/auth.py` | — | **270** |
| `web/routers/users.py` | — | **287** |
| `web/routers/telegram.py` | — | **984** |

## What is left, in the plan's order

1. `web/routers/buckets.py` — the "S3 bucket browser & quota (WebUI session
   auth)" section, `web/app.py` ~1637 onwards: bucket list/create/delete,
   objects list/delete, content get/put, CORS, website, presign, shares,
   copy, search/reindex, quota, pins, version-history, GC, metrics, usage,
   health, jobs, pending-stale, channel-history, multipart recovery.
   `_bucket_current_usage`, `_bucket_quota`, `_public_s3_origin` and the
   `*Request` models move with their consumers; `_stream_object_response` and
   `_stream_object_upload` are shared with `rest.py` — decide before moving
   either.
2. `web/routers/s3admin.py` — S3 credential CRUD/reveal, multipart recovery,
   reindex. Every handler keeps `_require_interactive_session(request, ...)`;
   dropping it is the escalation path described in `web/deps.py`. The
   duplicate `/api/v1/admin/s3/credentials` and `/api/v1/admin/s3-credentials`
   route pairs must both stay, in the same order.
3. `web/routers/rest.py` — **last**. The `/api/v1/buckets/{bucket}/...` data
   plane plus `_stream_object_upload`, `_valid_rest_key`,
   `_enforce_bucket_quota` and the read gate `_rest_read_gate`. It shares
   those with `buckets.py` and `public.py`; moving it first would leave two
   copies of the quota/read gate, which is how the original design bug would
   come back.
4. Only then delete the temporary re-exports from `web/app.py`, checking
   `grep` for importers (tests reach `webapp.*` directly) and, for the auth
   helpers, `web/deps.py`.

`web/app.py` still owns the app object, middleware, `lifespan`, `_log`/
`LOG_BUFFER`, `db_connect`, config read/write/redact/validate, `_audit`,
`_enforce_user_permission`, `_rest_read_gate`, `_secure_mkdir`/`_secure_write`,
`storage_transport`, the scheduler loops, `_create_default_admin` and the
uvicorn entry point.

## Traps found while doing this

- **A helper called through `_webapp().<own name>` is a landmine.** The
  aborted in-flight move in the shared tree left `telegram.py` calling
  `_app._mask_phone`, `_app._probe_telegram_session`, `_app._record_flood_wait`
  and friends through a proxy, i.e. each module calling itself through
  `web.app`'s re-exports. It happens to work only while the re-export exists
  and would break the moment cleanup removes it. Helpers a router owns are
  called **directly** in that router; only genuinely app-owned names go
  through `_webapp()`.
- **Concurrent agents on one working tree.** `web/app.py` was rewritten
  underneath this session mid-edit, twice, and one snapshot had already lost
  `telegram_session_health_loop` from `web/app.py` while `lifespan` still
  called it. Build and verify in a worktree (`git worktree add --detach`) and
  cherry-pick; do not trust an interleaved tree.
- **`pytest -n 4` subprocess tests time out under load.**
  `tests/storage/test_storage_sigkill.py` (30 s) and
  `tests/web/test_e2e_crypto.py` (120 s) each run a subprocess; on a loaded
  machine they exceed it and fail. Both pass in isolation. Treat a lone
  `subprocess.TimeoutExpired` there as environmental, rerun it alone.
- **`python` outside the venv lacks `cryptography`.** Use `.venv/bin/python` /
  `.venv/bin/pytest`; a bare `python -c "import web.app"` fails with
  `ModuleNotFoundError: cryptography` and looks like a regression.

## Evidence

Run in the detached worktree at `dc54233` after each router, and again on
`main` after the cherry-picks:

```
python -m compileall -q teledrive web            # clean
bandit -q -r teledrive web -ll                   # exit 0, no findings
pytest tests/meta/test_route_surface.py -q       # 2 passed (file unedited)
pytest tests/web -q -n 4                         # 249 passed (each router)
pytest tests/meta -q -n 4                        # 150 passed
pytest tests/ -q -n 4                            # 2018 passed, 109 skipped
                                                 # (after users and after telegram)
```

The full run after `auth.py` was 2015 passed / 3 failed, the three being the
subprocess timeouts above; all three pass in isolation and the same three
suites are green in the later full runs.
