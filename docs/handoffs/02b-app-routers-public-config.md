# 02b — `web/routers/public.py` + `web/routers/config.py` (steps 3 and 4)

Move-only. Two commits, one per router. No test edited, no snapshot change,
no behaviour change.

## Base

The task named `b688d18`, but other work landed while this step ran. The two
commits are:

| Commit | Parent | Contents |
|---|---|---|
| `adca54f` | `00a6ace` | `web/routers/public.py`, `web/routers/__init__.py`, `web/app.py` |
| `0b2948f` | `adca54f` | `web/routers/config.py`, `web/routers/__init__.py`, `web/app.py` |

The working tree was being edited concurrently by another agent
(`web/deps.py`, `web/permissions.py`, `tests/meta/test_route_surface.py`,
`.github/workflows/quality-security.yml`, `docs/S3_SPECS.md`, plus untracked
storage files). None of those were staged. Verification was run in a
throwaway worktree checked out at `0b2948f` so the results are not polluted by
that concurrent work.

## `web/routers/public.py` (531 lines)

`router = APIRouter()` with no prefix. Routes, in registration order (the
order matters: the certificate routes stay before `/{page_name}`):

| Method | Path | Tags / schema | Gate |
|---|---|---|---|
| GET | `/settings/general` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/settings/telegram` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/s3/credentials` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/s3/buckets` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/settings` | `include_in_schema=False` | redirect to `/settings/general` |
| GET | `/storage` | `include_in_schema=False` | redirect to `/settings/telegram` |
| GET | `/s3` | `include_in_schema=False` | redirect to `/s3/buckets` |
| GET | `/` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/{page_name}.html` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/login` | `include_in_schema=False` | public page |
| GET | `/server.cer` | `include_in_schema=False` | public |
| GET | `/api/v1/certificate.cer` | `System`, summary kept | public |
| GET | `/server.crt` | `include_in_schema=False` | public |
| GET | `/api/v1/certificate.pem` | `System`, summary kept | public |
| GET | `/{page_name}` | `include_in_schema=False` | in-handler auth, redirect |
| GET | `/share/{token}` | `Sharing`, summary kept | public (rate limited) |
| POST | `/share/{token}` | `Sharing`, summary kept | public (rate limited) |
| GET | `/site/{bucket}` | `include_in_schema=False` | public (CSP sandbox) |
| GET | `/site/{bucket}/{path:path}` | `include_in_schema=False` | public (CSP sandbox) |

Helpers moved with their only consumers: `_serve_static_page` (also used by
`web/s3_governance_api.py`, which imports it from `web.app`, so it is
re-exported), `_share_rate*`, `_hash_share_password`, `_share_html`,
`_load_active_share`, `_stream_share`, `_SITE_*`, `_site_*`, `_serve_site`.
The module-level rate-limit dict `_share_rate` moved too and is re-exported
from `web.app`; tests mutate `webapp._share_rate`, which still clears the one
dict because the import binds the same object.

## `web/routers/config.py` (157 lines)

| Method | Path | Tags / schema | Gate |
|---|---|---|---|
| GET | `/api/v1/config` | `Configuration`, summary kept | `Depends(require_auth)` |
| GET | `/api/config` | `Configuration`, `include_in_schema=False` | `Depends(require_auth)` |
| PUT | `/api/v1/config` | `Configuration`, `OKResponse`, summary kept | `Depends(require_auth)` + `_same_origin` + interactive session |
| PUT | `/api/config` | `Configuration`, `include_in_schema=False` | same |
| WS | `/api/v1/logs/stream` | no tags | in-handler session check (`close(4401)`) |
| GET | `/api/v1/logs` | `System`, summary kept | `Depends(require_auth)` (admin-only by path) |
| GET | `/api/logs` | `System`, `include_in_schema=False` | `Depends(require_auth)` (admin-only by path) |
| GET | `/api/health` | `System`, `OKResponse`, summary kept | public |

Moved helpers: `_FILE_ONLY_STATE_KEYS`, `_reject_file_only_settings`,
`OKResponse`. `OKResponse` had exactly these two consumers. The service
settings helpers at the top of `web/app.py` (`settings_bind_address`,
`settings_web_port`, `settings_s3_port`, `_reload_service_settings`) were
**not** moved: they are startup/deployment configuration used by
`web/unified.py`, not routes. "Settings" in this router means the deployment
settings document and its file-only-key guard.

## Includes and the trap that shaped them

`web/routers/__init__.py` exports `public_router` and `config_router`.
`web/app.py` includes them at the bottom, next to `s3_governance_api`, before
anything can call `permission_registry()`.

**FastAPI 0.142 does not copy an included router's routes into `app.routes`.**
`app.include_router(...)` appends one lazy `_IncludedRouter` placeholder that
resolves at request time. The frozen snapshot test iterates `app.routes`
directly, so a plain `include_router` made all 19 public routes disappear
from the surface; `PermissionRegistry(app.routes)` would also have missed
them, silently dropping them from the permission map.

Because the snapshot must stay byte-identical, `web/app.py` gained:

```python
def _include_router_eagerly(router) -> None:
    for route in router.routes:
        if hasattr(route, "dependency_overrides_provider"):
            route.dependency_overrides_provider = app
    app.router.routes.extend(router.routes)
```

and the two routers are registered with it instead of `include_router`. The
routers have absolute paths and no include-time prefix/tags/dependencies, so
this is equivalent to the pre-0.142 eager include.

The existing `s3_governance_api` router is still included lazily. Its routes
are therefore still absent from `app.routes` **and from the permission
registry** — a pre-existing gap, outside a move-only commit. It is the reason
a concurrent agent was adding `web.permissions.route_views()` and editing the
snapshot test while this step ran. This handoff deliberately does not depend
on that work; if it lands, `_include_router_eagerly` can be replaced by
`include_router` plus `route_views`, and the s3-governance gap closes at the
same time. Coordinate before doing that: the snapshot test is currently
modified in the working tree by that other agent.

## Call-time app state (why handlers use `_webapp()`)

`web/routers/*` must not import `web.app` at module scope (cycle). Each
module has `_webapp()` returning `import web.app as module`, and reads
app-owned state at call time. This is not cosmetic: tests monkeypatch
`webapp.db_connect`, `webapp.storage_transport`,
`webapp.STORAGE_SCRATCH_DIR`, `webapp.CONFIG_PATH`, `webapp._CONFIG_CACHE`,
`webapp._settings_store`, `webapp.LOG_BUFFER` and `webapp._log`. A
module-level `from web.app import db_connect` would freeze the old object and
break them.

The only body that could not move textually is `logs_stream`: it assigned a
module global (`global _main_event_loop`). It now does
`_webapp()._main_event_loop = asyncio.get_running_loop()`, which writes the
same attribute `_log` reads in `web/app.py`. `_LOG_WAITERS` and `LOG_BUFFER`
are read from `_webapp()` for the same reason.

## Line counts

| File | Before (this step) | After |
|---|---|---|
| `web/app.py` | 5766 | **5185** |
| `web/routers/public.py` | — | **531** |
| `web/routers/config.py` | — | **157** |

## What is left, in the plan's order

1. `web/routers/auth.py` — login/logout/me, `_get_current_user`,
   `_session_token_digest`, `db_connect` companions.
2. `web/routers/users.py` — "Detailed user management & role control" plus
   "User management".
3. `web/routers/telegram.py` — session management + channel management.
4. `web/routers/buckets.py` — bucket browser & quota.
5. `web/routers/s3admin.py` — S3 credential CRUD/reveal, multipart recovery,
   reindex.
6. `web/routers/rest.py` last — the `/api/v1/buckets/...` data plane,
   `_stream_object_upload`, `_valid_rest_key`, `_enforce_bucket_quota`.

`web/app.py` still owns `_log`/`LOG_BUFFER`, `db_connect`,
`read_raw_config`/`_redacted_config`/`validate_and_write_config`,
`_audit`, `_get_current_user`, `_rest_read_gate`, `_secure_mkdir`,
`storage_transport`, the middleware, startup and the app object. Those are
imported at call time by the routers that need them.

## Cleanup notes

- `web/app.py` now has imports that only the moved sections used (`hashlib`,
  `hmac`, `_html`, `secrets`, `threading`, `deque`, `_url_quote`, maybe
  `Path`). They were left in place to keep the commits move-only. Drop them
  in the step that removes the temporary re-exports.
- `docs/handoffs/02a`'s unused imports (`HTTPBearer`,
  `HTTPAuthorizationCredentials`, `READ_METHODS`, `is_admin_only`,
  `urlsplit`) are still there for the same reason.
- `web/permissions.py`'s docstring still points at `web.app._required_roles`;
  it lives in `web.deps`.

## Evidence (isolated worktree at `0b2948f`)

```
python -m compileall -q teledrive web            # clean
bandit -q -r teledrive web -ll                   # exit 0, no findings
pytest tests/web -q -n 4                         # 249 passed
pytest tests/meta/test_route_surface.py -q       # 2 passed (file unedited)
pytest tests/meta -q -n 4                        # 149 passed, 1 failed
pytest tests/ -q -n 4                            # 2002 passed, 109 skipped,
                                                 # 1 failed
```

The failure in both runs is
`tests/meta/test_ci_workflows.py::test_every_test_file_is_referenced_by_a_real_ci_workflow`:
`tests/storage/test_telegram_accounts_store.py` is not named in any workflow.
It reproduces at `adca54f` and touches neither `web/app.py` nor `web/routers/`;
it arrived with the concurrent stores change (`095fb51`). Not fixed here.
