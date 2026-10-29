# 02 — splitting `web/app.py` (do after 01)

Read `00-baseline.md` and `01-split-web-s3.md` first. Do this **after** the
`web/s3.py` split, because that split removes the gateway's coupling and makes
this one easier to verify.

## Why this is riskier than 01

`web/app.py` is 5 962 lines, 220 functions, ~112 routes, and it holds the
middleware, the startup hooks, the permission registry wiring and every
router. FastAPI registers a route **at import time from the decorator**, so a
careless move can silently change the path, the method, or the auth
dependency. The registry caches on first use, so a route added after the cache
is built never appears in the permission catalog — meaning `admin:*` would not
cover it and no role would be granted it.

## Step 0 — pin the surface before moving anything

Write a test that snapshots the authorization surface and assert on it:

```
python - <<'PY'
import web.app as a
rows = sorted((m, p, getattr(r.endpoint, "__module__", ""))
              for r in a.app.routes
              for m in (getattr(r, "methods", ()) or ()))
PY
```

Capture `(method, path, permission, admin_only)` for every route into
`tests/meta/test_route_surface.py` as a literal. That file is the contract:
the refactor may change which module a handler lives in, and must not change
the set of `(method, path, permission)` triples. Do this **before** the first
move so the snapshot is provably the pre-refactor surface.

## Target layout

Move by audience, matching the existing section comments:

| New module | Section in the current file |
|---|---|
| `web/routers/auth.py` | login/logout/me/change-password, session helpers |
| `web/routers/users.py` | "Detailed user management & role control" + "User management" |
| `web/routers/telegram.py` | "Telegram session management" + "Telegram channel management" |
| `web/routers/buckets.py` | "S3 bucket browser & quota" |
| `web/routers/rest.py` | the `/api/v1/buckets/{bucket}/...` data plane, `_stream_object_upload` |
| `web/routers/s3admin.py` | S3 credential CRUD/reveal, multipart recovery, reindex |
| `web/routers/public.py` | "Signed public share links", "Public website hosting", certificate, nested UI routes |
| `web/routers/config.py` | config GET/PUT, logs, health, settings |
| `web/deps.py` | `require_auth`, `require_api_scope`, `_same_origin`, role policy, permission registry access, `_log` |
| `web/errors.py` | `_telegram_error_response`, `_credential_error`, the exception handlers |

`web/app.py` keeps: app construction, middleware, startup/shutdown, the
`include_router(...)` calls, and the uvicorn entry point.

## The order that keeps the suite honest

1. **Snapshot test** (step 0). Commit it alone.
2. `web/deps.py` + `web/errors.py` — everything imports them, nothing imports
   them back. Move only; keep the names identical so `web/app.py` re-exports
   during the transition.
3. `web/routers/public.py` — the only section with no authenticated principal.
   Easiest to verify and it shrinks the file by the largest single block.
4. `web/routers/config.py`, then `auth.py`, then `users.py`.
5. `web/routers/telegram.py`, then `buckets.py`, then `s3admin.py`.
6. `web/routers/rest.py` last: it is the hottest path and it shares
   `_stream_object_upload`, `_enforce_bucket_quota` and the read gate with
   other handlers.
7. Delete the temporary re-exports only when `grep` shows no importer left.

## Per-router checklist (every one of them)

- [ ] `router = APIRouter()` has **no** prefix. The paths are absolute today
      and the permission registry matches on the full path; adding a prefix
      changes both the API and the permission names.
- [ ] Every state-changing handler still calls `_same_origin(request)`.
- [ ] Every handler keeps its exact `Depends(require_auth)` /
      `Depends(require_api_scope(...))` dependency. A moved route with a
      missing dependency is an unauthenticated route, and the snapshot test
      above is the only thing that will catch it.
- [ ] `include_router` happens **before** `permission_registry()` is first
      called anywhere (including at module import time in a test).
- [ ] The handler keeps its `name=`/`summary=` so OpenAPI does not drift
      (`tests/web/test_openapi.py` asserts on the schema).
- [ ] Helper functions go **above** the decorator block. A helper placed
      between a decorator and its function is registered as a route; this
      happened twice already and produced a `422 {"loc": ["query", ...]}`.

## Special care

- `_require_interactive_session` guards every secret-bearing S3 credential
  handler. If it moves to `deps.py`, keep the call in each handler.
- `_create_default_admin` and the schema/migration calls belong to startup.
  Do not move them into a router.
- The audit middleware prefixes every log line with the **request path**. The
  middleware must therefore stay on the outer app, not on a router.
- Rate-limit dicts (`_share_rate`, `AUTH_FAILURES`) are module-level state. If
  a handler moves and the dict does not, two copies of the limiter exist and
  the limit doubles. Move state with its consumer, or import it.

## Definition of done

- `wc -l web/app.py` under ~800.
- The step-0 snapshot test unchanged and green.
- `pytest tests/s3 tests/web tests/storage tests/meta -q -n 4` green.
- `python scripts/ops/sync_s3_inventory.py --check` green.
- A handoff describing, per router, exactly which routes moved and any
  behaviour you had to touch (there should be none).
