# 00 — baseline: what the code looks like and how to split it

Written before any refactor. Read this first; it is the shared map.

> **This section describes the tree at the START of the refactor.** The live
> map is [docs/MODULE_MAP.md](../MODULE_MAP.md) — read that for where code
> lives today.

## Current shape

| File | Lines | What it is |
|---|---|---|
| `web/app.py` | ~5 960 | FastAPI application: auth, users, S3 credential admin, Telegram session/channel admin, bucket browser, REST data plane, public share links, website hosting, settings, logs |
| `web/s3.py` | ~5 110 | The S3 gateway: SigV4 verification, routing, every S3 operation, policy/ACL/ABAC authorization |
| `web/s3_governance_api.py` | ~400 | `/s3/governance` writes (policy, ABAC, encryption, replication, tiering, reports, notifications, logging) |
| `web/permissions.py` | ~350 | Route → permission registry, role map, admin-only classification |
| `teledrive/storage/catalog.py` | ~1 445 | Bucket/head/version catalog, publish CAS, delete paths |
| `teledrive/storage/manifest.py` | ~1 000 | Object manifests, chunks, aliases, writer fences, SSE-C markers |
| `teledrive/storage/schema.py` | ~390 | The one schema coordinator (22 ordered steps, cross-process lock) |
| `web/static/app.js` | ~1 470 | The whole WebUI: one Alpine component with every page's state |

`web/app.py` already has section markers, which are the natural split seams:

```
1733  Nested UI routes
1788  public certificate distribution
2074  Detailed user management & role control
2364  Telegram session management
3118  Telegram channel management
3417  User management
3508  S3 bucket browser & quota
5609  Signed public share links
5795  Public website hosting
```

## Target layout

Split by **who can call it**, not by entity. That is the boundary the
permission registry already encodes, and it keeps the authorization story
readable in one file per surface.

```
web/app.py                 app factory, middleware, startup, include_router calls only
web/routers/auth.py        login/logout/me/password, session issue
web/routers/users.py       user CRUD, role, sessions
web/routers/config.py      GET/PUT config, logs, health
web/routers/telegram.py    session request/verify, channels, health-check, quotas
web/routers/buckets.py     WebUI bucket browser, quota, pins, shares admin
web/routers/rest.py        the /api/v1/buckets/{bucket}/... data plane
web/routers/public.py      /share/{token}, /s3/... public pages, certificate
web/routers/s3admin.py     S3 credential CRUD, reveal, multipart recovery
web/s3/__init__.py         gateway entry (keeps `import web.s3` working)
web/s3/signing.py          SigV4 parsing/verification
web/s3/authorization.py    policy + ABAC + ACL decision point
web/s3/objects.py          object operations
web/s3/buckets.py          bucket operations
web/s3/multipart.py        multipart operations
web/s3/governance_routes.py the per-bucket metadata configuration operations
web/static/pages/*.js      one Alpine component per page, imported by app.js
```

## Invariants that MUST survive any move

These are load-bearing and each one has a test. If a split breaks one, the
split is wrong, not the test.

1. **One permission registry.** `web.permissions.PermissionRegistry` is built
   from the live route table. A router included without its final prefix, or a
   route registered after the registry is cached, changes the authorization
   surface. `permission_registry()` is cached on first use; the cache must be
   built after every router is included.
2. **`admin:*` expands over the live table.** `teledrive/api_keys.py` learns
   it through `set_route_permissions_provider`, installed inside
   `permission_registry()`. Do not move that hook to import time.
3. **No DDL outside `teledrive/storage/schema.py`.** No `create_all` and no
   `ALTER TABLE` in a router or a store constructor.
4. **`_same_origin` (CSRF header + Origin match) on every state change.**
   Moving a handler into another module must keep the call; the middleware
   does not do it for you.
5. **Secret-bearing handlers are interactive-session only**
   (`_require_interactive_session`): S3 credential issue/edit/revoke/reveal.
6. **The S3 inventory is generated.** `scripts/ops/sync_s3_inventory.py`
   rewrites `docs/S3_SPECS.md`, the route-guard counters and the meta totals
   from `teledrive/s3/operation_manifest.json`. Never edit those by hand; CI
   runs `--check`.
7. **Schema steps are append-only.** `SCHEMA_VERSION` is the step count, so
   editing a shipped step never runs on an existing database. Append.
8. **HTTP exceptions, not leaked internals.** Error text must not contain a
   filesystem path, SQL, or a secret. Three audit findings were exactly this.

## Landmines found the hard way

- A helper defined **between a decorator and its function** is registered as a
  route by FastAPI. This happened twice in one session and produced a
  confusing `422 {"loc": ["query", "manifests"]}`. When adding helpers near a
  route, put them above the decorator block.
- `TestClient` shares one cookie jar for the whole client. A second login
  silently replaces the session the rest of the test uses; log in with a
  bearer token and clear the jar (`tests/__init__.py::login_headers`).
- `pytest -n 4` forbids random values at import time (no `uuid4()` or
  `os.urandom()` in `parametrize`).
- MySQL: no `ON CONFLICT`, no `INSERT OR IGNORE`, no `RETURNING`, no default
  on `TEXT`, and `information_schema` probes must filter by `DATABASE()`.
- SQLite: an `Integer` primary key reuses rowids, so a child table without a
  foreign key can silently re-attach to a new parent (this caused a session
  resurrection bug).

## Landmine added later (read this before touching routes)

**FastAPI 0.142 does not copy an included router's routes into
`app.routes`.** `app.include_router(...)` appends one lazy `_IncludedRouter`
that resolves at request time. Anything that enumerates `app.routes` -- a
permission registry, a snapshot test, a "what routes exist" script -- silently
misses every router-included endpoint while the app keeps serving them
correctly.

This cost 44 routes before it was caught:

* the 19 public routes dropped out of the permission registry the moment
  `web/routers/public.py` was included, and
* the 25 S3 governance routes had **never** been in it, because that router
  was included lazily from the day it was written. `_actor()` still
  authenticated and role-gated them, so it was not an open door -- but they
  were absent from `admin:*`'s expansion and from the surface snapshot.

Use `web.permissions.route_views(app)`. It flattens both shapes (a normal
route, or an included router's effective contexts) and is what the registry
and `tests/meta/test_route_surface.py` read. Do not mutate
`app.router.routes` by hand to work around this; that reintroduces a second
registration path.

## How to verify a step

```
python -m compileall -q teledrive web
bandit -q -r teledrive web -ll
pytest tests/s3 tests/web tests/storage tests/meta -q -n 4
python scripts/ops/sync_s3_inventory.py --check
```

Baseline before the refactor: **1790 passed, 48 skipped, bandit clean,
inventory 114 supported / 0 partial / 2 unsupported.**
