# Module map

Where code lives after the split of the original monolith, so a new endpoint,
store or table lands in the module that owns it instead of growing
`web/app.py` back. Line counts are measured with `wc -l` on the current tree;
they are a size signal, not the boundary.

## 1. HTTP surface

| Module | Lines | Responsibility |
| --- | ---: | --- |
| `web/app.py` | 1576 | App construction, middleware stack, lifespan/startup, the `include_router` calls, shared upload/read cores (`_stream_object_upload`, `_stream_object_response`, `_rest_read_gate`), settings read/write, auth bootstrap, and re-exports of names the tests monkeypatch. |
| `web/s3.py` | 191 | The S3 gateway's public import path: the ASGI `app`, both middlewares, `ENVELOPE_ENABLED`, and re-exports from `web/s3_gateway/*`. |
| `web/routers/rest.py` | 279 | REST data plane `/api/v1/buckets/**`, authorized by per-route API-key permissions. Reaches shared cores through `_webapp()`. |
| `web/routers/auth.py` | 280 | Login/logout/me, password change helpers, session resolution, PBKDF2 and the login throttle. |
| `web/routers/users.py` | 287 | User CRUD, roles, password reset, session revocation, the durable audit listing. |
| `web/routers/telegram.py` | 930 | Telegram session request/verify, health, quotas, channels, flood-wait, strategy, replication. |
| `web/routers/config.py` | 168 | Config GET/PUT, log buffer and WebSocket stream, health, settings guards. |
| `web/routers/public.py` | 544 | Share links, website hosting, the public certificate, and HTML page shells. Public routes authenticate inside the handler. |
| `web/routers/buckets.py` | 1079 | WebUI bucket browser: bucket CRUD, object browse/download/upload via session, quota, pins, CORS, share admin, search/reindex, usage. |
| `web/routers/s3admin.py` | 965 | S3 credential CRUD/reveal, API keys, multipart and pending-upload recovery, GC administration, storage jobs. |
| `web/deps.py` | 295 | `require_auth` (session + API key), `require_api_scope`, `_same_origin`, delegation/lifetime ceilings, role gate, `permission_registry()`. |
| `web/permissions.py` | 472 | Route-to-permission registry, role map, `is_admin_only`, `route_views()`. |
| `web/errors.py` | — | Error shaping and credential scrubbing. |
| `web/s3_gateway/*` | — | S3 implementation: `dispatch`, `objects`, `buckets`, `multipart`, `metadata_ops`, `authorization`, `checksums`, `ranges`, `xml`, `context`, `common`. |
| `web/s3_governance_api.py` | 1281 | `/s3/governance` write surface: policy, ABAC, encryption, replication, tiering, reports, notifications, logging. |
| `web/static/app.js` | 167 | Alpine bootstrap: shared primitives (`api`, `toast`, `confirmDelete`), role getters, `init`, guarded spreads of page groups. |
| `web/static/<group>.js` | — | `credentials`, `buckets`, `telegram`, `governance`, `admin`; each exports `<group>State()`/`<group>Methods()` and is loaded only where used, **before** `app.js`. |

## 2. Storage and data access

| Module | Lines | Responsibility |
| --- | ---: | --- |
| `teledrive/storage/schema.py` | 726 | **The only DDL issuer.** 27 append-only, idempotent steps; `SCHEMA_VERSION` is the step count; a real cross-process lock (flock / `pg_advisory_xact_lock` / `GET_LOCK`). |
| `teledrive/storage/catalog.py` | 132 | `BucketCatalog` assembly: construction, static validators, cross-cutting transaction helpers, table re-exports. |
| `teledrive/storage/catalog_tables.py` | — | Table and index declarations. |
| `teledrive/storage/catalog_buckets.py` | 273 | Bucket create/list/delete, versioning state, public read, Public Access Block, ownership. |
| `teledrive/storage/catalog_versions.py` | 775 | `publish`, `delete_marker`, `delete_version`, `remove_current`, rename, listings, legacy head indexing. |
| `teledrive/storage/catalog_lock.py` | 174 | Object lock, retention, legal hold, read gate, access counters. |
| `teledrive/storage/catalog_acl.py` | — | Bucket and object ACL grants. |
| `teledrive/storage/manifest.py` | 712 | Manifests, chunks, aliases, writer fences, encryption markers. |
| `teledrive/storage/envelope.py` / `sse.py` | 163 / 250 | Envelope (SSE-S3) key wrapping and SSE-C primitives. |
| `teledrive/storage/engine.py` | 936 | Upload/read orchestration over the transport and catalog. |
| `teledrive/storage/gc_collect.py` | 575 | Physical collection: candidates, leases, execution, journal. |
| `teledrive/storage/copy.py` / `quota.py` / `audit.py` | 185 / — / 80+ | Copying, quota enforcement, durable security trail. |
| `teledrive/stores/*` | — | Typed table access: `users`, `sessions`, `shares`, `pins`, `telegram_pending`, `telegram_accounts`, `content_index`. |
| `teledrive/s3/*` | — | Protocol modules (SigV4, policy, ACL, tagging, lifecycle, multipart, reports, tiering, ...); the machine-readable inventory is `operation_manifest.json`. |

## 3. Layering rules

1. **Routers own HTTP, stores own rows, storage owns objects.**
   `web/routers/*` parses and authorizes a request, then calls a function in
   `teledrive/stores/*` or a catalog/engine method. It must not open its own
   transaction or invent SQL. The split exists because three dialect bugs and
   a permission read/write mismatch all came from handlers doing database work
   inline.
2. **Raw SQL only for annotated read-only aggregates.** A `text()` query is
   permitted when it is a cross-table count/sum for an observability endpoint
   and carries a comment saying so — the `GET /api/v1/metrics` scrape is the
   model. Anything that mutates a row belongs in a typed store, because
   `ON CONFLICT`, `INSERT OR IGNORE` and `RETURNING` are not portable across
   the three tested backends.
3. **`schema.py` is the only DDL issuer.** No `create_all`, `ALTER TABLE`,
   `CREATE INDEX` or `DROP` anywhere else. Step bodies may live in the module
   that owns the tables (for example the content-search FTS/tsvector
   structures), but the coordinator decides when they run. This prevents the
   duplicate-ALTER, never-runs and startup-race failures the project already
   shipped.
4. **`include_router` only.** Never mutate `app.router.routes`. FastAPI 0.142
   keeps an included router lazy, so iterating `app.routes` misses every
   router endpoint. `web.permissions.route_views()` flattens both shapes and
   synthesizes a `WEBSOCKET` method for sockets; the registry and the surface
   snapshot must both read through it. Skipping this dropped 19 routes from
   the permission map once.
5. **One route, one permission.** The registry derives a permission from
   method + path template. A new route that is not deliberately public and has
   no permission fails the surface test.
6. **A page loads every fragment its `init()` reaches.** Script order matters:
   fragments before `app.js`. `tests/web/test_page_composition.py` checks the
   markup and documents its blind spot, so follow `init()` by hand for a new
   call.

## 4. Where to add something

### A new HTTP route

1. Pick the router by **audience**, not entity: REST data plane →
   `web/routers/rest.py`; WebUI bucket UI → `buckets.py`; credential/key/GC
   admin → `s3admin.py`; config/logs → `config.py`; Telegram → `telegram.py`;
   user management → `users.py`; public/share/website → `public.py`; S3 →
   `web/s3_gateway/` dispatched from `dispatch.py`.
2. Add the handler with `Depends(require_auth)` (or the router's existing
   dependency), and call `_same_origin(request)` for a state change.
3. If the route must be admin-only, add its surface to `web/permissions.py`
   (`_ADMIN_ONLY_PREFIXES`, the session-mutation set, or the bucket
   quota/website rule) rather than an ad-hoc role check.
4. Update `tests/meta/test_route_surface.py` in the **same commit**. The table
   is a review artifact: a moved route that loses its dependency is an
   unauthenticated route, and only the surface assertion catches that.
5. Add behaviour tests named for the behaviour, and make sure a real workflow
   references the file — `tests/meta/test_ci_workflows.py` fails an
   unscheduled module.

### A new store function

Add it to the matching `teledrive/stores/<table>.py`. Take the `Database`
wrapper, return plain dicts/dataclasses (not `Row`), commit once at the end of
a logical operation, use `LIMIT 1` plus a deterministic `ORDER BY` whenever a
`WHERE` can match several rows, and write portable UPDATE-then-INSERT instead
of an upsert dialect. If the table has no store yet, create one and move only
the calls that table owns.

### A new table or column

Append a step to `_STEPS` in `teledrive/storage/schema.py` and raise
`SCHEMA_VERSION` implicitly by doing so. The step must be idempotent
(`checkfirst` / a column-existence probe before `ALTER`), because a whole
stale range is re-run once. Declare the `Table` in the owning module (usually
`catalog_tables.py` or the feature module) and export it where existing code
expects it. Never issue the DDL from a store constructor.

## 5. Meta-tests that enforce this map

| Test | Rule it pins |
| --- | --- |
| `tests/meta/test_route_surface.py` | The exact `(method, path, permission, admin_only)` surface, in both directions; every non-public route has a permission (currently 160 surface entries, 139 permissioned method/path pairs plus one WebSocket). |
| `tests/meta/test_schema_ddl_is_centralized.py` | No DDL text outside `schema.py`, except the declared step-owned module. |
| `tests/meta/test_no_swallowed_name_errors.py` | A broad `except Exception` must not hide a name its scope cannot resolve. |
| `tests/web/test_page_composition.py` | Markup and fragment script tags agree; fragments load before `app.js`. |
| `tests/meta/test_ci_workflows.py` | Every `tests/test_*.py` module is referenced by a real, unconditional pytest step. |
| `tests/meta/test_docs_nav.py` | Every docs page is in `mkdocs.yml`, every relative link resolves, no placeholder survived. |

A refactor that changes one of these rules is not a refactor; it is an
authorization or schema change and needs its own review.
