# Module map

Where things live now. Read this before adding code, so a new endpoint or
store lands in the right file instead of growing `web/app.py` back.

Line counts are indicative; the point is the boundary, not the number.

## HTTP surface

| Module | What belongs there |
|---|---|
| `web/app.py` | App construction, the middleware stack, startup/shutdown, `include_router` calls, the REST data plane (`/api/v1/buckets/{bucket}/…`), the shared upload/read cores (`_stream_object_upload`, `_stream_object_response`), and re-exports of every name the tests reach. |
| `web/routers/auth.py` | Login, logout, me, password change, session helpers, login throttling. |
| `web/routers/users.py` | User CRUD, role changes, password reset, session revocation, `GET /admin/audit`. |
| `web/routers/telegram.py` | Telegram session request/verify, health check, quotas, channels, flood-wait, strategy, replication. |
| `web/routers/config.py` | Config GET/PUT, logs (REST + websocket), health, settings. |
| `web/routers/public.py` | Share links, website hosting, certificates, and the HTML page shells. Nothing here has an authenticated principal; page shells authenticate inside the handler. |
| `web/routers/buckets.py` | The WebUI bucket browser: bucket CRUD, object browse/download/upload via session, quota, pins, CORS, share admin, search/reindex, usage. |
| `web/routers/s3admin.py` | S3 credential CRUD/reveal, API keys, multipart and pending-upload recovery, GC administration, storage jobs. |
| `web/deps.py` | `require_auth` (session + API key), `require_api_scope`, `_same_origin`, the delegation/lifetime ceilings, the role gate, `permission_registry()`. |
| `web/errors.py` | Error shaping: `_scrub_text`, `_credential_error`, `_telegram_error_response`. |
| `web/permissions.py` | Route → permission registry, the role map, `is_admin_only`, and `route_views()`. |
| `web/s3.py` | The S3 gateway's public import path: the ASGI `app`, both middlewares, and re-exports. |
| `web/s3_gateway/*` | The S3 implementation: `dispatch`, `objects`, `buckets`, `multipart`, `metadata_ops`, `authorization`, `checksums`, `ranges`, `xml`, `context`, `common`. |
| `web/s3_governance_api.py` | The `/s3/governance` write surface (policy, ABAC, encryption, replication, tiering, reports, notifications, logging). |

## Storage

| Module | What belongs there |
|---|---|
| `teledrive/storage/schema.py` | **The only place that issues DDL.** Append-only steps, a recorded version, a real cross-process lock per backend. |
| `teledrive/storage/catalog.py` | `BucketCatalog` assembly: `__init__`, the static validators, the cross-cutting transaction helpers, and re-exports of every table. |
| `teledrive/storage/catalog_tables.py` | The table and index declarations. |
| `teledrive/storage/catalog_buckets.py` | Bucket create/list/delete, versioning state, public read, public access block, ownership. |
| `teledrive/storage/catalog_versions.py` | `publish`, `delete_marker`, `delete_version`, `remove_current`, rename, listings, `index_legacy_current_heads`. |
| `teledrive/storage/catalog_lock.py` | Object lock, retention, legal hold, the read gate, access counters. |
| `teledrive/storage/catalog_acl.py` | Bucket and object ACL grants. |
| `teledrive/storage/manifest.py` | Object manifests, chunks, aliases, writer fences, encryption markers. |
| `teledrive/storage/envelope.py` | Envelope (SSE-S3) keys: derive the KEK, wrap/unwrap a per-object data key. |
| `teledrive/storage/sse.py` | SSE-C primitives. |
| `teledrive/storage/gc_collect.py` | Physical collection: candidates, leases, execution, the journal. |
| `teledrive/storage/copy.py` / `quota.py` / `audit.py` | Copying, quota enforcement, the durable security trail. |
| `teledrive/stores/*` | Typed access to the SQL tables: `users`, `sessions`, `shares`, `pins`, `telegram_pending`, `telegram_accounts`, `content_index`. |

## WebUI assets

| Module | What belongs there |
|---|---|
| `web/static/app.js` | The Alpine component's bootstrap: shared primitives (`api`, `toast`, `confirmDelete`), role getters, `init`, and the guarded spreads of the page groups. |
| `web/static/<page-group>.js` | `credentials`, `buckets`, `telegram`, `governance`, `admin` — each exports `<group>State()` / `<group>Methods()` and is loaded only on the pages that call it, **before** `app.js`. |

## Rules that keep this shape

1. **A route belongs to the module that matches its audience**, not its entity.
2. **`include_router` only.** Never mutate `app.router.routes`; FastAPI 0.142
   keeps includes lazy and `route_views()` flattens them.
3. **`tests/meta/test_route_surface.py` is the contract.** It asserts all 159
   `(method, path, permission, admin_only)` tuples in both directions. A move
   that changes one is a bug in the move.
4. **No DDL outside `schema.py`** — enforced by `test_schema_ddl_is_centralized.py`.
5. **No `try/except Exception` around an unresolvable name** — enforced by
   `test_no_swallowed_name_errors.py`. Two real bugs had that shape and were
   silently dead.
6. **A page's script tags must load every fragment its `init()` reaches**, not
   only what its markup calls. `test_page_composition.py` checks the markup
   and knows its own blind spot; follow `init()` by hand.
