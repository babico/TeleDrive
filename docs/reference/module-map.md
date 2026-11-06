# Module map

Where code lives after the split of the original monolith, so a new endpoint,
store or table lands in the module that owns it instead of growing
`web/app.py` back. Line counts are measured with `wc -l` on the current tree;
they are a size signal, not the boundary.

## 1. HTTP surface

| Module | Lines | Responsibility |
| --- | ---: | --- |
| `web/app.py` | 1074 | App construction, middleware stack, lifespan/startup, the `include_router` calls, shared upload/read cores (`_stream_object_upload`, `_stream_object_response`, `_rest_read_gate`), the settings-document cache, auth bootstrap, and re-exports of settings/scheduler names the tests monkeypatch. Settings machinery lives in `web/settings_runtime.py`, scheduler loops in `web/schedulers.py`. |
| `web/s3.py` | 235 | The S3 gateway's public import path: the ASGI `app`, its HTTP middlewares (audit, encoded-control-key normalization, bootstrap gate), `ENVELOPE_ENABLED`, and re-exports from `web/s3_gateway/*`. |
| `web/routers/rest.py` | 282 | REST data plane `/api/v1/buckets/**`, authorized by per-route API-key permissions. Reaches shared cores through `_webapp()`. |
| `web/routers/auth.py` | 445 | Login/logout/me, the self-service password change and bootstrap probe, session resolution, PBKDF2 and the login throttle. |
| `web/routers/users.py` | 287 | User CRUD, roles, password reset, session revocation, the durable audit listing. |
| `web/routers/telegram.py` | 961 | Telegram session request/verify, health, quotas, channels, flood-wait, strategy, replication. |
| `web/routers/config.py` | 168 | Config GET/PUT, log buffer and WebSocket stream, health, settings guards. |
| `web/routers/public.py` | 544 | Share links, website hosting, the public certificate, and HTML page shells. Public routes authenticate inside the handler. |
| `web/routers/buckets.py` | 1079 | WebUI bucket browser: bucket CRUD, object browse/download/upload via session, quota, pins, CORS, share admin, search/reindex, usage. |
| `web/routers/s3admin.py` | 965 | S3 credential CRUD/reveal, API keys, multipart and pending-upload recovery, GC administration, storage jobs. |
| `web/deps.py` | 295 | `require_auth` (session + API key), `require_api_scope`, `_same_origin`, delegation/lifetime ceilings, role gate, `permission_registry()`. |
| `web/permissions.py` | 472 | Route-to-permission registry, role map, `is_admin_only`, `route_views()`. |
| `web/errors.py` | 79 | Error shaping and credential scrubbing. |
| `web/s3_gateway/*` | — | S3 implementation: `dispatch`, `objects`, `buckets`, `multipart`, `metadata_ops`, `authorization`, `checksums`, `ranges`, `xml`, `context`, `common`. |
| `web/s3_governance_api.py` | 1339 | `/s3/governance` write surface: policy, ABAC, encryption, replication, tiering, reports, notifications, logging. |
| `web/static/app.js` | 218 | Alpine bootstrap: shared primitives (`api`, `toast`, `confirmDelete`), role getters, `init`, guarded spreads of page groups. |
| `web/static/<group>.js` | — | `credentials`, `buckets`, `telegram`, `governance`, `admin`; each exports `<group>State()`/`<group>Methods()` and is loaded only where used, **before** `app.js`. `teledrive-crypto.js` holds the browser-side encryption helpers. |

## 2. Storage and data access

| Module | Lines | Responsibility |
| --- | ---: | --- |
| `teledrive/storage/schema.py` | 1120 | **The only DDL issuer.** 31 append-only, idempotent steps (`SCHEMA_VERSION` is the step count; v1.0.10 shipped 30); a real cross-process lock (flock / `pg_advisory_xact_lock` / `GET_LOCK`). Every step is catalogued in [Schema steps](schema-steps.md). |
| `teledrive/storage/catalog.py` | 139 | `BucketCatalog` assembly: construction, static validators, cross-cutting transaction helpers, table re-exports. |
| `teledrive/storage/catalog_tables.py` | 107 | Table and index declarations. |
| `teledrive/storage/catalog_buckets.py` | 229 | Bucket create/list/delete, versioning state, public read, Public Access Block, ownership. |
| `teledrive/storage/catalog_versions.py` | 878 | `publish`, `delete_marker`, `delete_version`, `remove_current`, rename, listings, legacy head indexing. |
| `teledrive/storage/catalog_lock.py` | 212 | Object lock, retention, legal hold, read gate, access counters. |
| `teledrive/storage/catalog_acl.py` | 101 | Bucket and object ACL grants. |
| `teledrive/storage/manifest.py` | 712 | Manifests, chunks, aliases, writer fences, encryption markers. |
| `teledrive/storage/envelope.py` / `sse.py` | 163 / 265 | Envelope (SSE-S3) key wrapping and SSE-C primitives. |
| `teledrive/storage/engine.py` | 987 | Upload/read orchestration over the transport and catalog. |
| `teledrive/storage/cold_store.py` | 1046 | Sealed cold archive (`ColdBlobStore`), archive/restore state machine, leases and generation fences. |
| `teledrive/storage/gc_collect.py` | 618 | Physical collection: candidates, leases, execution, journal. |
| `teledrive/storage/copy.py` / `quota.py` / `audit.py` | 204 / 115 / 146 | Copying, quota enforcement, durable security trail. |
| `teledrive/stores/*` | — | Typed table access: `users`, `sessions`, `shares`, `pins`, `telegram_pending`, `telegram_accounts`, `content_index`. |
| `teledrive/s3/*` | — | Protocol modules (SigV4, policy, ACL, tagging, lifecycle, multipart, reports, tiering, directory buckets, ...); the machine-readable inventory is `operation_manifest.json`. |

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
| `tests/meta/test_route_surface.py` | The exact `(method, path, permission, admin_only)` surface, in both directions; every non-public route has a permission (currently 163 surface entries: 140 permissioned method/path pairs plus one WebSocket). |
| `tests/meta/test_schema_ddl_is_centralized.py` | No DDL text outside `schema.py`, except the declared step-owned module. |
| `tests/meta/test_no_swallowed_name_errors.py` | A broad `except Exception` must not hide a name its scope cannot resolve. |
| `tests/web/test_page_composition.py` | Markup and fragment script tags agree; fragments load before `app.js`. |
| `tests/meta/test_ci_workflows.py` | Every `tests/test_*.py` module is referenced by a real, unconditional pytest step. |
| `tests/meta/test_docs_nav.py` | Every docs page is in `mkdocs.yml`, every relative link resolves, no placeholder survived. |

A refactor that changes one of these rules is not a refactor; it is an
authorization or schema change and needs its own review.

## 6. Complete module inventory

Every non-package Python module under `web/` and `teledrive/`, plus the
non-vendor frontend files, with `wc -l` on the current tree. The tables above
explain the load-bearing modules; this list is the completeness check, so a
new module is added here (and every path below resolves today).

### Web

| Module | Lines |
| --- | ---: |
| `web/app.py` | 1074 |
| `web/certs.py` | 82 |
| `web/container_healthcheck.py` | 72 |
| `web/deps.py` | 295 |
| `web/errors.py` | 79 |
| `web/permissions.py` | 472 |
| `web/s3.py` | 235 |
| `web/s3_governance_api.py` | 1339 |
| `web/schedulers.py` | 293 |
| `web/settings_runtime.py` | 522 |
| `web/unified.py` | 112 |
| `web/routers/auth.py` | 445 |
| `web/routers/buckets.py` | 1079 |
| `web/routers/config.py` | 168 |
| `web/routers/public.py` | 544 |
| `web/routers/rest.py` | 282 |
| `web/routers/s3admin.py` | 965 |
| `web/routers/telegram.py` | 961 |
| `web/routers/users.py` | 287 |
| `web/s3_gateway/authorization.py` | 195 |
| `web/s3_gateway/buckets.py` | 1346 |
| `web/s3_gateway/checksums.py` | 148 |
| `web/s3_gateway/common.py` | 299 |
| `web/s3_gateway/context.py` | 71 |
| `web/s3_gateway/dispatch.py` | 958 |
| `web/s3_gateway/metadata_ops.py` | 751 |
| `web/s3_gateway/multipart.py` | 743 |
| `web/s3_gateway/objects.py` | 1392 |
| `web/s3_gateway/ranges.py` | 146 |
| `web/s3_gateway/xml.py` | 166 |
| `web/static/admin.js` | 365 |
| `web/static/app.js` | 218 |
| `web/static/buckets.js` | 382 |
| `web/static/credentials.js` | 751 |
| `web/static/governance.js` | 391 |
| `web/static/teledrive-crypto.js` | 129 |
| `web/static/telegram.js` | 294 |

### Teledrive

| Module | Lines |
| --- | ---: |
| `teledrive/api_keys.py` | 376 |
| `teledrive/db.py` | 521 |
| `teledrive/settings.py` | 279 |
| `teledrive/settings_store.py` | 111 |
| `teledrive/uploader.py` | 184 |
| `teledrive/s3/acl.py` | 289 |
| `teledrive/s3/annotations.py` | 365 |
| `teledrive/s3/aws_chunked.py` | 236 |
| `teledrive/s3/batch_delete.py` | 137 |
| `teledrive/s3/bucket_encryption.py` | 205 |
| `teledrive/s3/bucket_flags.py` | 135 |
| `teledrive/s3/bucket_listing.py` | 139 |
| `teledrive/s3/checksums.py` | 55 |
| `teledrive/s3/conditions.py` | 61 |
| `teledrive/s3/cors.py` | 266 |
| `teledrive/s3/credentials.py` | 417 |
| `teledrive/s3/directory_buckets.py` | 590 |
| `teledrive/s3/lifecycle.py` | 1183 |
| `teledrive/s3/metadata_journal.py` | 815 |
| `teledrive/s3/multipart.py` | 1005 |
| `teledrive/s3/notifications.py` | 810 |
| `teledrive/s3/object_metadata.py` | 130 |
| `teledrive/s3/ownership.py` | 77 |
| `teledrive/s3/policy.py` | 834 |
| `teledrive/s3/post_policy.py` | 229 |
| `teledrive/s3/public_access.py` | 76 |
| `teledrive/s3/replication.py` | 419 |
| `teledrive/s3/report_configs.py` | 584 |
| `teledrive/s3/report_runner.py` | 503 |
| `teledrive/s3/restore.py` | 153 |
| `teledrive/s3/route_guard.py` | 384 |
| `teledrive/s3/select.py` | 884 |
| `teledrive/s3/sigv4.py` | 580 |
| `teledrive/s3/tagging.py` | 384 |
| `teledrive/s3/tiering.py` | 573 |
| `teledrive/s3/versioning.py` | 61 |
| `teledrive/s3/website.py` | 225 |
| `teledrive/s3/write_conditions.py` | 82 |
| `teledrive/storage/audit.py` | 146 |
| `teledrive/storage/catalog.py` | 139 |
| `teledrive/storage/catalog_acl.py` | 101 |
| `teledrive/storage/catalog_buckets.py` | 229 |
| `teledrive/storage/catalog_lock.py` | 212 |
| `teledrive/storage/catalog_tables.py` | 107 |
| `teledrive/storage/catalog_versions.py` | 878 |
| `teledrive/storage/cold_store.py` | 1046 |
| `teledrive/storage/content_index.py` | 200 |
| `teledrive/storage/copy.py` | 204 |
| `teledrive/storage/cutover_acceptance.py` | 206 |
| `teledrive/storage/engine.py` | 987 |
| `teledrive/storage/envelope.py` | 163 |
| `teledrive/storage/gc.py` | 298 |
| `teledrive/storage/gc_collect.py` | 618 |
| `teledrive/storage/gc_safety.py` | 192 |
| `teledrive/storage/history_inventory.py` | 184 |
| `teledrive/storage/jobs.py` | 547 |
| `teledrive/storage/legacy_bridge.py` | 85 |
| `teledrive/storage/manifest.py` | 712 |
| `teledrive/storage/mtproto_rate_guard.py` | 301 |
| `teledrive/storage/placement.py` | 28 |
| `teledrive/storage/quota.py` | 115 |
| `teledrive/storage/rebuild.py` | 240 |
| `teledrive/storage/reconcile_inventory.py` | 98 |
| `teledrive/storage/recovery.py` | 238 |
| `teledrive/storage/schema.py` | 1120 |
| `teledrive/storage/sse.py` | 265 |
| `teledrive/storage/target_resolver.py` | 55 |
| `teledrive/storage/telethon_adapter.py` | 163 |
| `teledrive/storage/user_mode.py` | 899 |
| `teledrive/stores/content_index.py` | 85 |
| `teledrive/stores/pins.py` | 60 |
| `teledrive/stores/sessions.py` | 118 |
| `teledrive/stores/shares.py` | 135 |
| `teledrive/stores/telegram_accounts.py` | 341 |
| `teledrive/stores/telegram_pending.py` | 101 |
| `teledrive/stores/users.py` | 191 |
