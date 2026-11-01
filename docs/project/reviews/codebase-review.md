# TeleDrive — Codebase Review

**Audit point:** `main` @ `054af3a` (`fix(storage): MySQL-compatible PAB default and schema-scoped column probe`), 2026-10-26.
**Scope:** `teledrive/`, `web/`, `web/static/`, `tests/`, `scripts/ops/`.
**Method:** `find`/`wc`, `grep`, Python AST scan, GitHub REST API, `git diff --check`/`git apply --check` (read-only).
**Note:** During the audit the working tree contained uncommitted changes from another process under `.github/workflows/*`, `Dockerfile`, `docker-compose.yml`, `config.example.yaml`, `teledrive/settings.py`, `web/app.py`, `tests/meta/test_ci_workflows.py` and `deploy/`. Those changes are outside this report's scope; all line numbers refer to the **committed `054af3a` tree** above and may have drifted relative to the temporary working tree.

---

## 0.1 Fix status (2026-10-26)

Findings closed after the audit — each with a regression test:

| Finding | State | Commit / evidence |
|---|---|---|
| **P4** privilege escalation via API key (mint/rotate/revoke) | ✅ Closed | `9c4769d` — delegation ceiling: a key can only delegate within its own permission set; `test_api_key_cannot_mint_beyond_its_own_permissions`, `..._rotation_cannot_steal_a_more_privileged_key`, `..._cannot_revoke_above_its_own_authority` |
| **P8** batch delete / CopyObject / UploadPartCopy ACL bypass | ✅ Closed | `9c4769d` — each batch entry is checked with its own key, both copy paths are checked against the source ACL; `test_batch_delete_honours_per_object_acl`, `test_copy_object_honours_the_source_object_acl` |
| **P9** ACL ownership can be transferred (takeover) | ✅ Closed | `9c4769d` — ownership cannot be changed; any other Owner name is 400; `test_block_public_acls_locks_acl_writes_to_the_owner` |
| **P11** expired credential reveal + presign scope | ✅ Closed | `9c4769d` — `reveal()` refuses expired, presign requires `s3:GetObject`; `test_reveal_refuses_expired_credential` |
| **P3** physical GC open to operator | ✅ Closed | `9c4769d` — GC toggle + collect are now admin-only; `test_physical_gc_is_admin_only` |
| **P7** audit identity can be spoofed | ✅ Closed | `4365694` — an unverified Basic name is written as `unverified-basic`; verified live (`[unverified-basic] ... -> 401`) |
| **P5** Session ↔ bearer permission asymmetry | ✅ Closed | Role→permission map (`web/permissions.py`): admin all permissions, operator all data/storage, viewer read-only; session and Basic use the same map. `test_auth_single_model.py` |
| **P6** Legacy Basic = unconditional admin | ✅ Closed | Basic is verified against the `users` table with PBKDF2, `enabled` and the real role are enforced; the configuration password does not authenticate. On first boot the fixed `admin`/`admin` is only added if no `admin` row exists, and an existing row is never overwritten. `test_auth_single_model.py`, `docs/UPGRADING.md` §7 |
| O4 schema initialisation race | ⏳ Open | Requires a separate migration/lock refactor (§3.3) |
| P1/P2/P10, O1/O5/O12, A1–A4 | ⏳ Open | Structural refactor; should be handled in the order in §4 |

## 0. Executive Summary

- There are **20,051 lines** of production code (`teledrive/**/*.py`, `web/*.py`) and **3,506 lines** of frontend (`web/static/*.js|html`, vendor included; 3,402 of business code). Test code is **~23,500 lines**; the test/production ratio is healthy (~1.17).
- But **42% of the production code is in two files**: `web/app.py` (5,031) + `web/s3.py` (3,388). Those two files carry 129 routes and 59+ handlers.
- SQLAlchemy is used **not as an ORM but as a query builder/DBAPI**: 0 declarative models, **9 separate `MetaData`**, 46 `Table`, 5 `Index`, 15 `ForeignKey`, **125 `text()` calls**.
- The highest risks are not code volume but **the number of authorization layers**: session + cookie, legacy Basic, two separate bearer paths, S3 SigV4, S3 ACL intersection and the public share token are all active at once. Across those layers 3 critical bypasses and 1 privilege-escalation path were found.
- All 3 open PRs were opened from old `main` SHAs. #24 is still applicable (docs-only); #22 is fully superseded; only the static SQL cleanup of #25 should be salvaged.

**Total findings: 76** (15 inventory + 12 ORM + 11 permission + 15 refactor + 3 PR + 20 small cuts).

---

## 1. Large File Inventory (>= 600 lines)

> Sorted by line count, descending. The largest HTML file is `buckets.html` (325 lines), so there is **no 600+ HTML**; HTML is therefore discussed in a separate paragraph. `web/static/vendor/*` was excluded from the line inventory because it is minified/vendor (Tailwind runtime 400 KB, Alpine 56 KB — §6/C19).

| # | File | Lines | Type | Split? | Concrete split proposal |
|---|-------|------:|-----|---------------|---------------------|
| 1 | `web/app.py` | 5,031 | Python | **Yes, mandatory** | `web/app_factory.py` + `web/routers/{auth,users,api_keys,s3_credentials,telegram,storage_buckets,storage_jobs,gc,shares,config,system}.py` + `web/security.py` + `web/logging.py` + `web/config_store.py`. A single 5,000-line module also breaks test isolation. |
| 2 | `web/s3.py` | 3,388 | Python | **Yes, mandatory** | `web/s3/{router,responses,authz,bucket_controls,objects,multipart,acl,object_lock,listing,form_upload}.py`. `_handle()` alone is ~450 lines (2821-3270). Protocol parsing already lives in `teledrive/s3/*`; `web/s3.py` should only dispatch. |
| 3 | `tests/web/test_auth_rbac.py` | 1,437 | Test | Yes | Four files: `test_auth_*`, `test_rbac_*`, `test_admin_storage_*`, `test_telegram_*`. |
| 4 | `web/static/app.js` | 1,184 | JS | **Yes** | A single `app()` Alpine component carries the state of every page. `static/js/{http,upload,crypto,files,buckets,shares,keys,logs}.js`; each HTML should load only its own component. |
| 5 | `tests/s3/test_s3_post_policy.py` | 1,124 | Test | Yes | Presigned POST scenarios + boto3 fixtures should be separated; shared fixtures into `conftest.py`. |
| 6 | `tests/meta/test_ci_workflows.py` | 1,122 | Test | No (meta) | Having one file that audits the workflow YAMLs is defensible; still, `test_ci_matrix.py` + `test_ci_guards.py` could be split out. |
| 7 | `teledrive/storage/catalog.py` | 1,080 | Python | **Yes** | `storage/catalog/{buckets,objects,versions,acls}.py`; `BucketCatalog` should remain a thin facade. The ACL/PAB block (347-467) and version listing (769-920) are independent. |
| 8 | `tests/e2e/test_database_live.py` | 1,036 | Test | Yes | By feature: schema/lease, manifest/chunk, multipart, tags/metadata, version/GC, rate-guard. The shared parametrize fixture should be kept. |
| 9 | `teledrive/storage/user_mode.py` | 850 | Python | **Yes** | `storage/mtproto_credentials.py` (1-327), `storage/user_runtime.py` (328-512), `storage/send_journal.py` (513-606), `storage/user_transport.py` (607-850). |
| 10 | `teledrive/s3/multipart.py` | 764 | Python | Yes | `s3/multipart/{store,parts,completion,recovery}.py`. The completion lease/fence code must be tested separately. |
| 11 | `scripts/ops/acceptance.py` | 692 | Script | Partly | The CLI orchestrator can stay; each gate should be split into `scripts/ops/checks/*.py`. |
| 12 | `tests/s3/test_s3_gateway.py` | 667 | Test | Yes | `test_gateway_crud.py`, `test_gateway_listing.py`, `test_gateway_copy.py`, `test_gateway_presign.py`. |
| 13 | `tests/storage/test_storage_engine.py` | 625 | Test | Yes | Should be split into chunking, ranged read, verification, failure/retry. |
| 14 | `teledrive/storage/engine.py` | 611 | Python | Borderline | File integrity/digest helpers (46-64) could be split out; the main class is cohesive, splitting is not mandatory. |
| 15 | `teledrive/db.py` | 601 | Python | Yes | `db/schema.py` (metadata + Tables), `db/migrations.py`, `db/engine.py`, `db/queries.py` (Database methods). |

**HTML note:** `buckets.html` 325, `credentials.html` 276, `telegram.html` 270, `api-management.html` 267. On their own they are not 600, but the same modal/table/empty-state markup is copied across 4 files. It should be extracted into shared `<template>`/Alpine components or a server-side partial.

---

## 2. ORM Status

### 2.1 Usage pattern

SQLAlchemy here is **not an ORM**: there is no declarative base, no `relationship()`, no `Session`/`sessionmaker` (0 matches). Everything is Core `Table` + `select/insert/update/delete` + raw `text()`. `DBRow` (`teledrive/db.py:176`) is merely a dict/tuple wrapper around `Row`.

**Conclusion:** there is no unit-of-work, no cascade, no lazy loading, no identity map and no model-level validation. That may be a choice; but combined with 9 separate `MetaData` and `create_all` inside constructors, consistency is lost.

### 2.2 Findings

**O1 — 9 separate `MetaData` (high).**
`teledrive/db.py:18`, `teledrive/storage/manifest.py:21`, `teledrive/storage/catalog.py:25`, `teledrive/storage/jobs.py:28`, `teledrive/api_keys.py:19`, `teledrive/s3/credentials.py:19`, `teledrive/s3/multipart.py:32`, `teledrive/storage/mtproto_rate_guard.py:21`, `teledrive/storage/user_mode.py:27`.
Because tables in the same database are spread across different metadata, SQLAlchemy cannot resolve string `ForeignKey`; no FK can be defined between related tables.

**O2 — 46 `Table`, only 5 `Index`, 15 `ForeignKey` (high).**
Verified with `grep -c`. In particular most of the manifest/catalog/S3 metadata tables have no FK and no query index. This makes the answer to "is there a foreign key?" change module by module.

**O3 — 125 raw `text()` calls (high).**
Distribution: `web/app.py` 87, `teledrive/storage/catalog.py` 15, `teledrive/storage/gc_collect.py` 12, `teledrive/storage/user_mode.py` 9, `teledrive/storage/engine.py` 1, `teledrive/storage/content_index.py` 1.
Densest areas: users/sessions (`web/app.py:1322-1762`), telegram sessions/channels (`1989-2740`), quota/pin/share (`3385-3922`), metrics (`3750-3860`). Some of this SQL contradicts the model definitions (e.g. `ON CONFLICT`).

**O4 — f-string / dynamic SQL (medium-high).**
- `teledrive/db.py:488`, `:506`, `:518` — `ALTER TABLE {table_name} ADD {rendered}`. The table name and column rendering come from internal code; still a Bandit B608 risk.
- `teledrive/storage/catalog.py:114` — `PRAGMA table_info({table})`; `:128` — `WHERE table_name = '{table}' AND table_schema = {schema}`. `table` is a constant, `schema` a dialect constant; there is no injection in practice, but the pattern is bad.
- `teledrive/storage/gc_collect.py:186` and `:190` — `f"SELECT COUNT(*) {base} ..."`; suppressed with `# nosec B608`. Even though `base` is a module constant, this is the code PR #25 rightly wants to clean up.

**O5 — Manual ALTERs have replaced the migration system (high).**
`teledrive/db.py:475-518` (files/telegram_sessions/pending), `teledrive/storage/catalog.py:121-180` (bucket PAB/object lock), `teledrive/storage/gc_collect.py:73-89` (gc grace), `web/app.py:761-772` and `:919-931` (users.enabled, **an exact copy**), `teledrive/storage/content_index.py:69-79` (FTS/tsvector DDL).
Even if these look idempotent, there is no version number, no downgrade, no ordering and no auditability.

**O6 — Schema initialisation race (critical).**
`db.py:544-554` only takes a PostgreSQL advisory lock for `_setup_schema`. But `BucketCatalog.__init__` (`catalog.py:201`), `ManifestStore.__init__` (`manifest.py:133`), `StorageUploadJobs.__init__` (`jobs.py:82`), `ApiKeyStore.__init__` (`api_keys.py:94`), `S3CredentialStore.__init__` (`credentials.py:86`), `MultipartStore.__init__` (`multipart.py:105`), `MtprotoRateGuard.__init__` (`mtproto_rate_guard.py:65`), `UserSessionRuntime` (`user_mode.py:516`) and `RetainedMediaGC.__init__` (`gc_collect.py:100-101`) call `create_all` **outside the lock**.
If two workers start at once, a `CREATE TABLE` race and a double `ALTER TABLE` inside `ensure_versioning_column` can be observed. `_versioning_column_ensured` (`catalog.py:98`) is process-local, so it provides no cross-worker protection.

**O7 — Missing / inconsistent FKs (high).**
- `storage_published_versions.object_id` and `.bucket` → no FK (`catalog.py:77-83`).
- `storage_removed_versions.object_id` → no FK (`catalog.py:86-90`).
- `storage_object_acl_grants.bucket`, `storage_bucket_acl_grants.bucket` → no FK (`catalog.py:54-68`).
- `storage_multipart_uploads.bucket`, `.completed_object_id` → no FK (`multipart.py:33-43`).
- `storage_multipart_parts.object_id`, `storage_multipart_etags.object_id` → no FK (`multipart.py:44-52`, `68-72`).
- `storage_upload_jobs.bucket`, `.object_id` → no FK (`jobs.py:29-47`).
- `user_sessions.user_id` → no FK (`db.py:167-173`).
- `share_links.bucket`, `bucket_account_pins.account`, `files.tg_account` → string, no FK.
Result: orphan rows can appear after `delete_bucket` (O10).

**O8 — Missing indexes (medium-high).**
- `storage_object_aliases.source_object_id`: because the PK is `(object_id, source_object_id)`, GC's `WHERE a.source_object_id = o.id` query (`gc_collect.py:179-180`, `:370`, `:445`) cannot use an index. **The most concrete missing index.**
- `storage_upload_jobs(state, lease_until)`: `claim_next` (`jobs.py:180-187`) scans on every round.
- `storage_multipart_uploads(bucket, state)`: `delete_bucket` and the stale list scan it.
- `user_sessions(user_id)`: full scan on user delete/session revoke.
- `storage_gc_queue(enqueued_ns)`: grace query.
The 5 existing indexes: `files(status)`, `files(tg_account)`, `published_versions(bucket,key_hash,committed_ns)`, `storage_objects(bucket)`, `storage_objects(status)`.

**O9 — The MySQL contract contradicts the code (critical, because README/CI support MySQL).**
- `web/app.py:3735` and `:3902` — `ON CONFLICT (bucket) DO UPDATE` (SQLite/PostgreSQL; syntax error on MySQL).
- `web/app.py:3634` — `INSERT OR IGNORE` (SQLite-only).
- `web/app.py:3598-3602` — `LIKE '%.' || :ext` (SQLite/PostgreSQL; MySQL needs `CONCAT`).
- `teledrive/storage/content_index.py:61-64` — content search is silently disabled on MySQL.
- `teledrive/storage/catalog.py:119-128` the MySQL schema filter was added (latest commit), but the endpoints above are still broken.
`tests/e2e/test_database_live.py` parametrizes MySQL but does not cover the quota/pin/share/reindex endpoints.

**O10 — `delete_bucket` leaves orphan metadata (high).**
`catalog.py:1040-1080` only deletes `storage_bucket_tags`, `storage_bucket_lifecycle`, `storage_bucket_cors`. The following remain:
`storage_bucket_acl_grants`, `storage_object_acl_grants`, `bucket_quotas`, `bucket_account_pins`, `share_links` (bucket-scoped records). If a bucket with the same name is recreated, the old ACL/quota/pin/share suddenly become active. **This is a security bug**, not merely cosmetic.

**O11 — Object-lock default retention is not atomic with publish (high).**
`catalog.py:952` and `:990` commit the head/published version; `apply_default_lock` is only called afterwards in a separate transaction (`:955`, `:991`). If a crash happens between the two steps, the new version stays **unlocked** even though the bucket is "Object Lock enabled + default retention". The WORM claim does not hold under that race. `test_s3_object_lock.py:138` only tests the happy path.

**O12 — Consistency plan (small to large).**
1. **Freeze and measure:** generate `docs/SCHEMA.md` from the existing `MetaData`; compare the table/column/FK/index inventory in CI.
2. **Alembic baseline:** a single `alembic/` directory, `render_as_batch=True` (SQLite), `compare_type=True`, `compare_server_default=True`. The first revision marks the existing schema as the "baseline".
3. **`MetaData` merge (domain by domain):** `teledrive/db/schema.py` single metadata; `core` → `manifest` → `catalog` → `s3` → `jobs` → `auth`. Table names must not change; modules only import the `Table` objects.
4. **Move `create_all` calls to one place:** remove them from all constructors; guard them inside `connect_database`/`_setup_schema` with a PostgreSQL advisory lock + MySQL `GET_LOCK` + SQLite `BEGIN IMMEDIATE`.
5. **Turn manual ALTERs into revisions:** `ensure_versioning_column`, `_ensure_grace_column`, the users.enabled block. Leave a no-op shim for one release.
6. **FK/index migration order:** `storage_buckets` → `storage_objects` → `storage_object_heads` → `storage_published_versions`/`storage_removed_versions` → `storage_chunks`/`storage_object_aliases` → S3 metadata → jobs/multipart → auth. Orphan row cleanup first; `NOT VALID` + `VALIDATE` on PostgreSQL, batch rebuild on SQLite, online DDL on MySQL.
7. **Reduce raw SQL:** first quota/pin/share/users (repetitive, low risk), then GC metrics. Each module should use its own store.
8. **Tests:** 3 backends × migration upgrade, concurrent startup (2 processes), orphan-FK failure test, MySQL quota/reindex smoke.

**Risks:** SQLite table rebuild locks; MySQL requires an index for an FK; existing orphan rows block adding FKs; long locks on large tables; test fixtures breaking while `create_all` is removed; Alembic downgrade must not affect Telegram data (relatively safe since it is metadata-only).

---

## 3. API Key / Permission Node

### 3.1 Existing layers

| Layer | Entry point | Identity | Permission check | CSRF | Note |
|--------|---------------|--------|----------------|------|-----|
| Browser session (cookie or `td_sess_` bearer) | `require_auth` → `_get_current_user` | `user_sessions` table, SHA-256 digest | Outer gate `_required_roles` + inner gate `PermissionRegistry.role_allows` | `_same_origin` inside the handler, 51 call sites | Role→permission map; viewer has read-only permissions (P5 closed). |
| HTTP Basic | `require_auth` → `_verify_basic_credentials` | `users` table, PBKDF2 + `enabled` | Same outer role gate as session + inner permission map | Handler `_same_origin` | The configuration password is not an identity; there is no unconditional admin path (P6 closed). |
| REST API key (9 legacy endpoints) | `require_api_scope` (`:1272`) | `td_live_` + `api_credentials.digest` | `ApiKeyStore.authorize(token, required)` (`api_keys.py:145`) | None (not a cookie) | The `required` string is hard-coded in the handler. |
| General API key (all routes, including admin) | `require_auth` (`:523-547`) | same store | `PermissionRegistry.permission_for` (`permissions.py:186`) + `authorize` | Handler `_same_origin` | No role policy; the key's permission is whatever it is. |
| S3 SigV4 header | `verify_header_signature` (`sigv4.py:279`) | `access_key` | `S3CredentialStore.resolve(access_key, action)` (`credentials.py:120`) | N/A | `action` is selected in the giant if/elif at `web/s3.py:2836-3050`. |
| S3 presigned | `_presigned_signature` (`sigv4.py:84`) | same | expiry + resolve | N/A | Presign URL generation is in an admin route. |
| S3 POST policy | `_handle_form_upload` (`web/s3.py:701`) | policy credential | `verify_post_policy` + `resolve(...,"s3:PutObject")` + ACL (`:740-750`) | N/A | Browser form upload. |
| S3 resource ACL | `_acl_allows` (`web/s3.py:1889`) → `acl.permits` (`acl.py:67`) | access_key | `own scopes ∩ grants` | N/A | Only narrows; if there is no ACL the baseline is open. |
| Public share | `_load_active_share`/`_stream_share` (`web/app.py:4909-4932`) | token | expiry + download_count + password | N/A | There is an atomic slot claim. |
| WebSocket log | `logs_stream` (`web/app.py:2915`) | cookie session | only `_get_current_user` | N/A | No role/route policy; a viewer can watch logs (consistent with GET logs). |

### 3.2 Findings

**P1 — Three separate permission catalogs (high, drift).**
The same 9 REST permissions in three places:
1. `teledrive/api_keys.py:31-41` `ENDPOINT_PERMISSIONS`
2. `web/permissions.py:22-32` `CURATED_PERMISSIONS`
3. `web/app.py:4632/4646/4698/4777` strings embedded in handlers.
The S3 action list is likewise in two places: `teledrive/s3/credentials.py:31-54` and `web/s3.py:2836-3050`. When a new route is added only the registry is updated; the strings of the old 9 endpoints and the S3 action mapping stay in sync by hand.

**P2 — Path-sniffing based role policy (high).**
`_required_roles` (`web/app.py:469-494`) decides using method + `request.url.path`; there is no role on the route decorator. The `if method == "GET": return None` line (`:483-484`) opens every GET to viewer. Result:
- `/api/v1/admin/users` GET → admin (because it is checked earlier) but `/api/v1/admin/storage/buckets/{b}/quota` GET → **viewer** (the quota check comes after the `:492` GET return).
- If a new `/api/v1/admin/...` route is added and its path pattern is not in the list, the default becomes `_ROLE_WRITE`; a route that should be admin-only can be opened to operator.
- Alias normalisation (`:478-480`) only maps `/api/*` → `/api/v1/*`; no other prefix/encoding case is tested.

**P3 — Physical GC is not an "owner gate" but an operator gate (critical).**
`PUT /api/v1/admin/storage/gc` (`web/app.py:3996`) and `POST .../gc/collect` (`:4022`) make `_required_roles` return `_ROLE_WRITE` at the end (`:494`). That is, an **operator** can enable GC and delete Telegram media by writing `confirm="PHYSICAL-GC"` / `"DELETE-RETAINED"`. Code and documentation say "owner decision"; the reality is operator. The same route can also be called with an API key (bearer skips the role policy). `tests/storage/test_gc_collect.py:161` only tests with an admin fixture; there is no operator-rejection test.

**P4 — Privilege escalation via API key mint/rotate (critical).**
`POST /api/v1/admin/keys` (`web/app.py:1556-1575`) passes the incoming `payload.scopes` to `ApiKeyStore.create(..., extra_allowed=route_permissions)` without comparing them to the calling key's own permissions. `require_auth` has no role policy on the bearer path (`:519-547`).
Result: a key holding only `post:/api/v1/admin/keys` can mint a new key with **any route permission** (e.g. `delete:/api/v1/admin/users`, `post:/api/v1/admin/s3/credentials`). Likewise `POST .../keys/{identifier}/rotate` (`:1590-1602`) can rotate **another key** via the path parameter and obtain the new secret; if the target key has higher permissions this is a full takeover. `tests/web/test_per_route_permissions.py:85` tests minting but not escalation.

**P5 — Asymmetry between session and bearer (high). ✅ Closed.**
A viewer session could read every GET API; the API key issued for the same user required a separate permission for each route. Every API route now has a permission and the permissions of a session/Basic principal are derived from its role (`web/permissions.py`): admin everything, operator all data/storage but no user/key/credential/GC/quota/website/config writes, viewer read-only. The per-route scope semantics of API keys are unchanged.

**P6 — Legacy Basic = unconditional admin (high). ✅ Closed.**
Basic is now verified against the `users` table (PBKDF2, `enabled`, real role); unknown users and the configuration password are rejected. `web.user`/`web.password` are no longer service settings; on first boot the fixed `admin`/`admin` is created only if no row named `admin` exists, and an existing row's hash/role/enabled values are preserved. The breaking change and migration are in `docs/UPGRADING.md` §7.

**P7 — Audit identity can be spoofed (medium-high).**
`_extract_user` (`web/app.py:181-228`) decodes the Basic header **without verifying the password** and returns the username (`:205-213`). `_audit_log_middleware` (`:1044-1045`) writes that value to the log. So anyone sending `Authorization: Basic YWRtaW46eA==` can make the audit log say "admin", even on a failed request. Also, because `name_for_token` does not check revoked/expired, the name of a revoked key still shows up in the log. This breaks forensic traceability.

**P8 — S3 ACL is not enforced on batch delete and copy source (critical).**
The ACL gate inside `_handle` (`web/s3.py:3147-3157`) uses `key if separator else None`. A batch delete URL is a bucket path (`POST /bucket?delete`), so `key=None` and only the **bucket ACL** is evaluated; `_handle_batch_delete` (`:820-898`) does not check the object ACL for each key. A credential restricted by object ACL to "only this key" can delete that key if it has a WRITE grant on the bucket.
Likewise `_handle_copy_object` (`:2282-2400`) only checks `store.resolve(owner,"s3:GetObject")` for the source; `catalog.acl_grants_for(src_bucket, src_key)` and `acl_permits` are **not called**. An object whose access is closed by the source object ACL can be copied by a credential with GetObject scope. Multipart `UploadPartCopy` (`:1762-1785`) carries the same pattern.

**P9 — S3 ACL ownership can be transferred (critical).**
`_validated_acl` (`web/s3.py:1915-1933`) does not force the documented `Owner` field to equal the caller; it only requires it to be an "active credential". The `BlockPublicAcls` check (`:1960-1965`, `:1999-2004`) only kicks in **if a stored owner exists**; on the first ACL write there is no stored owner. Therefore any credential with `s3:PutBucketAcl` permission can write an ACL with `Owner=<itself>` and a grant set and lock out the real bucket owner. `tests/s3/test_s3_acl.py:182` only tests the stored-owner scenario.

**P10 — `extra_allowed` / `admin:*` / public routes (medium).**
`extra_allowed` is only used **at issue time** (`api_keys.py:97-110`); there is no re-validation against the route registry during `authorize`. `LEGACY_SCOPE_EXPANSION["admin:*"]` only expands to the 9 REST permissions (`api_keys.py:44-55`), so despite the name it does not cover new routes. Also `PermissionRegistry` pulls routes that are not public, such as `/api/v1/auth/login`, into the catalog (`permissions.py:126-142` only treats specific prefixes as public); granting a permission for login is meaningless and is catalog noise.

**P11 — S3 credential reveal/presign validations are missing (medium).**
`S3CredentialStore.reveal` (`credentials.py:153-173`) checks revoked but **does not check expiry**; the secret of an expired credential can be revealed. `admin_presign_object` (`web/app.py:3317-3325`) reveals the credential if `credential_id` is given without checking whether it has `s3:GetObject`; the URL is later rejected by the resolver, but this is unnecessary secret exposure and a misleading error. Also S3 credential issue/update/revoke (`:4533-4618`) produce no audit log; only reveal logs (`:4571`).

### 3.3 Proposal for a single canonical permission path

A single decision point inside `web/security.py`:

```python
@dataclass(frozen=True)
class Principal:
    kind: Literal["session", "basic", "api_key", "s3", "share", "anonymous"]
    subject: str
    roles: frozenset[str]
    permissions: frozenset[str]

def authenticate(request) -> Principal | None: ...
def authorize(principal, method, path, *, resource=None) -> None: ...
```

Rules:
1. **Identity:** Session → `_get_current_user`; Basic → only a fixed identity and a **verified** password; API key → digest + scopes; S3 → access_key + action.
2. **Permission:** for a session, the `ROLE_PERMISSIONS` map (viewer/operator/admin) expands into the permission names in the route registry. For bearer, `expand_scopes`. That way both sides go through the same `authorize(principal, permission)` function.
3. **Route declaration:** `Depends(require("get:/api/v1/admin/keys", roles={"admin"}))`; path sniffing is removed.
4. **CSRF:** one dependency only for cookie-based principals; not applied to bearer/S3.
5. **S3:** `authorize` calls the identity policy (credential scope) first, then the resource policy (ACL intersection). Batch delete and copy source call `authorize(..., resource=(bucket,key))` separately for each key/source.
6. **Audit:** `request.state.principal` is written only from the verified principal; it is not re-derived from a header.
7. **Catalog:** `ENDPOINT_PERMISSIONS` + `CURATED_PERMISSIONS` merge into one file; the S3 action map is generated from `credentials.PERMISSIONS`.

---

## 4. The 15 Most Valuable Refactors (risk reduction / effort)

| # | Location | Problem | Concrete action | Effort | Protecting test |
|---|-----|---------|---------------|------|---------------|
| 1 | `web/app.py:1556-1602` | Privilege escalation via API key mint/rotate | In mint/rotate, run the `request.state` principal's permission set through a subset check; reject target permissions unless `admin:*` | **S** | `tests/web/test_per_route_permissions.py:60-105`, `tests/web/test_api_keys.py` (add escalation test) |
| 2 | `web/s3.py:3147-3157`, `:820-898`, `:2282-2400` | Batch delete and copy source skip the object ACL | Call `_acl_allows` for every key/source; return a per-entry `AccessDenied` in batch | **M** | `tests/s3/test_s3_acl.py`, `test_s3_batch_delete.py`, `test_s3_copy.py` (new bypass tests) |
| 3 | `web/app.py:469-494`, `:3996`, `:4022` | Physical GC open to operator | `roles={"admin"}` for `/admin/storage/gc*`; additionally re-auth/owner confirmation in GC collect | **S** | `tests/storage/test_gc_collect.py:161` (add operator rejection) |
| 4 | `teledrive/storage/catalog.py:1040-1080` | Bucket delete leaves ACL/quota/pin/share orphans | Clean every bucket-scoped table before deleting; add FK/cascade | **S** | `tests/e2e/test_database_live.py:439` (add ACL/quota/pin/share cleanup) |
| 5 | `web/s3.py:1915-1933` | ACL Owner can be transferred | `acl_owner` may only be the caller; require an owner on the first write too | **S** | `tests/s3/test_s3_acl.py:182` (reject owner transfer) |
| 6 | `web/app.py:181-228`, `:1044` | Audit identity spoofed from the Basic header | Remove `_extract_user`; use `request.state.principal` | **S** | `tests/web/test_security.py` (spoof attempt) |
| 7 | `teledrive/db.py:470-518`, all `__init__`s | Schema init race and scattered migration | Lock all `create_all`/ALTERs under a single `_setup_schema`; move to Alembic | **M** | `tests/e2e/test_database_live.py` + new concurrent-startup test |
| 8 | `web/app.py:3598-3634`, `:3735`, `:3902` | SQL broken on MySQL | `ON CONFLICT` → dialect-aware upsert; `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`/`INSERT IGNORE`; `\|\|` → `CONCAT` | **M** | MySQL-parametrized `test_database_live.py` + quota/reindex smoke |
| 9 | `teledrive/api_keys.py:31-55`, `web/permissions.py:22-32`, `web/app.py` handlers | 3 copies of the permission catalog | A single `permissions_catalog.py`; handlers read from the registry instead of hard-coded strings | **M** | `tests/web/test_per_route_permissions.py:36` |
| 10 | `web/app.py:518-579` | Session/Basic/bearer are three separate decision paths | The `Principal`/`authorize` model in §3.3 | **L** | `test_auth_rbac.py`, `test_per_route_permissions.py` |
| 11 | `web/app.py` (5,031) | Giant router file | Router packaging + `create_app()` factory | **L** | All `tests/web` suite |
| 12 | `web/s3.py` (3,388) | Giant S3 dispatch | Handler modules; `_handle` only routes | **L** | All `tests/s3` suite |
| 13 | `web/app.py` 87 `text()` | ORM bypass, dialect fragility | A Core store layer for users/sessions/quota/pin/share; leave raw SQL only for complex reports | **L** | `test_auth_rbac.py`, `test_rest_api.py`, `test_database_live.py` |
| 14 | `teledrive/storage/catalog.py:77-90`, `manifest.py:56-96` | Missing PK/FK/index | `published_versions.object_id/bucket`, `removed_versions.object_id`, `aliases.source_object_id` index; FK migration | **M** | `test_storage_catalog.py`, `test_database_live.py` |
| 15 | `teledrive/storage/user_mode.py:46-93` | Dead/duplicate function definitions | Delete `_session_from_file` and the first `_session_from_file_for`; remove `_split_list` if unused | **XS** | `tests/storage/test_storage_user_mode.py` |

---

## 5. PR Triage

Verified with the GitHub API (`/repos/babico/TeleDrive/pulls/{22,24,25}` + `/files`) and local `git apply --check`. The API's `mergeable` field returned `unknown` at query time, so textual conflict was measured with a local apply-check.

| PR | Title | Base SHA | Age | Files | Conflict | Recommendation |
|----|--------|----------|-----|-------|---------|-------|
| **#22** | fix(ci/docs): verify Telethon storage roadmap and repair config-only job regression | `3aa70d1` (**23 commits** behind main) | 3 days | 12 files, +239/−43, 9 commits (9 docs/config + 3 test) | `tests/storage/test_storage_jobs.py:205` apply-check **FAIL**; 7 files also changed on main | **CLOSE** |
| **#24** | docs(ci): count six automatic workflows plus manual endurance correctly | `8c40325` (13 commits behind) | 2 days | 6 docs, +7/−7, 1 commit | Apply-check **clean**; no textual conflict | **REBASE + MERGE** |
| **#25** | fix(gc/security): restore CI gate and reconcile Telethon-only operational docs | `65e0b64` (12 commits behind) | 2 days | 5 docs + `gc_collect.py`, +32/−17, 2 commits | `gc_collect.py:101` apply-check **FAIL** (Phase A rewrite); the docs part is clean | **EXTRACT-PARTS + CLOSE** |

### #22 — CLOSE

- The test fix was already made on main **in a different form**: `tests/storage/test_storage_jobs.py:208-217` now tests the config-only root and the 422/503 distinction. The PR's hunk in the same file therefore does not apply.
- `docs/VERIFICATION_2026-10-22.md` is a snapshot from the 3aa70d1 moment; the 23 commits since then (Phase A–E, ACL, PAB, object lock, per-route permissions) make that report **wrong**.
- The `TODO.md`/`README` changes conflict with newer metadata-parity text.
- **Rationale:** "the safest direction that preserves the newest work" — do not bring back the old roadmap narrative. There is no independent part worth extracting.

### #24 — REBASE + MERGE

- The docs are still wrong: `docs/CI_WORKFLOWS.md:21` "first seven workflows", `docs/TELETHON_STORAGE.md:172` "seven mandatory workflows", `docs/IMPLEMENTATION_STATUS.md:21` "seven workflows", `TODO.md:9` "six of seven".
- The PR fixes exactly these; apply-check applies cleanly to the current tree. The risk is very low.
- **Rationale:** it does not regress new work, it only brings the operator documentation closer to reality. Before merging, re-verify the workflow count against the current commit once more (CI changes in the working tree may affect the number).

### #25 — EXTRACT-PARTS + CLOSE

- `gc_collect.metrics` still uses `f"SELECT COUNT(*) {base}"` (`gc_collect.py:186`, `:190`) and suppresses it with `# nosec B608`. The PR's static SQL cleanup is **valuable**.
- However the PR's base predates Phase A; `gc_collect.py` has been rewritten since (queue/grace/lifecycle). Rebasing risks regressing the new GC code.
- **Rationale:** apply the static SQL fix by hand onto the current `metrics()` (drop the base fragment, write both queries out in full), fold the docs fixes into #24, then close #25 as superseded. Per the owner rule, do not merge an old branch blindly.

---

## 6. Death by 1000 Cuts

**C1 — Duplicate `_session_from_file_for` definition (dead code).**
`teledrive/storage/user_mode.py:51-60` and `:83-93` define the same name twice; the second overrides the first. The first definition never runs. `tests/storage/test_storage_user_mode.py` does not catch it.

**C2 — Unused `_session_from_file` and `_split_list`.**
`user_mode.py:46` and `:63` are called from nowhere (verified with `grep`). They should be deleted.

**C3 — The `users.enabled` ALTER block is copied twice.**
`web/app.py:760-772` and `:919-931` are identical. Also `enabled` already exists in the `teledrive/db.py:151` metadata; the migration should move into `db._setup_schema`.

**C4 — The same expensive query twice in the quota check.**
`web/app.py:3702` and `:3706` each call `_bucket_current_usage`; one call is enough.

**C5 — 4+ separate GROUP BYs for Telegram metrics.**
`web/app.py:2144-2170` (session list) and `:3824-3860` (Prometheus) scan the same tables separately. This should go into a single `telegram_usage_snapshot()` helper.

**C6 — Config is parsed three times.**
`settings_bind_address` (`:88`), `settings_web_port` (`:97`), `settings_s3_port` (`:106`) each do `load_settings(uploader.load_config(...))`; `web/unified.py:55-57` calls all three back to back. A single `load_service_settings()` is enough.

**C7 — Key hash logic in two places.**
`BucketCatalog._keyhash` (`catalog.py:212`) is SHA-256 hex; `web/app.py:3683` does the same calculation by hand. It should go into a shared helper; otherwise when one changes the quota lookup silently breaks.

**C8 — The number of broad `except Exception: pass` is high.**
There are 90 `except Exception` in production; `web/app.py:203`, `:212`, `:225`, `:459`, `:2160-2170`, `:3824-3860` swallow errors in particular. A swallowed error on the auth path turns into "no identity"; on the metrics path it silently shows zero. At minimum, type-based logging via `_log` should be mandatory.

**C9 — Audit log identity from an unverified header.**
See P7. `_extract_user` decodes Basic without the password.

**C10 — S3 credential issue/update/revoke without audit.**
`web/app.py:4533-4618` never calls `_log`; only reveal (`:4571`) logs. Secret generation and permission changes should be audited.

**C11 — `reveal` ignores expiry.**
`credentials.py:153-173` only looks at `revoked`. `test_s3_admin.py:129` only tests revealing an active credential.

**C12 — Presign credential selection does not verify permission/expiry.**
`web/app.py:3317-3325` reveals `credential_id` if given, without checking `s3:GetObject` or expiry.

**C13 — `delete_bucket` orphans.**
See O10. ACL grants in particular restore old ownership on a recreated bucket.

**C14 — MySQL SQL leaks.**
See O9. `web/app.py:3598`, `:3634`, `:3735`, `:3902`.

**C15 — Content search silently absent on MySQL.**
`teledrive/storage/content_index.py:61-64` returns on MySQL without doing anything; `/admin/storage/search` returns empty results. Instead of telling the user "not supported", it silently returns empty.

**C16 — Public routes in the permission catalog.**
`/api/v1/auth/login` and `/api/auth/login` enter the registry (`permissions.py:126-142` is not in the public list), although they do not use `require_auth`. This produces meaningless permissions in the catalog.

**C17 — `GROUP_DESCRIPTIONS` maintained by hand.**
`web/permissions.py:36-113` carries the route list by hand; when a new route is added the description falls back to "API endpoints under ...". It could be generated from the registry.

**C18 — The frontend loads a 400 KB Tailwind runtime + 56 KB Alpine on every page.**
`web/static/index.html:7-8` (and the other 10 HTML files) pull `/static/vendor/tailwindcss.js` + `alpine.min.js`. The Tailwind JIT runtime runs in production; it requires `unsafe-eval` in the CSP (`web/app.py:1099`). Move to build-time CSS + small component JS.

**C19 — `app.js` is a single Alpine component.**
1,184 lines, carrying the state of every page and the upload/crypto/log flows. It should be split into page-based components; otherwise every page loads unnecessary code.

**C20 — Test gaps (tricky paths).**
There is no test for:
- API key mint/rotate escalation (P4),
- operator enabling GC (P3),
- batch delete/copy source ACL bypass (P8),
- ACL owner transfer (P9),
- concurrent schema init / double ALTER (O6),
- MySQL quota/pin/reindex (O9),
- audit identity spoof (P7),
- `publish` + default lock crash window (O11),
- ACL/quota/pin/share cleanup after bucket delete (O10).

**Positive note:** there is **no** `TODO`/`FIXME`/`XXX`/`HACK` marker in the code (only "see TODO" in a comment at `teledrive/db.py:75`). Technical debt lives in `TODO.md` (41 KB) and in behaviour; in-code marker discipline is good.

---

## 7. Recommended Implementation Order

1. **Week 1 (S):** P4 (key escalation), P3 (GC role), P9 (ACL owner), P7 (audit spoof), O10 (bucket delete), O11 (default lock transaction).
2. **Week 2 (M):** P8 (batch/copy ACL), O6 (schema lock), O9 (MySQL SQL), O8 (alias index).
3. **Week 3–4 (M/L):** O1/O5/O12 (single metadata + Alembic), P1/P2/P10 (single permission catalog), §3.3 canonical auth.
4. **Ongoing:** router split of `web/app.py` and `web/s3.py`; a registry test and at least one negative permission test with every new route.

---

## 8. Conclusion

**File written:** `docs/CODEBASE_REVIEW.md`
**Total findings:** **76** (15 inventory + 12 ORM + 11 permission + 15 refactor + 3 PR + 20 small cuts).

**The 5 most valuable items:**
1. **API key mint/rotate privilege escalation** (`web/app.py:1556-1602`) — a single low-privilege key can mint keys for the entire admin surface.
2. **S3 ACL bypasses** (`web/s3.py:820-898`, `:2282-2400`) — object ACL is not enforced on batch delete and copy source.
3. **Physical GC open to operator** (`web/app.py:469-494`, `:3996`, `:4022`) — "owner decision" is in practice an operator/API-key gate.
4. **Schema initialisation race** (`db.py:544-554` vs every `__init__` `create_all`) — risk of double ALTER/duplicate table on multi-worker startup.
5. **Orphan ACL/quota/pin/share on bucket delete** (`catalog.py:1040-1080`) — a bucket recreated under the same name brings back the old security metadata.

> Note: all of #1–#5 are fixable with **S/M** effort; none requires a large refactor. The large refactor (app.py/s3.py split, MetaData merge) should be done **after** these security fixes.
