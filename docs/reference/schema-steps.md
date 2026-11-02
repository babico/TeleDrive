# Schema migration steps

TeleDrive has exactly one place that issues DDL: the migration coordinator in `teledrive/storage/schema.py`. Every store constructor calls `ensure_schema()`, which either proves the schema is current with one cheap `SELECT` or takes a real cross-process lock and applies every pending step. This page documents all 27 steps: what each one creates, which subsystem owns it, what data it touches, and what a code rollback would leave behind. It is the reference for operators checking an upgrade and for developers appending step 28.

The step list is append-only. `SCHEMA_VERSION` is simply the length of the `_STEPS` list, so adding a step bumps the version; steps are never reordered, edited after shipping, or removed. The source of truth is [`teledrive/storage/schema.py`](https://github.com/babico/TeleDrive/blob/main/teledrive/storage/schema.py); if this page and the code disagree, the code wins and this page needs a fix.

## How a migration runs

The coordinator serializes migrations at three levels, cheapest first:

1. **Process-local cache.** A `weakref.WeakSet` remembers engines this process already verified. Every constructor call after the first is a pure in-memory lookup: no connection, no query, no DDL.
2. **Version probe.** The first call per engine reads `SELECT MAX(version) FROM schema_migrations`. When the recorded version matches `SCHEMA_VERSION`, the process stops there. A missing bookkeeping table reads as -1 (fresh database), an empty one as 0.
3. **Cross-process lock.** Only when the version is stale does the coordinator take a real lock, re-check the version (another worker may have just finished), create the `schema_migrations` bookkeeping table if needed, and run every step in order, recording `(version, name, applied_at)` after each.

The lock is per backend, because the three supported databases have different primitives:

| Backend | Lock | Scope and timeout |
| --- | --- | --- |
| SQLite | `flock` on a sidecar `<database>.schema-lock` file | Non-blocking attempts retried every 20 ms until a 30-second deadline, then `TimeoutError`. `:memory:` and `file:` URI databases skip the file lock. The lock is independent of SQLite's own POSIX byte-range locks. |
| PostgreSQL | `pg_advisory_xact_lock(715273001)` on a dedicated connection | Held until the guard connection commits, including when a step raises. The steps themselves each run in their own transaction on pooled connections. |
| MySQL | `GET_LOCK('teledrive.schema.migrations', 30)` / `RELEASE_LOCK` on a dedicated connection | Session-level lock with a bounded 30-second wait. Session scope is what makes it safe across the implicit commits MySQL DDL causes. |
| Other dialects | None (`_null_lock`) | In-process serialization only. A documented limit, not a supported path. |

### Idempotency guarantees

An interrupted migration is safe to re-run because every step is idempotent by construction:

- `metadata.create_all(...)` uses `checkfirst`, so existing tables are skipped.
- Column additions go through `_add_columns`, which probes the existing column set first (`PRAGMA table_info` on SQLite, `information_schema.columns` filtered by the current schema on PostgreSQL and MySQL) and only issues the missing `ALTER TABLE ... ADD COLUMN` statements. When the target table does not exist at all, the helper returns quietly; `create_all` owns that table's definition.
- Index steps create each named index with `checkfirst=True`.
- `_ensure_unique_index` inspects existing unique constraints and indexes before creating a named unique index, so a brand-new database (which already got the constraint from `create_all`) does not get a duplicate.
- The dedupe helper materialises its keep-set in a session-scoped `TEMPORARY` table and drops it again, so the statements leave nothing behind on a re-run.
- Bookkeeping writes are `DELETE` + `INSERT` per version, so a re-run replaces the row rather than failing the primary key.

Correctness over cleverness: when several steps were added at once, the whole list is re-run on the next start of a stale database; each step is a no-op for the parts that already exist.

## Step families

| Version | Step name | Family | Effect in one line |
| --- | --- | --- | --- |
| 1 | `core` | Core platform | Web/core tables (users, sessions, Telegram accounts, shares, quotas, leases) plus defensive columns for older databases. |
| 2 | `verification_attempts` | Core platform | Brute-force cap on the Telegram login-code pending row. |
| 3 | `gc_leases` | Garbage collection | Durable physical-GC leases so two collectors cannot delete the same Telegram messages. |
| 4 | `manifest` | Manifest and catalog | The immutable object graph: objects, chunks, encryption markers, aliases, fences, replicas, content index. |
| 5 | `catalog` | Manifest and catalog | Buckets, ACL grants, object heads, published and removed versions. |
| 6 | `tagging` | S3 configuration | Object tags, pending-tag journal, bucket tags. |
| 7 | `metadata_journal` | S3 configuration | Metadata-change journal and metadata configuration. |
| 8 | `notifications` | S3 configuration | Notification and logging configuration plus the durable event outbox. |
| 9 | `annotations_and_metadata` | S3 configuration | Object annotations and HTTP metadata for objects and multipart uploads. |
| 10 | `tiering` | S3 configuration | Intelligent-Tiering configurations. |
| 11 | `reports` | S3 configuration | Analytics, inventory and metrics report configurations. |
| 12 | `api_keys` | Core platform | REST API keys (`api_credentials`). |
| 13 | `settings` | Core platform | The single encrypted service settings document. |
| 14 | `multipart` | Upload pipelines | Six tables covering multipart uploads, parts and completion bookkeeping. |
| 15 | `upload_jobs` | Upload pipelines | Durable local-file upload jobs. |
| 16 | `mtproto` | Upload pipelines | MTProto rate-guard and user-mode send-intent tables. |
| 17 | `gc` | Garbage collection | GC state, queue, leases, collected log; re-runs the manifest `create_all`; adds the grace-period column. |
| 18 | `credentials` | Credentials and encryption | S3 SigV4 credentials (`storage_s3_credentials`) and the ABAC `tags` column. |
| 19 | `s3_config` | S3 configuration | All bucket-scoped S3 subresource tables (encryption, CORS, lifecycle, policy, ABAC, replication, website). |
| 20 | `legacy_columns` | Manifest and catalog | Defensive columns on buckets, objects, chunks and multipart uploads for pre-coordinator databases. |
| 21 | `content_search` | Search and audit | Dialect-aware full-text structures for content search. |
| 22 | `hot_indexes` | Garbage collection | The alias source index that GC candidate checks and dedup lookups filter on. |
| 23 | `gc_indexes` | Garbage collection | Indexes for the GC queue enqueue time and the object-heads probe. |
| 24 | `share_object_id` | Manifest and catalog | Pins a share link to the object version it was issued for. |
| 25 | `security_audit` | Search and audit | The durable, append-only security-event trail. |
| 26 | `envelope_encryption` | Credentials and encryption | Envelope (SSE-S3) columns on the object encryption marker. |
| 27 | `unique_telegram_identities` | Core platform | One row per Telegram account and per channel: dedupe, then unique indexes. |

The sections below follow this family grouping; step numbers inside each family are the recorded `schema_migrations.version` values.

## Core platform

Owned by `teledrive/db.py`, `teledrive/api_keys.py` and `teledrive/settings_store.py`. These tables predate the S3 gateway: they carry users, login state, Telegram accounts and the service document.

### Step 1 - `core`

Runs `create_all` on the core metadata, creating: `leases`, `telegram_sessions`, `telegram_channels`, `telegram_session_pending`, `bucket_account_pins`, `bucket_quotas`, `share_links`, `users`, `flood_waits` and `user_sessions`. It then adds defensive columns for databases created by older releases:

- `files`: `tg_account`, `claim_token`, `claim_ts`. The `files` table belongs to pre-catalog releases and is no longer part of any metadata; on a current database the helper finds no table and skips silently.
- `telegram_sessions`: `authorized` (health-probe result), `health_checked_at`, `soft_quota_bytes`.
- `telegram_session_pending`: `session_string` (the serialized code-request client, so verify-code reuses the MTProto auth key that Telegram bound the phone-code hash to).
- `users`: `enabled` (RBAC flag; the two duplicated inline ALTERs that older web code ran now live here).

A downgrade would leave these tables and columns in place; older code tolerates them because `users.enabled` and every other added column carries a server default, so inserts that omit it still succeed.

### Step 2 - `verification_attempts`

Adds `telegram_session_pending.attempts INTEGER NOT NULL DEFAULT 0`. A Telegram login code is five digits; without a cap, an unlimited retry loop is a brute force against the account, so the pending row is destroyed after a bounded number of wrong codes. It is its own step rather than a column in step 1 because editing a shipped step would never run on an already-migrated database. A downgrade leaves a NOT NULL column with a default that older inserts satisfy.

### Step 12 - `api_keys`

Creates `api_credentials`, the REST API key table (id, name, hashed secret material, scopes, expiry, revocation). A downgrade leaves an orphan table that older code ignores.

### Step 13 - `settings`

Creates `service_settings`, the single-row encrypted settings document. Older releases kept settings only in `config/config.yaml`; the row is seeded on first read, so a downgrade simply falls back to the file, which the current code keeps writing on every save.

### Step 27 - `unique_telegram_identities`

Enforces one row per Telegram account and per channel. Both the session and channel upserts are UPDATE-then-INSERT, and their race recovery assumes the database rejects a duplicate INSERT; without the constraint, two concurrent logins created phantom sessions in listings, duplicate account labels in Prometheus scrapes and credentials probed twice.

The step is the only data-modifying migration in the list. For each of `telegram_sessions.account` and `telegram_channels.channel_id` it first deduplicates: the keep-set is computed deterministically (the row with the latest `updated_at`, ties broken by the lowest `id`) into a temporary table, then the losers are deleted, then the named unique index (`uq_telegram_sessions_account`, `uq_telegram_channels_channel_id`) is created unless an equivalent constraint already exists. A downgrade does not remove the indexes or revive the deleted rows; older code that races on login will simply start accumulating duplicates again. Operators who deliberately kept duplicate rows must export them before upgrading, because the deletion is permanent.

## Manifest and catalog

Owned by `teledrive/storage/manifest.py` and `teledrive/storage/catalog_tables.py`. This is the versioned object graph every surface (Web UI, REST, S3) reads and writes.

### Step 4 - `manifest`

Creates the manifest tables: `storage_objects` (immutable object rows with lock, retention, access-tracking and storage-class columns), `storage_chunks` (the Telegram chunk journal, with the `uq_storage_chunk_message` uniqueness of account/chat/message), `storage_object_encryption` (SSE-C marker), `storage_object_aliases` (server-side copy pointers into the chunk journal), `storage_writer_fences` (single-writer leases), `storage_replica_chunks` (cross-account replicas) and `object_content_index` (extracted text per object), plus the indexes `ix_storage_objects_bucket`, `ix_storage_objects_status` and `ix_storage_object_aliases_source`. A downgrade leaves the whole graph in place; older code that expects it keeps working.

### Step 5 - `catalog`

Creates the catalog tables: `storage_buckets`, `storage_object_acl_grants`, `storage_bucket_acl_grants`, `storage_object_heads` (the current pointer per bucket + key hash), `storage_published_versions` and `storage_removed_versions`, plus the indexes `ix_storage_object_heads_object` and `ix_storage_published_versions_key`. Versioning semantics (delete markers, revocation) live here, not in the manifest; a downgrade preserves history rows but loses whatever newer versioning behavior the step list grew.

### Step 20 - `legacy_columns`

Defensive ALTERs for databases created before the coordinator existed, kept as lessons from the original inline migrations:

- `storage_buckets`: `versioning_state`, `object_lock_enabled`, `object_lock_default_mode`, `object_lock_default_days`, `public_access_block` (VARCHAR, not TEXT, because MySQL cannot DEFAULT a TEXT column), `object_ownership`, `public_read`.
- `storage_objects`: `retention_until_ns`, `legal_hold`, `retention_mode`, `access_count`, `last_accessed_ns`, `storage_class`, `restore_until_ns`.
- `storage_chunks` and `storage_multipart_uploads`: `encryption` (per-chunk SSE-C metadata as JSON; nullable with no server default for the same MySQL reason, NULL meaning plaintext).

Every column either is nullable or carries a default, so older code inserting without it continues to work after a downgrade.

### Step 24 - `share_object_id`

Adds `share_links.object_id VARCHAR(36)`, nullable. A link used to be bound to a key, so it silently re-targeted replaced content and revived after an unlink plus re-upload; an unauthenticated capability then served bytes it was never issued for. New links serve exactly the pinned version; legacy rows stay NULL and key-bound. A downgrade returns to key-bound semantics for links created after the upgrade, which is precisely the vulnerability the step closed.

## S3 configuration

Owned by the `teledrive/s3/` modules. Bucket-scoped subresources and object-level extras that the AWS surface exposes.

### Step 6 - `tagging`

Creates `storage_object_tags` and `storage_pending_tags` in the tagging module's own metadata, and `storage_bucket_tags` in the shared catalog metadata.

### Step 7 - `metadata_journal`

Creates `storage_metadata_journal` and `storage_metadata_configs`.

### Step 8 - `notifications`

Creates the notification configuration tables `storage_notification_configs` and `storage_logging_configs` in the catalog metadata, and `storage_event_outbox` (the durable webhook outbox with retries) in its own outbox metadata.

### Step 9 - `annotations_and_metadata`

Creates `storage_object_annotations` (annotations are a separate store from tags) and, in the manifest metadata, `storage_object_http_metadata` and `storage_multipart_http_metadata` (Content-Type, cache-control and friends for objects and in-flight multipart uploads).

### Step 10 - `tiering`

Creates `storage_tiering_configs`, the Intelligent-Tiering configurations. Remember that tiering here is an access gate in the catalog, not a cold backend; no Telegram chunk ever moves.

### Step 11 - `reports`

Creates `storage_report_configs`, the analytics, inventory and metrics report configurations.

### Step 19 - `s3_config`

Creates every bucket-scoped S3 subresource table by importing `bucket_encryption`, `cors`, `lifecycle`, `policy`, `replication` and `website` (the imports register their tables in the shared `catalog_metadata` as a side effect) and then running one `create_all` over the fully populated catalog metadata and the manifest metadata. That covers `storage_bucket_encryption`, `storage_bucket_cors`, `storage_bucket_lifecycle`, `storage_bucket_policy`, `storage_bucket_abac`, `storage_replication_configs` and `storage_website_configs`, including any table a future module registers in those metadata. A downgrade leaves the configuration rows in place; the older binary simply never reads them.

## Upload pipelines

Owned by `teledrive/s3/multipart.py`, `teledrive/storage/jobs.py`, `teledrive/storage/mtproto_rate_guard.py` and `teledrive/storage/user_mode.py`.

### Step 14 - `multipart`

Creates the six multipart tables: `storage_multipart_uploads`, `storage_multipart_parts`, `storage_multipart_completion_parts`, `storage_multipart_completion_leases`, `storage_multipart_etags` and `storage_multipart_object_parts`. In-flight uploads survive a downgrade as orphan rows; abandoned ones are reclaimed by physical GC, which is owner-gated.

### Step 15 - `upload_jobs`

Creates `storage_upload_jobs`, the durable queue for local-file upload jobs with lease columns for multi-worker claiming and source identity columns for deduplication.

### Step 16 - `mtproto`

Creates the rate-guard tables `storage_mtproto_chat_send_slots`, `storage_mtproto_chat_cooldowns` and `storage_mtproto_flood_observations`, and the user-mode table `storage_mtproto_send_intents`. These are coordination state; a downgrade leaves them populated but unread, and the newer binary rebuilds its view from live traffic.

## Garbage collection

Owned by `teledrive/storage/gc_collect.py`. Physical deletion of Telegram media is owner-gated and never runs because of a migration; these steps only prepare the bookkeeping. See [Garbage collection](../operate/garbage-collection.md) for the operational contract.

### Step 3 - `gc_leases`

Creates `storage_gc_leases` (object_id primary key, `claimed_ns`, `owner`). Two concurrent `collect()` calls used to pick the same candidate and both call transport delete, so the same Telegram messages were deleted twice and the loser rolled its SQL back after the bytes were already gone. The lease is durable, so it also survives a crash: a stale row expires and the next run resumes the object, which is safe because chunk deletion is idempotent. The step ships separately from step 17 because editing a shipped step would never run on an already-migrated database.

### Step 17 - `gc`

Runs `create_all` on `gc_collect.metadata` - which is the manifest module's metadata, where the GC tables register themselves - creating `storage_gc_state` (the singleton enabled/grace row), `storage_gc_queue` (explicit collection requests from version deletes, multipart aborts and lifecycle expirations), `storage_gc_leases` (a no-op repeat of step 3) and `storage_gc_collected` (the permanent audit log of collected objects), plus the index `ix_storage_gc_queue_enqueued`. It also adds the defensive column `storage_gc_state.grace_seconds`. Because the metadata is shared, this step re-runs the manifest `create_all` from step 4; with `checkfirst` that is a no-op.

### Step 22 - `hot_indexes`

Defensively creates `storage_object_aliases` and its index `ix_storage_object_aliases_source` (in case a database predates the alias table), so the index never references a missing table. GC asks "is any alias still pointing at this object?" for every candidate, and the same index serves the dedup lookup; without it both were full table scans.

### Step 23 - `gc_indexes`

Defensively creates `storage_gc_queue` with `ix_storage_gc_queue_enqueued` (the queued scope filters on the grace window) and `storage_object_heads` with `ix_storage_object_heads_object` (the GC "is this a head anywhere?" probe filters by `object_id`, which is not part of that table's primary key). On a current database both already exist from steps 17 and 5; the step exists for databases that were migrated before the indexes were added to the table definitions.

## Credentials and encryption

### Step 18 - `credentials`

Creates `storage_s3_credentials` (id, name, unique access key, Fernet-encrypted secret, permission list, expiry, revocation flag) and adds the defensive column `tags` (TEXT, nullable; ABAC principal tags) for databases that predate it. Secrets are encrypted with the S3 master key; a database backup alone never reveals an AWS secret. A downgrade leaves the table but the older binary loses whatever permission scopes were added later.

### Step 26 - `envelope_encryption`

Adds three columns to `storage_object_encryption`: `wrapped_key` (the per-object AES-256-GCM data key, wrapped by the KEK derived from the deployment master key), `key_wrap` (`VARCHAR(16) DEFAULT 'none'`) and `envelope_aad` (the identity the wrapped key is bound to: the object id for a single PUT, the upload id for a completed multipart). All are envelope-mode (SSE-S3) fields; NULL means SSE-C or plaintext, and the SSE-C key is never persisted in any form. A downgrade leaves the columns ignored.

## Search and audit

### Step 21 - `content_search`

Creates the dialect-aware full-text structures for content search, which key search alone cannot serve:

- SQLite: an FTS5 virtual table `object_content_fts` (`CREATE VIRTUAL TABLE IF NOT EXISTS`).
- PostgreSQL: a generated `tsvector` column `tsv` on `object_content_index` (`language 'simple'`, no stemming) with a GIN index `ix_object_content_tsv`.
- MySQL: nothing; content search stays a SQLite/PostgreSQL accelerator rather than an error.

Failures are swallowed with a warning by design: search is an accelerator, and a database without the structures simply returns no content matches. The step creates structures only; the running service backfills existing heads lazily through the bounded reindex candidates query. A downgrade leaves the virtual table and the generated column in place, unread.

### Step 25 - `security_audit`

Creates `security_audit_events`, the durable security-event trail (credential issue/edit/revoke/reveal, API-key issue/rotate, config writes, user changes, physical GC start/finish, presign and share creation), with actor, target and a scrubbed detail blob, exposed to admins at `GET /api/v1/admin/audit`. The table is append-only and refuses to store anything shaped like a credential. The in-memory log buffer that preceded it was bounded and lost on restart, so no investigation could answer "who revealed this credential last week". A downgrade loses access to the trail but the rows remain for a later re-upgrade.

## Downgrades and residue

There is no down-migration, ever. The upgrade procedure is therefore: back up the database, upgrade, and if you must return to the previous code, restore the pre-upgrade backup. See [Upgrade](../operate/upgrade.md) for the sequence. What a code rollback leaves behind, mechanically:

- The recorded `schema_migrations.version` stays at 27. An older binary with a smaller `SCHEMA_VERSION` sees the database as current and performs no DDL, so the rollback itself never migrates anything down.
- Orphan tables (`security_audit_events`, `storage_report_configs`, and so on) and orphan columns (`wrapped_key`, `object_id`, ...) remain. Older code ignores them; every defensive column is nullable or carries a server default, so older inserts still succeed.
- Step 27 is the exception that matters: it deleted duplicate rows, and that deletion is not reversible by rolling back code. Restoring the backup is the only way back.
- The reverse direction is not safe: newer code on an older schema re-runs the full idempotent step list, which is correct, but the version probe means a partially applied migration completes rather than rolls back. Back up before every major version jump.

## Adding step 28

For developers: append a `(name, function)` pair to `_STEPS` and nothing else. The version bump is automatic (`SCHEMA_VERSION = len(_STEPS)`). Never edit or reorder a shipped step - an already-migrated database will never run it again, which is exactly why steps 2, 3 and the index steps exist as separate versions. Keep the step idempotent: `checkfirst` for tables and indexes, column probes before ALTERs, and temporary-table materialisation for any dedupe. See the module docstring in [`teledrive/storage/schema.py`](https://github.com/babico/TeleDrive/blob/main/teledrive/storage/schema.py) for the design constraints, and [Databases](../guide/databases.md) for the supported backends.
