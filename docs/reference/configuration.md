# Configuration reference

Every service setting TeleDrive reads, where it is stored, its default, and
what changing it does. The list is generated from
[`config.example.yaml`](https://github.com/babico/TeleDrive/blob/main/config.example.yaml),
[`teledrive/settings.py`](https://github.com/babico/TeleDrive/blob/main/teledrive/settings.py),
[`teledrive/settings_store.py`](https://github.com/babico/TeleDrive/blob/main/teledrive/settings_store.py),
[`teledrive/uploader.py`](https://github.com/babico/TeleDrive/blob/main/teledrive/uploader.py)
and the configuration handlers in [`web/app.py`](https://github.com/babico/TeleDrive/blob/main/web/app.py);
when this page and a running deployment disagree, those files win.

## 1. Precedence: SQL document, bootstrap file, defaults

Settings are **not** read from environment variables, with two classes of
exception listed below. The authoritative copy lives in the SQL database, so
two workers sharing a database always agree.

| Layer | Location | Authority |
| --- | --- | --- |
| SQL settings document | table `service_settings`, one encrypted row (`id = 'config'`) | Authoritative after the first boot. Written on every WebUI save. |
| Bootstrap file | `config/config.yaml` (`TELEDRIVE_CONFIG`, default relative path) | Seeds SQL on first boot, and is the fallback when the row is missing or undecryptable. Rewritten from the SQL document on read, so a stale mounted file self-heals. |
| Code defaults | `web.app.default_config()` and `teledrive/settings.py` | Used when neither layer supplies a key. |

The document contains secrets (`api_hash`, session strings), so
`SettingsStore` encrypts it with the S3 master key (Fernet). A changed or
missing master key makes the row undecryptable; the service logs that, falls
back to the file, and re-seeds SQL on the next save instead of failing
startup. The file is mode `0600`, symlinks are refused, and the containing
directory is mode `0700`.

A WebUI save validates by loading the candidate into a temporary file,
running `uploader.load_config`/`validate_config` and opening the database
before replacing the real file. The SQL write happens after the file write and
never fails the save on its own.

Two `state` keys cannot be changed over HTTP because each is a takeover or
code-execution primitive:

| Key | Why it is file-only |
| --- | --- |
| `state.database_url` / `state.db_path` | Redirecting the URL makes the next start bootstrap `admin`/`admin` into a fresh database and orphans the real data. |
| `state.db_extra_packages` | pip-installed at every boot, so it is arbitrary code execution that survives restarts. |

## 2. Environment variables

Deployment plumbing is environment-only by owner policy, so the host port
mapping, the in-container listener and the healthcheck can never disagree.
Most of these variables are read in `teledrive/settings.py`; the S3 gateway
variables are read in `teledrive/s3/`. The four listener/TLS
pairs are deliberately **ignored** in `config.yaml` even though a generated
default file still contains legacy `web.port`/`web.s3_port` keys.

| Variable | Default | Effect |
| --- | --- | --- |
| `TELEDRIVE_CONFIG` | `config/config.yaml` | Path to the bootstrap file. |
| `TELEDRIVE_WEB_PORT` | `8080` | WebUI/REST listener port, inside the container and in Compose. |
| `TELEDRIVE_S3_PORT` | `9000` | S3 gateway listener port. |
| `TELEDRIVE_BIND_ADDRESS` | `0.0.0.0` inside the container | Bind address; Compose uses it for the host-side mapping (default `127.0.0.1`). |
| `TELEDRIVE_SSL_CERTFILE` | empty | Enables TLS on the WebUI/REST listener. A combined PEM (chain + key) needs only this. |
| `TELEDRIVE_SSL_KEYFILE` | empty | Private key for a split certificate pair. |
| `TELEDRIVE_S3_SSL_CERTFILE` | empty | Enables TLS on the S3 listener, independently of the WebUI. |
| `TELEDRIVE_S3_SSL_KEYFILE` | empty | S3 private key for a split pair. |
| `TELEDRIVE_TRUSTED_PROXY` | empty/false | Trust `X-Forwarded-Proto` for Secure cookies and generated URLs, and use the leftmost public `X-Forwarded-For` address for throttles. |
| `TELEDRIVE_S3_MASTER_KEY` | empty | Fernet key value used when no key file is configured. |
| `TELEDRIVE_S3_MASTER_KEY_FILE` | `/config/s3-master.key` | File containing the Fernet master key. Populated from `storage.s3_master_key_file` at settings reload. |
| `TZ` | `Europe/Istanbul` in Compose | Container timezone only; timestamps in SQL are epoch values. |
| `PUID` / `PGID` | `1000` | Host uid/gid the container runs as. Must own `./config` and `./data`. |
| `TELEDRIVE_DB_EXTRA_PACKAGES` | empty | Docker **build** argument (`docker-compose.yml`), pip-installed into the image. Runtime installation is configured separately through `state.db_extra_packages`. |
| `TELEDRIVE_DATA_DIR` | `/data` | Root for stateful defaults: scratch, auth, sessions, logs, SQLite roots, site-packages and the cold archive. |
| `TELEDRIVE_COLD_ARCHIVE_DIR` | `<TELEDRIVE_DATA_DIR>/cold-archive` | Root of the local-filesystem cold archive used by tiering and `RestoreObject`. |
| `TELEDRIVE_S3_VHOST_SUFFIX` | empty | Public suffix for virtual-hosted-style S3 requests. Empty means path-style only. |
| `TELEDRIVE_S3_REGION` | `us-east-1` | Region used in the SigV4 credential scope for S3 Express requests. |
| `TELEDRIVE_S3_DIRECTORY_ZONE_ID` | `use1-az1` | Logical compatibility zone in a directory-bucket name; not an AWS Availability Zone. |
| `TELEDRIVE_S3_SESSION_LIFETIME_SECONDS` | `300` | Directory-bucket `CreateSession` lifetime, clamped to 30–3600 seconds. |
| `TELEDRIVE_S3_INTERNAL_HOST` | `127.0.0.1` | Host the WebUI governance bridge uses to reach the loopback S3 listener. |

`settings.py` also accepts legacy environment fallbacks for keys that
normally live in the file: `TELEDRIVE_ALLOWED_HOSTS`,
`TELEDRIVE_REST_MAX_UPLOAD_BYTES`, `TELEDRIVE_MAX_REQUEST_BYTES`,
`TELEDRIVE_STORAGE_SCRATCH_DIR`, `TELEDRIVE_JOB_SOURCE_ROOT`,
`TELEDRIVE_JOB_AUTO_RUN`, `TELEDRIVE_ALLOWED_SQLITE_ROOTS`,
`TELEDRIVE_AUTH_FAILURE_LIMIT`, `TELEDRIVE_AUTH_FAILURE_WINDOW_SECONDS`,
`TELEDRIVE_AUTH_DIR`, `TELEDRIVE_ALLOWED_SOURCE_ROOTS`,
`TELEDRIVE_ALLOWED_SESSION_ROOTS`, `TELEDRIVE_ALLOWED_LOG_ROOTS`,
`TELEDRIVE_SPLIT_DIR`, `TELEDRIVE_SPLIT_MIN_FREE_BYTES`,
`TELEDRIVE_LOCK_DIR`, `TELEDRIVE_ENCRYPTION`,
`TELEDRIVE_NOTIFICATION_DESTINATIONS` and the legacy
`TELEDRIVE_STORAGE_MTPROTO_API_ID` / `_API_HASH` / `_SESSION_FILE` triple.
The file wins when both are set. Treat these as compatibility shims, not the
documented way to configure a deployment.

## 3. `web` — request handling and login throttle

| Key | Type | Default | What it changes |
| --- | --- | --- | --- |
| `allowed_hosts` | comma string or list | `localhost,127.0.0.1,[::1]` | `Host` values the app accepts. Set the public hostname before exposing the UI. |
| `rest_max_upload_bytes` | integer | `2147483648` (2 GiB) | Largest single-shot REST/WebUI upload body. Larger files need S3 multipart. |
| `max_request_bytes` | integer | `33554432` (32 MiB) | Hard ceiling for any accepted HTTP request body. |
| `auth_failure_limit` | integer >= 1 | `5` | Failed logins allowed per `(username, client)` inside the window before HTTP 429. |
| `auth_failure_window_seconds` | integer >= 1 | `300` | Sliding window for the login throttle. |
| `auth_dir` | string | `/data/auth` | Directory for login session storage. |
| `bind_address`, `port`, `s3_port`, `ssl_certfile`, `ssl_keyfile` | — | generated defaults | **Legacy and ignored.** Listeners and TLS are environment-only (section 2). |

Authentication has no configuration keys. First boot creates the hardcoded
`admin`/`admin` account; see [Security policy](../security/policy.md).

## 4. `storage` — Telegram transport and encryption

| Key | Type | Default | What it changes |
| --- | --- | --- | --- |
| `channel` | string | empty | Dedicated private broadcast channel. A numeric ID must be visible in the user's dialogs; a title is resolved as a fallback. Saved Messages is refused. When empty, the channel activated in the WebUI is used. |
| `encryption` | `none` or `envelope` | `none` | `envelope` makes the server encrypt every chunk with a per-object AES-256-GCM data key wrapped by the master key. It disables deduplication, replication and content search for encrypted objects. Invalid values fail at startup. |
| `strategy` | `single`, `round_robin`, `failover`, `parallel` | `round_robin` | How uploads choose among `apis`. Invalid values stop the runtime. |
| `scratch_dir` | string | `/data/tmp` | Staging directory for split/assembled payloads. |
| `s3_master_key_file` | string | `/config/s3-master.key` | Fernet key file for S3 credential secrets and the settings document. |
| `replica_account` | string | empty | Account label that receives a second copy of every new object. An unknown label logs a warning and disables replication. |
| `notification_destinations` | comma string | empty | Owner-approved HTTP(S) webhook origins/prefixes. Empty means every notification destination is rejected. |
| `apis` | list of maps | empty | Authorized USER MTProto credential sets. Each entry needs `api_id` (int), `api_hash` (string) and either `session_file` or `session_string`; `account` is an optional unique label defaulting to `mtproto-user`, `mtproto-user-2`, ... Every set must resolve the same channel. Sessions stored in SQL by the WebUI take precedence over this list. |

`storage.apis` is a list of *user* sessions. A Bot token cannot be used: the
runtime verifies the account is not a bot and that it can post to the channel.

## 5. `telegram` — legacy section

The Bot-era `telegram:` section is tolerated but no longer supplies
credentials. `uploader.load_config` still reads `telegram.strategy` into
`AppConfig.strategy` and `validate_config` still rejects an unknown value, but
the live transport uses `storage.strategy`. Do not add `api_id`, `api_hash`
or `bot_token` here expecting them to be used.

## 6. `jobs` — durable local-file queue

| Key | Type | Default | What it changes |
| --- | --- | --- | --- |
| `source_root` | string | `/uploads` | Root scanned by the optional watcher and accepted for legacy import. Must be inside `paths.source_roots`. |
| `auto_run` | boolean | `true` | Process explicitly queued upload jobs automatically. |
| `watch` | boolean | `false` | Periodically scan `source_root` and enqueue new/changed files. |
| `watch_interval_seconds` | integer >= 5 | `30` | Watcher period. |
| `watch_bucket` | string | empty | Bucket receiving watched files. The watcher does nothing while this is empty. |

## 7. `state` — SQL catalog

| Key | Type | Default | What it changes |
| --- | --- | --- | --- |
| `database_url` | SQLAlchemy URL | `sqlite:////data/state.db` | Shared catalog. SQLite, PostgreSQL and MySQL are tested. |
| `db_path` | string | — | Legacy alias for `database_url`; still accepted. |
| `db_extra_packages` | list or comma string | empty | Drivers not bundled in the image. Installed into a writable runtime directory and prepended to `sys.path`; a configured driver that fails to install is a startup error. |
| `allowed_sqlite_roots` | comma string or list | `/data` | Directories a SQLite database file may live under. |

PostgreSQL/MySQL credentials belong in the URL. Use a database TLS parameter
where the driver supports it and keep the URL out of logs; `redact_database_url`
removes the password in the config API and error text.

## 8. `paths` — filesystem allowlists

| Key | Type | Default | What it changes |
| --- | --- | --- | --- |
| `source_roots` | string | `/uploads` | Approved roots for local-file ingestion. |
| `session_roots` | string | `/data/sessions` | Approved roots for Telethon session files. |
| `log_roots` | string | `/data` | Approved roots for the log file. |
| `split_dir` | string | `/data/tmp` | Temporary directory used when splitting large uploads. |
| `split_min_free_bytes` | integer >= 1 | `536870912` (512 MiB) | Free-space floor before a split upload starts. |
| `lock_dir` | string | `/data/tmp` | Directory for cross-process lock files. |

These are enforced by `uploader.validate_storage_paths` and the legacy bridge:
a path outside its allowlist is rejected, not silently accepted.

## 9. `upload` — legacy scanner and filter

| Key | Type | Default | What it changes |
| --- | --- | --- | --- |
| `source_dir` | string | `/uploads` | Legacy scanner source directory; also used by cutover validation. |
| `allowed_extensions` | list of strings | `[]` | If non-empty, the legacy bridge accepts only these extensions. Lowercased on read. |
| `max_file_size_mb` | integer >= 0 | `0` | If non-zero, the legacy bridge rejects larger files. `0` means no limit. |
| `sleep_min_seconds`, `sleep_max_seconds`, `max_files_per_run`, `max_files_per_day`, `retry_attempts`, `backoff_base_seconds`, `floodwait_buffer_seconds`, `caption_template`, `send_mode` | — | written by `default_config()` | **Inert.** No service code reads them; the durable job queue and MTProto rate guard own pacing. |

## 10. `logging` and `app`

| Section | Key | Type | Default | What it changes |
| --- | --- | --- | --- | --- |
| `logging` | `log_path` | string | `/data/uploader.log` (generated default); `/data/teledrive.log` is the startup fallback when the key is absent | Rotating log file, subject to `paths.log_roots`. |
| `logging` | `level` | string | `INFO` | Python log level. |
| `app` | `auto_run` | boolean | not written | **Inert.** Jobs are controlled by `jobs.auto_run`. |
| `app` | `run_interval_minutes` | integer | not written | **Inert.** No scheduler reads it. |

## 11. Settings that no longer exist

These keys may still be present in an old file. They are stripped on read and
never authorize anything; the next save persists the cleaned document.

| Removed key | Replaced by |
| --- | --- |
| `web.user`, `web.password`, `web.password_file`, `web.allow_insecure` | The local `users` table: login session cookie or `td_sess_` bearer, plus API keys. HTTP Basic has no code path at all. |
| `security.*` Basic-auth keys from older forks | Same. |
| Upload scanner pacing keys listed as inert in section 9 | The durable job queue, `jobs.*`, and the MTProto rate guard. |
| `telegram.bot_token` / Bot API credentials | A Telethon USER session in `storage.apis` or the `telegram_sessions` table. |

If a deployment still relies on the retired Basic password to reach the UI,
the upgrade path is the login page with the local account (or the bootstrapped
`admin`), then issue API keys for automation. See [Upgrade](../operate/upgrade.md).

## 12. Validating a change

There is no separate config-check command. The write path is the check: a
WebUI/API save only replaces the file after `load_config`, `validate_config`
and a database connection succeed. For a file edited on disk, restart and
watch the log for `settings:`/`startup` lines; an invalid
`storage.encryption` or `storage.strategy` is a startup error, not a silent
fallback. The full validation contract is in
[CI and tests](ci.md#2-run-checks-locally).
