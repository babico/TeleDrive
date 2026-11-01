# Configure

TeleDrive reads configuration from three places with different jobs:
environment variables for deployment plumbing, `config/config.yaml` as the
first-boot seed, and an encrypted settings document in SQL that becomes the
authoritative copy after the first save. This page explains the order, how to
change a value without having it silently reverted, and the keys that matter
most. The exhaustive key list is in
[Configuration reference](../reference/configuration.md).

## The three layers

| Layer | Where it lives | What belongs there |
| --- | --- | --- |
| Environment | `.env`, Compose `environment:` | Ports, bind address, TLS paths, `PUID`/`PGID`, `TZ`, trusted-proxy mode, extra DB driver packages. Deployment plumbing only. |
| Bootstrap file | `config/config.yaml` (mounted at `/config/config.yaml`) | The complete settings document used on first start and after a disaster. Written with mode `0600`. |
| SQL settings document | one encrypted row, `service_settings.id = 'config'` | The authoritative document after first boot. Written by every settings save. |

Precedence, in order:

1. **SQL document**, when the row exists and can be decrypted.
2. **`config/config.yaml`**, when the row is missing or undecryptable. The
   service then seeds SQL from the file, so the next start is SQL-backed.
3. **Built-in defaults** from `teledrive/settings.py` for keys absent from the
   document.

Ports and TLS are the exception: they are read **only** from the environment,
never from `config.yaml`, because the same value must drive the host port
mapping, the in-container listener and the healthcheck.

## Changing a setting

| Method | Use it for | Notes |
| --- | --- | --- |
| Web UI settings pages | Day-to-day changes: allowed hosts, limits, storage policy, Telegram accounts, S3 credentials. | A save writes the SQL row **and** rewrites `config.yaml`. |
| `PUT /api/v1/config` | Automation | Requires an interactive login session (cookie), not an API key, and the `x-teledrive-csrf: 1` header. |
| Editing `config/config.yaml` by hand | First bootstrap, disaster recovery, or a value that must exist before the service starts. | Once SQL holds the row, the service rewrites the file from SQL; a manual edit is reverted on the next read. |
| Editing `.env` | Ports, TLS, bind address, `PUID`/`PGID`, `TZ` | Requires recreating the container: `docker compose up -d`. |

!!! warning "Hand edits lose to SQL"
    If you change `config.yaml` on a running installation and the change does
    not appear, that is the designed behaviour: the SQL document wins and the
    file is a materialized mirror. Use the UI or the API, or make the file
    authoritative again as described below.

### Making the file authoritative again

Stop the service first, then delete the one settings row:

```bash
# SQLite deployment, from the host
sqlite3 data/state.db "DELETE FROM service_settings WHERE id = 'config';"

# PostgreSQL
psql "$DATABASE_URL" -c "DELETE FROM service_settings WHERE id = 'config';"
```

On the next start the service seeds a new row from `config/config.yaml`.
Everything that existed only in that settings document and was never written
back to the file is now gone. Telegram sessions and objects live in their own
tables and are not affected by this deletion, but back up the database before
changing settings at this level.

## Secrets and the master key

TeleDrive needs a 32-byte Fernet key, called the S3 master key. It protects:

- the encrypted `service_settings` document (which contains Telegram
  `api_hash` values and other operator settings);
- the stored secret half of every S3 credential;
- the key-encryption key for envelope encryption, when
  `storage.encryption: envelope` is set.

The key is read from `storage.s3_master_key_file` (default
`/config/s3-master.key`) or, if that is unset, from the
`TELEDRIVE_S3_MASTER_KEY` environment variable. In the shipped Compose
deployment, use the file. The file must be mode `0600` and owned by the
container user.

```bash
openssl rand -base64 32 > config/s3-master.key
chmod 600 config/s3-master.key
```

Back the key up separately from the database. A master-key change has two
different consequences:

- the settings document becomes undecryptable; the service falls back to
  `config.yaml` and re-seeds on the next save;
- existing S3 credential secrets cannot be decrypted. Re-issue those
  credentials, or restore the old key.

Never commit the key, and never place it in the same backup as an unencrypted
database dump if that dump also contains the encrypted settings row.

## Important keys and defaults

| Key | Default | Notes |
| --- | --- | --- |
| `web.allowed_hosts` | `localhost,127.0.0.1,[::1]` | Exact `Host` header allowlist. See below. |
| `web.rest_max_upload_bytes` | `2147483648` (2 GiB) | Largest single REST upload body. |
| `web.max_request_bytes` | `33554432` (32 MiB) | Largest HTTP request body for non-upload routes. |
| `web.auth_failure_limit` | `5` | Failed logins per window before throttling. |
| `web.auth_failure_window_seconds` | `300` | Window for the login throttle. |
| `web.auth_dir` | `/data/auth` | Reserved auth directory, created at startup. |
| `storage.channel` | empty | Dedicated private channel. Empty means "use the channel activated in the UI". |
| `storage.encryption` | `none` | `none` or `envelope`; see [Encryption](../guide/encryption.md). |
| `storage.strategy` | `round_robin` | `single`, `round_robin`, `failover` or `parallel`. |
| `storage.scratch_dir` | `/data/tmp` | Staging directory for chunk splits. |
| `storage.s3_master_key_file` | `/config/s3-master.key` | Fernet key file described above. |
| `storage.apis` | empty | File-based Telegram credential sets; see [Telegram accounts](../guide/telegram-accounts.md). |
| `state.database_url` | `sqlite:////data/state.db` | SQLAlchemy URL; see [Databases](../guide/databases.md). |
| `jobs.source_root` | `/uploads` | Local import root. |
| `jobs.auto_run` | `true` | Run explicitly queued durable jobs. |
| `jobs.watch` | `false` | Periodic folder auto-sync. |
| `jobs.watch_interval_seconds` | `30` | Minimum 5. |
| `paths.source_roots` | `/uploads` | Approved roots for local-file jobs. |
| `paths.session_roots` | `/data/sessions` | Approved roots for session files. |
| `logging.log_path` | `/data/teledrive.log` | File log destination when the key is absent. See the log note below. |

`state.database_url`, `state.db_path` and `state.db_extra_packages` are
**file-only**: the config API cannot change them, so a stolen session cannot
point the service at a different database.

## `allowed_hosts`

The web middleware compares the `Host` header (without the port) against this
list using exact string matching. It does not accept wildcards. If you reach
the UI at `https://teledrive.example.com`, add that name. If you publish the
ports on a LAN address, add that IP. Behind a reverse proxy, the proxy must
forward the original `Host` header unchanged, and you should enable
`TELEDRIVE_TRUSTED_PROXY=1` so forwarded scheme and client address are
honored.

A request with an unlisted host gets `400 Invalid host header`. This is the
usual cause of "it works on localhost but not through my proxy".

## Limits and quotas

There are three different mechanisms, and they are not interchangeable:

| Mechanism | Scope | Enforced or advisory |
| --- | --- | --- |
| `web.max_request_bytes`, `web.rest_max_upload_bytes` | HTTP body size | Hard limit, rejected before storage. |
| Bucket quota (`max_size_bytes`, `max_objects`) | One bucket | Hard limit checked at publish time; set per bucket in the UI. |
| Telegram account soft quota (`soft_quota_bytes`) | One MTProto account | Advisory routing preference: when the selected account is over quota, the sender prefers an under-quota account. It does not reject an upload. |

Bucket quotas are set on **S3 -> Buckets -> Quota**. Account soft quotas are
set on **Settings -> Telegram** in the account table. The account view also
separates current usage from retained (deleted but not physically collected)
bytes, because physical GC is owner-gated.

## The storage section

The storage section is where the Telegram side is configured. The minimum
shape for a file-based setup:

```yaml
storage:
  channel: "-1001234567890"     # or @username
  strategy: round_robin
  encryption: none
  s3_master_key_file: "/config/s3-master.key"
  apis:
    - api_id: 111111
      api_hash: "YOUR_API_HASH"
      session_file: "/config/mtproto-user.session"
      account: mtproto-user
```

Accounts created from the UI are stored in SQL and take precedence over
`storage.apis`; you do not need both. Every credential set must resolve the
same channel. See [Telegram accounts](../guide/telegram-accounts.md) for the
session lifecycle and rotation semantics.

## Logs

Activity is available in three places:

- **Logs** page in the UI (`/logs`), admin-only, with a live stream;
- `GET /api/v1/logs`, admin-only, recent redacted entries;
- the rotating file log. Its path is `logging.log_path`; when the key is
  absent the runtime fallback is `/data/teledrive.log`. The minimal file that
  the service writes on a completely fresh boot declares
  `/data/uploader.log`, so check the key in your own file rather than assuming
  the fallback. Rotated files are gzipped at 10 MiB, five kept.

The file log carries object keys, request paths and failure detail. Treat it
as operational data, not as a public artifact.

## Where to go next

- Every supported key, with types and defaults:
  [Configuration reference](../reference/configuration.md).
- Database URLs and migration behaviour: [Databases](../guide/databases.md).
- Telegram credentials and channels:
  [Telegram accounts](../guide/telegram-accounts.md).
- Encryption modes: [Encryption](../guide/encryption.md).
