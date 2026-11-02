# Upgrade TeleDrive

This page is for an operator moving an existing installation to the current
`main` / 1.0.8 line. It lists the upgrade sequence, the schema version, and
every operator-visible breaking change that needs a decision. It does not
repeat the installation guide; see [Install](../start/install.md) for the
container layout.

Back up `config/`, the SQL database and the S3 master key first. A
database-only backup is **not** a backup of Telegram media, and a Telegram
channel is not a backup of the catalog.

## Before you upgrade

| Asset | Why |
| --- | --- |
| SQL database | Object graph, users, API keys, S3 credentials, jobs, settings row. |
| `config/config.yaml` | Bootstrap and disaster-recovery settings. |
| `config/s3-master.key` | Decrypts S3 secrets and the `service_settings` row. A different key cannot read the old data. |
| Telegram session (`/data/sessions`, `telegram_sessions`, or `config/*.session`) | Needed to read existing chunks. |
| A note of the current schema version | Tells you whether the upgrade will migrate. |

For SQLite, use the online tool; it is safe while the service runs:

```bash
python scripts/ops/backup_metadata.py \
  --database data/state.db \
  --output /secure-backups/pre-upgrade-$(date +%F).db
```

For PostgreSQL and MySQL, take a native consistent dump (`pg_dump -Fc`,
`mysqldump --single-transaction`). Then read
[Backup and restore](../operate/backup-restore.md) before relying on it.

Record the version you are leaving (SQLite example):

```bash
python -c "import sqlite3; print(sqlite3.connect('data/state.db').execute('select max(version) from schema_migrations').fetchone())"
```

## How to upgrade

The image used by the Compose file is built locally as `teledrive:local`;
there is no image reference to pull in the shipped Compose file.

```bash
# 1. Back up (see above), then fetch the new code.
git pull --ff-only

# 2. Rebuild and recreate the single container.
docker compose up -d --build

# 3. Confirm it came up.
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
docker compose logs --tail=120 teledrive
```

`docker compose up -d --build` recreates the container. Migrations run
automatically on startup; there is no separate migrate command.

## Schema migrations

`SCHEMA_VERSION` is the length of the append-only step list in
`teledrive/storage/schema.py`, currently **27**. Migrations run
automatically on startup — there is no separate migrate command and no
step you must run by hand. The per-step reference, including what each
step creates and what a rollback would leave behind, is
[Schema steps](../reference/schema-steps.md).

The coordinator:

- reads the highest applied version from `schema_migrations`;
- if it is current, performs no DDL;
- otherwise takes a cross-process lock and runs every idempotent step in order
  (SQLite `flock` on `<db>.schema-lock`, PostgreSQL advisory lock, MySQL
  `GET_LOCK` — all with a 30-second timeout);
- records the new version.

Three consequences matter during an upgrade:

- An interrupted migration is safe to re-run; every step is idempotent.
- Steps are append-only and there is no down-migration. Rolling back the code
  after the schema advanced requires restoring the pre-upgrade database
  backup.
- On a busy database the lock wait is bounded at 30 seconds. If another
  worker is mid-migration longer than that, the starting worker fails with a
  timeout rather than queueing indefinitely; let the first worker finish and
  start again. A stopped container while another holds the lock is the
  normal cause.

Before a major version jump, check three things:

1. **Backup.** Take the database backup described under
   [Before you upgrade](#before-you-upgrade). Step 27 deletes duplicate rows;
   only the backup can bring them back.
2. **Recorded version.** Note the value of
   `select max(version) from schema_migrations` before upgrading, so you can
   say afterwards which steps ran.
3. **Concurrent workers.** Every worker that opens the same database runs
   the same serialized migration. One worker migrates while the others wait
   on the lock; you do not need to drain workers first, but avoid restarting
   the whole fleet simultaneously on a slow database, because each worker's
   lock wait is capped at 30 seconds.

Step 27 deduplicates `telegram_sessions.account` and
`telegram_channels.channel_id` (keeping the most recently updated row) before
adding unique indexes. If you deliberately kept duplicate rows, export them
first.

## Breaking changes

### HTTP Basic and the config password are gone

There is no authenticated identity other than the login-form session (cookie
or `td_sess_` bearer token) and an API key. `web.user`, `web.password`,
`web.password_file` and `web.allow_insecure` are no longer settings; they are
stripped from the config file and the SQL document when read.

First boot creates a hardcoded `admin` / `admin` administrator, only when no
`admin` row exists, and never overwrites an existing row. If the previous
deployment authenticated only with the config password, there is no credential
to carry over.

#### Locked-out admin

Recovery requires filesystem and database access, not a network token. Run it
from a checkout with the runtime requirements installed:

```bash
python scripts/ops/reset_local_password.py --config config/config.yaml \
  --username admin --role admin
```

The script prompts twice, accepts any non-empty password at or above its
minimum (default 5, a typo check rather than a policy), updates the role and
enables the account. It revokes that user's existing sessions. Deleting the
`admin` row and restarting also recreates `admin` / `admin`.

!!! warning "SQLite path when running from the host"
    In the container, `config.yaml` points at `/data/state.db`. On the host
    that path usually does not exist. For a SQLite deployment, point the
    script at the host file instead:

    ```bash
    python scripts/ops/reset_local_password.py \
      --database "sqlite:///$PWD/data/state.db" \
      --username admin --role admin
    ```

    For PostgreSQL or MySQL, the `--config` form works when the database is
    reachable from the host.

### Deployment plumbing moved to environment variables

Ports, bind address, trusted-proxy mode and TLS paths are environment-only.
They are not read from `config.yaml`, because the same value must drive the
host mapping, the in-container listener and the healthcheck.

Remove these old listener keys from the file:

```yaml
# BEFORE - no longer read
web:
  bind_address: "0.0.0.0"
  port: 8080
  s3_port: 9000
  ssl_certfile: "/config/tls/server.crt"
  ssl_keyfile: "/config/tls/server.key"
```

Use `.env` or the Compose `environment:` block:

```env
TELEDRIVE_WEB_PORT=8080
TELEDRIVE_S3_PORT=9000
TELEDRIVE_BIND_ADDRESS=127.0.0.1

TELEDRIVE_SSL_CERTFILE=/config/ssl/server.crt
TELEDRIVE_SSL_KEYFILE=/config/ssl/server.key

TELEDRIVE_S3_SSL_CERTFILE=/config/ssl/server.crt
TELEDRIVE_S3_SSL_KEYFILE=/config/ssl/server.key

# Only when TLS terminates in front of the application:
# TELEDRIVE_TRUSTED_PROXY=1
```

Each listener has an independent TLS pair. A combined PEM needs only the
`_CERTFILE` variable. `deploy/tls/generate.sh` writes the material under
`config/ssl` and prints the matching lines.

### Service settings now live in SQL

On the first boot after upgrading, the service creates one encrypted
`service_settings` row and seeds it from `config/config.yaml`. From then on the
SQL row is authoritative:

- a settings save writes both the SQL row and the mounted file;
- rebuilding from an older mounted `config.yaml` does not roll settings back;
- a missing row is seeded from the file;
- an undecryptable row (master-key change) falls back to the file and is
  re-seeded on the next save; startup does not fail.

Because the row contains Telegram `api_hash` values and other operator
settings, it is encrypted with the S3 master key. A master-key change has two
different outcomes: settings recover from the file, but stored S3 credential
secrets cannot be decrypted and must be re-issued.

Multiple workers sharing one database now read the same document, so a UI save
does not need a restart to reach the other worker.

### S3 ownership default changed

The default ownership model is `BucketOwnerEnforced`: object-ACL grants are
ignored for access decisions, bucket ACLs still constrain bucket-level access,
and the owner plus any bucket policy still apply.

A bucket that relied on object-ACL grants must opt into `ObjectWriter`:

```python
import boto3

s3 = boto3.client("s3", endpoint_url="https://s3.example.com", ...)
s3.put_bucket_ownership_controls(
    Bucket="my-bucket",
    OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
)
```

`BucketOwnerPreferred` behaves like `ObjectWriter` and also adds an automatic
owner `FULL_CONTROL` grant when an object is uploaded with
`x-amz-acl: bucket-owner-full-control`.

### S3 credential scopes are not retroactively granted

The permission catalog grew from 18 scopes to 90 in the current tree. New
credentials get whatever list is requested; existing credentials keep the
permissions stored when they were issued. Nothing is auto-granted.

A credential that must call a newly added operation needs that exact scope,
added on **S3 -> Credentials** (Edit) or with
`PUT /api/v1/admin/s3-credentials/{identifier}`. Read-only compatibility
probes have their own scopes.

Two related changes:

- Creating a credential without a `permissions` list now grants a **read-only**
  set. It used to grant every permission.
- Issuing, editing, revoking or revealing an S3 credential requires an
  interactive login session. An API key receives `403`, because a credential
  is itself a secret and letting a key mint one bypassed the delegation
  ceiling. Presigned URLs and `PUT /api/v1/config` are interactive-only for
  the same reason.

The identifier may be the credential id or its access key. `PUT` enforces the
same expiry bounds as `POST` and refuses to revive an expired credential.

### Share links pin the object version

`share_links` gained `object_id` (schema step 24). A new link serves exactly
the version that existed when it was created: overwriting the key no longer
changes what the URL returns, and an unlink plus re-upload does not revive it.
A link that cannot resolve its pinned version answers the same uniform `404`
as an expired link.

Links created before this release have `object_id = NULL` and stay key-bound.
Re-issue them if you need the pinning guarantee. A failed request no longer
consumes a download slot; only a request that actually streams counts.

### The audit trail is admin-only and durable

`GET /api/logs` and the live log websocket are admin-only. The buffer carries
object keys, request paths and failure detail.

Security events are also stored in `security_audit_events` (schema step 25)
and exposed at `GET /api/v1/admin/audit`. That covers credential
issue/edit/revoke/reveal, API-key issue/rotate, config writes, user changes,
physical GC start/finish, presign and share creation, with the actor, target
and a scrubbed detail blob. The table is append-only and refuses to store
anything shaped like a credential.

### Envelope encryption is available and opt-in

`storage.encryption: envelope` makes encryption at rest a server property: one
fresh AES-256-GCM data key per object, wrapped by a key derived from the S3
master key, with only the wrapped form persisted. This is the SSE-S3 shape;
clients send plaintext.

```yaml
storage:
  encryption: envelope
```

Then set a bucket default or ask per request:

```bash
aws s3api put-bucket-encryption --bucket backups \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

The cost is explicit: encrypted objects are **not** deduplicated, **not**
replicated and **not** content-indexed. `envelope.capabilities()` reports
exactly those three and the UI shows them. Enabling it is not retroactive;
existing objects keep their current form.

`aws:kms` stays `501` in both modes, and asking for `AES256` while the setting
is `none` is also `501` naming the setting, rather than silently storing
plaintext. SSE-C is unchanged and always available.

### Object lock and tiering change behaviour

Object Lock is one-way. Enabling it is permanent; the default retention can
only be extended, never shortened. `COMPLIANCE` retention is extend-only and
cannot be cleared while active. Retained and held versions refuse explicit and
batch version deletes, and GC/lifecycle will not touch them.
`x-amz-bypass-governance-retention` is rejected `501`; there is no
governance-elevation model. Test on a disposable bucket first.

Intelligent-Tiering is an **access gate**, not a cold backend. Enabling a
tiering configuration starts access counting and lets the scheduler move
`storage_class` by idle time. An archived object answers
`403 InvalidObjectState` to GET, HEAD and ranged reads until `RestoreObject`
opens a bounded restore window. No Telegram chunk is moved, compressed or
deleted, and there is no Glacier durability or retrieval pricing. Deleting the
tiering configuration stops future transitions; already-transitioned objects
keep their class until a new configuration matches the bucket.

### S3 operations that now refuse instead of pretending

- `PUT ?retention` / `?legal-hold` with a streaming payload must carry a
  verifiable `x-amz-checksum-sha256`; otherwise the change is refused.
- A `Range` header longer than 20 digits is `416`, not `500`.
- A REST read of an archived object is `403 InvalidObjectState`; a read of an
  SSE-C object without the key is `400` naming SSE-C, including on the public
  website and the WebUI download button.
- An unlink of an object under legal hold or retention is `403`.

### Two-person deletion approval is no longer required

The physical-GC gate list was: independent backup, restore drill, writer
barrier and a two-person deletion approval. **The last one is removed by owner
decision.** The other three still gate `deletion_permitted`, which remains
`False`, and `scripts/ops/verify_production_bundle.py` still verifies the
technical evidence and any signature that is supplied.

Upgrading never turns physical GC on. See
[Garbage collection](../operate/garbage-collection.md).

### Legacy upload settings are no longer read

The legacy direct-send scanner is gone; chunk I/O lives in the unified storage
transport. These `upload:` keys and the legacy `telegram:` account keys are
ignored and should be deleted:

```yaml
upload:
  sleep_min_seconds: 60
  sleep_max_seconds: 90
  max_files_per_run: 12
  max_files_per_day: 100
  retry_attempts: 5
  backoff_base_seconds: 10
  floodwait_buffer_seconds: 5
  caption_template: "{name}"
  send_mode: "document"
telegram:
  api_id: 12345
  api_hash: "..."
  target: "me"
```

`upload.source_dir`, `upload.allowed_extensions` and
`upload.max_file_size_mb` remain: the legacy import and cutover checks still
use them as the source-root and allowlist filter. Telegram credentials come
only from `storage.apis` or the SQL session rows.

## Verify after upgrading

1. `docker compose ps` reports `(healthy)`; both `/api/health` and
   `/__health` answer.
2. Log in and confirm the settings you expect are shown. Save one harmless
   setting, rebuild the container, and confirm it survived.
3. `boto3` PUT/GET a small object and a ranged GET with checksum mode enabled.
4. Open **S3 -> Credentials** and confirm every credential used for policy,
   ownership, object lock, website, notification, replication, SSE-C,
   metadata configuration, reporting or tiering has the required scopes.
5. Check **Settings -> Telegram**: the account table should show the expected
   accounts and health, not `UNAUTHORIZED`.
6. Confirm physical GC is still off unless you deliberately enabled it and
   completed the owner gates.

## Rolling back

There is no schema downgrade. To return to the previous code:

1. stop the container;
2. restore the SQL backup taken before the upgrade;
3. check out the previous commit;
4. `docker compose up -d --build`.

Restoring the database also restores the settings row as it was; keep the
matching master key. A container rebuild alone does not roll back a migration.
