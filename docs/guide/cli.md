# Command line

TeleDrive has one service entry point and a set of standalone operator scripts. `pyproject.toml` declares no `[project.scripts]` console entry points, so there is no `teledrive` binary on your `PATH`: the service runs as `python -m web.unified`, which the container image invokes as its `CMD`. Everything else is a Docker Compose command or a script under `scripts/` that must be run with the project's Python environment.

The scripts are **not copied into the container image**; the image contains only `teledrive/` and `web/`. Run them from a repository checkout on the host with a virtual environment that has `requirements.txt` installed:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The examples below use `.venv/bin/python` explicitly so they work without activating the environment. If a script needs to run inside the container, `docker compose cp` it to `/tmp` first (the container root filesystem is read-only, but `/tmp` is a writable tmpfs) and `docker compose exec teledrive python /tmp/script.py ...`.

## Container lifecycle

```bash
# Build and start (first run writes config/config.yaml at mode 0600)
docker compose up -d --build

# State and health
docker compose ps
docker compose logs --tail=200 teledrive
docker compose logs -f teledrive

# Restart after a settings save or an upgrade
docker compose restart teledrive

# Stop and remove the container (named bind mounts stay)
docker compose down
```

`docker compose up` uses `docker-compose.override.yml` when present. The default container:

- runs as `${PUID}:${PGID}` and expects that user to own `./config` and `./data`;
- has a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, and a 256-process limit;
- mounts `./config` at `/config`, `./data` at `/data`, and `./uploads` read-only at `/uploads`;
- exposes the web listener and the S3 listener as `${TELEDRIVE_WEB_PORT:-8080}` and `${TELEDRIVE_S3_PORT:-9000}`;
- has a 30-second stop grace period so Telethon can disconnect and SQLite can checkpoint.

The healthcheck runs `python -m web.container_healthcheck`, which reads the same port and TLS environment as the service. `docker compose ps` showing `unhealthy` after the 20-second start period usually means the web listener failed to bind or TLS material is unreadable.

`docker compose down -v` does not delete bind-mounted data, but it is still a stop, not a backup. Deleting `./data` removes the SQL catalog, auth sessions, logs and scratch; deleting `./config` removes the deployment settings and Telegram session files.

## Start the service without Docker

The unified process serves both listeners and derives its settings from `config/config.yaml` and the environment:

```bash
TELEDRIVE_CONFIG=./config/config.yaml .venv/bin/python -m web.unified \
  --host 127.0.0.1 --web-port 8080 --s3-port 9000
```

`--host`, `--web-port` and `--s3-port` override the config file for that run. TLS, proxy trust and port variables are read from the environment in this mode; see [Configuration](../reference/configuration.md).

## Database initialisation and migration

There is no separate `init-db` command. The schema coordinator runs when a component first opens the configured database, so the first service start (or the first script that calls `connect_database`) creates the tables and applies ordered, idempotent migration steps. The SQLite default is `sqlite:////data/state.db`; PostgreSQL and MySQL use a normal SQLAlchemy URL in `state.database_url`.

Consequences worth knowing:

- Starting the service against a fresh database creates it, including the bootstrap `admin` user.
- An upgrade applies pending schema steps on startup; back up `config/`, the database and the S3 master key first.
- Schema creation needs DDL rights. Reduce the SQL principal's privileges after migration if your database supports it.
- `state.database_url` and `state.db_extra_packages` cannot be changed from the REST API; edit `config/config.yaml` on the host.

## Interactive Telegram session helper

`scripts/dev/create_storage_user_session.py` creates a Telethon USER `StringSession` before the first start. It needs the Telegram application API credentials in the environment and prompts interactively for the phone number, the login code and the optional 2FA password.

```bash
export TELEDRIVE_STORAGE_MTPROTO_API_ID=123456
export TELEDRIVE_STORAGE_MTPROTO_API_HASH=0123456789abcdef0123456789abcdef

mkdir -p config
.venv/bin/python scripts/dev/create_storage_user_session.py \
  --output config/mtproto-user.session
chmod 600 config/mtproto-user.session
```

Rules enforced by the script:

- `--output` defaults to `config/mtproto-user.session`; its parent directory must already exist.
- It refuses to overwrite an existing file or a symlink, and writes at mode 0600 with `O_EXCL` and `O_NOFOLLOW`.
- It refuses bot accounts: the identity must be a real Telegram user.
- It does **not** take API credentials as command-line flags. Setting them in the environment is the documented path; do not commit them or leave them in shell history.

The resulting path must be inside the `./config` mount so the container can read it. Reference it from `storage.apis[].session_file` (for example `/config/mtproto-user.session`). Get API credentials from [my.telegram.org/apps](https://my.telegram.org/apps).

The alternative is the browser flow on **Settings → Telegram**, which stores the session in SQL and writes a session file under `AUTH_DIR/sessions`. Phone codes and 2FA passwords are used once and never stored.

!!! warning "A session file is an account credential"
    Anyone who obtains the session string can act as that Telegram account. Keep `./config` at mode 0700, the file at 0600, and never paste it into an issue, CI log or container environment variable.

## Password recovery

`scripts/ops/reset_local_password.py` is the supported local lockout recovery. It reads the database URL from the bootstrap config (or takes `--database`), prompts twice for a new password on a TTY, sets it and revokes that user's sessions. It never accepts the password in argv or an environment variable.

```bash
.venv/bin/python scripts/ops/reset_local_password.py \
  --config config/config.yaml \
  --username admin \
  --role admin
```

When run on the host against the Docker deployment, the config's `sqlite:////data/state.db` points inside the container, not at `./data/state.db`. Pass an explicit host URL:

```bash
.venv/bin/python scripts/ops/reset_local_password.py \
  --database "sqlite:///$PWD/data/state.db" \
  --username admin --role admin
```

| Flag | Meaning |
| --- | --- |
| `--config` | Bootstrap config, default `config/config.yaml` |
| `--database` | Override the URL from the config |
| `--username` | Required; the user is created if it does not exist |
| `--role` | `admin`, `operator` or `viewer` (default `admin`) |
| `--min-length` | Sanity floor only, default 5; use at least 8 for a real password |

The script prints whether the user was `created` or `updated` and confirms that all its sessions were revoked. It requires the same filesystem and database access the service has, which is why it is not a network feature.

!!! danger "This is an authority change, not a password reminder"
    Running it against the wrong database creates or rewrites a local administrator there. It also revokes the user's active dashboard sessions. Confirm the URL before typing the password.

## TLS certificate generation

`scripts/ops/generate_ssl.py` creates a self-signed certificate and key, then prints the exact environment lines to add to `.env` or the Compose environment. It refuses to overwrite existing TLS material.

```bash
mkdir -p data/tls
.venv/bin/python scripts/ops/generate_ssl.py \
  --out ./data/tls --hostname localhost --days 365
```

Because `./data` is mounted at `/data`, the printed paths are the in-container paths:

```text
TELEDRIVE_SSL_CERTFILE=/data/tls/server.crt
TELEDRIVE_SSL_KEYFILE=/data/tls/server.key
TELEDRIVE_S3_SSL_CERTFILE=/data/tls/server.crt
TELEDRIVE_S3_SSL_KEYFILE=/data/tls/server.key
```

Set the web pair, the S3 pair, or both independently, then restart. A combined PEM works with only the `CERTFILE` variables. The certificate is self-signed: import `server.crt` into the client trust store, or download `/server.cer` (DER) from **Settings → General**. Verify a running HTTPS listener with:

```bash
.venv/bin/python scripts/ops/generate_ssl.py \
  --out ./data/tls --test https://127.0.0.1:8443 --insecure
```

`--test` only accepts an `https://` URL. `--insecure` disables hostname and chain verification for the probe; it does not change the server.

## Metadata backup and verification

These two scripts handle **SQLite** only. PostgreSQL and MySQL must use their native backup tools; the scripts do not wrap `pg_dump` or `mysqldump`. Neither script copies Telegram payloads, and neither is a full disaster-recovery solution.

```bash
# Online, transactionally consistent snapshot of the live SQLite file
.venv/bin/python scripts/ops/backup_metadata.py \
  --database ./data/state.db \
  --output ./data/backups/state-$(date +%Y%m%d-%H%M%S).db

# Read-only verification, optionally against the printed SHA-256 receipt
.venv/bin/python scripts/ops/verify_metadata_backup.py \
  --database ./data/backups/state-20261101-120000.db \
  --sha256 <64-hex-digest>
```

`backup_metadata.py` opens the source read-only, uses SQLite's online backup API, runs `PRAGMA integrity_check`, writes a new file at mode 0600 and commits it with an atomic hard link. It refuses an existing destination, a symlink source, a non-regular source, or a destination equal to the live database. It prints `Backup complete. SHA-256: ...`.

`verify_metadata_backup.py` checks the checksum if supplied, runs `integrity_check` and `foreign_key_check`, requires the core storage tables, and verifies that current heads and published versions point at objects with matching bucket and key hash. It prints a JSON summary and exits non-zero on any inconsistency. It never mutates the snapshot.

Run the backup while the service is running if you must, but a snapshot is not a substitute for quiescing writes during an upgrade. Test the restore in an isolated directory, never over the live database.

## Native PostgreSQL and MySQL restore rehearsal

`scripts/ops/rehearse_native_database_restore.py` is a **CI acceptance fixture**, not a production restore tool. It seeds a non-production database with a synthetic object, a pending upload, a multipart part, tags, credentials and job rows, computes a receipt, and then verifies the same state through the production stores after you restore a native dump into a separate database.

```bash
# Seed the disposable source database named by the environment
.venv/bin/python scripts/ops/rehearse_native_database_restore.py seed \
  --url-env DB_TEST_POSTGRES_URL \
  --receipt /tmp/dr-receipt.json \
  --source /tmp/dr-source.bin

# Verify a RESTORED database (must not be the source database)
.venv/bin/python scripts/ops/rehearse_native_database_restore.py verify \
  --url-env DB_TEST_POSTGRES_URL \
  --receipt /tmp/dr-receipt.json \
  --restore-database teledrive_restored
```

`--url-env` accepts only `DB_TEST_POSTGRES_URL` or `DB_TEST_MYSQL_URL`. The verify phase refuses the database name `teledrive` and refuses to run without `--restore-database`, because verifying the source would prove nothing. The fixture uses a hard-coded, publicly known test Fernet key; never point it at production.

## GC preview and collection

The read-only planner is a script; execution is an API action behind the owner gate.

```bash
.venv/bin/python scripts/ops/gc_dry_run.py \
  --database "sqlite:///$PWD/data/state.db" \
  --object-id <object-uuid> \
  --min-age-seconds 604800 \
  --output ./data/gc-plan-<object-uuid>.json
```

It enumerates every SQL reference for one failed object, verifies the plan is internally consistent, and writes a private 0600 JSON file. It never deletes Telegram messages, SQL rows or metadata. The summary includes `reference_blocked`, `reference_blockers`, `deletion_permitted`, `dry_run` and `remote_history_scan_required`.

Physical collection has no CLI. Use the dashboard or:

```bash
# Preview (default dry_run=true)
curl -sS -b td.cookies -H 'X-TeleDrive-CSRF: 1' \
  -H 'Content-Type: application/json' \
  -d '{"scope":"revoked","dry_run":true,"limit":50}' \
  http://127.0.0.1:8080/api/v1/admin/storage/gc/collect
```

Enabling GC requires `PUT /api/v1/admin/storage/gc` with `{"enabled": true, "confirm": "PHYSICAL-GC"}`. Execution requires the typed confirmation `DELETE-RETAINED`, an enabled gate, and `min_age_seconds` of at least 3600. Read [Garbage collection](../operate/garbage-collection.md) before enabling it.

!!! danger "Collection deletes Telegram payloads permanently"
    This is the one irreversible operation in the product. It re-verifies each candidate immediately before deletion, records a durable audit start and finish, and leaves partial failures retryable, but it cannot resurrect deleted Telegram messages. Independent payload backup and a rehearsed restore are prerequisites, not optional niceties.

## S3 inventory bookkeeping

`scripts/ops/sync_s3_inventory.py` is a maintainer tool, not an operator tool. The operation manifest (`teledrive/s3/operation_manifest.json`) is the source of truth; the script recomputes the supported/partial/unsupported counts and rewrites the totals in `docs/reference/s3-specs.md` and the assertions in two test files.

```bash
# Verify only; this is what CI runs
.venv/bin/python scripts/ops/sync_s3_inventory.py --check

# Apply the rewrites
.venv/bin/python scripts/ops/sync_s3_inventory.py
```

It fails loudly if a pattern it must rewrite is missing or appears more than once, rather than leaving the repository half-synced. Do not run the write mode casually: it edits tracked documentation and tests.

## Other operator scripts

These are real, supported scripts in the repository. Most are read-only or write only to a new file.

| Command | Purpose |
| --- | --- |
| `scripts/ops/rehearse_telegram_dr.py` | Verify a sealed SQLite snapshot and read one object's original bytes through a read-only USER session; no production writes or deletes |
| `scripts/ops/inventory_telegram_history.py` | Read-only inventory of channel message markers; the 0600 JSON contains Telegram coordinates and is not a restore manifest |
| `scripts/ops/rebuild_from_telegram.py` | Rebuild an isolated catalog from a verified recovery plan; requires a **new** database, never the production one |
| `scripts/ops/verify_legacy_cutover.py` | Verify every eligible legacy source against finished jobs and independently readable Telegram bytes; queues and uploads nothing |
| `scripts/ops/verify_production_bundle.py` | Offline verifier for dual-attested release evidence bundles; requires owner and operator public keys |
| `scripts/ops/s3_large_roundtrip.py` | Upload/download acceptance test with random 100 MiB–4 GiB files and SHA-256 verification; uses real S3 credentials from the environment |
| `scripts/ops/capacity_probe.py` | Long-duration synthetic endurance probe against SQLite and a disk-backed transport; no live Telegram credentials |
| `scripts/ops/acceptance.py` | Interactive, fail-closed acceptance assistant that writes a sanitized report |
| `scripts/dev/setup_telegram_e2e.py` | Prepare the live USER MTProto end-to-end test fixture |
| `scripts/dev/docker_fault_scenarios.py` | Drive the Docker fault-injection scenarios |

Each script documents its own flags in `--help`. The recovery scripts that authenticate to Telegram read credentials from a protected environment and must be run on an owner-controlled host, in an isolated staging directory, never against the production database while a writer is active.
