# Databases

TeleDrive keeps the object graph, users, credentials, jobs, quotas and audit
trail in one SQL database. The payload bytes are in Telegram; the database is
the index that makes them addressable. This page covers the supported
backends, connection URLs, migration behaviour, backup pointers and what is
actually lost when the database is.

## Supported backends

| Backend | Driver in the image | Status |
| --- | --- | --- |
| SQLite | Python standard library | Default. Best for one container, one process. |
| PostgreSQL | `psycopg` 3 | Recommended for anything that matters, and for multiple workers. Tested in CI against PostgreSQL 17. |
| MySQL | `PyMySQL` | Supported and tested in CI against MySQL 8.4. MariaDB shares the dialect and driver but is not in the CI matrix. |

Other synchronous SQLAlchemy dialects can be installed, but only these three
are exercised by the project's database workflows. Do not assume an untested
dialect has working migrations.

## Connection URLs

Set `state.database_url` in `config/config.yaml`. The value is file-only: the
config API cannot change it.

```yaml
state:
  # SQLite, absolute path inside the container (four slashes)
  database_url: "sqlite:////data/state.db"

  # PostgreSQL via psycopg 3
  # database_url: "postgresql+psycopg://teledrive:password@db:5432/teledrive?sslmode=require"

  # MySQL via PyMySQL
  # database_url: "mysql+pymysql://teledrive:password@db:3306/teledrive?charset=utf8mb4"
```

Accepted shorthands:

| Form | Result |
| --- | --- |
| `postgres://...` or `postgresql://...` | Rewritten to `postgresql+psycopg://...`. |
| `mysql://...` | Rewritten to `mysql+pymysql://...`. |
| A bare filesystem path | Treated as a SQLite file, resolved against the config directory. |
| `sqlite:///relative.db` | Resolved against the config directory. |
| `sqlite:////absolute/path.db` | Used as written. |

`state.allowed_sqlite_roots` (default `/data`) constrains where a SQLite file
may live. Moving the database outside that root requires updating the key, or
startup validation refuses the path. For a host install, change
`state.database_url` and the allowed root together.

## SQLite

SQLite is the default because it needs no server. The operational caveats are
real:

- **One writer at a time.** WAL mode lets readers continue during a write, but
  two concurrent writers still serialize. The service sets
  `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=30000` on every
  connection, so a competing writer waits up to 30 seconds instead of failing
  immediately. It does not make write concurrency unlimited.
- **Keep it on local disk.** WAL and file locking assume a local filesystem.
  A network share or a bind mount backed by a network filesystem is not safe.
- **One process is the comfortable deployment.** A single container runs one
  process. Multiple web workers against one SQLite file are not the tested
  configuration; use PostgreSQL for that.
- **Three files matter.** `state.db`, `state.db-wal` and `state.db-shm` form
  one database while the service runs. Use the online backup tool, not a
  plain `cp`, unless the service is stopped and the WAL has been checkpointed.

The schema coordinator runs a `flock` on a sidecar `<db>.schema-lock` file
when migrations are needed. That file lives next to the database and must be
writable.

## PostgreSQL and MySQL

Use a server database when you need concurrent processes, a managed backup
regime, or a database host separate from the container.

- PostgreSQL is the recommended production target. It is the backend used by
  the multi-worker test workflow and it has an explicit advisory lock for
  migrations (`pg_advisory_xact_lock`).
- MySQL migrations use a named `GET_LOCK('teledrive.schema.migrations')` with
  a 30-second timeout. DDL causes implicit commits, so the lock is
  session-scoped, not transaction-scoped.
- Use `utf8mb4` on MySQL. The schema stores object keys and metadata that are
  not ASCII.
- Keep the connection close to the application. The engine uses
  `pool_pre_ping=True`; there is no application-level retry that survives a
  database restart mid-transaction.

## Migrations

All DDL goes through one coordinator in `teledrive/storage/schema.py`:

- `SCHEMA_VERSION` is the number of append-only steps, currently **31** on
  `main` (the v1.0.10 tag ships 30).
- The service records the highest applied version in `schema_migrations`. A
  warm database costs one `SELECT` per process; an up-to-date process performs
  no DDL.
- Only when the version is stale does it take a real cross-process lock
  (SQLite `flock`, PostgreSQL advisory lock, MySQL `GET_LOCK`), re-check the
  version, and run the idempotent steps in a fixed order.
- Steps are append-only. Adding a step bumps the version; existing steps are
  never edited or removed. An interrupted migration is safe to re-run because
  every step is idempotent.
- The full catalogue of all 31 steps, their families, locking and undo
  residue, lives in the [Schema steps](../reference/schema-steps.md)
  reference.

Migrations run automatically at startup and on first database access. There is
no separate migrate command and no down-migration. Rolling back to older code
after the schema advanced is not supported: restore the database backup taken
before the upgrade together with the older code.

## Credentials and TLS

Create a dedicated role, not the server superuser. Migrations create tables,
indexes and columns, so the role needs schema DDL rights in addition to normal
DML:

- **PostgreSQL:** `CONNECT`, `USAGE` and `CREATE` on the target schema,
  `SELECT`/`INSERT`/`UPDATE`/`DELETE` on its tables, and `USAGE` on its
  sequences.
- **MySQL:** `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `ALTER`,
  `INDEX`, `REFERENCES` on the target database. `GET_LOCK` needs no extra
  grant.

The database URL, including the password, sits in `config.yaml` (mode `0600`)
and in the encrypted SQL settings document. Restrict access to the config
mount and the database backup. Prefer a secret manager that renders the file
at deploy time over a password committed to a Compose file.

For TLS, append driver parameters to the URL:

```text
postgresql+psycopg://user:pass@db/teledrive?sslmode=verify-full&sslrootcert=/config/pg-ca.pem
mysql+pymysql://user:pass@db/teledrive?ssl_ca=/config/mysql-ca.pem
```

`sslmode=require` encrypts but does not verify the server identity; use
`verify-full` where you can.

## Extra driver packages

Two mechanisms exist, and they are not the same:

| Mechanism | When it runs | Use |
| --- | --- | --- |
| `TELEDRIVE_DB_EXTRA_PACKAGES` build arg in `docker compose` | At image build, installed with pip into the image | Extra drivers you want baked into the image. |
| `state.db_extra_packages` in `config.yaml` | At startup, installed into `/data/site-packages` and prepended to `sys.path` | A driver added without rebuilding, on a writable data volume. |

The built-in image already carries SQLite, `psycopg` and `PyMySQL`. A
configured extra package must install and import, or startup fails loudly
instead of silently falling back.

## Backup

The database is not backed up by copying the Telegram channel. Protect these
as separate recovery inputs:

- the SQL database;
- the S3 master key;
- the Telegram session credentials;
- `config/config.yaml`.

For SQLite, use the online backup tool from the host:

```bash
python scripts/ops/backup_metadata.py \
  --database data/state.db \
  --output /secure-backups/teledrive-$(date +%F).db
```

It uses SQLite's online backup API, runs `PRAGMA integrity_check`, writes mode
`0600`, refuses to overwrite, and prints a SHA-256. Verify a copy without
touching the live database:

```bash
python scripts/ops/verify_metadata_backup.py \
  --database /secure-backups/teledrive-2026-11-01.db \
  --sha256 EXPECTED_SHA256
```

For PostgreSQL use `pg_dump -Fc`; for MySQL use `mysqldump
--single-transaction`. Rehearse the restore into a **new, empty, isolated**
database. The full procedure, including what the verifier does and does not
prove, is in [Backup and restore](../operate/backup-restore.md).

## What breaks if the database is lost

The bytes in Telegram survive, but almost nothing can find them:

| Lost data | Consequence |
| --- | --- |
| `storage_objects`, `storage_object_heads`, `storage_chunks` | No bucket/key mapping, no chunk order, no size or SHA-256. Objects become unindexed Telegram messages. |
| `storage_buckets`, policies, ACLs, ownership, quotas | No authorization model and no bucket names. |
| `users`, `user_sessions` | No WebUI login. Recovery needs filesystem access and the local reset script. |
| API keys and `storage_s3_credentials` | Every REST and S3 client stops authenticating. The S3 secrets are also encrypted with the master key. |
| `service_settings` | Settings fall back to `config.yaml`; changes that were only saved in the settings document are gone. Telegram sessions are in their own table and are not affected. |
| Jobs, multipart uploads, audit events | In-flight work is lost; the audit trail stops before the loss. |

The recovery tools (`scripts/ops/inventory_telegram_history.py`,
`scripts/ops/rebuild_from_telegram.py`) can inventory and, with a separately
proven plan, rebuild a new isolated catalog. They are not a substitute for a
database backup, and they cannot invent a bucket/key mapping that the lost
metadata never contained.

Physical GC remains disabled (`deletion_permitted` is `False`), so deleting an
object does not erase its Telegram media. That is a recovery aid, not a backup
strategy.
