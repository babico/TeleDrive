# Backup and restore

TeleDrive keeps object bytes in Telegram and every pointer, version, chunk coordinate and encryption marker in SQL. This page is the operator runbook for protecting that state, rehearsing a restore and verifying a recovered instance. It does not turn Telegram into an independent payload backup.

## What must be backed up

A recoverable TeleDrive installation needs all of the following inputs, taken as one coordinated set. The SQL backup alone is not enough, and the Telegram channel alone is not enough.

| Asset | Default location | Why a restore fails without it | Handling |
| --- | --- | --- | --- |
| Metadata database | `state.database_url` in `config/config.yaml` (default `sqlite:////data/state.db`) | Holds object heads and versions, chunk journal, dedup aliases, MTProto send intents, durable jobs, bucket policy, object-lock/tiering state, service settings, users, audit trail and GC state | Native consistent dump or `scripts/ops/backup_metadata.py`; keep the archive on encrypted storage and record its SHA-256 |
| Bootstrap config | `./config/config.yaml` | Seeds the encrypted `service_settings` row on first boot and remains the disaster-recovery copy when that row cannot be decrypted | Protected copy; no real secrets in source control |
| Environment file / Compose environment | `.env`, `docker-compose.override.yml` or the orchestrator secret store | Ports, TLS paths, `TELEDRIVE_TRUSTED_PROXY`, master-key path and database driver packages are environment-only | Protected copy of the exact values, not a screenshot |
| S3 master key | `storage.s3_master_key_file` (default `/config/s3-master.key`) or `TELEDRIVE_S3_MASTER_KEY` | Decrypts S3 credential secrets and the `service_settings` row; it is also the KEK source for envelope encryption | Separate secret backup, independent of the SQL archive; never rotate during a recovery |
| Telegram session files | `storage.apis[].session_file`, commonly `/config/mtproto-user.session` | A Telethon `StringSession` is the account authorization used to read and write the channel | Owner-only (`0600`) secret copy; one owner per file |
| TLS material (optional) | `./config/ssl` or another mounted path | Only needed to avoid re-issuing certificates and re-trusting clients | Back up separately, or regenerate and redistribute |
| Original source media (optional) | `jobs.source_root` / `paths.source_roots` (default `/uploads`) | TeleDrive did not create these files and does not store a second copy | Back up with the owner's normal file-backup system |

Never put the master key, session files or a database dump in Git, CI artifacts or a public bucket. Record each archive's SHA-256 and restore instructions in the operator's private change record.

### Why Telegram media alone is useless

A Telegram message contains bytes and a caption. It does not contain the S3 bucket, object key, version identity, chunk ordinal, byte offset, length, SHA-256, dedup alias, encryption marker or retention decision. Those live in SQL:

- `storage_chunks` maps each object to `(account, chat_id, message_id, ordinal, offset, size, sha256)`.
- `storage_object_heads` and `storage_published_versions` decide which bytes are the current object and which are history.
- `storage_object_aliases` says a payload is shared, so deleting it would break another object.
- `storage_object_encryption` carries the SSE-C fingerprint or the wrapped envelope key.
- `storage_mtproto_send_intents` records whether a send was acknowledged, uncertain or still pending.

Reconstructing that graph by scanning a channel is not supported. With envelope encryption, the wrapped data keys are in SQL; without the catalog and the master key the ciphertext is unrecoverable. Treat the SQL backup and the Telegram account as two halves of one recovery set.

## Consistent database backups

Take the SQL backup while writes are either stopped or covered by a database snapshot. A hot SQL snapshot is transactionally consistent for SQL, but Telegram sends happen outside that transaction. An upload acknowledged after the snapshot can leave an unreferenced message; that is retained media, not data loss, but it is a reason to drain jobs before a high-value backup.

### PostgreSQL

Use `pg_dump` in custom format under a dedicated backup role. Keep the password in a restricted `.pgpass` file, not in `argv` or a committed script.

```bash
export PGPASSFILE=/secure-backups/.pgpass
pg_dump \
  --format=custom \
  --no-owner --no-privileges \
  --host=db.example.internal --port=5432 \
  --username=teledrive_backup --dbname=teledrive \
  --file=/secure-backups/teledrive-$(date -u +%Y%m%dT%H%M%SZ).dump
sha256sum /secure-backups/teledrive-*.dump
pg_restore --list /secure-backups/teledrive-*.dump > /secure-backups/teledrive-*.list
```

`pg_dump` reads a consistent MVCC snapshot without blocking normal reads and writes. Record the `--list` output with the dump; it proves the archive is readable before an incident.

### MySQL and MariaDB

Use a transactionally consistent InnoDB dump and include routines and triggers so a restore cannot silently lose application logic:

```bash
mysqldump \
  --defaults-extra-file=/secure-backups/.my.cnf \
  --single-transaction --routines --triggers \
  --databases teledrive \
  > /secure-backups/teledrive-$(date -u +%Y%m%dT%H%M%SZ).sql
gzip -9 /secure-backups/teledrive-*.sql
sha256sum /secure-backups/teledrive-*.sql.gz
```

`--single-transaction` gives a consistent snapshot for InnoDB tables. Confirm the storage engine of every table first; a MyISAM table is not covered by that snapshot. Test the restore with the same MySQL/MariaDB major version and the same SQL mode.

### SQLite

Use the online backup API, not `cp`, and verify the result:

```bash
python scripts/ops/backup_metadata.py \
  --database /data/state.db \
  --output /secure-backups/teledrive-$(date -u +%Y%m%dT%H%M%SZ).db
```

The script opens the source read-only, takes an online snapshot, runs `PRAGMA integrity_check`, writes the destination as a new `0600` regular file and refuses to overwrite an existing backup. It prints the SHA-256; save that receipt separately.

```bash
python scripts/ops/verify_metadata_backup.py \
  --database /secure-backups/teledrive-YYYYMMDDTHHMMSSZ.db \
  --sha256 EXPECTED_SHA256_FROM_BACKUP_OUTPUT
```

The verifier checks the archive hash, SQLite integrity, foreign keys, current head pointers, published-version metadata and removed-version bookkeeping. It does not contact Telegram and does not authorize GC.

Do not copy a live SQLite file with `cp` while the service is running: the copy can miss the write-ahead log. Stop the container first if you must use filesystem tools.

## Restore drill with the native fixture

`scripts/ops/rehearse_native_database_restore.py` is a disposable-database rehearsal. It seeds realistic version history, delete markers, chunk boundaries, send intents, a queued job, a synthetic flood-wait observation and a test S3 credential, then compares the source and restored database through the production stores. It never contacts Telegram, never deletes a Telegram message and uses a test-only master key.

The script accepts only two URL environment variables: `DB_TEST_POSTGRES_URL` and `DB_TEST_MYSQL_URL`. The source database must be disposable; the restore target must be a separate non-production database.

```bash
# 1. Seed the disposable source database and write a receipt.
export DB_TEST_POSTGRES_URL='postgresql+psycopg://teledrive:password@db.example.internal/teledrive_drill'
python scripts/ops/rehearse_native_database_restore.py seed \
  --url-env DB_TEST_POSTGRES_URL \
  --receipt /secure-backups/drill-receipt.json \
  --source /tmp/drill-seed.bin

# 2. Dump the source exactly as production would be dumped.
pg_dump --format=custom --no-owner --no-privileges \
  --dbname=teledrive_drill --file=/secure-backups/drill.dump

# 3. Restore into a NEW, EMPTY database.
createdb --host=db.example.internal --username=teledrive teledrive_restore
pg_restore --exit-on-error --no-owner \
  --dbname=teledrive_restore /secure-backups/drill.dump

# 4. Verify the restored database through the production stores.
python scripts/ops/rehearse_native_database_restore.py verify \
  --url-env DB_TEST_POSTGRES_URL \
  --receipt /secure-backups/drill-receipt.json \
  --restore-database teledrive_restore
```

For MySQL set `DB_TEST_MYSQL_URL` and use `mysqldump --single-transaction` plus a restore into a new `teledrive_restore` schema. `verify` refuses `--restore-database teledrive`, so an operator cannot point the check at the production database name by accident.

A successful verify prints `restore_valid: true` and confirms the exact head, generation, SHA-256, version visibility, removed versions, multipart part rows, tags, acknowledged send intent, unjournaled receipt, synthetic flood observation, queued job state and S3 credential decryptability. Any difference fails the run.

The same fixture runs in CI against real PostgreSQL and MySQL. CI evidence proves the SQL backup/restore machinery; it does not prove recovery of the owner's original Telegram media.

For that, the owner-executed read-only rehearsal of one original object has its own single-page checklist: [DR checklist](dr-checklist.md).

## Restore procedure

1. Declare the incident and stop the TeleDrive container. Do not start a second writer against the same SQL database or Telegram session.
2. Provision a clean host or database server with the same TeleDrive release. The release's schema coordinator will apply pending migrations up to schema version 31 on `main` (the v1.0.10 tag ships 30).
3. Restore the SQL archive into a new, empty database. Do not overwrite a production database as a test.
4. Restore `config/config.yaml`, the environment file, the S3 master key and every Telegram session file. Set owner-only permissions and verify the master key is a valid 32-byte Fernet value.
5. Keep upload jobs from starting until validation is complete. Set `TELEDRIVE_JOB_AUTO_RUN=0` or `jobs.auto_run: false` for the first boot.
6. Start the service and wait for the container healthcheck. Confirm no migration error and no schema-lock timeout in the logs.
7. Verify the SQL graph, the Telegram session and one real object before re-enabling jobs.
8. Re-enable jobs only after the owner accepts the verification.
9. Record the restore time, backup SHA-256, schema version, object sample and approver in the private change record.

SQLite restore details:

```bash
python scripts/ops/verify_metadata_backup.py \
  --database /secure-backups/teledrive-YYYYMMDDTHHMMSSZ.db \
  --sha256 EXPECTED_SHA256
docker compose stop teledrive
mv /data/state.db /data/state.db.pre-restore
mv /data/state.db-wal /data/state.db-wal.pre-restore 2>/dev/null || true
mv /data/state.db-shm /data/state.db-shm.pre-restore 2>/dev/null || true
install -m 0600 /secure-backups/teledrive-YYYYMMDDTHHMMSSZ.db /data/state.db
docker compose up -d teledrive
```

Restoring the database file without the master key leaves S3 credentials and the encrypted settings row unreadable. Restoring it without the session files leaves every object metadata row readable but every byte operation unavailable.

## Verification after restore

| Check | Command or endpoint | Pass condition |
| --- | --- | --- |
| Schema version | `SELECT MAX(version) FROM schema_migrations;` | `31` on `main` (`30` for the v1.0.10 tag) |
| Container liveness | `docker compose ps` and `GET /api/health` | Healthy; `{"ok": true}` |
| Both listeners | `python -m web.container_healthcheck` | Exit status 0; probes `/api/health` and S3 `/__health` |
| Telegram session | `GET /api/v1/admin/storage/telegram-sessions` | The expected account is present and `authorized` is true |
| Catalog heads | `GET /api/v1/buckets/{bucket}/objects` | Expected keys and sizes, no unexpected delete markers |
| Version history | `GET /api/v1/buckets/{bucket}/versions?key=...` | Expected current version and retained history |
| Object read | `GET /api/v1/buckets/{bucket}/content?key=...` | Bytes match the recorded SHA-256 |
| S3 data plane | Signed `GET`/`HEAD` through the S3 listener, then a ranged GET | Correct body and `Content-Range`; no `SignatureDoesNotMatch` |
| S3 credential decrypt | `GET /api/v1/admin/s3-credentials` as admin | Credentials list without a master-key 503 |
| Jobs | `GET /api/v1/admin/storage/jobs` or `GET /api/v1/admin/storage/health` | No job stuck in `running`; queued work is intentional |
| Audit trail | `GET /api/v1/admin/audit` as admin | Rows exist and the newest entries are from the restore window |

A metadata read proves only that SQL survived. A successful object read proves that SQL, the session file, the channel and the Telegram bytes survived together.

## RPO and RTO expectations

| Measure | What it means here |
| --- | --- |
| RPO | The age of the newest verified SQL dump plus the matching config, master key and session copies. TeleDrive has no built-in continuous replication, WAL shipping or point-in-time recovery. |
| RTO | Time to provision a host, restore SQL, restore secrets, start the service and validate one object. It is dominated by database restore and Telegram read throughput, not by the container start. |
| Payload RPO | Telegram has no operator-controlled backup window. A message deleted in Telegram, a channel lost or an account revoked is outside this runbook's RPO. |
| Measurement | Record dump start/end, restore start/end and the first successful object read in every drill. Use the measured values, not a vendor promise. |

Use a nightly logical dump plus a weekly full drill as a baseline. Increase frequency when the catalog changes faster than the acceptable replay window. Keep at least one copy on a host that is independent of the TeleDrive host and its database server.

## What this does not cover

- **Original owner media.** Files under the upload source root are not copied by TeleDrive. Back them up separately.
- **Telegram account loss.** Losing the phone number, the 2FA password, the API credentials or the session file can make the channel unreadable. Telegram support is not a recovery path.
- **Telegram-side deletion or channel loss.** A message removed in Telegram, a deleted channel or a revoked account is not restored by SQL.
- **Independent payload backup.** No second copy of Telegram media is created by the backup scripts. Physical GC remains gated for this reason; see [Garbage collection](garbage-collection.md).
- **Encrypted objects without the master key.** Envelope-encrypted objects need the wrapped key in SQL and the exact master key. Rotating or losing that key makes the ciphertext unreadable.
- **In-flight sends.** A send acknowledged after the SQL snapshot can be absent from the catalog. It is retained, not lost, but it is not a usable object.
- **GC authorization.** A restore does not prove an independent backup, a restore drill or a writer barrier. Those are owner evidence for the enable decision; the dry-run contract's `deletion_permitted` stays false and never authorizes deletion.

## Operator checklist

| Done | Item | Evidence |
| --- | --- | --- |
| [ ] | SQL dump completed with the native tool or `backup_metadata.py` | Dump file, SHA-256, `pg_restore --list` or verifier JSON |
| [ ] | `config/config.yaml` copied from the same deployment | File SHA-256 and release commit |
| [ ] | Environment values recorded, including `TELEDRIVE_TRUSTED_PROXY` and master-key path | Protected copy |
| [ ] | S3 master key backed up independently | Separate secret record |
| [ ] | Every `storage.apis[].session_file` backed up `0600` | Owner-only archive |
| [ ] | Restore rehearsal executed on a disposable database | `restore_valid: true` receipt |
| [ ] | Schema version recorded | `31` on `main` (`30` for the v1.0.10 tag) |
| [ ] | Health, session, catalog and one object read verified after restore | Command output in the change record |
| [ ] | Jobs kept disabled until acceptance | `jobs.auto_run: false` or `TELEDRIVE_JOB_AUTO_RUN=0` |
| [ ] | Physical GC left disabled unless the owner gates are complete | `GET /api/v1/admin/storage/gc` shows `enabled: false` |

See [Upgrade](upgrade.md) for the release-specific database and settings changes, and [Monitoring](monitoring.md) for the health and audit surfaces used after a restore.
