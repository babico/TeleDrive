# Troubleshooting

Most TeleDrive failures are visible in one of four places: the HTTP result line in the application log, the S3 XML error body, the durable security audit, or the admin storage endpoints. This page maps the symptoms an operator actually sees to the code path that produced them and names the line or endpoint that confirms the diagnosis. Start with the response body, not the status code alone.

## First-response checklist

```bash
# Container and both listeners
docker compose ps
docker compose logs --tail=200 teledrive

# Liveness and metrics
curl -s http://127.0.0.1:8080/api/health
curl -s -H "Authorization: Bearer $TELEDRIVE_API_KEY" \
  http://127.0.0.1:8080/api/v1/metrics

# Session, jobs and storage
curl -s -H "Authorization: Bearer $TELEDRIVE_API_KEY" \
  http://127.0.0.1:8080/api/v1/admin/storage/telegram-sessions
curl -s -H "Authorization: Bearer $TELEDRIVE_API_KEY" \
  http://127.0.0.1:8080/api/v1/admin/storage/health
```

As an admin session, `GET /api/v1/logs?limit=200` reads the in-memory buffer and `GET /api/v1/admin/audit?limit=100` reads the durable trail. The log line format is `[timestamp] [user] [source] message`; request lines end in `-> <status> (<ms>ms)`. There is no request id, so correlate by method, path and time.

## S3 and signature failures

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| `401 Unauthorized` on the S3 listener | TeleDrive's S3 gateway returns `403` for authentication failures. A `401` usually comes from a proxy or an intermediate basic-auth layer | Remove the proxy challenge or send the SigV4 `Authorization` header to the S3 upstream | Proxy error log; S3 log line shows no `403` for that path |
| `403 AccessDenied` with `AWS Signature V4 Authorization required` | No `Authorization` header, a malformed header, or an unsigned request | Sign the request; for browser uploads use a presigned URL or the form endpoint | S3 log `PUT /bucket/key -> 403`; body code `AccessDenied` |
| `403 RequestTimeTooSkewed` | Client clock differs from the server by more than 15 minutes, or the signed date does not match the credential scope date | Enable NTP on the client; re-sign with the current UTC time | Body code `RequestTimeTooSkewed`; log only shows `403` |
| `403 SignatureDoesNotMatch` on every request | The proxy rewrote Host, dropped a non-default port, normalized the path, re-encoded the query, or changed a signed header | Forward `Host` unchanged (`$http_host` in nginx), disable path rewrites and `merge_slashes` | Compare the client's signed Host with the upstream Host; S3 log `-> 403`; body `SignatureDoesNotMatch` |
| `403 SignatureDoesNotMatch` only for one client | The client signed a different Host or path than it sent, for example a virtual-host name that the proxy rewrote | Use path-style or preserve the virtual-host Host exactly | Body code; proxy access log versus client request |
| `403 AccessDenied` with `Unsupported SigV4 service` | The credential scope names a service other than `s3` or `s3express` | Sign with `s3` for normal buckets | Body message; request `Authorization` header scope |
| `403 AccessDenied` with `S3 Express signing is only valid for directory-bucket operations` | A normal bucket operation was signed with the `s3express` scope | Use the `s3` scope for normal buckets | Body message; credential scope |
| `403 AccessDenied` with `Unknown, expired, revoked or unauthorized access key` | The access key is unknown, expired, revoked, or lacks the operation's permission | Check the credential in `GET /api/v1/admin/s3-credentials`; issue a new key if needed | Audit `credential.revoke`; body message; S3 log `-> 403` |
| `400 XAmzContentSHA256Mismatch` | An unsigned upload omitted a signed `Content-MD5` or `x-amz-checksum-sha256` | Send a signed payload hash or a signed checksum header | Body code; S3 log `PUT /bucket/key -> 400` |
| `400 InvalidRequest` with `Signed SHA-256 payload required` | `x-amz-content-sha256` is neither a hash nor `UNSIGNED-PAYLOAD` | Use a supported payload mode; prefer a signed SHA-256 | Body message; S3 log `-> 400` |

## Objects, hosts and HTTP sessions

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| `404 NoSuchKey` immediately after a delete | The delete wrote a delete marker or removed the head. This is expected S3 behaviour, not a lost object | Read the intended version with `?versionId`, or restore the head from a verified SQL backup | `HEAD` response has `x-amz-delete-marker: true`; `GET /api/v1/buckets/{bucket}/versions?key=...` |
| `405 MethodNotAllowed` on `GET ?versionId=...` | The requested version id is itself a delete marker | Request the prior version id, or remove the marker under the normal versioning rules | Body code; `x-amz-delete-marker: true` |
| `400 {"detail": "Invalid host header"}` | The Host is not in `web.allowed_hosts` | Add the public hostname to `web.allowed_hosts` or `TELEDRIVE_ALLOWED_HOSTS` | Response body; there is no app request line because the host check runs before request logging |
| `403 Missing CSRF protection header` | A state-changing browser request did not send `X-TeleDrive-CSRF: 1` | Send the header; API-key requests use Bearer auth instead of the CSRF flow | Log `POST /api/... -> 403`; body detail |
| `403 Cross-origin state change rejected` | The `Origin` host does not match the `Host` header | Use the same public origin through the proxy; do not mix hostnames | Body detail; compare `Origin` and `Host` in the proxy log |
| `403 API token is invalid, expired or lacks permission` | The API key is expired, revoked, or missing the exact route permission | Issue a key with the required `method:path` permission, or use an admin session | `GET /api/v1/admin/keys`; log `-> 403`; audit `api_key.rotate` |
| `429 Too many failed attempts` on login | Five failed logins for the same username and client within 300 seconds (`auth_failure_limit` / `auth_failure_window_seconds`) | Wait for the window, or restart to clear the in-memory counter; fix the credential | Log `POST /api/v1/auth/login -> 429`; the counter is per process and not durable |
| Cannot log in as admin at all | Password forgotten, account disabled, or no usable session | Run the local recovery script; it revokes existing sessions | Script output, or login `401 Invalid credentials` / `403 Account is disabled` |
| `503 REST uploads are disabled by policy` | `rest_max_upload_bytes` is below 1 | Set a positive limit if uploads are intended | Log `PUT /api/v1/buckets/.../content -> 503`; config value |

## Telegram sessions, uploads and quotas

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| `503 Authorized Telethon USER session is required` on REST or `503 ServiceUnavailable` on S3 | No connected USER MTProto session, or the runtime failed to start | Re-authorize through the WebUI request-code/verify-code flow; check the session file | `GET /api/v1/admin/storage/telegram-sessions` shows `authorized: false`; `teledrive_telegram_session_authorized 0`; log `storage_transport`/session warning |
| Upload fails closed before any bytes are consumed | The transport verifies the target before staging; a missing or unauthorized session fails the request instead of accepting a body it cannot store | Fix the session, then retry | S3 log `PUT /bucket/key -> 503`; REST `503`; no chunk rows created |
| `413 EntityTooLarge` with `Upload exceeds configured maximum` | The single object or multipart part exceeds `rest_max_upload_bytes` | Raise the limit deliberately or split the upload | S3 XML body; config value; log `-> 413` |
| `413 EntityTooLarge` with `Upload exceeds bucket quota (max size)` or `(max objects)` | The per-bucket quota would be exceeded | Raise the quota with `PUT /api/v1/admin/storage/buckets/{bucket}/quota`, or delete data | Body message; `teledrive_quota_used_*` versus `teledrive_quota_limit_*` |
| `500 Internal Server Error` reading an envelope-encrypted object | Older builds raised a bare 500 when the `EnvelopeError` import was missing. Current builds map it to `400 InvalidRequest` | Confirm the running build contains the fix; check the master key and wrapped marker | Current body code `InvalidRequest`; S3 log `-> 400`; a `500` means the old build or an unhandled code path |
| `503 S3 credentials are unavailable: the master key cannot be loaded` | `TELEDRIVE_S3_MASTER_KEY_FILE` points at an unreadable file, or `TELEDRIVE_S3_MASTER_KEY` is not a valid 32-byte Fernet value | Restore the master key file or environment value; do not generate a new key over stored credentials | `GET /api/v1/admin/s3-credentials` returns `503`; startup/settings log; file permissions |
| Service settings look stale after a key change | The encrypted `service_settings` row cannot be decrypted, so the app falls back to `config/config.yaml` | Restore the old master key, or accept the file settings and re-save | Log `settings: ... falling back to config.yaml`; a UI save re-seeds the row |
| Telegram `FloodWait` persists | The account is rate-limited; retries increase the cooldown | Wait for the cooldown, reduce concurrency, and do not retry in a tight loop | Log `MTProto flood-wait persists; reconcile protected intent before retry`; `teledrive_flood_cooldown_remaining_seconds`; `teledrive_flood_observations_total` |
| Session was revoked or expired | The Telegram account logged out the session, or the session file was replaced | Re-login and re-authorize the account; reconcile any pending send intent first | Log `session health: account=... UNAUTHORIZED (expired/revoked); re-login required`; metric `0`; session list |
| Download fails with `Telegram message/media was deleted or inaccessible` | The message is gone in Telegram, or the account cannot see the channel | Check the message in the authorized account; do not remap coordinates | Log source `storage`; object read fails while metadata still lists the object |

## Database, GC and recovery

| Symptom | Likely cause | Fix | Confirm with |
| --- | --- | --- | --- |
| Container starts but never becomes healthy; no `schema: migrated` line | A migration is waiting on the cross-process lock | Check for another worker or a stale database session. PostgreSQL waits on `pg_advisory_xact_lock`; SQLite and MySQL time out after 30 seconds | `SELECT MAX(version) FROM schema_migrations;`; PostgreSQL `pg_locks` / `pg_stat_activity`; MySQL `SHOW PROCESSLIST`; SQLite `<db>.schema-lock` existence |
| `timed out waiting for the schema migration lock` | A SQLite or MySQL migration lock is held by another process | Stop the extra worker or container; wait for the holder to finish; do not delete the database or the lock file under a live process | Startup log; SQLite sidecar path; MySQL `GET_LOCK` session |
| `database is locked` on SQLite | A long read transaction or an external writer holds the SQLite write lock; the busy timeout is 30 seconds | Stop external writers; keep one container; use PostgreSQL/MySQL for concurrent workloads | Log `EXCEPTION: OperationalError ... database is locked`; container stderr; `PRAGMA busy_timeout` is set to 30000 |
| GC collect returns `409 Physical GC is disabled; enable it first (owner gate)` | The owner toggle is false | Complete the backup, restore-drill and writer-barrier gates before enabling. Do not enable it just to clear the error | Audit has no `gc.collect.start`; `GET /api/v1/admin/storage/gc` shows `state.enabled: false` |
| GC plan says `deletion_permitted: false` | The plan contract never authorizes deletion; current builds have no path that flips the field to true | Treat the plan as read-only evidence of unmet owner gates; do not edit the JSON or bypass `verify_plan()` | `scripts/ops/gc_dry_run.py --database ... --object-id ... --output plan.json` output; `GET /api/v1/admin/storage/gc-audit` |
| GC reports a `failed[]` object after deleting some media | Telegram deletion succeeded but the SQL commit failed, a replica account is unavailable, or the process stopped mid-object | Stop the run, inspect the object and the journal, restore access, then attempt one controlled retry; if bytes are partly gone, restore the SQL backup | `GET /api/v1/admin/storage/gc-audit`; `storage_gc_collected`; log `physical gc collect DONE ... failed=N` |
| GC reports `skipped` with no failure | A head, alias, live key, lock, unresolved intent or lease won the safety race | This is correct fail-closed behaviour. Re-preview later; do not bypass the filter | `GET /api/v1/admin/storage/gc` and the dry-run candidate list |
| Local upload job returns `503 Configure TELEDRIVE_JOB_SOURCE_ROOT for local upload jobs` | The job source root is unset, missing or not a directory | Set `jobs.source_root` / `TELEDRIVE_JOB_SOURCE_ROOT` and mount it read-only | Log `POST /api/v1/admin/storage/jobs -> 503`; config value |

## Admin lockout recovery

The supported recovery path is local filesystem/database access, not a network bypass:

```bash
python scripts/ops/reset_local_password.py \
  --config config/config.yaml \
  --username admin \
  --role admin
```

The script reads the database URL from the config (or accepts `--database`), prompts twice for a password without putting it in `argv`, updates or creates the user, enables the account and deletes every existing session for that user. `--min-length` defaults to 5 as a typo check, not a password policy. A successful run prints `updated local user 'admin' with role 'admin'; all its sessions were revoked.`

If the database is unreachable, this script cannot help. Restore the database first, then run it. Do not delete the `admin` row as a first resort; it loses the account's history and can leave orphan session rows, while the supported script updates the password, enables the account and revokes sessions in one transaction.

## When to escalate

Escalate to the owner before doing any of the following:

- enabling physical GC or changing `deletion_permitted` expectations;
- replacing the S3 master key or rotating Telegram credentials during an incident;
- deleting SQL rows to clear a lock or a failed object;
- restoring a production database over a live one;
- removing an object-lock or legal-hold record to make a delete succeed.

For the backup and session prerequisites behind these warnings, see [Backup and restore](backup-restore.md). For GC safety, see [Garbage collection](garbage-collection.md). For logs, metrics and audit, see [Monitoring](monitoring.md).
