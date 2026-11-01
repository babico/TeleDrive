# Monitoring

TeleDrive exposes a small liveness surface, a Prometheus text endpoint, a bounded request log and a durable security audit trail. This page tells you what each one actually measures, which failures are worth alerting on, and how to tie a user complaint to a log line.

## Liveness endpoints

| Endpoint | Authentication | What it proves | What it does not prove |
| --- | --- | --- | --- |
| `GET /api/health` | None | The web process is accepting requests and can return JSON | Database reachability, Telegram session validity, catalog integrity |
| `GET /__health` on the S3 listener | None | The S3 ASGI app is accepting requests | Any S3 credential, bucket or Telegram operation |
| `python -m web.container_healthcheck` | Container-local | Both listeners answer with HTTP below 500 over the configured scheme and port | Successful object I/O |

The Docker image and `docker-compose.yml` use the same probe: `interval: 30s`, `timeout: 8s`, `start_period: 20s`, `retries: 5`. It reads `TELEDRIVE_WEB_PORT` / `TELEDRIVE_S3_PORT` and the per-listener TLS variables, so a remapped port cannot leave the healthcheck on a stale value. A TLS probe verifies the configured certificate chain and disables hostname checks because it connects to `127.0.0.1`.

`/api/health` is a liveness check, not a readiness check. A deployment with no Telegram session, an unreachable database or a broken master key can still answer `{"ok": true}`. Use the metrics and the authenticated admin endpoints below for readiness.

## Prometheus metrics

`GET /api/v1/metrics` returns Prometheus text exposition format 0.0.4 and requires authentication. The scrape principal needs the route permission `get:/api/v1/metrics`; a normal read role also satisfies the role gate. Issue a dedicated API key for the scraper and keep it in a file, not in the Prometheus configuration.

```yaml
# prometheus.yml
global:
  scrape_interval: 30s
  scrape_timeout: 10s

scrape_configs:
  - job_name: teledrive
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/teledrive-metrics-key
    static_configs:
      - targets: ["teledrive.example.com:8443"]
```

Point the target at the web listener, or at the reverse proxy if the proxy forwards `/api/v1/metrics` and preserves the Host header. If the listener uses a private CA, add the usual `tls_config.ca_file`.

### Metric families

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `teledrive_up` | gauge | none | Constant `1` while the handler runs. Use Prometheus `up` for scrape reachability |
| `teledrive_storage_jobs` | gauge | `state` | Durable upload jobs by state; emitted only when at least one job exists |
| `teledrive_quota_limit_bytes` | gauge | `bucket` | Configured bucket size limit; omitted when unlimited |
| `teledrive_quota_limit_objects` | gauge | `bucket` | Configured bucket object-count limit; omitted when unlimited |
| `teledrive_quota_used_bytes` | gauge | `bucket` | Current logical bucket size |
| `teledrive_quota_used_objects` | gauge | `bucket` | Current logical object count |
| `teledrive_telegram_session_authorized` | gauge | `account` | `1` authorized, `0` expired or revoked; omitted until a session is known |
| `teledrive_telegram_session_soft_quota_bytes` | gauge | `account` | Configured soft quota; omitted when unlimited |
| `teledrive_flood_observations_total` | counter | `account` | Observed Telegram flood-waits |
| `teledrive_flood_cooldown_remaining_seconds` | gauge | `account` | Active shared flood cooldown remaining |

Bucket quota usage is logical usage from current object heads, not the physical Telegram backlog. Retained bytes are reported separately by `GET /api/v1/admin/storage/gc` and are intentionally not a Prometheus family.

## Logs

There are two retention paths for the same application events, plus the container runtime's own JSON log.

| Path | Retention | Who can read it | Contents |
| --- | --- | --- | --- |
| In-memory `LOG_BUFFER` | 1,500 entries, lost on restart | Admin only through `GET /api/v1/logs`, the `/api/logs` alias and the websocket `/api/v1/logs/stream` | Timestamp, user, source and message |
| Rotating file | 10 MiB per file, 5 backups, rotated files gzip-compressed | Host operator with access to `/data` | Same line format as the buffer |
| Container JSON log | Docker `max-size: 10m`, `max-file: 5` | Host operator | Process stdout/stderr, including startup failures before the buffer exists |

The file path is the top-level `logging.log_path` value in the raw config, defaulting to `/data/teledrive.log`. Only the `teledrive` logger is attached to this handler at INFO. A missing or unwritable log path is logged as a startup warning and does not stop the service.

Log lines have the form:

```text
[2026-11-01 12:34:56] [alice] [http] GET /api/v1/buckets/media -> 200 (42ms)
```

`source` examples include `http`, `storage`, `telegram-session`, `gc`, `config`, `users`, `share`, `scheduler`, `watcher` and `startup`. S3 traffic uses the same `http` source and the access key id as the user, because SigV4 never transmits the secret.

The HTTP audit middleware writes a request line before the handler and a result line after it. It skips `/api/health`, `/__health` and `/static/`. Share tokens in `/share/<token>` are redacted before logging. A call that never reaches the middleware, such as a bad Host header rejection, has no request line.

## Audit trail

The durable trail is the `security_audit_events` table, exposed at `GET /api/v1/admin/audit` with optional `action`, `actor` and `limit` filters. It is admin-only and append-only. It records security events, not every request:

| Action family | Examples |
| --- | --- |
| Credentials and keys | `credential.issue`, `credential.edit`, `credential.revoke`, `credential.reveal`, `api_key.issue`, `api_key.rotate` |
| Identity and configuration | `user.create`, `user.update`, `user.delete`, `config.write` |
| Dangerous storage work | `gc.collect.start`, `gc.collect.done` |
| Delegated authority | `object.presign`, `share.create` |

Each row carries the actor, action, target, outcome, a scrubbed detail blob, the client IP and a nanosecond timestamp. The recorder rejects values shaped like TeleDrive credentials, sessions, Fernet tokens and password hashes. A failed audit write never fails the operation it describes.

There is no automatic retention or pruning. `prune(older_than_ns=...)` exists in the audit module but is an operator action with direct database access; no HTTP route deletes audit rows. A compliance requirement therefore needs an external archive or a scheduled database job.

The `client_ip` column is `request.client.host`, which is the reverse-proxy address when TeleDrive sits behind a proxy. Unlike the login and share throttles, the audit writer does not resolve `X-Forwarded-For`. Use the proxy's own access log when the real client address is required.

## What to alert on

| Alert | Expression | Why |
| --- | --- | --- |
| Scrape target down | `up{job="teledrive"} == 0` | The process or network path is unavailable; `teledrive_up` cannot report its own absence |
| Session unauthorized | `teledrive_telegram_session_authorized == 0` | Uploads and reads will fail until the session is re-authorized |
| Flood activity | `increase(teledrive_flood_observations_total[15m]) > 0` | Telegram is rate-limiting an account |
| Long cooldown | `max_over_time(teledrive_flood_cooldown_remaining_seconds[5m]) > 600` | The shared cooldown is material, not a single retry |
| Failed jobs | `teledrive_storage_jobs{state="failed"} > 0` | A durable upload exhausted its retries or was rejected |
| Size quota near limit | `teledrive_quota_limit_bytes > 0 and (teledrive_quota_used_bytes / on(bucket) teledrive_quota_limit_bytes) > 0.9` | The next upload may be rejected with `EntityTooLarge` |
| Object quota near limit | `teledrive_quota_limit_objects > 0 and (teledrive_quota_used_objects / on(bucket) teledrive_quota_limit_objects) > 0.9` | Object-count quota is about to block writes |
| No session metric at all | `absent(teledrive_telegram_session_authorized)` | A fresh install has no session; on a working deployment this is a regression |

`teledrive_up` is a constant self-report. If the endpoint stops answering, Prometheus records `up == 0` and there is no `teledrive_up` sample to evaluate.

## Capacity signals

| Signal | Where to read it | Response |
| --- | --- | --- |
| Bucket quota headroom | `teledrive_quota_used_*` versus `teledrive_quota_limit_*` | Raise the quota deliberately or delete data; do not silently disable the quota |
| Telegram soft quota | `teledrive_telegram_session_soft_quota_bytes` and the session list | Move writes to another account or raise the soft quota with the owner |
| Flood observations and cooldown | `teledrive_flood_observations_total`, `teledrive_flood_cooldown_remaining_seconds` | Reduce concurrency; do not retry in a tight loop |
| Session health | `teledrive_telegram_session_authorized` and `GET /api/v1/admin/storage/telegram-sessions` | Re-authorize through the WebUI request-code/verify-code flow |
| Job backlog | `teledrive_storage_jobs{state="queued"}` and `GET /api/v1/admin/storage/jobs` | Investigate the worker, source root and session before draining |
| Retained Telegram backlog | `GET /api/v1/admin/storage/gc` `metrics.retained_bytes` | This is expected while GC is disabled; do not enable GC as a capacity fix without the owner gates |
| Audit growth | Row count of `security_audit_events` | Archive or prune under a defined retention policy |

## Correlating a request with a log line

1. Note the method, path, response status and local time from the client or proxy.
2. Search the log buffer for the request line, for example `GET /api/v1/buckets/media from 10.0.0.5`.
3. Match the result line by the same method, path and the nearest timestamp: `GET /api/v1/buckets/media -> 403 (3ms)`. There is no request id, so time and path are the correlation key.
4. Read the `[user]` field. A session is resolved to the username; an S3 request shows the access key id; an unauthenticated request shows `system` or `-` depending on the surface.
5. For an authority change, use the audit trail rather than the buffer: `GET /api/v1/admin/audit?action=credential.reveal&limit=50`.
6. For an S3 signature failure, the response body carries the exact code (`SignatureDoesNotMatch`, `RequestTimeTooSkewed`, `AccessDenied`). The log only carries the status.
7. For a failed upload, search for the source `storage` or `telegram-session`; job failures and session health are logged separately from the HTTP result.

The in-memory buffer is a debugging aid. If a restart or a 1,500-line burst has already evicted the line, use the rotating file and the durable audit trail.

See [Troubleshooting](troubleshooting.md) for the failure-code table and [Garbage collection](garbage-collection.md) for the GC audit and report fields.
