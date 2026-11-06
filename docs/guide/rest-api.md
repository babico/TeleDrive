# REST API

The REST API is the JSON control plane of the service, versioned under `/api/v1`. It covers session login, user and role administration, deployment configuration, the object catalog, API keys, S3 credentials, Telegram sessions, storage jobs, garbage collection, audit and metrics. The same process also serves the browser UI and the S3 gateway, so an object created through any surface is visible through the others immediately.

A small set of legacy aliases under `/api/*` still answers for compatibility: login, logout, `me`, the self-service password change, config read/save and logs. They are hidden from the generated schema and fold onto the `/api/v1` route for permission matching. New clients should use `/api/v1`. Health is the exception: `GET /api/health` is the only health path on the web listener and is public by design (the S3 listener has its own `GET /__health`).

## Base URL and listeners

| Surface | Default URL | Notes |
| --- | --- | --- |
| Web UI and REST | `http://127.0.0.1:8080` | `TELEDRIVE_WEB_PORT`; `/api/v1/...` |
| S3 gateway | `http://127.0.0.1:9000` | `TELEDRIVE_S3_PORT`; separate protocol, see [S3 API](s3-api.md) |
| Health | `GET /api/health` | Unauthenticated liveness only; `{"ok": true}` |

There is one container and one Python process. The listeners can use independent TLS settings (`TELEDRIVE_SSL_*` for web/REST, `TELEDRIVE_S3_SSL_*` for S3), and behind a reverse proxy the deployment must set `TELEDRIVE_TRUSTED_PROXY` before forwarded scheme and client address are honoured.

## Authentication

Two mechanisms are supported for humans and automation, plus SigV4 for S3. HTTP Basic has been removed completely.

### Session cookie

`POST /api/v1/auth/login` takes `{"username": "...", "password": "..."}` and, on success, sets the httpOnly `teledrive_session` cookie and returns:

```json
{
  "token": "td_sess_...",
  "user": {"id": 1, "username": "admin", "role": "admin"},
  "expires_at": 1767225600,
  "must_change_password": true
}
```

The session lasts seven days. The cookie is `SameSite=Lax` and becomes `Secure` when the web listener terminates TLS or a trusted proxy reports HTTPS. State-changing requests made with the cookie must also send `X-TeleDrive-CSRF: 1`; if an `Origin` header is present it must match the `Host`. The returned token can also be sent as `Authorization: Bearer td_sess_...`, but the cookie is the intended browser flow.

`POST /api/v1/auth/logout` revokes the server-side session and clears the cookie. `GET /api/v1/auth/me` returns the current user and `must_change_password`, which stays true while the bootstrap `admin`/`admin` password is unchanged.

### Bearer API key

Issue a key from **Access → API Management** or `POST /api/v1/admin/keys`. Keys look like `td_live_...` and are stored hashed; the secret is returned only at creation or rotation. Send it as:

```http
Authorization: Bearer td_live_...
```

An API key is not a user and has no role. It is authorized only for the exact permissions it was issued with, and a key cannot mint, rotate or revoke authority it does not itself hold, nor create a child key that outlives it.

### Which surface accepts which credential

This distinction matters:

- Session-only routes (browser administration) accept the cookie, a session bearer token, or a bearer API key whose scopes include that route's permission.
- The REST data plane `GET/POST/DELETE /api/v1/buckets...`, `PUT/HEAD/GET /api/v1/buckets/{bucket}/content` and the version/object listing routes accept **only a bearer API key** with the curated `rest:*` permission. A browser session cookie is not enough.
- A few secret-bearing actions require an **interactive session** even for an admin: issuing, editing, revealing or revoking S3 credentials, creating a presigned URL, saving deployment configuration, and S3-governance writes. A bearer API key is refused there by design.

## Roles and permissions

Dashboard users have one of three roles. The role-to-permission map is built from the live route table, so a newly added route is automatically admin-visible; an operator gains it unless it is classified admin-only, and a viewer gains it only when it is a read route.

| Role | Grants |
| --- | --- |
| `admin` | Every permission in the registry |
| `operator` | Every permission except user, API-key, S3-credential, physical-GC, bucket-quota, website-publish, audit/log and deployment-config administration. Requesting or verifying a Telegram login code, and globally revoking the stored session, are also admin-only; per-account deletion, health checks and soft quotas are not. |
| `viewer` | `GET`/`HEAD` routes and the curated REST read names, outside the admin-only surfaces |

A role that is not one of these three grants nothing.

Every `/api/v1` route carries exactly one permission name:

- The nine original REST data-plane routes keep short names: `rest:buckets:list`, `rest:buckets:create`, `rest:buckets:delete`, `rest:objects:list`, `rest:objects:list-versions`, `rest:objects:get`, `rest:objects:head`, `rest:objects:put`, `rest:objects:delete`.
- Every other route uses the canonical lowercase `method:path` form, for example `get:/api/v1/admin/storage/buckets`, `post:/api/v1/admin/storage/jobs`, `put:/api/v1/config`.
- Legacy grouped scopes remain accepted aliases for existing keys. Only the object/bucket families still expand to endpoint sets: `buckets:read`, `buckets:manage`, `objects:read`, `objects:write`, `objects:delete`. The retired groups `jobs:read`, `jobs:manage`, `accounts:read`, `accounts:manage`, `settings:read`, `settings:manage` and `keys:manage` are accepted but expand to an **empty** set, so a key that holds only one of them authorizes nothing; reissue it with per-endpoint names.
- `admin:*` is a real wildcard over the whole live route table, not just the nine curated names.

`GET /api/v1/admin/keys/permissions` returns the catalog (`routes`, `groups`, `legacy_scopes`). `GET /api/v1/admin/roles` returns the resolved role map with permission counts and groups. Both are the authoritative answer for a given build.

Admin-only surfaces, for every method, include `/api/v1/admin/users`, `/api/v1/admin/keys`, `/api/v1/admin/s3/credentials` (and the `/s3-credentials` alias), `/api/v1/admin/storage/gc`, `/api/v1/admin/audit`, `/api/v1/admin/storage/shares`, `/api/v1/logs`, bucket `/quota` and `/website`, the Telegram login-code request/verify routes and the global session revocation, and writes to `/api/v1/config`. S3-governance writes are additionally admin-only in their handlers.

## Requests, responses and limits

- Request and response bodies are JSON except object content, which is `application/octet-stream`.
- Errors use FastAPI's shape: `{"detail": "message"}`. A few handlers return a structured detail object (for example the Telegram FloodWait response and the `409` when deleting a Telegram account that still stores objects); treat `detail` as either a string or an object with a `message` field.
- Status codes follow the handler: `400` invalid input, `401` not authenticated, `403` role/scope/CSRF failure, `404` missing object or bucket, `409` conflict or stale generation, `413` quota or size limit, `415` wrong upload content type, `422` schema validation, `429` throttle, `503` storage or master-key unavailable.
- Browser JSON bodies are limited to 32 MiB (`web.max_request_bytes`). The binary content routes are exempt from that buffer and use `web.rest_max_upload_bytes` instead, 2 GiB by default; `0` disables REST uploads (the handler answers `503`).
- Object keys must be 1–1024 UTF-8 bytes; bucket names 3–63 characters. A content upload must declare `Content-Type: application/octet-stream`.
- Listings are cursor-based, not offset-based. Object listing accepts `prefix`, `after` (last key seen) and `limit` 1–1000, default 100. Job, audit and log listings accept `limit` with their own maxima (1000 for jobs and audit, 1500 for logs). There is no total-count field and no `Link` header.
- Bucket quotas are enforced on REST uploads, S3 uploads, copies and durable jobs. HTTP upload surfaces answer `413` before the payload reaches Telegram; a durable job that would breach the quota is marked `failed` with the quota message in `last_error` instead.

## Rate limiting

There is no global request-per-second limiter on authenticated API traffic. The throttles that do exist are specific:

| Scope | Limit | Response |
| --- | --- | --- |
| Login | 5 failures per username + client within 300 s; the next attempt is refused | `429 Too many failed attempts; try again later` |
| Public share links | 60 requests per client IP per 60 s | `429 Too many requests` |
| Telegram login code | Telegram's own FloodWait, recorded and counted down | `429` with wait fields |
| Telegram send/receive | Per-account flood cooldowns and soft quotas in the storage layer | Job failure/retry, not an HTTP limit |

Failed upload jobs are not retried automatically; an operator retries them explicitly. Telegram FloodWait is respected by the storage engine, and the remaining cooldown is exposed on the session listing and in metrics.

## Endpoint groups

| Group | Prefix | Credential | Purpose |
| --- | --- | --- | --- |
| Auth | `/api/v1/auth` | public / session | Login, logout, current user, self-service password change |
| Users and roles | `/api/v1/admin/users`, `/admin/roles` | session (admin) | User CRUD, password, role, session revocation |
| Audit | `/api/v1/admin/audit` | session (admin) | Durable security events, filter by action and actor |
| Configuration | `/api/v1/config` | session (admin writes) | Redacted settings read, validated save |
| Logs and health | `/api/v1/logs`, `/api/v1/logs/stream`, `/api/health`, `/api/v1/metrics` | session/API key (logs are admin) | Activity buffer, live stream, Prometheus text |
| REST data plane | `/api/v1/buckets` | bearer API key (`rest:*`) | Bucket create/delete, object list/put/get/head/unlink, versions |
| WebUI storage | `/api/v1/admin/storage/buckets` | session/API key with route scope | Bucket browser, upload/download, copy, quota, pin, CORS, website, presign |
| Shares | `/api/v1/admin/storage/shares`, `/share/{token}` | admin / anonymous token | List and revoke share links; public download |
| Search | `/api/v1/admin/storage/search` | session | Key or content search, reindex |
| API keys | `/api/v1/admin/keys` | session (admin) | List, permissions, issue, rotate, revoke |
| S3 credentials | `/api/v1/admin/s3/credentials` | interactive session (admin) | List, issue, edit, reveal, revoke |
| Telegram | `/api/v1/admin/storage/telegram-session*`, `/telegram-sessions`, `/channels`, `/strategy`, `/replication` | session/API key | Session login, account health and quotas, channels, routing, replica target |
| Jobs and recovery | `/api/v1/admin/storage/jobs*`, `/pending-stale`, `/s3-multipart`, `/mtproto-unresolved`, `/channel-history` | session/API key | Durable jobs, stale upload recovery, forensic inventories |
| Garbage collection | `/api/v1/admin/storage/gc`, `/gc/collect`, `/gc-audit`, `/gc-candidates` | session (admin) | Owner gate, preview and collection |
| Storage health | `/api/v1/admin/storage/health`, `/usage`, `/active-channel`, `/version-history`, `/versions` | session/API key | Dashboard data, version restore |
| S3 governance | `/api/v1/admin/s3-governance/{bucket}/*`, `/s3-governance/signing-credentials` | session (admin writes, operator reads) | Policy, ownership, PAB, lock, website, notifications, replication, tiering, reports, rearchive and signing-credential selection |
| Certificates | `/api/v1/certificate.cer`, `/api/v1/certificate.pem`, `/server.cer`, `/server.crt` | public | DER and PEM public-certificate download for trust bootstrap |

All admin paths in the table are relative to `/api/v1` where the row omits it (for example `/admin/storage/health` means `/api/v1/admin/storage/health`).

A few useful read routes:

| Method and path | Returns |
| --- | --- |
| `GET /api/v1/admin/storage/health` | Job state counts, alerts, stale-upload samples, retained message count |
| `GET /api/v1/admin/storage/telegram-sessions` | Accounts with usage, retained bytes, cooldown, flood count, health |
| `GET /api/v1/admin/storage/jobs?limit=100` | Durable job rows without lease tokens |
| `GET /api/v1/admin/storage/version-history?bucket=...` | Published versions and delete markers |
| `GET /api/v1/admin/storage/usage?days=30` | Daily object and byte series |
| `GET /api/v1/admin/audit?limit=50&action=user.create` | Durable security trail |
| `GET /api/v1/metrics` | Prometheus text format |

## OpenAPI and interactive docs

The application is constructed with `docs_url`, `redoc_url` and `openapi_url` disabled and then serves its own authenticated routes:

| Path | Content |
| --- | --- |
| `GET /openapi.json` | OpenAPI 3 schema for the routes that are in the schema |
| `GET /docs` | Swagger UI |
| `GET /redoc` | ReDoc |

All three call `require_auth`, so they need a session cookie or an acceptable bearer token; an anonymous request is `401`. Legacy aliases and internal routes are marked `include_in_schema=False`, so the schema is essentially the `/api/v1` surface plus the public `/api/health` and certificate endpoints. The S3 gateway has no OpenAPI document.

## Examples

### 1. Log in and inspect the session

```bash
curl -sS -c td.cookies \
  -H 'Content-Type: application/json' \
  -H 'X-TeleDrive-CSRF: 1' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}' \
  http://127.0.0.1:8080/api/v1/auth/login

curl -sS -b td.cookies http://127.0.0.1:8080/api/v1/auth/me
```

The second call returns the user object and `must_change_password`.

### 2. Create a bucket with an API key

The REST data plane needs a bearer key, not a cookie.

```bash
export TD_API_KEY='td_live_...'

curl -sS -X POST \
  -H "Authorization: Bearer $TD_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"backups"}' \
  http://127.0.0.1:8080/api/v1/buckets
```

### 3. Upload and read an object

```bash
curl -sS -X PUT \
  -H "Authorization: Bearer $TD_API_KEY" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @./archive.tar \
  'http://127.0.0.1:8080/api/v1/buckets/backups/content?key=daily/archive.tar'

curl -sS -H "Authorization: Bearer $TD_API_KEY" \
  'http://127.0.0.1:8080/api/v1/buckets/backups/content?key=daily/archive.tar' \
  -o archive.tar
```

Add `-H 'Range: bytes=0-1023'` for a partial read. A successful upload returns `{"id", "bucket", "key", "size", "sha256", "generation"}`. The `sha256` field is the object digest; `GET` and `HEAD` return the same value as a quoted `ETag`, and a partial read answers `206` with `Content-Range`.

### 4. List objects with a cursor

```bash
curl -sS -G -H "Authorization: Bearer $TD_API_KEY" \
  --data-urlencode 'prefix=daily/' \
  --data-urlencode 'limit=50' \
  --data-urlencode 'after=daily/2026-10-01.tar' \
  http://127.0.0.1:8080/api/v1/buckets/backups/objects
```

Pass the last returned `key` as the next `after` value. `generation` is the optimistic-concurrency token used by conditional unlink.

### 5. Issue a narrowly scoped API key

```bash
curl -sS -b td.cookies \
  -H 'X-TeleDrive-CSRF: 1' \
  -H 'Content-Type: application/json' \
  -d '{"name":"nightly backup","scopes":["rest:buckets:list","rest:objects:list","rest:objects:put","rest:objects:get"],"expires_at":1798761600}' \
  http://127.0.0.1:8080/api/v1/admin/keys
```

`token` is the only time the secret is returned. `expires_at` is optional Unix seconds; omit it for no expiry.

### 6. Queue a local file for upload

```bash
curl -sS -b td.cookies \
  -H 'X-TeleDrive-CSRF: 1' \
  -H 'Content-Type: application/json' \
  -d '{"bucket":"backups","key":"import/report.pdf","source_path":"/uploads/report.pdf"}' \
  http://127.0.0.1:8080/api/v1/admin/storage/jobs
```

The source must be a regular file under the configured `jobs.source_root`; a path outside it is rejected. The response is `{"id": "...", "state": "queued"}`. See [Local file jobs](local-jobs.md).

### 7. Read the security audit trail

```bash
curl -sS -b td.cookies \
  'http://127.0.0.1:8080/api/v1/admin/audit?limit=50&action=user.create'
```

`action` and `actor` are optional filters. The in-memory `/api/v1/logs` buffer is a debugging aid; this table is the durable trail.

## Metrics

`GET /api/v1/metrics` returns Prometheus text exposition 0.0.4 and requires the same authentication as any API route. It includes:

- `teledrive_up`
- `teledrive_storage_jobs{state=...}`
- `teledrive_quota_limit_bytes`, `teledrive_quota_limit_objects`, `teledrive_quota_used_bytes`, `teledrive_quota_used_objects` per bucket
- `teledrive_telegram_session_authorized{account=...}`
- `teledrive_telegram_session_soft_quota_bytes{account=...}`
- `teledrive_flood_observations_total{account=...}`
- `teledrive_flood_cooldown_remaining_seconds{account=...}`

Scrape it with the session cookie or a bearer key that holds the route's permission; an anonymous scrape is refused. See [Monitoring](../operate/monitoring.md).
