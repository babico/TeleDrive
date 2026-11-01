# Web UI

The dashboard is the browser surface of the same service that exposes the REST API and the S3 gateway. It is served on the web port (8080 by default) from the static pages in `web/static/`, and every action it performs is an ordinary `/api/v1/*` call made with the session cookie. There is no separate UI backend and no client-side copy of the catalog: what you see in the browser is the shared SQL catalog that REST, S3 and local upload jobs write to.

## Sign in and the first-login gate

Open `http://127.0.0.1:8080/`. On first boot, if no user named `admin` exists, the service creates exactly one account:

| Field | Value |
| --- | --- |
| Username | `admin` |
| Password | `admin` |
| Role | `admin` |

This bootstrap account is not configurable. No config key and no environment variable can change its name or password. If an `admin` row already exists it is left untouched, so a password you set survives restarts; deleting the row re-creates `admin`/`admin`, which is the documented lockout recovery.

The login form posts `{"username": ..., "password": ...}` to `POST /api/v1/auth/login`. On success the server sets the httpOnly `teledrive_session` cookie (seven days, `SameSite=Lax`, `Secure` when the web listener uses TLS or a trusted proxy forwarded HTTPS) and returns the same token in the JSON body for non-browser clients. HTTP Basic is not implemented: a `Basic` header is treated as no credential at all.

!!! danger "Change the bootstrap password immediately"
    While the shipped `admin`/`admin` password is still in use, `GET /api/v1/auth/me` reports `must_change_password: true` and every page redirects to **Access → Users**. Use the **Password** button on the `admin` row, enter at least eight characters, and save. The change also revokes that user's existing sessions, so you will sign in again. Until you do this, the deployment is one guess away from full control.

Signing out calls `POST /api/v1/auth/logout`, which deletes the server-side session row and clears the cookie. A browser that loses the cookie lands on `/login`.

## Navigation map

The sidebar has four groups. Each entry is a page shell that authenticates on load; the data it shows comes from the endpoints named below.

| Page | Route | Purpose | Main endpoints |
| --- | --- | --- | --- |
| Dashboard | `/` or `/dashboard` | Health cards, upload activity, Telegram accounts, physical GC | `/api/v1/admin/storage/health`, `/storage/usage`, `/storage/telegram-sessions`, `/storage/gc`, `/storage/buckets` |
| Queue | `/queue` | The durable local-file job queue | `/api/v1/admin/storage/jobs` |
| History | `/history` | Finished job runs and every published object version | `/storage/jobs`, `/storage/version-history` |
| Settings → General | `/settings/general` | Upload policy, database URL, automation, scratch, TLS certificate download | `/api/v1/config` |
| Settings → Telegram | `/settings/telegram` | Channels, USER session login, accounts, strategy, replication | `/admin/storage/channels`, `/telegram-session*`, `/telegram-sessions`, `/strategy`, `/replication` |
| S3 → Credentials | `/s3/credentials` | SigV4 keypairs for the S3 gateway | `/api/v1/admin/s3/credentials` |
| S3 → Buckets | `/s3/buckets` | Bucket and object browser, uploads, shares, quotas, CORS, pins | `/admin/storage/buckets*`, `/admin/storage/shares` |
| S3 → Governance | `/s3/governance` | Policy, ownership, public access block, object lock, website, notifications, replication, tiering, reports | `/api/v1/admin/s3-governance/*` |
| Access → API Management | `/api-management` | REST bearer keys and their per-endpoint scopes | `/api/v1/admin/keys` |
| Access → Users | `/users` | Dashboard users, roles, password resets | `/api/v1/admin/users` |
| Access → Logs | `/logs` | Live and historical activity log | `/api/v1/logs`, WebSocket `/api/v1/logs/stream` |

Legacy paths redirect: `/settings` → `/settings/general`, `/storage` → `/settings/telegram`, `/s3` → `/s3/buckets`.

Page shells are served to any authenticated role. What a page can actually read or change is decided per endpoint by the role map, so a viewer who opens **Users** sees an empty table and a permissions error, not a hidden back door. `GET /api/v1/admin/roles` returns the live role-to-permission map if you want to see the exact grant for your build.

## Dashboard

The four top cards come from `GET /api/v1/admin/storage/health`: queued plus running plus staged plus publishing jobs, failed jobs, completed jobs, and the active upload strategy. **Run next job** calls `POST /api/v1/admin/storage/jobs/run-next` and processes one queued durable job — it never deletes Telegram media.

Below the cards:

- **Telegram accounts** lists each account with current object count and bytes, any shared FloodWait cooldown, and the last health probe (authorized, unauthorized, or unknown). Probes run automatically every 30 minutes.
- **Upload activity** is a 30-day bar chart of published objects and bytes from `GET /api/v1/admin/storage/usage?days=30`.
- **Physical GC** shows the owner gate, logical versus physical storage, the retained backlog, and the collection controls. See [Garbage collection](../operate/garbage-collection.md) before using them.
- **Storage usage** shows per-bucket current size against the optional quota.

## Queue and History

**Queue** is the durable local-file job list. Each row is one `storage_upload_jobs` record: source path, state, attempt count, the Telegram account used, and the last error. The UI has no single-file enqueue form; jobs are created by the REST endpoint or by the optional folder watcher (see [Local file jobs](local-jobs.md)). **Run next job** on the dashboard is the manual worker trigger.

**History** has two panels:

- **Upload history** filters the same job list to terminal states (`done`, `failed`, `cancelled`).
- **Object versions** reads `GET /api/v1/admin/storage/version-history` and shows every published version and delete marker from every write path — browser upload, REST, multipart and server-side copy. Deleted objects remain listed; their Telegram media is retained until an owner-authorized physical GC run.

Direct S3 and REST uploads do not create upload jobs, so they appear only in the versions panel, never in the job queue.

## Settings → General

This page edits the deployment settings document. Saving calls `PUT /api/v1/config`, which validates the complete document, writes it atomically to `config/config.yaml` at mode 0600, and stores the authoritative copy in SQL. Only `admin` may save; every role may read the redacted document.

| Section | What it controls |
| --- | --- |
| Upload | Source directory, send mode, files per run and per day, send delay, retry/backoff, FloodWait buffer, maximum file size, caption template, allowed extensions |
| Database | The SQLAlchemy URL of the shared catalog (displayed redacted) |
| Automation | Legacy batch-runner toggle and interval |
| Storage | Scratch directory used to stage uploads |
| TLS certificate | Download `/server.cer` (DER) or `/server.crt` (PEM chain) |

Two values are deliberately file-only. A save that tries to change `state.database_url`, `state.db_path` or `state.db_extra_packages` is rejected with `400`; edit `config/config.yaml` on the host instead. The reason is that redirecting the database or installing a package at boot is a host-level takeover, not a dashboard setting. TLS is also environment-only (`TELEDRIVE_SSL_*` and `TELEDRIVE_S3_SSL_*`); the form only lets you download the public certificate.

The Automation section is the historic batch-runner switch. The durable job scheduler is governed by `jobs.auto_run` and the optional `jobs.watch` settings in `config/config.yaml`, not by this form.

## Settings → Telegram

This is the account and channel control room.

- **Channels** lists every configured storage channel. An operator or admin can add one (display name, channel ID or username, strategy, scratch directory), activate it, or remove it. Writes go to the active channel; every configured credential set must be able to post to it.
- **Active channel settings** switches the write target. Activation reloads the storage runtime.
- **Telegram session (USER MTProto)** starts an interactive login: enter API ID, API hash and phone, press **Send code**, then enter the code from the newest Telegram message and the 2FA password if the account has one. The code request is stored for five minutes, a wrong code can be retried at most five times, and FloodWait responses show a live countdown. Adding, requesting a code or verifying a code is an admin-only action; the resulting session becomes the identity every upload is sent as.
- **Authorized accounts** lists each session with phone (masked), API ID, current objects and bytes, retained bytes, soft quota, cooldown and health. **Check** probes one account immediately; **Delete** removes a session, and refuses without `force=true` while that account still stores chunks.
- **Upload routing strategy** applies to all accounts: `single`, `round_robin`, `failover` or `parallel`. A FloodWait on one account fails over to the others.
- **Cross-account replication target** designates a second account that receives a copy of each new upload's chunks. **Repair missing replicas** re-sends chunks that are missing from the target.

Soft quotas are advisory routing headroom: they are displayed here, in metrics and in health checks, but the hard limit is the per-bucket quota on **S3 → Buckets**.

## S3 → Credentials

This page issues the SigV4 keypairs that S3 clients use. A credential is not a user: it has no session and no access to this dashboard or the REST admin API.

- **Generate new credentials** asks for a name, an expiry (30/90/365 days, never, or a custom date), and the exact `s3:*` actions. Presets are starting points; every checkbox remains editable, and actions that can destroy data or change governance are flagged. Saving returns the access key ID and secret once.
- The list shows name, access key ID, scope families, expiry and status. **Show secret** decrypts the secret server-side and writes an audit entry; **Rotate** issues a replacement and revokes the old key immediately; **Revoke** ends access on the next request with no grace period.
- Revoking or expiring a key is irreversible. Instructions and the permission reference are on [S3 API](s3-api.md).

!!! warning "The secret is shown once"
    The create and rotate responses are the only time the secret is returned. It is held in browser memory only, never in local storage or the URL. Copy it into the client's configuration before dismissing the panel. A later reveal requires an admin session and is audit-logged.

All credential creation, editing, reveal and revocation requires an interactive admin session. A bearer API key is refused even if it holds the route's permission, because an S3 credential is itself a secret and could otherwise chain into broader authority.

## S3 → Buckets

The object browser works on the shared catalog, so an object uploaded here is immediately visible over REST and S3, and vice versa.

- **Buckets** lists name, current object count, total size and quota, with **New bucket** for admins. Creating a bucket uses the same 3–63 character name rules as S3. **Delete** requires the bucket to be empty and also removes its share links.
- **Upload** supports drag-and-drop and a file picker. The optional **Encrypt before upload** checkbox encrypts the file in the browser with AES-256-GCM using a passphrase you type; the passphrase never leaves the device and cannot be recovered. Such objects are stored as ciphertext, are not previewable, and can only be decrypted by a client that has the passphrase.
- **Search** runs in key mode by default, or in content mode over the plaintext full-text index. **Reindex** backfills content for existing text-extractable objects in bounded batches. Encrypted objects are not content-indexed.
- Per-object actions:
  - **Download** and **Preview** stream verified bytes through the session.
  - **Link** creates a presigned GET URL (1–604800 seconds) signed with an S3 credential that holds `s3:GetObject`.
  - **Share** creates a `/share/<token>` link bounded by expiry, download count and an optional password, all enforced server-side.
  - **Rename** and **Move** are catalog-level copies: no Telegram bytes move, the destination quota is checked, and the destination generation is fenced.
  - **Unlink** removes the key from the catalog. In a versioning-enabled bucket it writes a delete marker; in every case the Telegram media is retained until physical GC, so this is not an erase.
- **Quota** sets `max_size_bytes` and `max_objects`; blank means unlimited. Both S3 and REST uploads, server-side copies and durable jobs enforce it, answering `413` when it would be exceeded.
- **CORS** edits the bucket's browser rules (origins, methods, allowed headers, max age). CORS is a browser policy, never authentication.
- **Pin** fixes a bucket's uploads to one Telegram account; an explicit pin wins over strategy rotation and soft quotas.

Two links deserve their own warning. A presigned URL is anonymous authority that keeps working until it expires even if the session or credential owner is gone; only revoking the signing credential ends it early. A share link is likewise a complete credential for that one object. Treat both as secrets and prefer the shortest useful expiry.

## S3 → Governance

Every control on this page is an S3 configuration operation signed server-side with a real S3 credential; the browser never receives a secret key. An admin selects the bucket, optionally selects the signing credential, and saves. Operators can read the state; writes are admin-only.

| Tab | What it configures |
| --- | --- |
| Bucket policy | IAM-style JSON policy. Deny wins; `Principal.CanonicalUser` must be an existing access key; there is no IAM |
| Ownership | `BucketOwnerEnforced` (default), `ObjectWriter`, or `BucketOwnerPreferred`, deciding whether object ACL grants participate |
| Public access block | The four stored flags, default all on; turning one off relaxes a guard but publishes nothing by itself |
| Object lock | One-way enable with `GOVERNANCE` or `COMPLIANCE` default retention (1–3650 days). COMPLIANCE cannot be shortened or removed, even by an admin |
| Website | Index and error documents, plus the separate `public_read` gate |
| Notifications | Webhook destination from the owner allowlist, event selection and prefix/suffix filters. SQS, SNS and Lambda are rejected |
| Replication | AWS-shaped rules whose destination is a configured Telegram account label, not an ARN; enabled prefixes must not overlap |
| Intelligent-Tiering | `ARCHIVE_ACCESS` / `DEEP_ARCHIVE_ACCESS` configurations. The tier is an access gate in this catalog; Telegram bytes never move |
| Storage reports | Analytics, inventory and metrics configurations; the runner writes JSON Lines, gzip CSV or JSON into the destination |

!!! danger "`public_read` and Object Lock are one-way doors in practice"
    Turning on `public_read` publishes every current object in the bucket anonymously at `/site/<bucket>/`, readable by anyone who can reach the app host, with no login and no S3 credential. Saving asks for the `PUBLISH` confirmation; deleting the website configuration clears the flag. Enabling Object Lock cannot be undone from the UI, and COMPLIANCE retention cannot be shortened.

## Access → API Management

This page manages REST bearer keys. Unlike an S3 credential, an API key authorizes `/api/v1/*` calls and is scoped to individual endpoints.

- **Generate new key** takes a name, an expiry, and a set of permissions. The permission picker is built from the live route table (`GET /api/v1/admin/keys/permissions`): each entry is the canonical `method:path` name, and the nine original REST data-plane routes keep their short `rest:*` names. Legacy grouped scopes (`objects:read`, `buckets:manage`, …) remain selectable and expand to endpoint sets; `admin:*` expands to the whole live route table.
- The secret (`td_live_...`) is returned once and stored hashed.
- The list shows name, prefix, scopes, creation, last use, expiry and status. **Rotate** replaces the secret and revokes the old one; **Revoke** is immediate.
- Delegation is bounded: a key can only mint, rotate or revoke authority it already holds, and a child key cannot outlive the key that created it.

The page also links to `/docs`, `/redoc` and `/openapi.json`. All three require a session; see [REST API](rest-api.md).

## Access → Users

The user table lists username, role, enabled state, creation time and last login. Admin actions:

- **Add user** creates a username (1–64 characters of letters, digits, dot, dash or underscore), a password of at least eight characters, and a role (`admin`, `operator`, `viewer`).
- The role selector changes a user's role. The service refuses to remove the last enabled admin, and the bootstrap `admin` account cannot be renamed or deleted.
- **Password** sets a new password and revokes all of that user's sessions in the same transaction.
- **Delete** removes the user and their sessions together.

This is also the page the first-login gate sends you to while `admin`/`admin` is still active.

## Access → Logs

The log viewer shows the in-memory activity buffer with time, user, source and message. It supports a text filter, a line count (100–1500) and a **Live** toggle:

- **Live** opens the WebSocket `/api/v1/logs/stream`, which sends the last 200 entries and then every new line. If a proxy does not support WebSockets, the page falls back to polling every three seconds.
- **Hide polling noise** removes the page's own request lines from the view only; they remain in the log.

The endpoint and the WebSocket are admin-only because the buffer carries object keys, request paths and failure detail. Credentials are redacted before they reach the log, phone numbers are masked, and share tokens are replaced with `***` in request paths. The durable security trail — who changed which authority — is a separate store at `GET /api/v1/admin/audit`, not this page.

## Safety rails you will meet

- **CSRF and same-origin.** Every state-changing browser call carries `X-TeleDrive-CSRF: 1`, and a cross-origin `Origin` is rejected. The cookie is httpOnly; the page never reads or stores the session token.
- **Role gates.** Reads require any known role, writes require operator or admin, and the admin-only surfaces (users, API keys, S3 credentials, physical GC, bucket quota, website publishing, config writes, logs, audit, share administration, Telegram session mutations) require admin for every method. The per-route permission map narrows this further.
- **Brute-force throttle.** Five failed logins for the same username and client within 300 seconds answer `429` until the window passes. With a trusted proxy configured, the throttle keys on the real client address rather than the proxy.
- **Secrets are one-shot.** S3 credential secrets and API keys are shown only at creation or rotation. Existing S3 secrets can be revealed only by an interactive admin session, and every reveal is audit-logged.
- **Deletion is logical by default.** Buckets and objects disappear from the catalog, but Telegram media is not physically deleted until an owner enables physical GC and runs a collection. See [Garbage collection](../operate/garbage-collection.md).
- **Transport.** Bind the service to loopback or a trusted network, or put it behind TLS. A session cookie set over plain HTTP is not `Secure`, so anyone who can observe the connection can replay it.
