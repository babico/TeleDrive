# TeleDrive

**Telegram-backed personal file storage and automation** with a single-container Web UI/REST/S3 service and an S3-compatible gateway.

TeleDrive stores object payloads in Telegram and keeps object metadata, upload state, and references in a local or external SQL database. This fork supports multiple Telegram accounts through the `storage.apis` rotation list and a unified USER MTProto-backed object catalog for REST, S3, and durable local-file jobs.

> **Security:** ordinary Telegram cloud chats and Saved Messages are **not end-to-end encrypted**. Encrypt sensitive content before uploading if it must be confidential from Telegram.
>
> **Release boundary:** [v1.0.7](https://github.com/babico/TeleDrive/releases/tag/v1.0.7) is the published milestone. Newer `main` features may not be included in those binaries. Refer to [Project Status](docs/IMPLEMENTATION_STATUS.md) before treating unreleased features as production-ready.

## Documentation

| Guide | Use it for |
| --- | --- |
| **[README](README.md)** | Installation, configuration, primary workflows and supported interfaces |
| [CI and Test Guide](docs/CI_WORKFLOWS.md) | GitHub Actions, local tests, Docker fault injection and development acceptance |
| [Project Status and Acceptance](docs/IMPLEMENTATION_STATUS.md) | P0/P1/P2 capabilities, release boundaries, original-data production acceptance and recovery risks |
| [Backup and Restore](docs/BACKUP_RESTORE.md) | Database backup commands, isolation and restore checks |
| [Security Policy](docs/SECURITY.md) | Responsible disclosure, trusted components, credentials and network isolation |
| [Contributing](CONTRIBUTING.md) | Development workflow and documentation rules |
| [S3 Compatibility Matrix](docs/S3_SPECS.md) | 116-operation status matrix, supported limits and P2 advanced implementation roadmap |
| [Local Agent Acceptance Mission](docs/LOCAL_AGENT_ACCEPTANCE.md) | Docker test installation, real bytes, independent recovery and GC safety acceptance, with owner-only gates |
| [TODO and Roadmap](TODO.md) | The single prioritized plan: completed milestones, roadmap phases, S3 parity track and owner gates |

**Contents:** [Quick start](#1-quick-start-docker) · [Architecture](#2-storage-architecture) · [REST API](#3-rest-api) · [S3 gateway](#4-s3-compatible-api) · [Local jobs](#5-local-file-upload-jobs) · [CLI](#6-command-line-usage) · [Databases](#7-database-configuration) · [Security](#8-security-and-operational-limits) · [Development](#9-development-and-testing).

## 1. Quick start: Docker

Prerequisites: Docker Engine and Docker Compose v2. For modern REST/S3/local-job storage, use an authorized Telethon USER session with posting rights in a dedicated private broadcast channel. There is no Bot API transport; the unified engine is Telethon USER MTProto only and never uses Saved Messages.

~~~bash
git clone https://github.com/babico/TeleDrive.git
cd TeleDrive
mkdir -p config data uploads
cp .env.example .env
cp config.example.yaml config/config.yaml   # optional tidy template
chmod 600 .env config/config.yaml
~~~

Authentication is **token-based**: on first start the service creates a default administrator with username `admin` and password `admin`. Log in once at [`http://127.0.0.1:8080/login`](http://127.0.0.1:8080/login) and **change that password immediately** in **Users** (or via `PUT /api/v1/admin/users/{user_id}/password`) — the default is public knowledge and must not survive first contact with any shared network. The YAML file keeps **all** service settings; `.env` only holds `PUID`/`PGID`/`TZ` and the host-side port/bind mapping (`TELEDRIVE_WEB_PORT`, `TELEDRIVE_S3_PORT`, `TELEDRIVE_BIND_ADDRESS`). Adjust `PUID` and `PGID` to match the owner of the mounted directories. The service creates `config/config.yaml` with safe defaults on first start (or copy the tidy [`config.example.yaml`](config.example.yaml) template); add your authorized USER MTProto credentials there under the **`storage:`** section as an `apis:` list (see [Telethon USER Storage](docs/TELETHON_STORAGE.md)) — one or more `api_id`/`api_hash`/`session_file` sets sharing the same dedicated channel, with `round_robin` (default) or `failover` rotation. Create the private session before or after starting Docker: either run the interactive helper in [Section 4](#4-s3-compatible-api) on a trusted host, or use the **Storage** page in the WebUI, which walks through the Telegram code request/verification interactively. Without an authorized session, initial health/admin endpoints may run, but binary uploads fail closed.

~~~bash
docker compose up -d --build
docker compose ps
docker compose logs -f teledrive
~~~

| Endpoint | Host-local address | Purpose |
| --- | --- | --- |
| Web UI, admin REST API, Swagger | [`http://127.0.0.1:8080`](http://127.0.0.1:8080) | Account management, jobs, REST and API keys |
| SigV4 S3 gateway | `http://127.0.0.1:9000` | Path-style S3 endpoint for SDKs and CLI clients |

**One service, one container, one Python process.** Both listeners use the **same SQL catalog and Telegram object engine**. You do not need `docker compose --profile s3` and there is no second S3 container.

The service binds `0.0.0.0` inside the container; the Compose host mapping stays loopback by default. To publish the ports on a trusted private network, set `TELEDRIVE_BIND_ADDRESS=0.0.0.0` in `.env` (and optionally `TELEDRIVE_WEB_PORT`/`TELEDRIVE_S3_PORT` for custom host ports); this is only acceptable on networks you trust, since the listeners are then reachable from every host on that network. For access over untrusted networks, use an SSH tunnel, private VPN, or an HTTPS reverse proxy (see `scripts/ops/generate_ssl.py` for TLS); never expose login credentials, session tokens or S3 secrets over untrusted plaintext HTTP.

| Host folder | Container path | Purpose |
| --- | --- | --- |
| `./config` | `/config` | Settings and S3 master key |
| `./data` | `/data` | Sessions, metadata and internal temporary state |
| `./uploads` | `/uploads:ro` | Read-only source files for explicitly queued jobs |

To use a different source directory, change the host side of the `/uploads` mount, retaining the container-side path and read-only mode. The image has no GUI/X11/PySide6 dependency.

**Configure S3 before writing:** the gateway listener starts automatically, but writing S3 objects requires configured authenticated USER MTProto credentials, a persistent encryption key and scoped S3 credentials. See [Section 4](#4-s3-compatible-api).

### Web UI

The Web UI is multi-page. After logging in at `/login` you can switch between:

| Page | Purpose |
| --- | --- |
| `/dashboard` | Overview of storage, jobs and service health |
| `/queue` | Durable local-file upload job queue with retry controls |
| `/history` | Completed job and transfer history |
| `/storage` | Buckets, channels, active channel settings and Telegram session state |
| `/s3` | S3 bucket browser with per-bucket quotas, plus S3 gateway credentials |
| `/api-management` | REST and S3 credential issuance, rotation and revocation |
| `/logs` | Service logs with a live tail mode |
| `/users` | User management: create users, change roles and passwords |
| `/settings` | Service configuration editor |

## 2. Storage architecture

### Shared object catalog

| Entry point | How it writes | Can REST/S3 read it? |
| --- | --- | --- |
| REST `PUT /api/v1/buckets/{bucket}/content` | USER MTProto → `TelegramObjectStorage` → `BucketCatalog` | **Yes** |
| Signed S3 `PutObject` / multipart upload | Same Telegram chunk engine and SQL catalog | **Yes** |
| Authenticated local-file upload job | Explicit queued file → same shared object catalog | **Yes**, after the job finishes |
| Original Telethon folder scan/batch | User-session uploader and its legacy workflow | **Not automatically**; use the shared-job path for REST/S3 visibility |

The SQL catalog stores object heads, generations, checksums, version references, job state and encrypted S3 credential metadata. Object payloads remain in Telegram; the temporary upload scratch directory is **not** a second primary storage backend. Completed transfers have SHA-256 checks and byte-range reads. Failed/unknown Telegram acknowledgments remain protected from unsafe physical deletion.

### Telegram USER account and transport

Credential sets are configured as an `apis:` list under `storage:` in `config/config.yaml`; each set has its own session file and optional account label, and every set must resolve the same dedicated channel. The `storage.strategy` setting controls how sends rotate across the sets:

| Strategy | Behavior |
| --- | --- |
| `single` | Use the first enabled account |
| `round_robin` | Rotate preferred sending accounts between files (default) |
| `failover` | Try configured accounts in priority order |
| `parallel` | Independent account-affine workers with fallback |

**Unified storage never uses Saved Messages or Bot API**: select a private broadcast channel that the authorized user can post to. Historical `me` (Saved Messages) settings from the retired standalone uploader are not enabled in REST/S3. Respect Telegram rate limits, and never reuse a writable session among independent uploader processes.

The **REST/S3/local-job engine requires USER MTProto**: it fails closed without an authorized user session. No Bot credentials exist in the runtime. The same SQL catalog and bounded chunk engine are retained. Existing `api-bot` objects are readable using the authorized USER session only when the original **same channel** is accessible and the immutable SQL manifest retains real message IDs; full checksums are still verified. Old objects in inaccessible channels require a separately verified migration and backup. No existing media is automatically deleted.

## 3. REST API

The Web listener publishes an authenticated interface at:

| Endpoint | Purpose |
| --- | --- |
| `http://127.0.0.1:8080/docs` | Swagger UI |
| `http://127.0.0.1:8080/redoc` | ReDoc |
| `http://127.0.0.1:8080/openapi.json` | Machine-readable OpenAPI schema |

### Authentication

Authentication is token-based. Log in at [`http://127.0.0.1:8080/login`](http://127.0.0.1:8080/login) (or `POST /api/v1/auth/login`) with a username and password; the response returns a Bearer session token and sets an httpOnly `teledrive_session` cookie valid for seven days. The canonical API namespace is `/api/v1/auth/*`, `/api/v1/config`, `/api/v1/logs` and `/api/v1/admin/*`; the older `/api/auth/*`, `/api/config` and `/api/logs` paths remain working but undocumented aliases. **The browser UI uses only the httpOnly cookie** — no session token is kept in browser storage.

~~~bash
# Log in (default admin/admin on first start — change it immediately):
curl -fsS -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'
# => {"token":"td_sess_...","user":{...},"expires_at":...}

curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/openapi.json
~~~

Roles are enforced server-side on `/api/v1/admin/*` endpoints: **admin** has full access, **operator** may run storage/job operations and read logs, and **viewer** is read-only. Use an authenticated session for administrative API key issuance/rotation/revocation and include `X-TeleDrive-CSRF: 1` on administrative mutations. REST object calls use separately issued, scoped Bearer API keys; those are **not** S3 Access Key IDs. Session tokens are persisted only as SHA-256 digests, passwords are stored as salted PBKDF2 hashes, and repeated login failures are throttled.

HTTP Basic authentication (`web.user`/`web.password` in `config/config.yaml`) is retained **only** as a backward-compatibility fallback for scripts and API clients; it always authenticates as the admin user and is not the primary authentication path.

Key operations include bucket management, object listing, logical unlink, full object upload/download, metadata-only HEAD and checksum-verified Range GET. Administrative keys are shown once; only digests are persisted.

~~~bash
# First create the bucket and issue a scoped REST key in API Management.
curl -f -X PUT \
  'http://127.0.0.1:8080/api/v1/buckets/backups/content?key=folder%2Ffile.bin' \
  -H "Authorization: Bearer $TELEDRIVE_API_KEY" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '@file.bin'

curl -f -H "Authorization: Bearer $TELEDRIVE_API_KEY" \
  'http://127.0.0.1:8080/api/v1/buckets/backups/content?key=folder%2Ffile.bin' \
  -o restored.bin
~~~

The default REST upload ceiling is 2 GiB, configurable with `web.rest_max_upload_bytes` in `config/config.yaml`. Uploads require the configured authorized Telethon USER session with access to a dedicated private channel. Physical Telegram message deletion is **not** implied by an HTTP object delete.

## 4. S3-compatible API

For the **116-operation AWS S3 API compatibility matrix**, parameter-level limitations, unsupported-operation groups, and the P2 Advanced S3 work plan, see [S3 Specifications](docs/S3_SPECS.md).

The S3 endpoint is **part of the default container**, not a separate Compose profile. It implements a tested **subset** of S3 over the shared Telegram-backed catalog. It is **not AWS S3 feature parity**.

A connected user-MTProto server also exposes **admin-only, read-only** `GET /api/v1/admin/storage/channel-history?limit=100&include_external_markers=true`. Use `before_message_id=<next_before_message_id>` to enumerate older pages. Other authors' marker captions are reported only as **unverified clues**: do not use them to restore a bucket/key or authorize physical deletion without independent manifests and checksum evidence. Only an authorized USER session can run the unified service or enumerate channel history.

### Provision the S3 master key and credentials

An account holder creates the user StringSession **once** on a trusted interactive host (no credentials are written to Git). The server then reconnects automatically under that real user authorization:

~~~bash
# Set the Telegram API credentials privately in the shell; the program
# prompts for sign-in once and writes an authorized session file.
python scripts/dev/create_storage_user_session.py --output config/mtproto-user.session
chmod 600 config/mtproto-user.session
~~~

Run this interactively on a trusted host with Python dependencies installed, before the first Docker startup. Alternatively, create the session after startup from the WebUI **Storage** page (code request/verification against the configured channel; see [Telethon USER Storage](docs/TELETHON_STORAGE.md)). Ensure the resulting `0600` file is readable by the configured container `PUID`/`PGID`. The API ID/hash are from [my.telegram.org](https://my.telegram.org/apps). The script prompts for the real user's Telegram sign-in code and optional 2FA and refuses to overwrite an existing session. Its MTProto application/device metadata identifies the TeleDrive client accurately; it does **not** masquerade as an official Telegram Desktop/Android app. Choose a channel username or a numeric channel ID present in this user's dialogs. If selecting a numeric private channel, it must be visible among the user's first 5,000 dialogs. No user account => no user-only history access.

1. Save one or more authorized user StringSessions under `./config/` (mode 0600) using the interactive command below, then list them with their API credentials and the shared channel in the `storage:` section of `config/config.yaml` ([Telethon USER Storage](docs/TELETHON_STORAGE.md)). The user needs posting rights in that private **broadcast channel**, not Saved Messages. Existing installations from the pre-switch era must configure a user session before further uploads; **do not delete original media or SQL backups**.
2. Generate a persistent master encryption key once, on the trusted host:

~~~bash
python - <<'PY'
from pathlib import Path
from cryptography.fernet import Fernet
target = Path("config/s3-master.key")
if target.exists():
    raise SystemExit("Refusing to replace the existing S3 master key")
with target.open("xb") as stream:
    stream.write(Fernet.generate_key() + b"\n")
target.chmod(0o600)
PY
~~~

3. Install the `cryptography` package on the host if necessary. Ensure the container's `PUID`/`PGID` can **read** this file. Back up the key separately: losing it makes stored S3 secrets undecryptable.
4. Start the default Compose service and issue a **scoped** S3 access key and secret in **WebUI → API Management → S3-compatible gateway** . The secret appears once and is encrypted in SQL.

### SDK example

~~~python
import boto3
from botocore.config import Config

client = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id="YOUR_ACCESS_KEY_ID",
    aws_secret_access_key="YOUR_SECRET_ACCESS_KEY",
    region_name="us-east-1",
    config=Config(
        signature_version="s3v4",
        s3={"addressing_style": "path", "payload_signing_enabled": True},
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    ),
)
client.create_bucket(Bucket="backup-bucket")
client.put_object(Bucket="backup-bucket", Key="hello.txt", Body=b"Hello Telegram")
assert client.get_object(Bucket="backup-bucket", Key="hello.txt")["Body"].read() == b"Hello Telegram"
~~~

### Implemented features and limits

| Feature group | Available behavior |
| --- | --- |
| Authentication | Scoped encrypted S3 keys, SigV4 request checks, bounded signed/presigned operations |
| Buckets and listing | Create/Head/DeleteBucket; V1/V2 object listing, prefixes, delimiters, marker/continuation and URL encoding |
| Objects | Put/Get/Head/Delete (logical unlink), Range, CopyObject, conditional GET/HEAD and signed conditional writes/deletes |
| Multipart | UploadPart, Complete/Abort and guarded stale-completion recovery through an admin-only API |
| Metadata and versions | Selected published VersionId reads/listing, always-Enabled versioning, fixed private-only Public Access Block and incomplete-MPU lifecycle abort rules, object/bucket tags, metadata, CopySource, CORS and GetObjectAttributes (`ETag`, `ObjectSize`, full-object SHA-256 `Checksum`, `STANDARD`, historical `VersionId`, immutable multipart `ObjectParts` with bounded pagination) |
| Checksums | SHA-256, SHA-1, Content-MD5, CRC32, CRC32C and CRC64NVME validation where explicitly implemented |
| Known gaps | Object lifecycle expiration/transitions, bucket policies, SSE, full AWS delete-marker semantics, every multipart POST variant and unverified clients |

**Safety:** `UNSIGNED-PAYLOAD` writes are accepted only when an appropriately **signed, verifiable** checksum binds the actual received bytes. Public ACLs and unsupported archival tiers must not be inferred from AWS-style parameters. Failed conditional publications may retain protected, unpublished Telegram manifests rather than deleting uncertain remote media.

S3 client integrations tested in CI use **real** AWS CLI and rclone executables against the actual gateway and SQL with **synthetic Telegram transport**; real Telegram byte transfer is tested in separate live E2E workflows. For rclone use `type=s3`, `provider=Other`, `force_path_style=true` and your issued S3 key pair. Create buckets first if `no_check_bucket=true`.

### Bucket quotas

Each bucket can carry an optional quota — a maximum total size in bytes and/or a maximum object count — enforced server-side on uploads through both the REST API and the S3 gateway. Quotas are managed with the admin API (`GET`/`PUT /api/v1/admin/storage/buckets/{bucket}/quota`, body fields `max_size_bytes` and `max_objects`; `null` disables a limit) or edited directly on the **S3** page of the Web UI.

### Non-destructive storage and multipart maintenance

Before considering stale multipart recovery or garbage collection, inspect the admin-only endpoints and **dry-run** responses. The admin API provides `/api/v1/admin/s3-multipart/stale`, `/api/v1/admin/s3-multipart/{upload_id}/recover` (with `"execute": false` for preview), and `/api/v1/admin/storage/gc-candidates`. A stale completion may be explicitly returned to `active` under expiry/fencing conditions; it is not equivalent to deleting Telegram messages.

**Physical Telegram garbage collection remains disabled** until independently verified owner/alias/version/retention/backup/fencing controls and approval exist. The [P2 safety section](docs/IMPLEMENTATION_STATUS.md#41-physical-telegram-garbage-collection-disabled) describes the incomplete safeguards.

### Mount TeleDrive as a drive with rclone

TeleDrive's S3 listener works with [rclone](https://rclone.org) out of the box, turning the container into a mountable drive on any desktop. Create S3 credentials on the WebUI **S3** page (or via `POST /api/v1/admin/s3-credentials`), then:

```ini
# rclone config
[teledrive]
type = s3
provider = Other
access_key_id = <your S3 access key>
secret_access_key = <your S3 secret key>
endpoint = http://<host>:9000
region = us-east-1
```

```bash
rclone lsd teledrive:                      # list buckets
rclone copy big-backup.zip teledrive:backup-bucket
rclone mount teledrive: ~/TeleDrive --vfs-cache-mode writes &   # FUSE mount
```

Keep the endpoint on a trusted network (see `TELEDRIVE_BIND_ADDRESS`); rclone sends the S3 secret only over the connection you configure, so prefer HTTPS or a VPN for remote hosts.

## 5. Local-file upload jobs

The Docker mount `./uploads:/uploads:ro` gives the service read-only access to approved source files. Use the authenticated **durable job API** to publish files into the **same REST/S3 catalog**.

~~~bash
# Ensure the bucket exists. Then enqueue an existing local file:
curl -fsS -H "Authorization: Bearer $TOKEN" \
  -H "X-TeleDrive-CSRF: 1" \
  -H "Content-Type: application/json" \
  -d '{"bucket":"backups","key":"local/example.bin","source_path":"/uploads/example.bin"}' \
  http://127.0.0.1:8080/api/v1/admin/storage/jobs
~~~

With `jobs.auto_run: true` in `config/config.yaml` (the default) the service processes **explicitly queued** jobs automatically. Set it to `false` to disable background processing while retaining queue entries.

**Folder auto-sync** — set `jobs.watch: true` plus a `jobs.watch_bucket` (and optionally `jobs.watch_interval_seconds`, default 30) to make TeleDrive scan the source root periodically and enqueue new/changed files automatically, Dropbox-style. Uploads still flow through the durable job scheduler with quota enforcement; repeated scans are idempotent (same inode/mtime/size is not re-queued).

Jobs are persisted in SQL and protect against source mutation, unexpected generation changes and interrupted uploads. Keep the source file until the job reaches `done`. The admin API also supports job inspection/retry, stale-pending previews, history restore and safe health checks. Failed/uncertain remote sends do not authorize physical cleanup.

## 6. Command-line usage

TeleDrive is a single WebUI + REST + S3 service; there is no separate headless uploader CLI. All operation is through the WebUI, REST API, or S3-compatible API.

Background automation is configured through `jobs.auto_run` in `config/config.yaml`, not the Web UI settings page. Do not launch multiple client processes against the same writable Telethon session file. Ingestion of an existing folder is done through the admin `import-legacy` endpoint, which queues files as durable jobs in the shared SQL catalog using the configured Telethon transport; it never starts a separate direct-send path.

### Telegram account setup

1. Get a Telegram `api_id` and `api_hash` from [my.telegram.org](https://my.telegram.org/apps).
2. Choose a dedicated private broadcast channel (username or numeric ID visible in the user's dialogs) where the user can post.
3. Authenticate with the Telegram code and, if enabled, 2FA password — via the WebUI **Storage** page or `scripts/dev/create_storage_user_session.py`.
4. Test a small upload and confirm readback before enabling scheduled jobs.

A BotFather token is not used by the unified storage runtime. Historical Bot messages can be read through a USER session only when the original channel and exact message IDs remain accessible. Never commit user sessions, API hashes or other secrets.

## 7. Database configuration

Configure `state.database_url` in the YAML configuration or Web UI. SQLite needs no external server; the server image includes drivers for the tested PostgreSQL and MySQL/MariaDB integrations. Other synchronous SQLAlchemy dialects may work with separately reviewed drivers but are **not certified merely by accepting their URLs**. Engines are cached per database URL in a bounded LRU cache so repeated requests reuse pooled connections, and a WAL checkpoint on close keeps SQLite files self-contained.

~~~yaml
state:
  database_url: "sqlite:////data/state.db"
~~~

Representative alternatives:

~~~text
postgresql+psycopg://user:password@db:5432/teledrive
mysql+pymysql://user:password@db:3306/teledrive
~~~

For additional reviewed packages, set `TELEDRIVE_DB_EXTRA_PACKAGES` in `.env` (see [`.env.example`](.env.example); it is passed to the Docker image as a compose build arg) and rebuild the Docker image. Some database drivers require OS libraries in a derived Docker image. Enable DB TLS remotely and use least-privilege credentials. Back up the DB together with Telegram access and the S3 master key; see [Backup and Restore](docs/BACKUP_RESTORE.md).

## 8. Security and operational limits

- Keep WebUI/REST/S3 on the default loopback binding unless you publish them on a trusted private network (`TELEDRIVE_BIND_ADDRESS=0.0.0.0` in `.env`) or protect them with an HTTPS reverse proxy or VPN.
- Treat session files, `.env`, historical Bot tokens, `config.yaml`, the S3 master key and SQL backups as secrets.
- Docker defaults include non-root execution, a read-only filesystem, capability drops and a read-only source mount.
- Never assume a successful database-only restore is proof of original Telegram media recovery.
- Never enable automatic physical Telegram deletion or bypass unresolved ACK/reference fences.
- Use [Security Policy](docs/SECURITY.md) to report vulnerabilities privately and [Project Status](docs/IMPLEMENTATION_STATUS.md) to distinguish development CI from production acceptance.

## 9. Development and testing

Repository layout:

| Directory | Purpose |
| --- | --- |
| `teledrive/` | Telegram uploader, object engine, SQL state, recovery, API/transport adapters |
| `web/` | Unified WebUI/REST/S3 ASGI service and admin interface |
| `scripts/` | Setup, maintenance and CI tooling |
| `tests/` | Offline regression, integration and live test contracts |
| `.github/workflows/` | Categorized GitHub Actions pipelines |
| `.github/ci/` | Workflow-specific supporting Docker assets |

~~~bash
python -m pip install -r requirements.txt pytest httpx boto3
python -m pytest -q
python -m compileall -q teledrive web tests
docker compose config --quiet
# Isolated fault-injection acceptance:
bash scripts/dev/run_docker_fault_injection.sh
~~~

Seven mandatory GitHub Actions workflows validate a given commit. The delivery workflow also includes a guarded housekeeping job that deletes only merged, unchanged, unprotected branches with no open PR, after its release gate passes. Real User MTProto and multiworker tests use private **test-only** Telegram credentials. The test secrets can be configured using `python scripts/dev/setup_telegram_e2e.py --channel "TeleDrive E2E Storage" --create-if-missing` on a trusted local machine. Never upload live credentials to GitHub issues or the repository. See [CI and Test Guide](docs/CI_WORKFLOWS.md) for workflow names, command details, evidence and acceptance boundaries.

## Credits and license

Originally created by [Amjad P A](https://github.com/amjadlle/TeleDrive). Maintained here as the [babico/TeleDrive fork](https://github.com/babico/TeleDrive), with Docker, multi-account, REST/S3 and recovery enhancements. Licensed under [MIT](LICENSE).
