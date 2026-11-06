# Install

TeleDrive ships as one Docker container that runs one Python process: the web
UI, the REST API and the S3 gateway share a single SQL catalog and a single
Telegram storage engine. This page takes a clean host to a running, healthy
instance. It does not configure Telegram credentials or explain every setting;
those are in [Configure](configure.md) and [First upload](first-upload.md).

## Prerequisites

| Requirement | Why |
| --- | --- |
| Docker Engine with Compose v2 (`docker compose`, not `docker-compose`) | The shipped `docker-compose.yml` is the supported deployment. |
| `git` | You clone the repository; there is no published container image. |
| A Telegram account that can post to a **private broadcast channel** | Payload chunks are sent by that user over MTProto. |
| Telegram API credentials (`api_id`, `api_hash`) from [my.telegram.org/apps](https://my.telegram.org/apps) | Required when you connect the account, not to boot the service. |
| Free disk for `./data` and `./uploads` | SQLite catalog, scratch space and the local import source. |

The compose service drops all Linux capabilities and runs as `${PUID}:${PGID}`
with a read-only root filesystem. The user that owns `./config` and `./data`
must match those IDs, or the container cannot create its config, database or
logs.

## Clone and start

```bash
git clone https://github.com/babico/TeleDrive.git
cd TeleDrive
mkdir -p config data uploads
cp .env.example .env

# Fernet key used by the S3 credentials, the encrypted settings document and
# envelope encryption. Keep it out of Git and back it up separately.
openssl rand -base64 32 > config/s3-master.key
chmod 600 config/s3-master.key

# Point PUID/PGID at the owner of ./config and ./data if you are not uid 1000.
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 teledrive
```

`docker compose ps` reports the container as `(healthy)` once the start period
has passed. A first start on a clean checkout produces roughly this shape:

```text
$ docker compose up -d --build
[+] Building ...
[+] Running 1/1
 ✔ Container teledrive  Started
$ docker compose ps
NAME        IMAGE             SERVICE     STATUS                   PORTS
teledrive   teledrive:local   teledrive   Up 30 seconds (healthy)  127.0.0.1:8080->8080/tcp, 127.0.0.1:9000->9000/tcp
```

Healthy only means both listeners answer; it does not mean a Telegram session
is connected or that uploads work.

## What "one container" means

- The Compose file defines exactly one service, `teledrive`. There is no
  separate S3 container and no `--profile s3`.
- The process is `python -m web.unified`. It opens **two TCP listeners in the
  same process** and routes each request by the socket's local port: the web
  UI/REST listener and the S3 gateway listener.
- The job scheduler, lifecycle pass, tiering pass, notification sender,
  storage-report runner, folder watcher and Telegram health loop run inside
  that process. There is no worker sidecar.
- Both listeners use the same SQL database and the same Telegram channel. An
  object uploaded through the UI is immediately readable over S3, and the
  reverse.

## Directory layout

| Host path | Container path | Contents |
| --- | --- | --- |
| `./config` | `/config` | `config.yaml`, `s3-master.key`, optional `ssl/`, optional `*.session` files used by `storage.apis`. |
| `./data` | `/data` | `state.db` (SQLite plus `-wal`/`-shm`), `sessions/` (a plaintext mirror of UI-created session strings), `tmp/` (scratch, split and schema-lock files), `site-packages/` (extra DB drivers), and log files. |
| `./uploads` | `/uploads` | Mounted **read-only**. Source root for local-file upload jobs. |

`./config` and `./data` are writable and hold secrets. Do not put them on a
world-readable share, and do not commit them.

The container image also creates `/data/auth`, the configured `web.auth_dir`.
Human login sessions live in SQL; that directory is reserved, not a second
credential store.

## Environment variables

`.env` is deployment plumbing only. Business settings are seeded from
`config/config.yaml` and afterwards stored in SQL; see
[Configure](configure.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `PUID` / `PGID` | `1000` / `1000` | UID/GID the container runs as. Must own `./config` and `./data`. |
| `TZ` | `Europe/Istanbul` | Container timezone for log timestamps. |
| `TELEDRIVE_WEB_PORT` | `8080` | Web UI/REST port. The same value is used inside and on the host. |
| `TELEDRIVE_S3_PORT` | `9000` | S3 gateway port, inside and on the host. |
| `TELEDRIVE_BIND_ADDRESS` | `127.0.0.1` | Host-side bind address for both published ports. |
| `TELEDRIVE_SSL_CERTFILE` / `TELEDRIVE_SSL_KEYFILE` | empty | TLS for the web listener; a combined PEM needs only the certificate variable. |
| `TELEDRIVE_S3_SSL_CERTFILE` / `TELEDRIVE_S3_SSL_KEYFILE` | empty | Independent TLS pair for the S3 listener. |
| `TELEDRIVE_TRUSTED_PROXY` | empty | Set to `1` only when a reverse proxy terminates TLS in front of the app. |
| `TELEDRIVE_DB_EXTRA_PACKAGES` | empty | Extra Python DB drivers installed at image build time (Compose build arg) and re-applied at service startup. |

`TELEDRIVE_CONFIG=/config/config.yaml` is set by the Compose file and normally
needs no change. `TELEDRIVE_S3_MASTER_KEY` is also understood by the code, but
the shipped Compose file does not forward it; in Docker, use the key **file**
at `config/s3-master.key`. To use the environment variable instead, add it to
the Compose `environment:` block explicitly.

The full list is in
[.env.example](https://github.com/babico/TeleDrive/blob/main/.env.example).

## Ports

| Port | Listener | What it serves |
| --- | --- | --- |
| `8080` | Web UI + REST API | Browser dashboard, `/api/v1/*`, `/api/health`, `/docs`. |
| `9000` | S3 gateway | SigV4 S3 API and `/__health`. |

Both are published to loopback by default. Setting
`TELEDRIVE_BIND_ADDRESS=0.0.0.0` exposes them on every interface; do that only
on a trusted network or behind a TLS reverse proxy. The application also
checks the HTTP `Host` header against `web.allowed_hosts` (default
`localhost,127.0.0.1,[::1]`), so a new DNS name or LAN IP must be added there.

!!! warning "TLS before exposure"
    Plain HTTP sends the login password and the S3 signing headers in clear
    text. Either terminate TLS at a reverse proxy
    ([Reverse proxy](../operate/reverse-proxy.md)) or enable the per-listener
    TLS variables before binding to a non-loopback address.

## First boot

On the first start the service:

1. creates `config/config.yaml` with safe defaults and mode `0600` if the file
   is missing (the commented template at
   [config.example.yaml](https://github.com/babico/TeleDrive/blob/main/config.example.yaml)
   is a better starting point if you want documentation in the file);
2. creates the SQL schema, currently **version 31**;
3. creates one hardcoded administrator account, `admin` / `admin`, but only
   when no `admin` row already exists. It never overwrites an existing
   `admin` row.
4. seeds the encrypted `service_settings` SQL document from the config file
   (this needs the master key to be readable; without it the file stays
   authoritative and S3 credentials cannot be issued).

Until a Telegram USER session and a channel are configured, the UI and health
endpoints work but uploads fail closed with `503`. Change the administrator
password immediately; see [First upload](first-upload.md).

## TLS

Certificates live under the `./config` mount, for example
`/config/ssl/server.crt`, so no extra volume is needed. Each listener has an
independent pair, and either, both or neither may serve TLS.

```bash
./deploy/tls/generate.sh --combined
```

The script writes `config/ssl/server.pem` and prints the matching environment
lines. Put them in `.env` and recreate the container:

```env
TELEDRIVE_SSL_CERTFILE=/config/ssl/server.pem
TELEDRIVE_S3_SSL_CERTFILE=/config/ssl/server.pem
```

The unauthenticated `/server.crt` and `/server.cer` endpoints on the web
listener publish the certificate for client trust bootstrap. The healthcheck
reads the same variables and verifies the chain against the configured file,
so a TLS change cannot leave the probe on a stale scheme or port.

## Health check

```bash
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health   # {"ok":true}
curl -fsS http://127.0.0.1:9000/__health     # {"ok":true}
```

The Compose healthcheck is `python -m web.container_healthcheck`; it probes
both listeners and fails if either answers `5xx`. Neither probe contacts
Telegram or validates credentials. For liveness beyond the process, see
[Monitoring](../operate/monitoring.md).

## Running from a checkout (no Docker)

The repository has no console script, but the same process starts from a
checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
TELEDRIVE_CONFIG="$PWD/config/config.yaml" python -m web.unified
```

This is a development path, not the hardened deployment. The default settings
assume container paths (`/config`, `/data`, `/uploads`), so you must rewrite
`state.database_url`, `web.auth_dir`, `storage.scratch_dir`,
`jobs.source_root`, the `paths.*` roots and `logging.log_path` for a host
install, and create those directories yourself. Ports still come from the
environment. The container is the only path the project's Docker workflows
exercise.

## Upgrading

Do not rebuild over an installation without a backup. The upgrade sequence,
the current schema version and the breaking changes are in
[Upgrade](../operate/upgrade.md).
