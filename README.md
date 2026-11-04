# TeleDrive

[![Docs](https://img.shields.io/badge/docs-babico.github.io%2FTeleDrive-009688)](https://babico.github.io/TeleDrive/)
[![CI](https://github.com/babico/TeleDrive/actions/workflows/quality-security.yml/badge.svg)](https://github.com/babico/TeleDrive/actions/workflows/quality-security.yml)
[![License: WTFPL](https://img.shields.io/badge/license-WTFPL-blue)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB)](https://www.python.org/)

**Telegram-backed object storage with a web UI, a REST API and a real
S3-compatible gateway.**

TeleDrive keeps object payloads in a private Telegram channel and the object
graph in SQL, then exposes that store three ways — a browser dashboard, an
HTTP API, and an S3 endpoint that real `aws`, `boto3` and `rclone` clients
talk to. One container, one Python process, one catalog: an object uploaded
through the UI is immediately readable over S3, and the reverse.

```text
  browser / aws-cli / boto3 / rclone
                  │
        ┌─────────┴─────────┐
        │   TeleDrive        │   one container, one process
        │  WebUI · REST · S3 │
        └────┬──────────┬────┘
             │          │
      SQL catalog   Telethon USER MTProto
   (Postgres/MySQL/   (one private channel,
    SQLite)           chunked messages)
```

## What you get

- **S3 that is implemented, not proxied.** 114 of 116 AWS S3 operations,
  with SigV4 signing, real XML, real error codes, multipart, versioning,
  object lock, policies, replication, notifications, inventory/analytics
  reports and presigned URLs. The two stragglers have no possible backend
  and refuse by name. [Full matrix →](docs/reference/s3-specs.md)
- **A dashboard that does the hard parts.** Upload and download, browse
  buckets, rotate API keys, manage S3 credentials, import a local folder,
  connect Telegram accounts interactively, and read the audit trail.
- **One storage engine for every surface.** REST, S3 and durable local-file
  jobs share the same immutable chunk manifest, so no path can invent a
  parallel catalog.
- **Real database targets.** PostgreSQL, MySQL and SQLite, with a serialised
  migration path and the same SQL running on all three.
- **Optional encryption.** SSE-C per request, or opt-in SSE-S3 envelope
  encryption where the server holds the keys.
- **Operations in the box.** Integrity-verified reads, ranged and
  conditional GETs, quotas, lifecycle rules, tiering, metrics, a durable
  admin audit trail, backup/restore rehearsals, and a GC collector that is
  deliberately gated behind owner approval.

## Quick start

```bash
git clone https://github.com/babico/TeleDrive.git
cd TeleDrive
mkdir -p config data uploads
cp .env.example .env
docker compose up -d --build
```

Open `http://127.0.0.1:8080`, log in with the first-boot account
`admin` / `admin`, and **change the password immediately**. Then connect a
Telegram account from the Storage page and make your first upload.

The service runs as **one container**; the S3 gateway is a second listener in
the same process, not a separate service. There is no `--profile s3`.

> **Security:** ordinary Telegram cloud chats are not end-to-end encrypted.
> Encrypt content before upload if Telegram itself must not be able to read
> it, or enable envelope encryption.
>
> **Release boundary:** [v1.0.10](https://github.com/babico/TeleDrive/releases/tag/v1.0.10)
> is the last tagged release; `main` may be ahead of those binaries.

## Documentation

The full manual lives at **<https://babico.github.io/TeleDrive/>** and in
[`docs/`](docs/index.md).

| Start with | |
| --- | --- |
| [Install](docs/start/install.md) | Compose, volumes, ports, TLS |
| [Configure](docs/start/configure.md) | Environment, config file, SQL settings |
| [First upload](docs/start/first-upload.md) | Log in, connect Telegram, put an object |
| [S3 API](docs/guide/s3-api.md) | Clients, credentials, examples |
| [REST API](docs/guide/rest-api.md) | Endpoints, auth, pagination |
| [Backup and restore](docs/operate/backup-restore.md) | What to back up and how to prove it |
| [Garbage collection](docs/operate/garbage-collection.md) | Why physical deletion is gated |
| [Troubleshooting](docs/operate/troubleshooting.md) | Symptoms and causes |
| [Project status](docs/project/status.md) | What is validated, what is not |
| [Roadmap](docs/project/roadmap.md) | Open work and owner gates |
| [Changelog](CHANGELOG.md) | What changed and why |

## Development

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q -n 4
python -m compileall -q teledrive web
```

The test suite covers the S3 wire protocol against real boto3, the REST
surface against real HTTP, and the storage engine against real PostgreSQL and
MySQL in CI. See [CI and tests](docs/reference/ci.md) for the workflow
matrix and the fault-injection acceptance gates.

## License

Do what the fuck you want to. See [LICENSE](LICENSE) (WTFPL v2).

Originally created by [Amjad P A](https://github.com/amjadlle/TeleDrive);
maintained here as the [babico/TeleDrive fork](https://github.com/babico/TeleDrive)
with Docker, multi-account, REST/S3 and recovery work.
