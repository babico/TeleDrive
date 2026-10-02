# TeleDrive Docker Web UI

This branch adds a browser-based Web UI, Docker deployment, multi-account upload strategies, and a SQLAlchemy-backed state store.

## Start

```bash
cp .env.example .env
mkdir -p config data uploads
cp config.docker.example.yaml config/config.yaml
docker compose up -d --build
```

By default the Web UI binds only to loopback:

```text
http://127.0.0.1:8080
```

Before starting, set a strong password in `.env` (minimum 16 characters). A convenient generator is:

```bash
openssl rand -base64 32
```

Set `PUID=$(id -u)` and `PGID=$(id -g)` when your host user is not UID/GID 1000.

## Multi-account strategies

- `single`: first enabled account only.
- `round_robin`: rotates the preferred account per file and can fall back to the remaining accounts.
- `failover`: always tries accounts in configured order.
- `parallel`: creates concurrent workers, one preferred worker per account, with failover to other accounts.

FloodWait cooldown is tracked per Telegram account, so one throttled account does not pause the other accounts.

## Database

`state.database_url` accepts a synchronous SQLAlchemy database URL.

There is **no TeleDrive database vendor whitelist**. SQLite is the zero-config default; any SQLAlchemy dialect/DBAPI can be used when its Python driver/dialect and required system libraries are installed.

Examples:

```yaml
state:
  database_url: "sqlite:////data/state.db"
```

```yaml
state:
  database_url: "postgresql+psycopg://user:pass@db/teledrive"
```

```yaml
state:
  database_url: "mysql+pymysql://user:pass@db/teledrive"
```

```yaml
state:
  database_url: "oracle+oracledb://user:pass@db:1521/?service_name=FREEPDB1"
```

```yaml
state:
  database_url: "mssql+pyodbc://user:pass@db/teledrive?driver=ODBC+Driver+18+for+SQL+Server"
```

Third-party SQLAlchemy dialects can be installed during the image build:

```env
TELEDRIVE_DB_EXTRA_PACKAGES=oracledb
```

or:

```env
TELEDRIVE_DB_EXTRA_PACKAGES="cockroachdb psycopg[binary]"
```

Then rebuild:

```bash
docker compose build --no-cache
docker compose up -d
```

The configured dialect must be synchronous. If the dialect needs OS-level client libraries (for example some ODBC/Oracle configurations), extend the Dockerfile or use a derived image to install them.

## Persistent paths

- `./config:/config` — configuration
- `./data:/data` — Telegram sessions, auth handoff and default SQLite state
- `./uploads:/uploads` — source files

## Browser authentication

Set a password in `.env`:

```env
TELEDRIVE_WEB_USER=admin
TELEDRIVE_WEB_PASSWORD=change-this-password
```

Telegram login codes and 2FA prompts are submitted through the Web UI and written to account-specific auth handoff files inside `/data/auth`.


## Security defaults

The Docker deployment is intentionally fail-closed:

- Web authentication is required by default. An empty `TELEDRIVE_WEB_PASSWORD` prevents startup.
- `TELEDRIVE_ALLOW_INSECURE=1` is an explicit opt-out intended only for trusted local testing.
- The Web UI binds to `127.0.0.1` by default.
- `TELEDRIVE_ALLOWED_HOSTS` protects against Host-header and DNS-rebinding attacks. Add only the exact hostnames/IPs you use.
- For remote access, put TeleDrive behind an HTTPS reverse proxy/VPN. Do not expose Basic Auth directly over plain HTTP.
- The container runs non-root, drops all Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem, and mounts `/uploads` read-only.
- Telegram sessions, auth handoff files and `config.yaml` are created with restrictive permissions.
- API hashes and database passwords are redacted when configuration is returned to the browser.
- Queue rows use both a distributed lease and atomic per-file claims to avoid duplicate uploads across multiple app instances.
- Symlinks are not scanned, and Docker restricts source/session roots to `/uploads` and `/data/sessions`.
- FastAPI interactive docs/OpenAPI are disabled in the Web build.
- Security CI runs compile checks, regression tests, Bandit, pip-audit and a Docker build.
- Dependabot monitors Python, Docker and GitHub Actions dependencies.

If you expose TeleDrive through a reverse proxy, for example `teledrive.example.com`, set:

```env
TELEDRIVE_BIND_ADDRESS=127.0.0.1
TELEDRIVE_ALLOWED_HOSTS=teledrive.example.com
```

Terminate TLS at the reverse proxy. Restrict proxy/network access further if possible.

### Database drivers

`TELEDRIVE_DB_EXTRA_PACKAGES` is a **build-time trusted-admin input**, not a Web UI feature. Installing a SQLAlchemy dialect executes package installation code during image build. Prefer reputable packages and pin explicit versions where practical, for example:

```env
TELEDRIVE_DB_EXTRA_PACKAGES=oracledb==<reviewed-version>
```

The database account used by TeleDrive should have only the schema permissions needed for its own TeleDrive tables, not broad administrative rights.

### Secret files

Keep `.env`, `config/`, `data/` and `uploads/` out of source control. They are ignored by this branch. On a multi-user Linux host, also restrict the project directory itself.
