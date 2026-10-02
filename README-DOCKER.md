# TeleDrive Docker Web UI

This branch adds a browser-based Web UI, Docker deployment, multi-account upload strategies, and a SQLAlchemy-backed state store.

## Start

```bash
cp .env.example .env
mkdir -p config data uploads
cp config.docker.example.yaml config/config.yaml
docker compose up -d --build
```

Open `http://HOST:8080`.

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
