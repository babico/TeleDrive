#!/usr/bin/env python3
"""Local recovery: set a dashboard user's password (or create the user).

This is the supported recovery path when no admin password or API key is
known. It requires the same filesystem/database access
the service itself needs (the database URL is read from the deployment
config), so it is not a remote authentication path: there is deliberately no
network listener, token or environment-variable bypass.

Run it on the host or inside the container:

    python scripts/ops/reset_local_password.py --config config/config.yaml \
        --username admin --role admin

The password is read from a TTY prompt; it is never taken from argv (argv is
visible in the process list) or from the environment.
"""
from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path


def _load_database_url(config_path: Path) -> str:
    """The database named by the bootstrap file (settings may live in SQL)."""
    import yaml

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    state = raw.get("state") or {}
    url = state.get("database_url") or state.get("db_path")
    if not url:
        raise SystemExit("config has no state.database_url; pass --database")
    return str(url)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        default=Path("config/config.yaml"),
                        help="Deployment config file (bootstrap anchor).")
    parser.add_argument("--database",
                        help="Override the database URL from the config.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", choices=("admin", "operator", "viewer"),
                        default="admin")
    parser.add_argument("--min-length", type=int, default=8)
    args = parser.parse_args()

    # Imported here so --help works without the service dependencies.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import sqlalchemy

    from teledrive.db import connect_database
    from web.app import _hash_password

    if not args.config.is_file() and not args.database:
        parser.exit(2, f"config file not found: {args.config}\n")
    url = args.database or _load_database_url(args.config)

    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Repeat password: ")
    if password != confirmation:
        parser.exit(2, "passwords do not match\n")
    if len(password) < args.min_length:
        parser.exit(2, f"password must be at least {args.min_length} characters\n")

    db = connect_database(url, config_dir=args.config.parent)
    try:
        text = sqlalchemy.text
        row = db.connection.execute(text(
            "SELECT id FROM users WHERE username = :u"
        ), {"u": args.username}).fetchone()
        now = int(time.time())
        password_hash = _hash_password(password)
        if row is None:
            db.connection.execute(text(
                "INSERT INTO users (username, password_hash, role, enabled, "
                "created_at, updated_at) "
                "VALUES (:u, :ph, :r, 1, :now, :now)"
            ), {"u": args.username, "ph": password_hash, "r": args.role,
                "now": now})
            action = "created"
        else:
            db.connection.execute(text(
                "UPDATE users SET password_hash = :ph, role = :r, enabled = 1, "
                "updated_at = :now WHERE id = :id"
            ), {"ph": password_hash, "r": args.role, "now": now,
                "id": row[0]})
            # A reset must invalidate existing sessions like the UI does.
            db.connection.execute(text(
                "DELETE FROM user_sessions WHERE user_id = :id"
            ), {"id": row[0]})
            action = "updated"
        db.connection.commit()
    finally:
        db.close()
    print(f"{action} local user '{args.username}' with role "
          f"'{args.role}'; all its sessions were revoked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
