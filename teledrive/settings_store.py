"""Durable service-settings document, stored in SQL.

`config/config.yaml` remains the bootstrap and disaster-recovery source:
on the first start (or whenever the SQL document is missing or cannot be
decrypted) the file seeds the database. After that the SQL document is
authoritative, so every process reading the same database agrees on the
settings and a UI save survives a container rebuild that starts from a
stale mounted file.

The document contains secrets (the WebUI password, Telegram api_hash
values), so it is encrypted at rest with the same S3 master key that
protects credential secrets. A master-key change makes the row
undecryptable; callers fall back to the file rather than failing startup.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import BigInteger, Column, MetaData, String, Table, Text
from sqlalchemy import delete, insert, select, update

from teledrive.db import Database

_metadata = MetaData()
settings_document = Table(
    "service_settings", _metadata,
    # One well-known row: the whole config document as one encrypted blob.
    Column("id", String(32), primary_key=True),
    Column("payload", Text, nullable=False),
    Column("updated_at", BigInteger, nullable=False),
    Column("updated_by", String(120), nullable=False),
)
DOCUMENT_ID = "config"
MAX_DOCUMENT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class StoredSettings:
    document: dict
    updated_at: int
    updated_by: str


class SettingsStoreError(RuntimeError):
    """The SQL settings document exists but cannot be used."""


class SettingsStore:
    def __init__(self, db: Database, master_key: bytes | None):
        self.db = db
        self.master_key = master_key
        _metadata.create_all(db.engine, tables=[settings_document])

    def _cipher(self) -> Fernet:
        if not self.master_key:
            raise SettingsStoreError("no master key available")
        return Fernet(self.master_key)

    def load(self) -> StoredSettings | None:
        """The stored document, or None when it was never written."""
        row = self.db.connection.execute(select(
            settings_document.c.payload,
            settings_document.c.updated_at,
            settings_document.c.updated_by,
        ).where(settings_document.c.id == DOCUMENT_ID)).first()
        if row is None:
            return None
        try:
            raw = self._cipher().decrypt(row[0].encode()).decode()
            document = json.loads(raw)
        except (InvalidToken, ValueError, UnicodeError) as exc:
            # Rotation or corruption: the caller must fall back to the
            # bootstrap file instead of serving a broken configuration.
            raise SettingsStoreError(
                "stored settings cannot be decrypted (master key changed?)"
            ) from exc
        if not isinstance(document, dict):
            raise SettingsStoreError("stored settings are not a document")
        return StoredSettings(document, int(row[1]), row[2])

    def save(self, document: dict, *, by: str,
             now: int | None = None) -> None:
        if not isinstance(document, dict):
            raise ValueError("settings document must be a mapping")
        encoded = json.dumps(document, sort_keys=True, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ValueError("settings document exceeds 1 MiB")
        payload = self._cipher().encrypt(encoded.encode()).decode()
        now = int(time.time()) if now is None else now
        existing = self.db.connection.execute(select(
            settings_document.c.id).where(
            settings_document.c.id == DOCUMENT_ID)).first()
        if existing is None:
            self.db.connection.execute(insert(settings_document).values(
                id=DOCUMENT_ID, payload=payload, updated_at=now,
                updated_by=by[:120]))
        else:
            self.db.connection.execute(update(settings_document).where(
                settings_document.c.id == DOCUMENT_ID).values(
                payload=payload, updated_at=now, updated_by=by[:120]))
        self.db.commit()

    def clear(self) -> None:
        self.db.connection.execute(delete(settings_document).where(
            settings_document.c.id == DOCUMENT_ID))
        self.db.commit()
