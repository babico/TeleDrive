"""Owner-authorized user MTProto transport for the single REST/S3 catalog.

Only an existing user StringSession is accepted. Channel targets are required:
Saved Messages, bot sessions and private chat destinations are intentionally
not storage targets. The session runs on the web application's ASGI event loop.
An acknowledged send is persisted before the object engine writes its chunk.
Pending sends are never retried automatically after an ambiguous failure.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import logging
import os
import platform
import re
import time
from pathlib import Path
from typing import Any

from sqlalchemy import BigInteger, Column, Integer, MetaData, String, Table, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from .mtproto_rate_guard import MtprotoRateGuard
from .telethon_adapter import TelethonChunkTransport

_meta = MetaData()
_module_logger = logging.getLogger(__name__)
mtproto_send_intents = Table(
    "storage_mtproto_send_intents", _meta,
    Column("account", String(255), primary_key=True),
    Column("chat_id", BigInteger, primary_key=True),
    Column("object_id", String(36), primary_key=True),
    Column("ordinal", Integer, primary_key=True),
    Column("sha256", String(64), nullable=False),
    Column("size", BigInteger, nullable=False),
    Column("message_id", BigInteger),
)


def transport_mode() -> str:
    """Only one live transport exists: Telethon USER MTProto."""
    return "telethon"


def _session_from_file() -> str:
    filename = os.environ.get("TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE", "").strip()
    return _session_from_file_for(filename)


def _session_from_file_for(filename: str) -> str:
    if not filename:
        raise RuntimeError("Set TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE for user storage")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(filename, flags)
    with os.fdopen(fd, "r", encoding="ascii") as handle:
        value = handle.read(8193).strip()
    if not value or len(value) > 8192:
        raise RuntimeError("Invalid authorized user session file")
    return value


def _split_list(value: str, name: str) -> list[str]:
    items = [part.strip() for part in value.split(",")]
    if not items or any(not part for part in items):
        raise RuntimeError(f"Invalid {name} credential list")
    return items


def _validate_set_db(label: str, api_id: int, api_hash: str,
                    session_string: str) -> tuple[str, int, str, str]:
    if (api_id <= 0
            or not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label)
            or label == "api-bot"):
        raise RuntimeError("Invalid MTProto credential set")
    value = (session_string or "").strip()
    if not value or len(value) > 8192:
        raise RuntimeError("Invalid authorized user session")
    return label, api_id, api_hash, value


def _session_from_file_for(session_file: str) -> str:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(session_file, flags)
        with os.fdopen(descriptor, "r", encoding="ascii") as handle:
            value = handle.read(8193).strip()
    except OSError:
        raise RuntimeError("Invalid authorized user session file") from None
    if not value or len(value) > 8192:
        raise RuntimeError("Invalid authorized user session file")
    return value


def _config_storage_section() -> dict | None:
    """Read the `storage:` section.

    DB-stored channels/sessions take precedence (UI-managed). Falls back to
    the config.yaml storage section.
    """
    # Try DB first.
    try:
        import yaml
        cfg_path = os.environ.get("TELEDRIVE_CONFIG", "config/config.yaml").strip()
        db_url = None
        if cfg_path and os.path.isfile(cfg_path):
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(cfg_path, flags)
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                document = yaml.safe_load(handle) or {}
            state = document.get("state") or {}
            db_url = state.get("database_url") or state.get("db_path")
        if db_url:
            from teledrive.db import connect_database
            from sqlalchemy import text as _text
            conn = connect_database(str(db_url))
            try:
                ch = conn.connection.execute(_text(
                    "SELECT channel_id, strategy, scratch_dir FROM "
                    "telegram_channels WHERE is_active = 1 LIMIT 1"
                )).fetchone()
                if ch is None:
                    ch = conn.connection.execute(_text(
                        "SELECT channel_id, strategy, scratch_dir FROM "
                        "telegram_channels ORDER BY id LIMIT 1"
                    )).fetchone()
                if ch is not None:
                    channel_id, strategy, scratch_dir = ch
                    sessions = conn.connection.execute(_text(
                        "SELECT api_id, api_hash, session_string, account "
                        "FROM telegram_sessions"
                    )).fetchall()
                    apis = []
                    for srow in sessions:
                        apis.append({
                            "api_id": srow[0],
                            "api_hash": srow[1],
                            "session_string": srow[2],
                            "account": srow[3],
                        })
                    if apis:
                        return {
                            "channel": channel_id,
                            "strategy": strategy or "round_robin",
                            "scratch_dir": scratch_dir or "/data/tmp",
                            "apis": apis,
                        }
            finally:
                conn.close()
    except Exception:
        pass

    # Fall back to config.yaml.
    config_path = os.environ.get("TELEDRIVE_CONFIG", "config/config.yaml").strip()
    if not config_path or not os.path.isfile(config_path):
        return None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(config_path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
    except OSError:
        raise RuntimeError("Invalid deployment configuration file") from None
    section = document.get("storage")
    if section is None:
        return None
    if not isinstance(section, dict):
        raise RuntimeError("Invalid storage section in configuration")
    return section


def _config_api_sets(section: dict | None) -> list[tuple[str, int, str, str]] | None:
    """Read the `apis:` list from the storage section.

    Each entry needs api_id, api_hash and session_file; account labels are
    optional and default to mtproto-user, mtproto-user-2, ... Returns None
    when there is no `apis:` section.
    """
    entries = section.get("apis") if section else None
    if not entries:
        return None
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("Invalid apis credential list in configuration")
    sets = []
    labels: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RuntimeError("Invalid MTProto credential set")
        label = str(entry.get("account") or (
            "mtproto-user" if index == 0 else f"mtproto-user-{index + 1}"
        )).strip()
        try:
            api_id = int(entry.get("api_id"))
        except (TypeError, ValueError):
            raise RuntimeError("Invalid MTProto credential set") from None
        api_hash = str(entry.get("api_hash") or "").strip()
        # Support both file-based (config) and string-based (DB) sessions.
        session_string = entry.get("session_string")
        if not session_string:
            session_file = str(entry.get("session_file") or "").strip()
            if not session_file:
                raise RuntimeError("Invalid authorized user session file")
            session_string = _session_from_file_for(session_file)
        if label in labels:
            raise RuntimeError("Invalid MTProto credential set")
        labels.add(label)
        sets.append(_validate_set_db(label, api_id, api_hash, str(session_string)))
    return sets


def _db_credential_sets() -> list[tuple[str, int, str, str]] | None:
    """Read credential sets from the telegram_sessions DB table.

    Returns None when the table is empty or unavailable, so the config
    fallback can be used.
    """
    try:
        from teledrive.db import connect_database
        cfg_path = os.environ.get("TELEDRIVE_CONFIG", "config/config.yaml").strip()
        # Resolve database_url from config.
        import yaml
        if not cfg_path or not os.path.isfile(cfg_path):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(cfg_path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
        state = document.get("state") or {}
        db_url = state.get("database_url") or state.get("db_path")
        if not db_url:
            return None
        conn = connect_database(str(db_url))
        try:
            from sqlalchemy import text as _text
            rows = conn.connection.execute(_text(
                "SELECT api_id, api_hash, session_string, account, channel, "
                "strategy FROM telegram_sessions ORDER BY id"
            )).fetchall()
        finally:
            conn.close()
    except Exception:
        return None
    if not rows:
        return None
    sets = []
    labels: set[str] = set()
    for row in rows:
        api_id, api_hash, session_string, account, channel, strategy = row
        label = str(account or "mtproto-user").strip()
        if label in labels:
            continue
        labels.add(label)
        try:
            sets.append(_validate_set_db(label, int(api_id), str(api_hash),
                                        str(session_string)))
        except RuntimeError:
            continue
    return sets if sets else None


def _credential_sets() -> list[tuple[str, int, str, str]]:
    """Parse one or more authorized Telegram API credential sets.

    The deployment config (config.yaml) `storage.apis:` list is
    authoritative. Without it, TELEDRIVE_STORAGE_MTPROTO_API_ID / _API_HASH
    / _SESSION_FILE accept comma-separated lists of equal length (legacy
    fallback). Each set owns its own session; account labels default to
    mtproto-user, mtproto-user-2, ...
    """
    # DB-stored sessions take precedence (UI-managed).
    db_sets = _db_credential_sets()
    if db_sets:
        return db_sets
    section = _config_storage_section()
    configured = _config_api_sets(section)
    if configured is None:
        raise RuntimeError(
            "No Telegram session configured. Use the WebUI Settings -> "
            "Telegram session to create one, or set storage.apis in config.yaml."
        )
    return configured


def _active_channel_from_db() -> str | None:
    """The operator's active channel from the catalog (UI-managed).

    The runtime must not die at startup just because config
    storage.channel still holds a placeholder like 'me': channels are
    activated in the UI (telegram_channels.is_active) and every session
    row carries its channel. Either wins over the placeholder.
    """
    try:
        from teledrive.db import connect_database
        import yaml
        cfg_path = os.environ.get("TELEDRIVE_CONFIG",
                                  "config/config.yaml").strip()
        if not cfg_path or not os.path.isfile(cfg_path):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(cfg_path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
        state = document.get("state") or {}
        db_url = state.get("database_url") or state.get("db_path")
        if not db_url:
            return None
        conn = connect_database(str(db_url))
        try:
            from sqlalchemy import text as _text
            row = conn.connection.execute(_text(
                "SELECT channel_id FROM telegram_channels "
                "WHERE is_active = 1 ORDER BY id LIMIT 1")).fetchone()
            if row is None or not row[0]:
                row = conn.connection.execute(_text(
                    "SELECT channel FROM telegram_sessions "
                    "WHERE channel IS NOT NULL AND channel != '' "
                    "ORDER BY id LIMIT 1")).fetchone()
        finally:
            conn.close()
        if row and row[0]:
            return str(row[0]).strip()
    except Exception:
        return None
    return None


class UserSessionRuntime:
    """One or more user-authorized clients owned by the ASGI lifespan.

    Every credential set must resolve the SAME dedicated broadcast channel.
    round_robin distributes sends across sets; failover keeps the current
    set until a definite flood-wait rejection, then advances.
    """

    def __init__(self):
        self.client = None
        self.transport = None
        self.account = None
        self.chat_id = None
        self.strategy = "round_robin"
        # Cross-account replication target (storage.replica_account);
        # None disables replication. Hot-reloaded with the runtime.
        self.replica_account = None
        self._sets: dict[str, tuple[Any, Any]] = {}
        self._labels: list[str] = []
        self._index = 0

    def transports(self) -> dict[str, tuple[Any, Any]]:
        return dict(self._sets)

    async def start(self) -> None:
        if transport_mode() != "telethon":
            return
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        from telethon.tl.types import Channel

        if self._sets:
            raise RuntimeError("User storage clients already started")
        storage_section = _config_storage_section()
        strategy = str((storage_section or {}).get("strategy", "round_robin")).strip().lower()
        if strategy not in ("single", "round_robin", "failover", "parallel"):
            raise RuntimeError(
                "MTProto strategy must be single, round_robin, failover or parallel"
            )
        self.strategy = strategy
        target_id = str((storage_section or {}).get("channel", "")).strip()
        if (not target_id or target_id.lower() in ("me", "self", "saved messages")):
            # Placeholder or unset in config: use the channel the operator
            # activated in the UI (or the session's own channel). Without
            # this fallback the runtime dies at startup and every upload
            # 503s with 'session required' although the session is healthy.
            target_id = _active_channel_from_db() or ""
        if not target_id:
            raise RuntimeError("Invalid dedicated channel configuration")
        sets = _credential_sets()
        clients: list[tuple[str, Any]] = []
        resolved_chat: int | None = None
        try:
            for label, api_id, api_hash, session in sets:
                # These are honest TeleDrive client details, not a forged
                # official Telegram fingerprint. MTProto has no HTTP User-Agent.
                device_model = (
                    "TeleDrive Storage Client" if len(sets) == 1
                    else "TeleDrive Storage Client:" + label
                )
                client = TelegramClient(
                    StringSession(session), api_id, api_hash,
                    device_model=device_model,
                    system_version=platform.system(),
                    app_version="TeleDrive 2.1",
                    lang_code="en", system_lang_code="en",
                    receive_updates=False, flood_sleep_threshold=0,
                )
                await client.connect()
                clients.append((label, client))
                identity = await client.get_me()
                if identity is None or getattr(identity, "bot", False):
                    raise RuntimeError(
                        "MTProto storage requires an authorized Telegram USER session"
                    )
                if target_id.lstrip("-").isdigit():
                    # StringSession carries no entity cache. A private channel
                    # ID must be resolved from the user's own dialogs.
                    wanted = int(target_id)
                    channel = None
                    async for dialog in client.iter_dialogs(limit=5000):
                        if int(dialog.id) == wanted:
                            channel = dialog.entity
                            break
                    if channel is None:
                        raise RuntimeError(
                            "Configured channel not found in authorized user's dialogs"
                        )
                else:
                    try:
                        channel = await client.get_entity(target_id)
                    except Exception:
                        channel = None
                    if channel is None:
                        # The UI accepts human channel names; get_entity
                        # only resolves usernames/URLs. Match the dialog
                        # TITLE as a last resort.
                        wanted = target_id.casefold()
                        async for dialog in client.iter_dialogs(limit=5000):
                            if str(dialog.name or "").casefold() == wanted:
                                channel = dialog.entity
                                break
                    if channel is None:
                        raise RuntimeError(
                            "Configured channel not found in authorized "
                            "user's dialogs")
                if not isinstance(channel, Channel) or not getattr(
                        channel, "broadcast", False):
                    raise RuntimeError(
                        "MTProto storage target must be a channel, not Saved Messages"
                    )
                rights = getattr(channel, "admin_rights", None)
                if not (getattr(channel, "creator", False)
                        or (rights is not None
                            and getattr(rights, "post_messages", False))):
                    raise RuntimeError("User must have channel posting rights")
                chat_id = int(await client.get_peer_id(channel))
                if resolved_chat is None:
                    resolved_chat = chat_id
                elif chat_id != resolved_chat:
                    raise RuntimeError(
                        "Every MTProto credential set must target the same channel"
                    )
                self._sets[label] = (client, channel)
                self._labels.append(label)
        except BaseException:
            for _, client in clients:
                await client.disconnect()
            self._sets.clear()
            self._labels.clear()
            raise
        self.account = self._labels[0]
        self.chat_id = resolved_chat
        self.client = self._sets[self._labels[0]][0]
        self.transport = TelethonChunkTransport({
            label: pair for label, pair in self._sets.items()
        })
        # Cross-account replication: an operator-set target account that
        # is not among the loaded credential sets degrades to disabled
        # (with a log) rather than killing the runtime.
        replica = str((storage_section or {}).get(
            "replica_account", "") or "").strip()
        if replica and replica not in self._labels:
            _module_logger.warning(
                "replica_account %r is not a loaded credential set; "
                "replication disabled", replica)
            replica = ""
        self.replica_account = replica or None

    async def stop(self) -> None:
        clients = [pair[0] for pair in self._sets.values()]
        self.client = self.transport = None
        self.account = self.chat_id = None
        self._sets.clear()
        self._labels.clear()
        self._index = 0
        for client in clients:
            await client.disconnect()

    def advance(self) -> str:
        """Move to the next credential set and return its account label."""
        if not self._labels:
            # Legacy single-client wiring without start(): no rotation.
            return self.account
        self._index = (self._index + 1) % len(self._labels)
        self.account = self._labels[self._index]
        self.client = self._sets[self.account][0]
        return self.account

    def require(self, label: str | None = None):
        if self._sets and self._labels:
            selected = label or self._labels[self._index]
            client, channel = self._sets[selected]
            if not client.is_connected():
                raise RuntimeError("User Telegram session is not connected")
            if label is None:
                self.account = selected
            return TelethonChunkTransport({selected: (client, channel)})
        # Legacy single-client wiring without start().
        if (self.client is None or self.transport is None
                or not self.client.is_connected()):
            raise RuntimeError("User Telegram session is not connected")
        return self.transport


class UserSendJournal:
    def __init__(self, db):
        self.db = db
        _meta.create_all(db.engine)
        db.release_setup_snapshot()

    def start(self, account: str, chat_id: int, object_id: str, ordinal: int,
              sha256: str, size: int) -> None:
        if (not account or not chat_id or ordinal < 0 or size < 1
                or size > 1024 * 1024 * 1024
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)):
            raise ValueError("Invalid MTProto upload intent")
        try:
            self.db.connection.execute(insert(mtproto_send_intents).values(
                account=account, chat_id=chat_id, object_id=object_id,
                ordinal=ordinal, sha256=sha256, size=size, message_id=None,
            ))
            self.db.commit()
        except IntegrityError:
            self.db.connection.rollback()
            # A fully ACKNOWLEDGED intent may be re-opened for a re-send
            # of the same identity (replica repair, resume): the previous
            # remote outcome is known and resolved. An UNRESOLVED intent
            # still blocks — its remote acceptance is unknown.
            row = self.db.connection.execute(
                select(mtproto_send_intents.c.sha256,
                       mtproto_send_intents.c.size,
                       mtproto_send_intents.c.message_id).where(
                    mtproto_send_intents.c.account == account,
                    mtproto_send_intents.c.chat_id == chat_id,
                    mtproto_send_intents.c.object_id == object_id,
                    mtproto_send_intents.c.ordinal == ordinal,
                )
            ).first()
            if (row is not None and row[2] is not None
                    and str(row[0]) == sha256 and int(row[1]) == size):
                self.db.connection.execute(update(mtproto_send_intents).where(
                    mtproto_send_intents.c.account == account,
                    mtproto_send_intents.c.chat_id == chat_id,
                    mtproto_send_intents.c.object_id == object_id,
                    mtproto_send_intents.c.ordinal == ordinal,
                ).values(message_id=None))
                self.db.commit()
                return
            raise RuntimeError("Unresolved MTProto upload intent: reconcile before retry") from None

    def acknowledged(self, account: str, chat_id: int, object_id: str,
                     ordinal: int, message_id: int) -> None:
        changed = self.db.connection.execute(update(mtproto_send_intents).where(
            mtproto_send_intents.c.account == account,
            mtproto_send_intents.c.chat_id == chat_id,
            mtproto_send_intents.c.object_id == object_id,
            mtproto_send_intents.c.ordinal == ordinal,
            mtproto_send_intents.c.message_id.is_(None),
        ).values(message_id=message_id))
        if changed.rowcount != 1:
            self.db.connection.rollback()
            raise RuntimeError("MTProto upload receipt could not be journaled")
        self.db.commit()

    def unresolved_count(self) -> int:
        """Durable intents whose remote acceptance is still unknown."""
        return int(self.db.connection.execute(
            select(func.count()).select_from(mtproto_send_intents).where(
                mtproto_send_intents.c.message_id.is_(None)
            )
        ).scalar_one())

    def clear_rejected_send(self, account: str, chat_id: int, object_id: str,
                            ordinal: int, checksum: str, size: int) -> None:
        """Delete one intent ONLY after a definite, verified rejection.

        A flood-wait or a hard Telegram validation error proves the message
        was not accepted. Unknown outcomes must never reach this method.
        """
        if (not account or not chat_id or not object_id or len(object_id) > 36
                or ordinal < 0 or size < 1
                or not re.fullmatch(r"[0-9a-f]{64}", checksum)):
            raise ValueError("Invalid MTProto rejection identity")
        from sqlalchemy import delete
        result = self.db.connection.execute(delete(mtproto_send_intents).where(
            mtproto_send_intents.c.account == account,
            mtproto_send_intents.c.chat_id == chat_id,
            mtproto_send_intents.c.object_id == object_id,
            mtproto_send_intents.c.ordinal == ordinal,
            mtproto_send_intents.c.sha256 == checksum,
            mtproto_send_intents.c.size == size,
            mtproto_send_intents.c.message_id.is_(None),
        ))
        if result.rowcount != 1:
            self.db.connection.rollback()
            raise RuntimeError("MTProto rejection could not clear the exact intent")
        self.db.commit()


class UnifiedUserTransport:
    """All live I/O uses USER MTProto; old same-channel Bot messages remain readable."""

    def __init__(self, runtime: UserSessionRuntime, journal: UserSendJournal, *,
                 rate=None, min_upload_interval: float = 1.1):
        if not 0 <= min_upload_interval <= 60:
            raise ValueError("Invalid MTProto minimum upload interval")
        self.runtime = runtime
        self.journal = journal
        self.rate = rate if rate is not None else MtprotoRateGuard(journal.db)
        self.min_upload_interval = min_upload_interval
        self._next_upload = 0.0
        self._select_lock = asyncio.Lock()
        # account -> (monotonic_ts, over_quota) cache; soft quotas are
        # best-effort routing hints, never hard blocks.
        self._quota_cache: dict[str, tuple[float, bool]] = {}

    def _account_over_quota(self, account: str) -> bool:
        """Soft-quota check with a 60s cache; False on any error.

        Reads the account's soft_quota_bytes (telegram_sessions) and its
        current usage (storage_chunks). Table absence or DB errors
        degrade to 'not over' — uploads must never fail on monitoring.
        """
        now = time.monotonic()
        cached = self._quota_cache.get(account)
        if cached is not None and now - cached[0] < 60:
            return cached[1]
        over = False
        try:
            from sqlalchemy import text as _text
            conn = self.journal.db
            quota = conn.connection.execute(_text(
                "SELECT soft_quota_bytes FROM telegram_sessions "
                "WHERE account = :account"
            ), {"account": account}).scalar_one_or_none()
            if quota is not None:
                used = conn.connection.execute(_text(
                    "SELECT COALESCE(SUM(size), 0) FROM storage_chunks "
                    "WHERE account = :account"
                ), {"account": account}).scalar() or 0
                over = int(used) >= int(quota)
        except Exception:
            over = False
        self._quota_cache[account] = (now, over)
        return over

    def _pinned_account(self) -> str | None:
        """Bucket→account pin for the CURRENT upload bucket, if any.

        Explicit operator intent: a pin wins over the strategy rotation
        and over the soft-quota preference. Errors degrade to no pin.
        """
        try:
            from teledrive.storage.placement import current_upload_bucket
            bucket = current_upload_bucket()
            if not bucket:
                return None
            from sqlalchemy import text as _text
            row = self.journal.db.connection.execute(_text(
                "SELECT account FROM bucket_account_pins "
                "WHERE bucket = :bucket"
            ), {"bucket": bucket}).scalar_one_or_none()
            return str(row) if row else None
        except Exception:
            return None

    async def verify_target(self):
        self.runtime.require()

    def parallel_degree(self) -> int:
        """Concurrent send capacity: parallel strategy uses every set."""
        transports = getattr(self.runtime, "transports", None)
        labels = list(transports()) if callable(transports) else None
        strategy = getattr(self.runtime, "strategy", "round_robin")
        if strategy == "parallel" and labels:
            return len(labels)
        return 1

    async def _select(self, *, strategy: str, labels: list[str],
                      advance) -> str:
        """Atomically pick the account label for this send.

        round_robin and parallel pre-rotate so concurrent callers always
        receive distinct sets; single and failover stay on the current set
        (failover advances only after a definite rejection).
        """
        async with self._select_lock:
            account = self.runtime.account
            if (strategy in ("round_robin", "parallel")
                    and len(labels) > 1 and callable(advance)):
                advance()
        # Bucket→account pin: explicit operator intent wins over both
        # the strategy rotation and the soft-quota preference — but
        # only when the pinned account is actually available.
        if labels:
            pinned = self._pinned_account()
            if pinned and pinned in labels:
                return pinned
        # Soft-quota preference (best effort): when the selected account
        # is over its soft quota and an alternative is under quota,
        # prefer the alternative. All-over or unknown states keep the
        # strategy's original choice.
        if labels and len(labels) > 1:
            try:
                if self._account_over_quota(account):
                    for label in labels:
                        if label != account and not self._account_over_quota(label):
                            return label
            except Exception:
                pass
        return account

    def replica_account(self) -> str | None:
        """Live replication target account; None disables replication."""
        return getattr(self.runtime, "replica_account", None)

    async def upload(self, path: Path, *, object_id: str, ordinal: int,
                     checksum: str, force_account: str | None = None):
        from telethon.errors import FloodWaitError

        size = path.stat().st_size
        chat_id = self.runtime.chat_id
        # One or more authorized credential sets share the SAME channel.
        # A definite flood-wait proves the send was REJECTED, so the failed
        # set's intent is cleared and the next set retries with its own
        # fresh intent. Ambiguous outcomes never trigger cross-set retries.
        # Single-set runtimes keep the original intent across the bounded
        # same-set retry (legacy behavior).
        # A forced account (cross-account replication) pins every attempt:
        # replication either lands on the replica account or fails — it
        # must never silently rotate onto a different set.
        transports = getattr(self.runtime, "transports", None)
        labels = list(transports()) if callable(transports) else None
        strategy = getattr(self.runtime, "strategy", "round_robin")
        advance = getattr(self.runtime, "advance", None)
        if force_account is not None:
            if labels and force_account not in labels:
                raise RuntimeError(
                    "Forced upload account is not an available credential set")
            account = force_account
        elif labels:
            account = await self._select(
                strategy=strategy, labels=labels, advance=advance)
        else:
            account = self.runtime.account
        self.journal.start(account, chat_id, object_id, ordinal,
                           checksum, size)
        total_attempts = max(len(labels) * 2, 2) if labels else 2
        for attempt in range(total_attempts):
            if (attempt and force_account is None and labels
                    and len(labels) > 1 and callable(advance)):
                self.journal.clear_rejected_send(
                    account, chat_id, object_id, ordinal, checksum, size,
                )
                advance()
                account = self.runtime.account
                self.journal.start(account, chat_id, object_id, ordinal,
                                   checksum, size)
            try:
                try:
                    delegate = self.runtime.require(account)
                except TypeError:
                    delegate = self.runtime.require()
                # The SQL slot is shared by every worker using this
                # account/channel, not just this transport instance.
                shared_wait = self.rate.reserve_send_slot(
                    account, chat_id, self.min_upload_interval,
                )
                pause = max(shared_wait, self._next_upload - time.monotonic(), 0.0)
                if pause:
                    await asyncio.sleep(pause)
                # A different worker may receive a flood-wait after we
                # reserved this slot. Enforce the server cooldown even for
                # transports with min_upload_interval=0 (no local pacing).
                while True:
                    backoff = self.rate.shared_cooldown_wait(account, chat_id)
                    if not backoff:
                        break
                    await asyncio.sleep(min(backoff, 30.0))
                received_account, received_chat, message_id = await delegate.upload(
                    path, object_id=object_id, ordinal=ordinal, checksum=checksum,
                )
                if (received_account, received_chat) != (account, chat_id):
                    raise RuntimeError("MTProto send returned an unexpected account or channel")
                self.journal.acknowledged(account, chat_id, object_id, ordinal, message_id)
                self._next_upload = time.monotonic()
                return received_account, received_chat, message_id
            except FloodWaitError as exc:
                # Publish the cooldown for every worker before sleeping.
                wait = int(getattr(exc, "seconds", 1) or 1)
                self.rate.impose_shared_cooldown(account, chat_id, min(wait, 3600))
                if attempt + 1 < total_attempts:
                    continue
                raise RuntimeError(
                    "MTProto flood-wait persists; reconcile protected intent before retry"
                ) from None
            except Exception:
                raise RuntimeError(
                    "MTProto send outcome uncertain; reconcile protected intent before retry"
                ) from None
        raise RuntimeError(
            "MTProto send outcome uncertain; reconcile protected intent before retry"
        )

    async def delete(self, reference):
        """Physically delete a chunk's Telegram message (owner-gated GC).

        Account resolution mirrors download(): only the account that
        owns the message may revoke it; coordinates are never remapped.
        """
        transports = getattr(self.runtime, "transports", None)
        if callable(transports) and reference.account in transports():
            client, channel = transports()[reference.account]
            await TelethonChunkTransport({
                reference.account: (client, channel),
            }).delete(reference)
            return
        if reference.account == self.runtime.account:
            await self.runtime.require().delete(reference)
            return
        raise FileNotFoundError(
            "Historical source inaccessible to authorized Telethon user; "
            "do not remap remote media"
        )

    async def download(self, reference, destination):
        transports = getattr(self.runtime, "transports", None)
        if callable(transports) and reference.account in transports():
            client, channel = transports()[reference.account]
            return await TelethonChunkTransport({
                reference.account: (client, channel),
            }).download(reference, destination)
        if reference.account == self.runtime.account:
            return await self.runtime.require().download(reference, destination)
        if reference.account == "api-bot" and reference.chat_id == self.runtime.chat_id:
            # Only the ORIGINAL verified channel/message coordinates may be
            # rebound to a user session; immutable checksums still apply.
            rebound = replace(reference, account=self.runtime.account)
            return await self.runtime.require().download(rebound, destination)
        raise FileNotFoundError(
            "Historical source inaccessible to authorized Telethon user; "
            "do not remap remote media"
        )
