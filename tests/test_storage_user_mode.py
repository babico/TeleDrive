"""Fake-Telegram signed S3 and SQL safety tests for optional USER MTProto mode."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from test_s3_gateway import service, signed
from teledrive.storage.telethon_adapter import TelethonChunkTransport
from teledrive.storage.user_mode import (
    UserSessionRuntime, UserSendJournal, UnifiedUserTransport,
    mtproto_send_intents, transport_mode,
)
from teledrive.storage.bot_api_adapter import BotApiChunkTransport, BotFileIndex


class FakeUser:
    def __init__(self):
        self.connected = True
        self.posts = {}
        self.next_id = 0
        self.fail_after_remote_accept = False

    def is_connected(self):
        return self.connected

    async def get_peer_id(self, target):
        return -1001234567890

    async def send_file(self, target, path, caption, force_document):
        assert caption.startswith("teledrive:")
        assert force_document
        self.next_id += 1
        self.posts[self.next_id] = (Path(path).read_bytes(), caption)
        if self.fail_after_remote_accept:
            raise TimeoutError("simulated lost MTProto ACK")
        return SimpleNamespace(id=self.next_id, chat_id=-1001234567890)

    async def get_messages(self, target, ids):
        if ids not in self.posts:
            return None
        return SimpleNamespace(
            id=ids, media=True, message=self.posts[ids][1],
            chat_id=-1001234567890, out=True,
        )

    async def download_media(self, message, file):
        Path(file).write_bytes(self.posts[message.id][0])
        return file


def configured_runtime():
    user = FakeUser()
    runtime = UserSessionRuntime()
    runtime.client = user
    runtime.account = "mtproto-user"
    runtime.chat_id = -1001234567890
    runtime.transport = TelethonChunkTransport({
        runtime.account: (user, object()),
    })
    return runtime, user


def test_bot_is_default_and_bad_mode_fails_closed(monkeypatch):
    monkeypatch.delenv("TELEDRIVE_STORAGE_TRANSPORT", raising=False)
    assert transport_mode() == "bot"
    monkeypatch.setenv("TELEDRIVE_STORAGE_TRANSPORT", "telethon")
    assert transport_mode() == "telethon"
    monkeypatch.setenv("TELEDRIVE_STORAGE_TRANSPORT", "auto-fallback")
    with pytest.raises(RuntimeError):
        transport_mode()


def test_user_session_requires_file_and_disallows_saved_messages(monkeypatch, tmp_path):
    monkeypatch.setenv("TELEDRIVE_STORAGE_TRANSPORT", "telethon")
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_API_ID", "1234")
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_API_HASH", "a" * 32)
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_CHANNEL", "me")
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="dedicated channel"):
        asyncio.run(UserSessionRuntime().start())


def test_mtp_user_upload_and_s3_readback_with_bot_fallback(service, monkeypatch):
    import web.s3 as gateway

    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    earlier = signed(service, "PUT", "/backup-bucket/old.bin", b"original-bot-data")
    assert earlier.status_code == 200, earlier.text

    runtime, user = configured_runtime()
    def transport(db):
        fallback = BotApiChunkTransport(
            service[2], BotFileIndex(db),
            chat_id=-1001234567890, account="api-bot", min_upload_interval=0,
        )
        return UnifiedUserTransport(runtime, UserSendJournal(db), fallback)
    monkeypatch.setattr(gateway, "storage_bot_transport", transport)
    data = b"new-user-mtproto-bytes" * 19
    response = signed(service, "PUT", "/backup-bucket/user.bin", data)
    assert response.status_code == 200, response.text
    assert user.next_id == 1
    assert signed(service, "GET", "/backup-bucket/user.bin").content == data
    assert signed(service, "GET", "/backup-bucket/old.bin").content == b"original-bot-data"
    conn = service[3]()
    try:
        records = conn.connection.execute(
            select(mtproto_send_intents.c.account, mtproto_send_intents.c.message_id)
        ).all()
        assert records == [("mtproto-user", 1)]
    finally:
        conn.close()


def test_user_uncertain_ack_remains_fenced_and_gc_preview_is_blocked(service, monkeypatch):
    import web.s3 as gateway
    from teledrive.storage.gc_safety import GCReferenceGuard
    from teledrive.storage.manifest import ManifestStore, objects

    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    runtime, user = configured_runtime()
    user.fail_after_remote_accept = True
    def transport(db):
        return UnifiedUserTransport(runtime, UserSendJournal(db))
    monkeypatch.setattr(gateway, "storage_bot_transport", transport)
    response = signed(service, "PUT", "/backup-bucket/unknown.bin", b"uncertain-send")
    assert response.status_code >= 400
    assert len(user.posts) == 1
    assert signed(service, "GET", "/backup-bucket/unknown.bin").status_code == 404
    conn = service[3]()
    try:
        records = conn.connection.execute(select(
            mtproto_send_intents.c.object_id, mtproto_send_intents.c.message_id,
        )).all()
        assert len(records) == 1 and records[0].message_id is None
        guard = GCReferenceGuard(ManifestStore(conn))
        evidence = guard.evidence(records[0].object_id)
        assert "mtproto_send_intent_or_receipt" in evidence["reference_blockers"]
        assert evidence["deletion_permitted"] is False
    finally:
        conn.close()


def test_wrong_account_has_no_cross_transport_fallback(service):
    runtime, _ = configured_runtime()
    db = service[3]()
    try:
        user_transport = UnifiedUserTransport(runtime, UserSendJournal(db))
        ref = SimpleNamespace(account="other-user", chat_id=-1001234567890, message_id=1)
        with pytest.raises(FileNotFoundError):
            asyncio.run(user_transport.download(ref, Path("/tmp/never-written")))
    finally:
        db.close()
