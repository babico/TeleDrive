#!/usr/bin/env python3
"""Read-only original Telegram media DR rehearsal (owner-executed).

Verifies a sealed SQL snapshot, restores it into a disposable clone and
reads ONE owner-named original object back through the production chunk
engine: full bytes plus first/middle/cross-boundary/last Range reads,
and envelope (SSE-S3) key restore when the object is encrypted. No live
database is modified and no Telegram uploads or deletes are issued; the
snapshot is verified against its SHA-256 receipt before any use.

The CLI authenticates a read-only USER MTProto session against the
ORIGINAL channel; there is no Bot API transport. A one-object success is
a sample DR, never proof of complete archive recovery.

Exit codes:
  0  PASS (one verified sample object)
  1  unexpected failure or missing MTProto environment
  2  sealed snapshot rejected (SHA-256 receipt, integrity, schema)
  3  object or remote chunk not found in the restored catalog
  4  account/channel scope refused, or size budget exceeded
  5  payload/range/attestation verification failed
  6  encrypted object without usable key material

``--self-test`` exercises this whole machinery offline against a
synthetic sealed snapshot and a synthetic byte backend; it never touches
Telegram, the network or the live service.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.ops.verify_metadata_backup import InvalidSnapshot, verify_snapshot
from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import IntegrityError, TelegramObjectStorage
from teledrive.storage.envelope import EnvelopeError, derive_kek
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.sse import SSECError
from teledrive.storage.telethon_adapter import TelethonChunkTransport

EXIT_PASS = 0
EXIT_FAILURE = 1
EXIT_SNAPSHOT_REJECTED = 2
EXIT_OBJECT_NOT_FOUND = 3
EXIT_SCOPE_REFUSED = 4
EXIT_VERIFICATION_FAILED = 5
EXIT_KEY_MATERIAL = 6

# Every internal chunk boundary gets a cross-boundary Range check, but the
# count stays bounded so a snapshot with thousands of tiny chunks cannot
# turn the rehearsal into an unbounded read amplification.
MAX_BOUNDARY_RANGES = 16
SAMPLE_CLAIM = ("sample DR (one object); not complete archive recovery")
_CHANNEL_ID_PATTERN = re.compile(r"-100\d{6,}")


class ScopeError(FileNotFoundError):
    """Authorized account/channel scope does not match the catalog."""


class KeyMaterialError(RuntimeError):
    """Encrypted object cannot be restored with the supplied key material."""


class AttestationError(RuntimeError):
    """Independently attested digest or size disagrees with the catalog."""


class MissingEnvironment(RuntimeError):
    """Required MTProto environment variables are not set."""


def exit_code_for(exc: BaseException) -> int:
    """Map a rehearsal failure to its documented exit code."""
    if isinstance(exc, InvalidSnapshot):
        return EXIT_SNAPSHOT_REJECTED
    if isinstance(exc, ScopeError):
        return EXIT_SCOPE_REFUSED
    if isinstance(exc, FileNotFoundError):
        return EXIT_OBJECT_NOT_FOUND
    if isinstance(exc, (IntegrityError, AttestationError)):
        return EXIT_VERIFICATION_FAILED
    if isinstance(exc, (KeyMaterialError, SSECError, EnvelopeError)):
        return EXIT_KEY_MATERIAL
    return EXIT_FAILURE


class ReadOnlyUserChannelTransport:
    """Permit only an exact authorized channel and original SQL account label.

    Historical api-bot messages in the *same* channel may be read by a real
    Telegram user. No mutation method is exposed; no cross-channel fallback.
    Chunk hash and full-object integrity remain checked by the storage engine.
    """

    def __init__(self, client, channel, *, account: str, chat_id: int):
        self.account = account
        self.chat_id = chat_id
        self.reader = TelethonChunkTransport({account: (client, channel)})

    async def download(self, reference, destination):
        if (reference.chat_id != self.chat_id or
                reference.account not in (self.account, "api-bot")):
            raise ScopeError("Original account/channel scope does not match")
        return await self.reader.download(
            replace(reference, account=self.account), destination,
        )


def _planned_ranges(size: int, boundaries: list[int]) -> list[tuple[str, int, int]]:
    """First/middle/cross-boundary/last half-open windows, deduplicated."""
    if size <= 0:
        return []
    planned: list[tuple[str, int, int]] = []

    def window(label: str, start: int) -> None:
        planned.append((label, max(0, start), min(size, start + 37)))

    window("first", 0)
    window("middle", size // 2 - 17)
    internal = sorted({b for b in boundaries if 0 < b < size})
    if len(internal) > MAX_BOUNDARY_RANGES:
        stride = len(internal) / MAX_BOUNDARY_RANGES
        internal = sorted({
            internal[min(len(internal) - 1, int(index * stride))]
            for index in range(MAX_BOUNDARY_RANGES)
        })
    for index, boundary in enumerate(internal):
        window(f"cross-boundary-{index + 1}", boundary - 17)
    window("last", size - 37)
    unique: list[tuple[str, int, int]] = []
    seen: set[tuple[int, int]] = set()
    for label, start, end in planned:
        if start < end and (start, end) not in seen:
            seen.add((start, end))
            unique.append((label, start, end))
    return unique


async def verify_restored_telegram_object(
    snapshot: Path, receipt_sha256: str, *,
    bucket: str, key: str, account: str, chat_id: int,
    max_bytes: int = 64 * 1024 * 1024,
    transport, version_id: str | None = None,
    object_sha256: str | None = None, object_size: int | None = None,
    envelope_kek: bytes | None = None,
) -> dict:
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1024**3:
        raise ValueError("Invalid staging DR maximum object size")
    if transport is None:
        raise ValueError("No authorized Telegram read transport configured")
    if object_sha256 is not None and not re.fullmatch(
            r"[0-9a-fA-F]{64}", object_sha256):
        raise ValueError("Independent object SHA-256 must be 64 hex digits")
    if object_size is not None and (type(object_size) is not int
                                    or object_size < 0):
        raise ValueError("Independent object size must be a non-negative integer")
    original_report = verify_snapshot(Path(snapshot), receipt_sha256)
    with tempfile.TemporaryDirectory(prefix="teledrive-staging-dr-") as dirname:
        root = Path(dirname)
        clone = root / "restored-metadata.db"
        shutil.copyfile(snapshot, clone)
        # Verify the clone's identical bytes before any ORM may add tables.
        if hashlib.sha256(clone.read_bytes()).hexdigest() != receipt_sha256.lower():
            raise InvalidSnapshot("Staging clone differs from authenticated SQL snapshot")
        db = connect_database(str(clone))
        try:
            manifests = ManifestStore(db)
            catalog = BucketCatalog(manifests)
            if version_id is not None:
                if not catalog.is_visible_version(bucket, key, version_id):
                    raise FileNotFoundError(
                        "Requested VersionId is not a visible published version")
                obj = manifests.get(version_id)
            else:
                obj = catalog.get(bucket, key).item
            if obj.size > max_bytes:
                raise ValueError("Staging DR sample exceeds explicit size budget")
            # Independent owner evidence outranks the catalog's own claim.
            if object_size is not None and obj.size != object_size:
                raise AttestationError(
                    "Attested object size disagrees with the restored catalog")
            if object_sha256 is not None and not hmac.compare_digest(
                    obj.sha256.lower(), object_sha256.lower()):
                raise AttestationError(
                    "Attested object SHA-256 disagrees with the restored catalog")
            info = manifests.encryption_info(obj.id)
            sse_key = None
            encryption_mode = "plaintext"
            if info is not None:
                encryption_mode = str(info.get("mode"))
                if (info.get("mode") == "SSE-S3"
                        and info.get("key_wrap") == "envelope-v1"):
                    if envelope_kek is None:
                        raise KeyMaterialError(
                            "Object is envelope-encrypted; supply the deployment "
                            "master key with --master-key-file")
                    sse_key = manifests.envelope_key(obj.id, envelope_kek)
                else:
                    raise KeyMaterialError(
                        "Object uses customer-managed encryption; this rehearsal "
                        "does not accept SSE-C customer key material")
            engine = TelegramObjectStorage(
                manifests, transport, scratch_directory=root,
            )
            target = root / "verified-telegram-payload"
            await engine.download_to_path(obj.id, target, sse_key=sse_key)
            with target.open("rb") as media:
                digest = hashlib.sha256()
                read_size = 0
                while block := media.read(1024 * 1024):
                    digest.update(block)
                    read_size += len(block)
            if digest.hexdigest() != obj.sha256 or read_size != obj.size:
                raise IntegrityError("Staging DR Telegram payload checksum mismatch")
            if object_sha256 is not None and not hmac.compare_digest(
                    digest.hexdigest(), object_sha256.lower()):
                raise AttestationError(
                    "Attested object SHA-256 disagrees with the retrieved bytes")
            parts = manifests.parts(obj.id)
            boundaries = [part.offset + part.size for part in parts[:-1]]
            verified_ranges: list[list] = []
            for label, start, end in _planned_ranges(obj.size, boundaries):
                observed = b"".join([
                    piece async for piece in engine.iter_bytes(
                        obj.id, start=start, end=end, block_size=7,
                        sse_key=sse_key,
                    )
                ])
                with target.open("rb") as file:
                    file.seek(start)
                    expected = file.read(end - start)
                if observed != expected:
                    raise IntegrityError(
                        "Staging DR Telegram Range read differs from verified "
                        f"file ({label})")
                verified_ranges.append([label, start, end])
            return {
                "verified": True, "claim": SAMPLE_CLAIM,
                "archive_sha256": original_report["sha256"],
                "object_id": obj.id, "version_id": version_id,
                "size": obj.size, "sha256": obj.sha256,
                "verified_object_count": 1,
                "verified_ranges": verified_ranges,
                "chunk_count": len(parts),
                "encryption_mode": encryption_mode,
                "encrypted_key_restore_verified": info is not None,
                "independent_attestation_checked": object_sha256 is not None,
                "readback_bytes": read_size, "telegram_uploads": 0,
                "telegram_deletions": 0, "source_database_modified": False,
            }
        finally:
            db.close()


def _read_private_file(path: Path, limit: int, label: str) -> bytes:
    """Read an owner secret with O_NOFOLLOW; never echo its content."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        data = stream.read(limit)
    if not data or len(data) >= limit:
        raise KeyMaterialError(f"Invalid private {label} file")
    return data.strip()


def _load_envelope_kek(master_key_file: Path) -> bytes:
    """Derive the envelope KEK from the deployment master key file."""
    from cryptography.fernet import Fernet

    material = _read_private_file(Path(master_key_file), 256, "master key")
    try:
        Fernet(material)
    except (ValueError, TypeError) as exc:
        raise KeyMaterialError(
            "Master key file is not a valid 32-byte Fernet key") from exc
    return derive_kek(material)


async def open_read_only_user(session_file: Path, api_id: int,
                              api_hash: str, target: str, chat_id: int):
    """Connect an authorized USER session and resolve the exact channel."""
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.types import Channel

    if api_id <= 0 or not api_hash or not target:
        raise ValueError("Missing authorized user MTProto configuration")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(session_file, flags)
    with os.fdopen(descriptor, "r", encoding="ascii") as stream:
        session = stream.read(8193).strip()
    if not session or len(session) > 8192:
        raise ValueError("Invalid private user StringSession file")
    client = TelegramClient(
        StringSession(session), api_id, api_hash,
        device_model="TeleDrive Storage Client",
        app_version="TeleDrive 2.1",
        receive_updates=False, flood_sleep_threshold=0,
    )
    try:
        await client.connect()
        identity = await client.get_me()
        if identity is None or getattr(identity, "bot", False):
            raise ValueError("Staging original-media DR requires a USER session")
        if target.lstrip("-").isdigit():
            resolved = None
            async for dialog in client.iter_dialogs(limit=5000):
                if int(dialog.id) == int(target):
                    resolved = dialog.entity
                    break
            if resolved is None:
                raise FileNotFoundError("Original Telegram channel not in user dialogs")
        else:
            resolved = await client.get_entity(target)
        if not isinstance(resolved, Channel) or not getattr(resolved, "broadcast", False):
            raise ValueError("Staging original-media DR requires a broadcast channel")
        actual_chat_id = int(await client.get_peer_id(resolved))
        if actual_chat_id != chat_id:
            raise ValueError("Original Telegram channel identity mismatch")
        return client, resolved
    except Exception:
        await client.disconnect()
        raise


async def verify_original_user_channel(
    snapshot: Path, receipt_sha256: str, *, bucket: str, key: str,
    account: str, chat_id: int, target: str,
    session_file: Path, api_id: int, api_hash: str,
    max_bytes: int = 64 * 1024 * 1024,
    version_id: str | None = None,
    object_sha256: str | None = None, object_size: int | None = None,
    envelope_kek: bytes | None = None,
) -> dict:
    """Read owner-authorized original Telegram messages without mutations."""
    client, resolved = await open_read_only_user(
        session_file, api_id, api_hash, target or str(chat_id), chat_id,
    )
    try:
        reader = ReadOnlyUserChannelTransport(
            client, resolved, account=account, chat_id=chat_id,
        )
        return await verify_restored_telegram_object(
            snapshot, receipt_sha256, bucket=bucket, key=key,
            account=account, chat_id=chat_id, max_bytes=max_bytes,
            transport=reader, version_id=version_id,
            object_sha256=object_sha256, object_size=object_size,
            envelope_kek=envelope_kek,
        )
    finally:
        await client.disconnect()


def _tool_versions() -> dict:
    import platform
    from importlib import metadata

    versions = {"python": platform.python_version()}
    for distribution in ("Telethon", "telegram-auto-upload"):
        try:
            versions[distribution] = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            versions[distribution] = "not-installed"
    return versions


def _commit_sha() -> str | None:
    """Resolve the working tree's commit without shelling out to git."""
    marker = ROOT / ".git"
    try:
        if marker.is_file():  # linked worktree
            location = Path(
                marker.read_text(encoding="utf-8").strip().split(" ", 1)[1])
        elif marker.is_dir():
            location = marker
        else:
            return None
        head = (location / "HEAD").read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-f]{40,64}", head):
            return head
        if not head.startswith("ref: "):
            return None
        ref = location / head[5:]
        if ref.is_file():
            value = ref.read_text(encoding="utf-8").strip()
            return value if re.fullmatch(r"[0-9a-f]{40,64}", value) else None
        packed = location / "packed-refs"
        if packed.is_file():
            wanted = head[5:]
            for line in packed.read_text(encoding="utf-8").splitlines():
                sha, _, refname = line.partition(" ")
                if (refname.strip() == wanted
                        and re.fullmatch(r"[0-9a-f]{40,64}", sha)):
                    return sha
    except OSError:
        return None
    return None


def redact(text: str, secrets: list[str]) -> str:
    """Strip operator-private values and channel/phone-shaped numbers."""
    redacted = text
    for secret in secrets:
        value = str(secret)
        if len(value) >= 4:
            redacted = redacted.replace(value, "[REDACTED]")
    return _CHANNEL_ID_PATTERN.sub("[REDACTED:channel-id]", redacted)


def write_evidence_record(directory: Path, record: dict) -> Path:
    """Persist the redacted evidence record as a new owner-only file."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = directory / f"dr-rehearsal-{stamp}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True, indent=2)
        handle.write("\n")
    return path


def _operator_secrets(args, session_file: Path | None) -> list[str]:
    secrets = [args.bucket, args.key, args.account, args.target or "",
               str(args.chat_id)]
    api_hash = os.environ.get("TELEDRIVE_STORAGE_MTPROTO_API_HASH", "")
    if api_hash:
        secrets.append(api_hash)
    if session_file is not None:
        try:
            secrets.append(_read_private_file(
                Path(session_file), 8193, "session").decode("ascii", "ignore"))
        except (OSError, KeyMaterialError, UnicodeDecodeError):
            pass
    return secrets


def _build_evidence_record(args, result: dict | None,
                           failure: dict | None, stderr_text: str,
                           secrets: list[str]) -> dict:
    record = {
        "status": "PASS" if failure is None else "FAIL",
        "claim": SAMPLE_CLAIM,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "commit_sha": _commit_sha(),
        "tool_versions": _tool_versions(),
        "script_sha256": hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest(),
        "snapshot_sha256": args.sha256.strip().lower(),
        "verified_object_count": 1 if result else 0,
        "object_size": result["size"] if result else None,
        "object_sha256": result["sha256"] if result else None,
        "version_id": getattr(args, "version_id", None),
        "verified_ranges": result["verified_ranges"] if result else [],
        "chunk_count": result["chunk_count"] if result else None,
        "encryption_mode": result["encryption_mode"] if result else None,
        "encrypted_key_restore_verified": (
            result["encrypted_key_restore_verified"] if result else None),
        "independent_attestation_checked": bool(
            getattr(args, "object_sha256", None)),
        "telegram_uploads": 0,
        "telegram_deletions": 0,
        "source_database_modified": False,
        "failure": failure,
        "redaction_note": (
            "bucket, key, account, target, chat id, api hash and session "
            "material are replaced with [REDACTED] before sharing"),
    }
    record["stderr_redacted"] = redact(stderr_text, secrets)
    record["stdout_redacted"] = redact(
        json.dumps(result, sort_keys=True) if result else "", secrets)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", type=Path,
                        help="Sealed SQL snapshot file (never the live database)")
    parser.add_argument("--sha256",
                        help="SHA-256 receipt recorded when the snapshot was sealed")
    parser.add_argument("--bucket",
                        help="Original bucket holding the sample object")
    parser.add_argument("--key", help="Original object key to verify")
    parser.add_argument("--account",
                        help="Original SQL account label that stored the object")
    parser.add_argument("--chat-id", type=int,
                        help="Original Telegram chat id of the channel")
    parser.add_argument("--target", default=None,
                        help="Channel username or id; defaults to --chat-id")
    parser.add_argument("--version-id", default=None,
                        help="Optional published VersionId instead of the current head")
    parser.add_argument("--object-sha256", default=None,
                        help="Independently known full-object SHA-256 to cross-check")
    parser.add_argument("--object-size", type=int, default=None,
                        help="Independently known full-object size to cross-check")
    parser.add_argument("--master-key-file", type=Path, default=None,
                        help="Deployment master key file, for envelope-encrypted objects")
    parser.add_argument("--evidence-dir", type=Path, default=None,
                        help="Private 0700 directory for the redacted evidence record")
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024,
                        help="Explicit per-object read budget (default 64 MiB)")
    parser.add_argument("--self-test", action="store_true",
                        help="Run the offline synthetic self-test and exit")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    missing = ["--" + name.replace("_", "-") for name in
               ("snapshot", "sha256", "bucket", "key", "account", "chat_id")
               if getattr(args, name) in (None, "")]
    if missing:
        parser.error("the following arguments are required: " + ", ".join(missing))
    stderr_capture = io.StringIO()
    result: dict | None = None
    failure: dict | None = None
    exit_code = EXIT_PASS
    try:
        with contextlib.redirect_stderr(stderr_capture):
            if (not os.environ.get("TELEDRIVE_STORAGE_MTPROTO_API_ID")
                    or not os.environ.get("TELEDRIVE_STORAGE_MTPROTO_API_HASH")):
                raise MissingEnvironment(
                    "TELEDRIVE_STORAGE_MTPROTO_API_ID and "
                    "TELEDRIVE_STORAGE_MTPROTO_API_HASH must be set")
            api_id = int(os.environ["TELEDRIVE_STORAGE_MTPROTO_API_ID"])
            api_hash = os.environ["TELEDRIVE_STORAGE_MTPROTO_API_HASH"]
            session_file = Path(os.environ.get(
                "TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE",
                "config/mtproto-user.session",
            ))
            envelope_kek = (_load_envelope_kek(args.master_key_file)
                            if args.master_key_file else None)
            result = asyncio.run(verify_original_user_channel(
                args.snapshot, args.sha256, bucket=args.bucket, key=args.key,
                account=args.account, chat_id=args.chat_id, target=args.target,
                session_file=session_file, api_id=api_id, api_hash=api_hash,
                max_bytes=args.max_bytes, version_id=args.version_id,
                object_sha256=args.object_sha256, object_size=args.object_size,
                envelope_kek=envelope_kek,
            ))
    except Exception as exc:
        failure = {"exit_code": exit_code_for(exc),
                   "error_type": type(exc).__name__}
        exit_code = failure["exit_code"]
    if args.evidence_dir is not None:
        session_file = Path(os.environ.get(
            "TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE",
            "config/mtproto-user.session",
        ))
        record = _build_evidence_record(
            args, result, failure, stderr_capture.getvalue(),
            _operator_secrets(args, session_file))
        try:
            path = write_evidence_record(args.evidence_dir, record)
            if result is not None:
                result["evidence_file"] = str(path)
        except OSError as exc:
            failure = {"exit_code": exit_code_for(exc),
                       "error_type": type(exc).__name__}
            exit_code = EXIT_FAILURE
    if failure is not None:
        sys.stderr.write(
            f"DR rehearsal failed: {failure['error_type']} "
            f"(exit {exit_code}); see docs/operate/dr-checklist.md\n")
        return exit_code
    print(json.dumps(result, sort_keys=True))
    return EXIT_PASS


# --- Offline self-test -------------------------------------------------------


class _SyntheticByteBackend:
    """Disk-free stand-in for one Telegram channel's message store."""

    def __init__(self, chat_id: int):
        self.chat_id = chat_id
        self.messages: dict[int, bytes] = {}
        self.sent = 0
        self.downloads = 0
        self.deletions = 0

    async def send_file(self, target, path, caption=None, force_document=False):
        self.sent += 1
        self.messages[self.sent] = Path(path).read_bytes()
        return SimpleNamespace(id=self.sent, chat_id=self.chat_id)

    async def get_peer_id(self, target):
        return self.chat_id

    async def get_messages(self, peer, ids):
        return SimpleNamespace(id=ids, media=ids in self.messages)

    async def download_media(self, message, file):
        self.downloads += 1
        if message.id not in self.messages:
            raise FileNotFoundError("Synthetic message was removed")
        Path(file).write_bytes(self.messages[message.id])
        return str(file)

    async def delete_messages(self, chat_id, message_ids, revoke=False):
        self.deletions += 1
        raise AssertionError("The DR rehearsal must never delete messages")


def _build_self_test_fixture(root: Path) -> SimpleNamespace:
    """A synthetic live catalog, its sealed snapshot and its byte backend."""
    from scripts.ops.backup_metadata import backup_sqlite

    live = root / "live"
    live.mkdir()
    state = live / "state.db"
    backend = _SyntheticByteBackend(-1001234567890)
    payload = bytes((index * 31 + 7) % 256 for index in range(150_003))
    secret_payload = bytes((index * 17 + 3) % 256 for index in range(200_001))
    kek = derive_kek(b"self-test master key material")
    plaintext = live / "sample.bin"
    plaintext.write_bytes(payload)
    encrypted = live / "encrypted.bin"
    encrypted.write_bytes(secret_payload)
    db = connect_database(str(state))
    try:
        catalog = BucketCatalog(ManifestStore(db))
        catalog.create_bucket("dr-selftest", int(time.time()))
        transport = TelethonChunkTransport({"api-bot": (backend, object())})
        engine = TelegramObjectStorage(
            catalog.manifests, transport, chunk_size=64 * 1024,
            scratch_directory=live,
        )
        stored = asyncio.run(engine.put_file(
            "dr-selftest", "originals/sample.bin", plaintext))
        catalog.publish(stored.id, now=int(time.time()))
        sealed_secret = asyncio.run(engine.put_file(
            "dr-selftest", "originals/encrypted.bin", encrypted,
            envelope_kek=kek))
        catalog.publish(sealed_secret.id, now=int(time.time()))
        # An object journaled under a distinct original USER account: a
        # reader under any other account label must be refused.
        owner_only = live / "owner-stored.bin"
        owner_only.write_bytes(bytes(range(256)) * 4)
        owner_engine = TelegramObjectStorage(
            catalog.manifests,
            TelethonChunkTransport({"original-owner": (backend, object())}),
            chunk_size=64 * 1024, scratch_directory=live,
        )
        owner_stored = asyncio.run(owner_engine.put_file(
            "dr-selftest", "originals/owner-stored.bin", owner_only))
        catalog.publish(owner_stored.id, now=int(time.time()))
    finally:
        db.close()
    archive = root / "sealed-archive.db"
    receipt = backup_sqlite(state, archive)
    return SimpleNamespace(
        state=state, archive=archive, receipt=receipt, backend=backend,
        payload=payload, secret_payload=secret_payload, kek=kek,
        state_sha256=hashlib.sha256(state.read_bytes()).hexdigest(),
        sent_after_seed=backend.sent,
    )


def _self_test() -> int:
    """Prove the rehearsal machinery end to end without owner data."""
    chat_id = -1001234567890
    scenarios: list[dict] = []

    def expect_failure(name, invoke, expected_type, expected_exit):
        try:
            invoke()
        except expected_type as exc:
            actual = exit_code_for(exc)
            scenarios.append({"name": name, "outcome":
                              "PASS" if actual == expected_exit else "FAIL",
                              "expected_exit": expected_exit, "exit": actual})
            if actual != expected_exit:
                raise AssertionError(
                    f"{name}: expected exit {expected_exit}, got {actual}")
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            raise AssertionError(
                f"{name}: expected {expected_type.__name__}, "
                f"got {type(exc).__name__}") from exc
        else:
            raise AssertionError(
                f"{name}: expected {expected_type.__name__}, nothing raised")

    try:
        with tempfile.TemporaryDirectory(
                prefix="teledrive-dr-selftest-") as dirname:
            fixture = _build_self_test_fixture(Path(dirname))
            base = dict(bucket="dr-selftest", account="api-bot", chat_id=chat_id)

            def reader(account="owner-user"):
                return ReadOnlyUserChannelTransport(
                    fixture.backend, object(), account=account, chat_id=chat_id)

            def run(**overrides):
                options = dict(base, transport=reader())
                options.update(overrides)
                return asyncio.run(verify_restored_telegram_object(
                    fixture.archive, fixture.receipt, **options))

            # Full happy path: snapshot receipt, independent attestation,
            # full bytes and first/middle/cross-boundary/last ranges.
            archive_before = fixture.archive.read_bytes()
            report = run(key="originals/sample.bin",
                         object_sha256=hashlib.sha256(
                             fixture.payload).hexdigest(),
                         object_size=len(fixture.payload))
            labels = {entry[0] for entry in report["verified_ranges"]}
            assert report["verified"] and report["claim"] == SAMPLE_CLAIM
            assert report["verified_object_count"] == 1
            assert report["size"] == report["readback_bytes"] == len(fixture.payload)
            assert report["sha256"] == hashlib.sha256(fixture.payload).hexdigest()
            assert report["archive_sha256"] == fixture.receipt
            assert report["encryption_mode"] == "plaintext"
            assert report["independent_attestation_checked"] is True
            assert {"first", "middle", "last"} <= labels
            assert any(label.startswith("cross-boundary-")
                       for label in labels), "no cross-boundary range verified"
            assert report["chunk_count"] == 3
            assert report["telegram_uploads"] == report["telegram_deletions"] == 0
            assert report["source_database_modified"] is False
            assert fixture.archive.read_bytes() == archive_before
            assert hashlib.sha256(
                fixture.state.read_bytes()).hexdigest() == fixture.state_sha256
            assert fixture.backend.sent == fixture.sent_after_seed
            scenarios.append({"name": "sample-object-verified", "outcome": "PASS",
                              "expected_exit": EXIT_PASS, "exit": EXIT_PASS})

            # Envelope-encrypted object restores only with the master key.
            encrypted_report = run(
                key="originals/encrypted.bin", envelope_kek=fixture.kek,
                object_sha256=hashlib.sha256(
                    fixture.secret_payload).hexdigest())
            assert encrypted_report["verified"]
            assert encrypted_report["encryption_mode"] == "SSE-S3"
            assert encrypted_report["encrypted_key_restore_verified"] is True
            assert encrypted_report["sha256"] == hashlib.sha256(
                fixture.secret_payload).hexdigest()
            scenarios.append({"name": "encrypted-key-restore-verified",
                              "outcome": "PASS", "expected_exit": EXIT_PASS,
                              "exit": EXIT_PASS})

            # Wrong snapshot SHA-256 receipt: refuse before any restore.
            try:
                asyncio.run(verify_restored_telegram_object(
                    fixture.archive, "0" * 64, **dict(
                        base, key="originals/sample.bin", transport=reader())))
                raise AssertionError("wrong receipt was accepted")
            except InvalidSnapshot as exc:
                assert exit_code_for(exc) == EXIT_SNAPSHOT_REJECTED
                scenarios.append({"name": "snapshot-digest-refused",
                                  "outcome": "PASS",
                                  "expected_exit": EXIT_SNAPSHOT_REJECTED,
                                  "exit": EXIT_SNAPSHOT_REJECTED})

            # Missing object in the restored catalog.
            expect_failure("missing-object",
                           lambda: run(key="originals/absent.bin"),
                           FileNotFoundError, EXIT_OBJECT_NOT_FOUND)

            # Unauthorized account/channel scope.
            expect_failure("scope-refused",
                           lambda: run(key="originals/owner-stored.bin",
                                       transport=reader("intruder")),
                           ScopeError, EXIT_SCOPE_REFUSED)

            # Corrupt remote chunk bytes.
            pristine = dict(fixture.backend.messages)
            fixture.backend.messages[1] = b"corrupted-payload" * 512
            expect_failure("corrupt-chunk",
                           lambda: run(key="originals/sample.bin"),
                           IntegrityError, EXIT_VERIFICATION_FAILED)
            fixture.backend.messages.clear()
            fixture.backend.messages.update(pristine)

            # Missing remote chunk message.
            del fixture.backend.messages[2]
            expect_failure("missing-remote-chunk",
                           lambda: run(key="originals/sample.bin"),
                           FileNotFoundError, EXIT_OBJECT_NOT_FOUND)
            fixture.backend.messages.clear()
            fixture.backend.messages.update(pristine)

            # Encrypted object without key material.
            expect_failure("encrypted-without-key",
                           lambda: run(key="originals/encrypted.bin"),
                           KeyMaterialError, EXIT_KEY_MATERIAL)

            # Read-only invariants across every scenario.
            invariants = {
                "source_database_modified": (
                    hashlib.sha256(fixture.state.read_bytes()).hexdigest()
                    != fixture.state_sha256),
                "archive_modified": (
                    fixture.archive.read_bytes() != archive_before),
                "telegram_uploads": (
                    fixture.backend.sent - fixture.sent_after_seed),
                "telegram_deletions": fixture.backend.deletions,
            }
            assert invariants == {"source_database_modified": False,
                                  "archive_modified": False,
                                  "telegram_uploads": 0,
                                  "telegram_deletions": 0}
    except AssertionError as exc:
        print(json.dumps({"self_test": "FAIL", "error": str(exc),
                          "scenarios": scenarios}, sort_keys=True))
        return 1
    print(json.dumps({"self_test": "PASS", "scenarios": scenarios,
                      "read_only_invariants": {
                          "source_database_modified": False,
                          "archive_modified": False,
                          "telegram_uploads": 0,
                          "telegram_deletions": 0,
                      }}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
