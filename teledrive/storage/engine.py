"""Telegram-backed immutable object write/read engine.

Each successful write stores all bytes in Telegram and atomically publishes a
SQL manifest. Staging is temporary; it is NEVER a durable S3 primary backend.
A failed/interrupted upload remains invisible until explicitly reconciled.

This module intentionally does not implement S3's HTTP semantics yet.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import os
import stat
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import AsyncIterator, Protocol
from uuid import uuid4

from sqlalchemy import delete, insert, select, update

from .manifest import (ChunkReference, ManifestStore, StoredObject,
                       ManifestError, chunks, content_index, object_encryption,
                       object_aliases, objects, replica_chunks)
from .sse import (SSECError, SSECKey, decrypt_chunk, encrypt_chunk,
                  verify_chunk_layout, verify_key_md5)

_engine_logger = logging.getLogger(__name__)


class IntegrityError(RuntimeError):
    """Source or Telegram chunk is missing, truncated or checksum-mismatched."""


class TelegramTransport(Protocol):
    async def upload(self, path: Path, *, object_id: str, ordinal: int,
                     checksum: str) -> tuple[str, int, int]:
        """Upload bytes and return (account_name, Telegram chat_id, message_id)."""
        ...

    async def download(self, reference: ChunkReference, destination: Path) -> None:
        """Download exactly one Telegram message body to a local regular file."""
        ...


def _regular_source(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    handle = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
        handle.close()
        raise ValueError("Source must be a regular file")
    return handle


def _digest_file(path: Path) -> tuple[int, str]:
    sha = hashlib.sha256()
    total = 0
    with _regular_source(path) as f:
        while block := f.read(1024 * 1024):
            sha.update(block)
            total += len(block)
    return total, sha.hexdigest()


class TelegramObjectStorage:
    def __init__(self, manifests: ManifestStore, transport: TelegramTransport,
                 *, chunk_size: int = 64 * 1024 * 1024,
                 scratch_directory: Path | None = None,
                 writer_ttl_seconds: int = 120):
        if chunk_size <= 0 or chunk_size > 1024 * 1024 * 1024:
            raise ValueError("chunk_size must be between 1 byte and 1 GiB")
        self.manifests = manifests
        self.transport = transport
        self.chunk_size = chunk_size
        self.scratch_directory = scratch_directory
        if writer_ttl_seconds < 5:
            raise ValueError("writer_ttl_seconds must be at least 5")
        self.writer_ttl_seconds = writer_ttl_seconds

    async def _keep_writer_alive(self, identifier: str, token: str,
                                 stop: asyncio.Event, lost: asyncio.Event) -> None:
        interval = max(1, self.writer_ttl_seconds // 3)
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
                return
            except asyncio.TimeoutError:
                pass
            try:
                if not self.manifests.heartbeat_writer(
                    identifier, token, int(time.time()), self.writer_ttl_seconds
                ):
                    lost.set()
                    return
            except Exception:
                lost.set()
                return

    async def put_file(self, bucket: str, key: str, source: Path, *,
                       on_begin=None, dedup: bool = True,
                       sse_key: SSECKey | None = None,
                       envelope_kek: bytes | None = None,
                       sse_mode: str | None = None) -> StoredObject:
        if sse_key is not None or envelope_kek is not None:
            # SSE-C content is deliberately not content-addressed: the same
            # plaintext under another key (or unencrypted) must never share
            # Telegram ciphertext.  AWS has the same property.
            dedup = False
        from teledrive.storage.placement import (
            reset_upload_bucket, set_upload_bucket)
        # Publish the bucket for the transport's placement decisions
        # (bucket→account pinning); scoped to this object's upload.
        placement_token = set_upload_bucket(bucket)
        try:
            # Content-addressed dedup is skipped for internal staging
            # uploads (multipart parts): completion physically re-owns
            # the staged parts' chunk rows, which requires them to be
            # chunked objects rather than aliases. Staging uploads are
            # not replicated either — completion re-owns their chunks,
            # so replica rows would point at the wrong object id.
            if dedup:
                deduped = self._dedup_lookup(source, bucket, key)
                if deduped is not None:
                    return deduped
            return await self._put_file_inner(
                bucket, key, source, on_begin=on_begin, replicate=dedup,
                sse_key=sse_key, envelope_kek=envelope_kek, sse_mode=sse_mode)
        finally:
            reset_upload_bucket(placement_token)

    def _dedup_lookup(self, source: Path, bucket: str,
                      key: str) -> StoredObject | None:
        """Content-addressed deduplication: identical published content
        is aliased instead of re-sent to Telegram.

        One local hashing pass (cheap next to a Telegram upload); a hit
        creates a fresh alias object for this bucket/key pointing at the
        existing content — the same aliasing mechanism CopyObject uses,
        fully GC-aware. Concurrent identical uploads may both miss (the
        loser's chunks simply remain for owner-gated GC).
        """
        try:
            digest = hashlib.sha256()
            size = 0
            with open(source, "rb") as handle:
                while block := handle.read(1 << 20):
                    digest.update(block)
                    size += len(block)
            if size == 0:
                return None  # empty objects are tiny; keep the normal path
            from sqlalchemy import text as _text
            from teledrive.storage.manifest import object_aliases, objects
            db = self.manifests.db
            # Encrypted objects store a plaintext SHA-256 in the manifest
            # for per-chunk integrity, but their Telegram bytes are
            # ciphertext.  Plaintext uploads must never alias them, and
            # uploads under different customer keys must never alias each
            # other, so every SSE-C object is excluded from dedup.
            base = db.connection.execute(_text(
                "SELECT id FROM storage_objects WHERE sha256 = :sha "
                "AND status = 'ready' AND NOT EXISTS ("
                "SELECT 1 FROM storage_object_encryption e "
                "WHERE e.object_id = storage_objects.id"
                ") LIMIT 1"
            ), {"sha": digest.hexdigest()}).scalar_one_or_none()
            if base is None:
                return None
            base_id = self.manifests.resolve_content_id(base)
            base_obj = self.manifests.get(base_id)
            identifier = str(uuid4())
            now = int(time.time())
            db.connection.execute(insert(objects).values(
                id=identifier, bucket=bucket,
                object_key=key, status="ready", size=base_obj.size,
                sha256=base_obj.sha256, created_at=now, updated_at=now,
                error=None,
            ))
            db.connection.execute(insert(object_aliases).values(
                object_id=identifier, source_object_id=base_id,
            ))
            db.connection.commit()
            return StoredObject(
                id=identifier, bucket=bucket, key=key,
                size=base_obj.size, sha256=base_obj.sha256,
                created_at=now,
            )
        except Exception:
            # Dedup is an optimization: any failure falls back to a
            # normal upload.
            try:
                self.manifests.db.connection.rollback()
            except Exception:
                pass
            return None

    def _replica_target(self) -> str | None:
        """Live replication target from the transport, if any."""
        resolver = getattr(self.transport, "replica_account", None)
        try:
            return resolver() if callable(resolver) else None
        except Exception:
            return None

    def replication_destination(self, bucket: str, key: str) -> str | None:
        """The replica account label for one object, or None.

        A stored per-bucket S3 replication configuration is authoritative:
        when it exists but no enabled rule matches this key the object is
        deliberately not replicated (a configured prefix must never be
        silently ignored). Only buckets with no configuration fall back to
        the operator-wide ``storage.replica_account`` setting.
        """
        try:
            from teledrive.s3.replication import matching_destination
            configured, destination = matching_destination(
                self.manifests.db, bucket, key)
        except Exception:
            # An unreadable configuration disables replication for this
            # object rather than replicating against an unintended target.
            _engine_logger.warning(
                "replication configuration unreadable for %s/%s; "
                "replication disabled for this object", bucket, key,
                exc_info=True)
            return None
        if configured:
            return destination
        return self._replica_target()

    async def _replicate_chunk(self, identifier: str, ordinal: int,
                               checksum: str, part_path: Path,
                               primary_account: str,
                               replica: str | None) -> None:
        """Best-effort second Telegram copy of one chunk.

        The primary copy remains the source of truth: a failed replica
        send never fails the upload — the chunk is simply left for a
        later repair sweep. ``replica`` is the already-resolved decision
        (None means "do not replicate", never "use the global default").
        """
        if not replica or replica == primary_account:
            return
        try:
            account, chat_id, message_id = await self.transport.upload(
                part_path, object_id=identifier, ordinal=ordinal,
                checksum=checksum, force_account=replica,
            )
            self.manifests.append_replica(
                identifier, ordinal, account, int(chat_id),
                int(message_id), int(time.time()))
        except Exception:
            _engine_logger.warning(
                "replica send failed for object %s chunk %d",
                identifier, ordinal, exc_info=True)

    def _replica_ref(self, identifier: str, part: ChunkReference):
        """Replica coordinates for one chunk, as a fallback reference."""
        try:
            coords = self.manifests.replica_refs(identifier).get(part.ordinal)
            if not coords or coords[0] == part.account:
                return None
            return replace(part, account=coords[0], chat_id=coords[1],
                           message_id=coords[2])
        except Exception:
            return None

    async def repair_replicas(self, identifier: str) -> int:
        """Re-send the object's missing replica chunks; returns the count.

        Each primary chunk is downloaded and digest-verified before it is
        re-sent to the replica account, so a corrupt primary can never
        propagate into the replica copy. The target is resolved per object
        from its bucket's replication configuration (falling back to the
        operator-wide account only when the bucket has no configuration).
        """
        obj = self.manifests.get(identifier)
        replica = self.replication_destination(obj.bucket, obj.key)
        if not replica:
            return 0
        content_id = self.manifests.resolve_content_id(identifier)
        parts = self.manifests.parts(content_id)
        refs = self.manifests.replica_refs(content_id)
        repaired = 0
        with tempfile.TemporaryDirectory(
            prefix="teledrive-replica-", dir=self.scratch_directory
        ) as scratch:
            root = Path(scratch)
            for part in parts:
                coords = refs.get(part.ordinal)
                if coords is not None and coords[0] == replica:
                    continue
                target = root / f"part-{part.ordinal:08d}"
                await self.transport.download(part, target)
                size, sha = _digest_file(target)
                if size != part.ciphertext_size or sha != part.sha256:
                    raise IntegrityError(
                        "Primary chunk failed verification; refusing to "
                        "replicate corrupt bytes")
                account, chat_id, message_id = await self.transport.upload(
                    target, object_id=content_id, ordinal=part.ordinal,
                    checksum=part.sha256, force_account=replica,
                )
                self.manifests.append_replica(
                    content_id, part.ordinal, account, int(chat_id),
                    int(message_id), int(time.time()))
                repaired += 1
        return repaired

    async def _put_file_inner(self, bucket: str, key: str, source: Path, *,
                              on_begin=None, replicate: bool = False,
                              sse_key: SSECKey | None = None,
                              envelope_kek: bytes | None = None,
                              sse_mode: str | None = None
                              ) -> StoredObject:
        source = Path(source)
        with _regular_source(source) as handle:
            before = os.fstat(handle.fileno())
            identifier = self.manifests.begin(
                bucket, key, before.st_size, int(time.time()),
                sse_key_md5=(sse_key.key_md5_b64 if sse_key else None),
                envelope_kek=envelope_kek,
                sse_mode=sse_mode,
            )
            if envelope_kek is not None:
                # begin() generated the data key and stored only its wrapped
                # form; unwrap it here to encrypt this object's chunks.
                sse_key = self.manifests.envelope_key(identifier, envelope_kek)
            token = secrets.token_hex(24)
            self.manifests.start_writer(identifier, token, int(time.time()), self.writer_ttl_seconds)
            stop = asyncio.Event()
            lost = asyncio.Event()
            renewal = asyncio.create_task(self._keep_writer_alive(identifier, token, stop, lost))
            full_sha = hashlib.sha256()
            cipher_sha = hashlib.sha256() if sse_key is not None else None
            offset = 0
            ordinal = 0
            # Resolve the replica decision once per object: a stored
            # bucket configuration is prefix-aware, so every chunk of the
            # object shares the same answer.
            replica = (self.replication_destination(bucket, key)
                       if replicate else None)
            try:
                if on_begin is not None:
                    on_begin(identifier)
                degree_fn = getattr(self.transport, "parallel_degree", None)
                concurrency = degree_fn() if callable(degree_fn) else 1
                with tempfile.TemporaryDirectory(
                    prefix="teledrive-chunks-", dir=self.scratch_directory
                ) as scratch:
                    root = Path(scratch)
                    staged: list[tuple[int, int, int, str, Path, dict | None]] = []
                    while data := handle.read(self.chunk_size):
                        full_sha.update(data)
                        metadata = None
                        if sse_key is not None:
                            payload, metadata = encrypt_chunk(
                                sse_key, identifier, ordinal, data)
                            cipher_sha.update(payload)
                        else:
                            payload = data
                        # The stored/Telegram digest is always the digest of
                        # the bytes Telegram holds: ciphertext for SSE-C.
                        digest = hashlib.sha256(payload).hexdigest()
                        part = root / f"part-{ordinal:08d}"
                        with part.open("xb") as f:
                            f.write(payload)
                        part.chmod(0o600)
                        staged.append(
                            (ordinal, offset, len(data), digest, part, metadata)
                        )
                        offset += len(data)
                        ordinal += 1
                    # parallel strategy uploads up to one chunk per
                    # credential set concurrently; every other transport
                    # stays strictly sequential.
                    for index in range(0, len(staged), max(concurrency, 1)):
                        batch = staged[index:index + max(concurrency, 1)]
                        results = await asyncio.gather(*[
                            self.transport.upload(
                                part_path, object_id=identifier,
                                ordinal=ordinal_number, checksum=digest,
                            )
                            for (ordinal_number, _, _, digest,
                                 part_path, _metadata) in batch
                        ])
                        for (ordinal_number, part_offset, part_size, digest,
                             part_path, metadata), (account, chat_id,
                                                    message_id) in zip(
                                batch, results):
                            # The remote message may already exist if our SQL
                            # lease expired: reject publication and leave the
                            # marker for GC.
                            if lost.is_set() or not self.manifests.heartbeat_writer(
                                identifier, token, int(time.time()),
                                self.writer_ttl_seconds,
                            ):
                                raise ManifestError(
                                    "Writer ownership lost before chunk journal"
                                )
                            self.manifests.append(identifier, ChunkReference(
                                ordinal=ordinal_number, offset=part_offset,
                                size=part_size, sha256=digest,
                                account=account, chat_id=int(chat_id),
                                message_id=int(message_id),
                                encryption=metadata,
                            ), int(time.time()), writer_token=token)
                            if replicate:
                                await self._replicate_chunk(
                                    identifier, ordinal_number, digest,
                                    part_path, account, replica)
                            part_path.unlink()
                after = os.fstat(handle.fileno())
                if (offset != before.st_size or before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_size != after.st_size):
                    raise IntegrityError("Source changed during upload")
                if lost.is_set() or not self.manifests.heartbeat_writer(
                    identifier, token, int(time.time()), self.writer_ttl_seconds
                ):
                    raise ManifestError("Writer ownership lost before publication")
                result = self.manifests.finish(
                    identifier, full_sha.hexdigest(), int(time.time()),
                    writer_token=token,
                    encryption_etag=(cipher_sha.hexdigest()
                                     if cipher_sha is not None else None),
                )
                # Content search indexes PLAINTEXT.  SSE-C objects are
                # excluded by design: the server never retains the key and
                # must not leak plaintext into a searchable index.
                if sse_key is None:
                    try:
                        from .content_index import index_object_content
                        index_object_content(
                            self.manifests.db, result.id, source, key)
                    except Exception:
                        pass
                return result
            except BaseException as exc:
                # Do not delete recorded Telegram chunks here. They form a
                # recovery journal and may be needed by a later reconciler.
                try:
                    self.manifests.fail(identifier, type(exc).__name__, int(time.time()),
                                        writer_token=token)
                except Exception:
                    pass
                raise
            finally:
                stop.set()
                await renewal

    async def resume_file(self, bucket: str, key: str, source: Path,
                          identifier: str) -> StoredObject:
        """Resume journaled chunks after reclaiming an expired SQL writer.

        All saved Telegram messages and the corresponding source ranges are
        independently read/verified before uploading any missing tail bytes.
        A Bot API ACK committed to its SQL receipt index (but not to the
        chunk journal) can be recovered after independent byte-for-byte
        verification. Unknown ACKs still require manual reconciliation.
        No Telegram message is ever deleted by resume.
        """
        source = Path(source)
        if self.manifests.raw_encryption_info(identifier) is not None:
            # The client key is intentionally not stored, so an interrupted
            # SSE-C upload cannot be resumed without it.  Fail closed rather
            # than publishing or adopting unauthenticated bytes.
            raise SSECError(
                "InvalidRequest",
                "Interrupted SSE-C uploads cannot be resumed: the customer "
                "key is not retained")
        with _regular_source(source) as handle:
            before = os.fstat(handle.fileno())
            row = self.manifests.db.connection.execute(
                select(objects.c.bucket, objects.c.object_key, objects.c.size,
                       objects.c.status).where(objects.c.id == identifier)
            ).one_or_none()
            if (row is None or row[0] != bucket or row[1] != key
                    or int(row[2]) != before.st_size or row[3] != "pending"):
                raise ManifestError("Resumable manifest identity is invalid")
            token = secrets.token_hex(24)
            if not self.manifests.reclaim_writer(
                identifier, token, int(time.time()), self.writer_ttl_seconds
            ):
                raise ManifestError("Cannot reclaim an active or non-pending writer")
            stop, lost = asyncio.Event(), asyncio.Event()
            renewal = asyncio.create_task(
                self._keep_writer_alive(identifier, token, stop, lost)
            )
            full_sha = hashlib.sha256()
            offset, ordinal = 0, 0
            try:
                with tempfile.TemporaryDirectory(
                    prefix="teledrive-resume-", dir=self.scratch_directory
                ) as scratch:
                    root = Path(scratch)
                    for ref in self.manifests.recovery_parts(identifier):
                        if (ref.ordinal != ordinal or ref.offset != offset
                                or ref.size <= 0 or offset + ref.size > before.st_size):
                            raise ManifestError("Noncontiguous resumable chunk journal")
                        existing = root / f"saved-{ordinal:08d}"
                        await self.transport.download(ref, existing)
                        if not existing.is_file() or existing.stat().st_size != ref.size:
                            raise IntegrityError("Saved Telegram chunk missing or truncated")
                        section_sha = hashlib.sha256()
                        with existing.open("rb") as remote:
                            remaining = ref.size
                            while remaining:
                                amount = min(1024 * 1024, remaining)
                                local = handle.read(amount)
                                saved = remote.read(amount)
                                if len(local) != amount or saved != local:
                                    raise IntegrityError("Resumable Telegram bytes differ from source")
                                section_sha.update(local)
                                full_sha.update(local)
                                remaining -= amount
                        if section_sha.hexdigest() != ref.sha256:
                            raise IntegrityError("Resumable journal checksum mismatch")
                        existing.unlink()
                        offset += ref.size
                        ordinal += 1
                    while data := handle.read(self.chunk_size):
                        checksum = hashlib.sha256(data).hexdigest()
                        full_sha.update(data)
                        part = root / f"part-{ordinal:08d}"
                        with part.open("xb") as output:
                            output.write(data)
                        part.chmod(0o600)
                        find_receipt = getattr(self.transport, "recover_receipt", None)
                        receipt = (
                            find_receipt(identifier, ordinal, checksum, len(data))
                            if callable(find_receipt) else None
                        )
                        if receipt is not None:
                            # SQL ACK receipt is NOT proof of Telegram content.
                            # Reject missing/changed/foreign data instead of
                            # silently retransmitting or adopting wrong bytes.
                            if (receipt.ordinal != ordinal or receipt.size != len(data)
                                    or receipt.sha256 != checksum):
                                raise IntegrityError("Recovered ACK chunk metadata mismatch")
                            recovered = root / f"receipt-{ordinal:08d}"
                            await self.transport.download(receipt, recovered)
                            if (not recovered.is_file() or recovered.is_symlink()
                                    or recovered.stat().st_size != len(data)
                                    or recovered.read_bytes() != data):
                                raise IntegrityError("Recovered ACK bytes differ from source")
                            recovered.unlink()
                            account, chat_id, message_id = (
                                receipt.account, receipt.chat_id, receipt.message_id
                            )
                        else:
                            account, chat_id, message_id = await self.transport.upload(
                                part, object_id=identifier, ordinal=ordinal,
                                checksum=checksum,
                            )
                        if lost.is_set() or not self.manifests.heartbeat_writer(
                            identifier, token, int(time.time()), self.writer_ttl_seconds
                        ):
                            raise ManifestError("Resumed writer ownership lost")
                        self.manifests.append(
                            identifier, ChunkReference(
                                ordinal=ordinal, offset=offset, size=len(data),
                                sha256=checksum, account=account,
                                chat_id=int(chat_id), message_id=int(message_id),
                            ), int(time.time()), writer_token=token,
                        )
                        part.unlink()
                        offset += len(data)
                        ordinal += 1
                after = os.fstat(handle.fileno())
                if (offset != before.st_size or before.st_dev != after.st_dev
                        or before.st_ino != after.st_ino
                        or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_size != after.st_size):
                    raise IntegrityError("Resumed source changed during upload")
                if lost.is_set() or not self.manifests.heartbeat_writer(
                    identifier, token, int(time.time()), self.writer_ttl_seconds
                ):
                    raise ManifestError("Resumed writer ownership lost before publication")
                return self.manifests.finish(
                    identifier, full_sha.hexdigest(), int(time.time()),
                    writer_token=token,
                )
            except BaseException as exc:
                try:
                    self.manifests.fail(identifier, type(exc).__name__,
                                        int(time.time()), writer_token=token)
                except Exception:
                    pass
                raise
            finally:
                stop.set()
                await renewal

    async def _verified_fetch(self, part: ChunkReference,
                              target: Path) -> None:
        """Download one chunk reference, digest-verified, bounded retries.

        Telegram's remote file endpoint can occasionally return incorrect
        bytes on an otherwise successful HTTPS response. A GET may safely
        be repeated; a send MUST NOT be. Never expose any bytes until the
        independently journaled digest validates.
        """
        for attempt in range(3):
            target.unlink(missing_ok=True)
            await self.transport.download(part, target)
            if not target.is_file() or target.is_symlink():
                raise IntegrityError("Telegram chunk missing or unsafe")
            size, sha = _digest_file(target)
            if size == part.ciphertext_size and sha == part.sha256:
                return
            target.unlink(missing_ok=True)
            if attempt == 2:
                raise IntegrityError("Telegram chunk checksum mismatch")
            await asyncio.sleep(0.25 * (attempt + 1))

    async def iter_bytes(self, identifier: str, *,
                         start: int = 0, end: int | None = None,
                         block_size: int = 1024 * 1024,
                         sse_key: SSECKey | None = None,
                         envelope_kek: bytes | None = None) -> AsyncIterator[bytes]:
        """Stream a half-open [start,end) range, verifying each downloaded chunk.

        For an SSE-C object only the chunks overlapping the requested range
        are fetched and decrypted (GCM authenticates the whole chunk, then
        the plaintext is sliced), so a 1-byte range never decrypts the
        whole object.
        """
        obj = self.manifests.get(identifier)
        if end is None:
            end = obj.size
        if block_size <= 0 or start < 0 or end < start or end > obj.size:
            raise ValueError("Invalid range or block size")
        if start == end:
            return
        parts = self.manifests.parts(identifier)
        info = self.manifests.encryption_info(identifier)
        if info is not None and info.get("mode") == "SSE-S3":
            # Envelope: the server holds the key, so a caller that has the
            # master key does not need to supply one explicitly.
            if sse_key is None:
                if envelope_kek is None:
                    raise SSECError(
                        "InvalidRequest",
                        "The object is server-side encrypted; this reader has "
                        "no master key")
                sse_key = self.manifests.envelope_key(identifier, envelope_kek)
        if info is not None:
            if sse_key is None:
                raise SSECError(
                    "InvalidRequest",
                    "The object was stored with SSE-C; supply the customer key")
            verify_key_md5(info, sse_key)
            verify_chunk_layout(parts, self.manifests.resolve_content_id(identifier))
        elif sse_key is not None:
            raise SSECError(
                "InvalidRequest",
                "The object was not stored with SSE-C; remove the customer key")
        expected = 0
        with tempfile.TemporaryDirectory(
            prefix="teledrive-read-", dir=self.scratch_directory
        ) as scratch:
            root = Path(scratch)
            for part in parts:
                if part.offset != expected:
                    raise IntegrityError("Non-contiguous chunk manifest")
                expected += part.size
                if part.offset >= end:
                    break
                if part.offset + part.size <= start:
                    continue
                target = root / f"read-{part.ordinal:08d}"
                # Telegram's remote file endpoint can occasionally return
                # incorrect bytes on an otherwise successful HTTPS response.
                # A GET may safely be repeated; a send MUST NOT be. Never
                # expose any bytes until the independently journaled digest
                # validates. Re-read the same immutable message, boundedly,
                # and fail closed if every attempt disagrees with the manifest.
                # When the primary message is unavailable or corrupt, the
                # cross-account replica is tried before failing the read.
                try:
                    await self._verified_fetch(part, target)
                except Exception:
                    replica_ref = self._replica_ref(identifier, part)
                    if replica_ref is None:
                        raise
                    await self._verified_fetch(replica_ref, target)
                local_start = max(0, start - part.offset)
                local_end = min(part.size, end - part.offset)
                if info is not None:
                    # Authenticate and decrypt exactly one overlapping chunk.
                    ciphertext = target.read_bytes()
                    plaintext = decrypt_chunk(
                        sse_key, ciphertext, part.encryption or {})
                    if len(plaintext) != part.size:
                        raise IntegrityError(
                            "Decrypted chunk length disagrees with the manifest")
                    position = local_start
                    while position < local_end:
                        block = plaintext[position:
                                          min(local_end, position + block_size)]
                        if not block:
                            raise IntegrityError(
                                "Telegram chunk truncated while streaming")
                        position += len(block)
                        yield block
                else:
                    with _regular_source(target) as file:
                        file.seek(local_start)
                        remaining = local_end - local_start
                        while remaining:
                            block = file.read(min(remaining, block_size))
                            if not block:
                                raise IntegrityError("Telegram chunk truncated while streaming")
                            remaining -= len(block)
                            yield block
                target.unlink()
            # Reaching end is only valid if manifests cover all requested bytes.
            if expected < end:
                raise IntegrityError("Missing part of requested range")

    async def iter_ciphertext(self, identifier: str, *,
                              block_size: int = 1024 * 1024) -> AsyncIterator[bytes]:
        """Stream the stored bytes (ciphertext for SSE-C) without a key.

        Used by multipart completion and rotation, which must verify and
        hash what Telegram holds but never decrypt with a key they do not
        have.  Every chunk is checked against its journaled ciphertext
        digest before any byte is yielded.
        """
        obj = self.manifests.get(identifier)
        total = 0
        with tempfile.TemporaryDirectory(
            prefix="teledrive-cipher-", dir=self.scratch_directory
        ) as scratch:
            root = Path(scratch)
            for part in self.manifests.parts(identifier):
                target = root / f"cipher-{part.ordinal:08d}"
                try:
                    await self._verified_fetch(part, target)
                except Exception:
                    replica_ref = self._replica_ref(identifier, part)
                    if replica_ref is None:
                        raise
                    await self._verified_fetch(replica_ref, target)
                total += part.size
                with _regular_source(target) as file:
                    while block := file.read(block_size):
                        yield block
                target.unlink()
        if total != obj.size:
            raise IntegrityError("Missing part of requested object")

    async def reencrypt(self, identifier: str, old_key: SSECKey | None,
                        new_key: SSECKey) -> str:
        """Rotate an object to ``new_key`` by re-encrypting every chunk.

        Bounded streaming: at most one plaintext chunk (the engine chunk
        size) is held in memory.  Chunks are re-uploaded to Telegram before
        a single SQL transaction swaps every chunk reference, the SSE-C
        marker and the ciphertext ETag.  A failure leaves the old manifest
        intact; the newly sent messages become ordinary GC candidates.
        """
        content_id = self.manifests.resolve_content_id(identifier)
        if content_id != identifier:
            raise SSECError(
                "NotImplemented",
                "Cannot rotate encryption on an aliased object; rotate the "
                "content object instead", 501)
        info = self.manifests.encryption_info(identifier)
        if info is not None:
            if old_key is None:
                raise SSECError(
                    "InvalidRequest",
                    "The object is SSE-C encrypted; supply the old customer key")
            verify_key_md5(info, old_key)
        elif old_key is not None:
            raise SSECError(
                "InvalidRequest",
                "The object is not SSE-C encrypted; remove the old key headers")
        parts = self.manifests.parts(identifier)
        if info is not None:
            verify_chunk_layout(parts, content_id)
        cipher_sha = hashlib.sha256()
        replacements: list[tuple[int, str, dict, str, str, int, int]] = []
        with tempfile.TemporaryDirectory(
            prefix="teledrive-rotate-", dir=self.scratch_directory
        ) as scratch:
            root = Path(scratch)
            for part in parts:
                current = root / f"old-{part.ordinal:08d}"
                try:
                    await self._verified_fetch(part, current)
                except Exception:
                    replica_ref = self._replica_ref(identifier, part)
                    if replica_ref is None:
                        raise
                    await self._verified_fetch(replica_ref, current)
                stored = current.read_bytes()
                if info is not None:
                    plaintext = decrypt_chunk(
                        old_key, stored, part.encryption or {})
                    if len(plaintext) != part.size:
                        raise IntegrityError(
                            "Decrypted chunk length disagrees with the manifest")
                else:
                    plaintext = stored
                # Re-encrypt under the DESTINATION object's identity so the
                # rotated chunks are bound to content_id and their final
                # manifest ordinals.
                payload, metadata = encrypt_chunk(
                    new_key, content_id, part.ordinal, plaintext)
                cipher_sha.update(payload)
                checksum = hashlib.sha256(payload).hexdigest()
                fresh = root / f"new-{part.ordinal:08d}"
                with fresh.open("xb") as handle:
                    handle.write(payload)
                fresh.chmod(0o600)
                account, chat_id, message_id = await self.transport.upload(
                    fresh, object_id=content_id, ordinal=part.ordinal,
                    checksum=checksum,
                )
                replacements.append((
                    part.ordinal, checksum, metadata, account,
                    int(chat_id), int(message_id), len(plaintext),
                ))
                current.unlink(missing_ok=True)
                fresh.unlink(missing_ok=True)
        digest = cipher_sha.hexdigest()
        now = int(time.time())
        try:
            row = self.db_ready_status(content_id)
            if row is None:
                raise SSECError("NoSuchKey", "Object is no longer readable", 404)
            for (ordinal, checksum, metadata, account, chat_id,
                 message_id, _size) in replacements:
                changed = self.manifests.db.connection.execute(
                    update(chunks).where(
                        chunks.c.object_id == content_id,
                        chunks.c.ordinal == ordinal,
                    ).values(
                        sha256=checksum, account=account, chat_id=chat_id,
                        message_id=message_id,
                        encryption=json.dumps(
                            metadata, sort_keys=True, separators=(",", ":")),
                    ))
                if changed.rowcount != 1:
                    raise ManifestError("Chunk journal changed during rotation")
            values = {
                "key_md5": new_key.key_md5_b64, "etag": digest,
                "digest_kind": ("ciphertext"
                                if info is not None
                                and info.get("digest_kind") == "ciphertext"
                                else "plaintext"),
            }
            if info is None:
                self.manifests.db.connection.execute(insert(object_encryption).values(
                    object_id=content_id, mode="SSE-C",
                    key_md5=values["key_md5"], etag=digest,
                    digest_kind=values["digest_kind"], created_at=now,
                ))
            else:
                self.manifests.db.connection.execute(
                    update(object_encryption).where(
                        object_encryption.c.object_id == content_id,
                    ).values(**values))
            if values["digest_kind"] == "ciphertext":
                self.manifests.db.connection.execute(update(objects).where(
                    objects.c.id == content_id).values(sha256=digest,
                                                       updated_at=now))
            # The old plaintext index is no longer truthful, and replica
            # rows point at the previous ciphertext (old messages stay for
            # GC; the normal repair sweep re-replicates the new bytes).
            self.manifests.db.connection.execute(delete(content_index).where(
                content_index.c.object_id == content_id))
            self.manifests.db.connection.execute(delete(replica_chunks).where(
                replica_chunks.c.object_id == content_id))
            self.manifests.db.commit()
        except BaseException:
            self.manifests.db.connection.rollback()
            raise
        return digest

    def db_ready_status(self, identifier: str):
        """Row exists and is READY (rotation must not revive a dead object)."""
        return self.manifests.db.connection.execute(
            select(objects.c.id).where(
                objects.c.id == identifier, objects.c.status == "ready")
        ).scalar_one_or_none()

    async def download_to_path(self, identifier: str, destination: Path,
                               *, sse_key: SSECKey | None = None) -> StoredObject:
        """Atomically publish a verified full object; never leave a partial file."""
        obj = self.manifests.get(identifier)
        info = self.manifests.encryption_info(identifier)
        destination = Path(destination)
        if destination.is_symlink():
            raise ValueError("Destination must not be a symlink")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".teledrive-", dir=destination.parent)
        temp = Path(name)
        total = 0
        sha = hashlib.sha256()
        try:
            with os.fdopen(fd, "wb") as output:
                async for block in self.iter_bytes(identifier, sse_key=sse_key):
                    output.write(block)
                    sha.update(block)
                    total += len(block)
                output.flush()
                os.fsync(output.fileno())
            plaintext_digest = info is None or info.get("digest_kind") == "plaintext"
            if total != obj.size or (plaintext_digest
                                     and sha.hexdigest() != obj.sha256):
                raise IntegrityError("Object checksum mismatch")
            os.chmod(temp, 0o600)
            os.replace(temp, destination)
            return obj
        finally:
            temp.unlink(missing_ok=True)
