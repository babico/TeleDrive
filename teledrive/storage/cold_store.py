"""Cold-archive blob store and the physical archive/restore state machine.

Handoff 08, phases A-C. This module turns the ARCHIVE_ACCESS /
DEEP_ARCHIVE_ACCESS catalog label into real, independently verifiable
bytes:

* :class:`ColdBlobStore` is the durable cold provider (local filesystem;
  a later S3-backed provider is out of scope). Every write is atomic
  (temp file + fsync + ``os.replace`` + directory fsync) and is verified
  by a hash-verified readback before anything is marked ``archived``.
* :class:`ArchiveStore` owns the resumable per-version state machine
  ``HOT -> ARCHIVING -> ARCHIVED -> RESTORING -> RESTORED_TEMP -> ARCHIVED``
  with a durable worker lease (the same pattern as
  ``teledrive.storage.gc_collect``), generation fences and restart
  recovery. Each archived immutable version carries a sealed manifest:
  source object/version, chunk lineage, byte counts, the whole-object
  SHA-256 of the archived (stored) byte stream, encryption metadata, the
  target URI, a verified receipt, the state and the timestamps.
* :class:`StagedReadEngine` serves GetObject bodies from the verified
  staged copy (per-chunk digest + GCM verification, exactly like the
  Telegram read path), so a restored object is served from the copy the
  restore verified.

Honesty contract
----------------

* The archived byte stream is the STORED representation - the exact bytes
  Telegram holds (ciphertext for SSE-C and envelope objects). The server
  never needs a client key to archive, and no key material ever reaches
  the archive: the manifest records only the encryption MODE, the key
  fingerprint (``key_md5``) and the digest kind, never keys, wrapped keys
  or KEKs.
* The Telegram chunks are NOT moved or deleted by archiving. The archive
  is an ADDITIONAL verified copy. Reducing the hot footprint stays
  behind the owner's physical-GC gate (phase C): an archived source may
  only be collected after ``archive_deletion_permitted`` re-verifies the
  cold bytes readback; a missing cold backend or a corrupt archive
  blocks deletion.
* ``RestoreObject`` tiers (Expedited/Standard/Bulk) are recorded but do
  NOT change scheduling: restores run first-in-first-out. No AWS Glacier
  retrieval-speed or pricing SLA is implied or claimed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import stat
import tempfile
import time
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import (BigInteger, Column, Index, Integer, MetaData,
                        String, Table, Text, select, update)

from teledrive.db import retry_deadlocked_write

_logger = logging.getLogger(__name__)

cold_metadata = MetaData()

# One row per archived immutable object version. The row is the catalog
# side of the sealed manifest file in the cold store; both are written
# before the state becomes ARCHIVED.
archive_versions = Table(
    "storage_archive_versions", cold_metadata,
    Column("object_id", String(36), primary_key=True),
    Column("bucket", String(63), nullable=False),
    Column("object_key", Text, nullable=False),
    # HOT -> ARCHIVING -> ARCHIVED -> RESTORING -> RESTORED_TEMP -> ARCHIVED
    Column("state", String(16), nullable=False),
    # Monotonic transition fence: every claim/transition increments it and
    # every completion is a CAS on the generation it read, so a worker
    # whose lease expired mid-work can never complete a stale transition.
    Column("generation", BigInteger, nullable=False),
    # sha256("<object_id>:<content sha256>:<size>"): replaying the same
    # enqueue is a no-op; a different key means the version's content
    # identity changed and the existing row is never silently re-targeted.
    Column("idempotency_key", String(64), nullable=False),
    Column("whole_sha256", String(64)),
    Column("stored_bytes", BigInteger),
    Column("target_uri", String(512)),
    Column("manifest", Text),
    # Durable worker lease (gc_collect pattern): survives crashes, expires,
    # and the next pass resumes the object idempotently.
    Column("lease_owner", String(64)),
    Column("lease_until_ns", BigInteger),
    Column("restore_days", Integer),
    Column("restore_tier", String(16)),
    Column("restore_until_ns", BigInteger),
    Column("requested_ns", BigInteger),
    Column("archived_ns", BigInteger),
    Column("restored_ns", BigInteger),
    Column("created_ns", BigInteger, nullable=False),
    Column("updated_ns", BigInteger, nullable=False),
    Column("error", Text),
)
Index("ix_storage_archive_state", archive_versions.c.state)

STATES = ("HOT", "ARCHIVING", "ARCHIVED", "RESTORING", "RESTORED_TEMP")
ARCHIVED_STATE = "ARCHIVED"
DAY_NS = 86_400_000_000_000
DEFAULT_LEASE_SECONDS = 900
DEFAULT_MAX_STAGED = 64
MAX_RESTORE_DAYS = 36500

_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}\Z")


class ColdStoreError(RuntimeError):
    """Cold backend unavailable, corrupt or failed readback verification."""


def default_cold_root() -> Path:
    """The deployment's cold-archive root, resolved at CALL time.

    ``TELEDRIVE_COLD_ARCHIVE_DIR`` wins (tests and non-Docker deployments
    point it anywhere); the default lives under the same ``TELEDRIVE_DATA_DIR``
    the web app reads, so the gateway, the schedulers and the GC fence all
    resolve one directory without teledrive importing web code.
    """
    raw = os.environ.get("TELEDRIVE_COLD_ARCHIVE_DIR")
    if raw:
        return Path(raw)
    data = os.environ.get("TELEDRIVE_DATA_DIR", "/data")
    return Path(data) / "cold-archive"


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry after an atomic rename inside it."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ColdBlobStore:
    """Durable local-filesystem cold provider (blob + sealed manifest).

    Layout under ``root``::

        archive/<shard>/<object_id>.blob            stored byte stream
        archive/<shard>/<object_id>.manifest.json   sealed manifest
        staging/<shard>/<object_id>.blob            bounded restore cache

    ``<shard>`` is the first two characters of the object id. Object ids
    are validated against a strict single-component pattern, so a request
    can never traverse outside the root.
    """

    def __init__(self, root: Path | str):
        self.root = Path(root)

    # -- paths -----------------------------------------------------------

    @staticmethod
    def _check_key(object_id: str) -> str:
        if not isinstance(object_id, str) or not _KEY_RE.fullmatch(object_id):
            raise ColdStoreError("Invalid cold-store object key")
        return object_id

    def _path(self, kind: str, object_id: str) -> Path:
        object_id = self._check_key(object_id)
        return self.root / kind / object_id[:2] / f"{object_id}.blob"

    def archive_path(self, object_id: str) -> Path:
        return self._path("archive", object_id)

    def manifest_path(self, object_id: str) -> Path:
        object_id = self._check_key(object_id)
        return self.root / "archive" / object_id[:2] / \
            f"{object_id}.manifest.json"

    def staged_path(self, object_id: str) -> Path:
        return self._path("staging", object_id)

    def staged_exists(self, object_id: str) -> bool:
        try:
            return self.staged_path(object_id).is_file()
        except ColdStoreError:
            return False

    def target_uri(self, object_id: str) -> str:
        object_id = self._check_key(object_id)
        return f"cold+local://archive/{object_id[:2]}/{object_id}.blob"

    # -- atomic writes ---------------------------------------------------

    def _atomic_write(self, destination: Path, data: bytes) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(
            prefix=".cold-tmp-", dir=destination.parent)
        temp = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, destination)
            _fsync_directory(destination.parent)
        finally:
            temp.unlink(missing_ok=True)

    def put_archive(self, object_id: str, data: bytes) -> None:
        """Atomically publish the archived byte stream (fsync + rename)."""
        self._atomic_write(self.archive_path(object_id), data)

    def write_manifest(self, object_id: str, document: dict) -> None:
        """Atomically publish the sealed manifest document."""
        payload = json.dumps(
            document, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")
        self._atomic_write(self.manifest_path(object_id), payload)

    def read_manifest(self, object_id: str) -> dict:
        path = self.manifest_path(object_id)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ColdStoreError(
                f"Sealed archive manifest unreadable for {object_id}"
            ) from exc
        if not isinstance(document, dict):
            raise ColdStoreError("Corrupt sealed archive manifest")
        return document

    # -- verification ----------------------------------------------------

    @staticmethod
    def _hash_file(path: Path) -> tuple[int, str]:
        digest = hashlib.sha256()
        total = 0
        with open(path, "rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
                total += len(block)
        return total, digest.hexdigest()

    def verify_archive(self, object_id: str, whole_sha256: str,
                       stored_bytes: int | None) -> bool:
        """True only when the cold blob exists and hashes back exactly.

        This is the phase-C fence primitive: a missing cold backend, a
        truncated blob or a corrupted one all answer False, which blocks
        physical deletion of the archived Telegram source.
        """
        try:
            total, digest = self._hash_file(self.archive_path(object_id))
        except OSError:
            return False
        if whole_sha256 is None:
            return False
        if stored_bytes is not None and total != int(stored_bytes):
            return False
        return digest == whole_sha256

    def read_archive(self, object_id: str, whole_sha256: str,
                     stored_bytes: int | None) -> bytes:
        """Read the archived bytes back, verifying the whole-object hash."""
        path = self.archive_path(object_id)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ColdStoreError(
                f"Cold archive bytes unavailable for {object_id}") from exc
        if stored_bytes is not None and len(data) != int(stored_bytes):
            raise ColdStoreError("Cold archive length mismatch")
        if hashlib.sha256(data).hexdigest() != whole_sha256:
            raise ColdStoreError("Cold archive checksum mismatch")
        return data

    # -- staged (hot) restore cache ---------------------------------------

    def write_staged(self, object_id: str, data: bytes,
                     whole_sha256: str) -> None:
        """Publish the staged copy: atomic write + fsync + readback verify."""
        self._atomic_write(self.staged_path(object_id), data)
        # Hash-verified readback BEFORE the row can say RESTORED_TEMP.
        total, digest = self._hash_file(self.staged_path(object_id))
        if total != len(data) or digest != whole_sha256:
            self.clear_staged(object_id)
            raise ColdStoreError("Staged copy failed readback verification")

    def clear_staged(self, object_id: str) -> None:
        """Expiry clears the staged copy, never the archive data."""
        try:
            self.staged_path(object_id).unlink(missing_ok=True)
        except ColdStoreError:
            pass


class StagedReadEngine:
    """Serve GetObject ranges from the verified staged restore copy.

    Mirrors ``TelegramObjectStorage.iter_bytes`` semantics: per-chunk
    stored-digest verification, GCM authentication before any plaintext is
    yielded, and the same SSE-C/envelope key rules. The chunk lineage
    comes from the sealed archive manifest, so reads do not depend on the
    SQL chunk journal.
    """

    def __init__(self, blob_store: ColdBlobStore, row: dict):
        try:
            document = (json.loads(row["manifest"])
                        if isinstance(row.get("manifest"), str)
                        else dict(row["manifest"]))
        except (TypeError, ValueError) as exc:
            raise ColdStoreError("Corrupt archive manifest") from exc
        if not isinstance(document, dict) or not document.get("chunk_lineage"):
            raise ColdStoreError("Archive manifest has no chunk lineage")
        self.manifest = document
        self.blob_store = blob_store
        self.object_id = row["object_id"]
        self.staged = blob_store.staged_path(self.object_id)

    async def iter_bytes(self, *, start: int = 0, end: int | None = None,
                         sse_key=None, block_size: int = 1024 * 1024,
                         ) -> AsyncIterator[bytes]:
        from teledrive.storage.sse import SSECError, decrypt_chunk, verify_key_md5
        size = int(self.manifest.get("size", 0))
        if end is None:
            end = size
        if block_size <= 0 or start < 0 or end < start or end > size:
            raise ValueError("Invalid range or block size")
        if start == end:
            return
        info = self.manifest.get("encryption")
        if info is not None:
            if sse_key is None:
                raise SSECError(
                    "InvalidRequest",
                    "The object was stored with SSE-C; supply the customer key")
            verify_key_md5(info, sse_key)
        elif sse_key is not None:
            raise SSECError(
                "InvalidRequest",
                "The object was not stored with SSE-C; remove the customer key")
        # Open the staged copy through a no-follow regular-file check so a
        # swapped symlink can never be served.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.staged, flags)
        handle = os.fdopen(fd, "rb")
        try:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ColdStoreError("Staged copy is not a regular file")
            covered = 0
            for chunk in self.manifest["chunk_lineage"]:
                offset = int(chunk["offset"])
                plain_size = int(chunk["size"])
                stored_offset = int(chunk["stored_offset"])
                stored_size = int(chunk["stored_size"])
                if offset != covered:
                    raise ColdStoreError("Non-contiguous archive lineage")
                covered = offset + plain_size
                if offset >= end:
                    break
                if offset + plain_size <= start:
                    continue
                handle.seek(stored_offset)
                stored = handle.read(stored_size)
                if len(stored) != stored_size:
                    raise ColdStoreError("Staged copy truncated")
                if hashlib.sha256(stored).hexdigest() != chunk["sha256"]:
                    raise ColdStoreError("Staged chunk checksum mismatch")
                if chunk.get("encryption"):
                    if sse_key is None:  # pragma: no cover - guarded above
                        raise ColdStoreError("Encrypted chunk without a key")
                    plaintext = decrypt_chunk(
                        sse_key, stored, chunk["encryption"])
                else:
                    plaintext = stored
                if len(plaintext) != plain_size:
                    raise ColdStoreError(
                        "Decrypted chunk length disagrees with the manifest")
                local_start = max(0, start - offset)
                local_end = min(plain_size, end - offset)
                position = local_start
                while position < local_end:
                    block = plaintext[position:min(local_end,
                                                   position + block_size)]
                    if not block:
                        raise ColdStoreError("Staged chunk truncated")
                    position += len(block)
                    yield block
            if covered < end:
                raise ColdStoreError("Missing part of requested range")
        finally:
            handle.close()


def _owner_tag() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"[:64]


def _idempotency_key(object_id: str, content_sha: str | None,
                     size: int) -> str:
    material = f"{object_id}:{content_sha or ''}:{int(size)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _encryption_metadata(info: dict | None) -> dict | None:
    """Non-secret encryption metadata for the sealed manifest.

    Only the mode, the key FINGERPRINT (``key_md5``, an AWS-published
    digest, not a key) and the digest kind are recorded. Wrapped keys,
    KEKs and any key material never reach the archive.
    """
    if not info:
        return None
    return {
        "mode": info.get("mode"),
        "key_md5": info.get("key_md5"),
        "digest_kind": info.get("digest_kind"),
    }


def _effective_restore_window(db, object_id: str, fallback) -> int | None:
    """The authoritative gate: the object's window, falling back to the
    archive row's mirror once the object row no longer exists."""
    from teledrive.storage.manifest import objects as objects_table
    window = db.connection.execute(select(
        objects_table.c.restore_until_ns).where(
        objects_table.c.id == object_id)).scalar_one_or_none()
    return fallback if window is None else window


def archive_row(db, object_id: str) -> dict | None:
    """The raw archive state-machine row, or None when never archived."""
    from teledrive.storage.manifest import objects as objects_table
    row = db.connection.execute(select(
        archive_versions.c.object_id, archive_versions.c.state,
        archive_versions.c.generation, archive_versions.c.manifest,
        archive_versions.c.restore_until_ns, archive_versions.c.error,
    ).where(archive_versions.c.object_id == object_id)).mappings().first()
    if row is None:
        return None
    result = dict(row)
    # The authoritative read gate stays objects.restore_until_ns; reflect
    # it here so callers see one truth.
    window = db.connection.execute(select(
        objects_table.c.restore_until_ns).where(
        objects_table.c.id == object_id)).scalar_one_or_none()
    result["object_restore_until_ns"] = window
    return result


def settle_expired_restore(db, object_id: str, *, now_ns: int,
                           blob_store: ColdBlobStore | None = None) -> bool:
    """Close an expired RESTORED_TEMP row and clear its staged copy.

    The authoritative gate is ``storage_objects.restore_until_ns`` (the
    row's mirror is the fallback once the object row is gone). Expiry
    clears the STAGED copy only; the archive blob and manifest are never
    touched. Returns True when a row was settled.
    """
    row = db.connection.execute(select(
        archive_versions.c.state, archive_versions.c.restore_until_ns,
    ).where(archive_versions.c.object_id == object_id)).first()
    if row is None or row[0] != "RESTORED_TEMP":
        return False
    window = _effective_restore_window(db, object_id, row[1])
    if window is not None and int(window) > int(now_ns):
        return False
    changed = db.connection.execute(update(archive_versions).where(
        archive_versions.c.object_id == object_id,
        archive_versions.c.state == "RESTORED_TEMP",
    ).values(
        state=ARCHIVED_STATE,
        generation=archive_versions.c.generation + 1,
        lease_owner=None, lease_until_ns=None,
        updated_ns=int(now_ns), error=None))
    if not changed.rowcount:
        db.connection.rollback()
        return False
    db.commit()
    cold = blob_store or ColdBlobStore(default_cold_root())
    cold.clear_staged(object_id)
    return True


def archive_deletion_permitted(db, object_id: str, *,
                               blob_store: ColdBlobStore | None = None) -> bool:
    """Phase-C fence for the physical-GC collector.

    An object that was never archived has no fence (True). An archived
    object may only be physically collected when its row is ARCHIVED and
    the cold bytes read back with the exact whole-object SHA-256: a
    missing cold backend, an in-flight archive/restore or a corrupt
    archive all BLOCK deletion.
    """
    row = db.connection.execute(select(
        archive_versions.c.state, archive_versions.c.whole_sha256,
        archive_versions.c.stored_bytes,
    ).where(archive_versions.c.object_id == object_id)).first()
    if row is None:
        return True
    if row[0] != ARCHIVED_STATE:
        return False
    cold = blob_store or ColdBlobStore(default_cold_root())
    try:
        return cold.verify_archive(object_id, row[1], row[2])
    except OSError:
        return False


class ArchiveStore:
    """SQL state machine + workers for physical archive and restore."""

    def __init__(self, catalog, blob_store: ColdBlobStore):
        self.catalog = catalog
        self.db = catalog.db
        self.blob_store = blob_store
        self._owner = _owner_tag()
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)

    # -- enqueue (tiering / lifecycle transitions) ------------------------

    def enqueue_archive(self, object_ids, *, now_ns: int | None = None) -> int:
        """Idempotently queue physical archival for ready versions.

        Repeating the request is a no-op while the row exists with the
        same idempotency key. Active restores are never disturbed.
        """
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        from teledrive.storage.manifest import objects as objects_table
        identifiers = [value for value in object_ids if value]
        if not identifiers:
            return 0
        rows = self.db.connection.execute(select(
            objects_table.c.id, objects_table.c.bucket,
            objects_table.c.object_key, objects_table.c.sha256,
            objects_table.c.size, objects_table.c.storage_class,
        ).where(objects_table.c.id.in_(identifiers),
                objects_table.c.status == "ready")).mappings().all()
        inserted = 0
        try:
            for row in rows:
                key = _idempotency_key(
                    row["id"], row["sha256"], row["size"])
                existing = self.db.connection.execute(select(
                    archive_versions.c.idempotency_key,
                    archive_versions.c.state,
                ).where(archive_versions.c.object_id == row["id"])).first()
                if existing is not None:
                    if (existing[0] != key
                            and existing[1] in (ARCHIVED_STATE, "HOT",
                                                "ARCHIVING")):
                        # Content identity drifted on an "immutable"
                        # version: never silently re-target the archive.
                        _logger.warning(
                            "archive idempotency key drifted for %s",
                            row["id"])
                    continue
                self.db.connection.execute(archive_versions.insert().values(
                    object_id=row["id"], bucket=row["bucket"],
                    object_key=row["object_key"], state="HOT",
                    generation=0, idempotency_key=key,
                    created_ns=now_ns, updated_ns=now_ns,
                ))
                inserted += 1
            self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        return inserted

    # -- restore requests (RestoreObject) ---------------------------------

    def request_restore(self, object_id: str, *, days: int,
                        tier: str | None = None,
                        now_ns: int | None = None) -> str:
        """Queue or gate a restore. Returns ``queued`` / ``conflict`` /
        ``legacy``.

        * ``legacy`` - no verified archive exists for this version (or the
          physical archive has not completed yet), so the hot Telegram
          copy is authoritative and the caller opens today's window gate.
        * ``queued`` - a verified ARCHIVED row moved to RESTORING; the
          restore worker copies the cold bytes to the staging cache and
          the window opens only after whole-SHA256 verification.
        * ``conflict`` - a restore is already in progress or active
          (AWS ``RestoreAlreadyInProgress``).
        """
        if type(days) is not int or not 1 <= days <= MAX_RESTORE_DAYS:
            raise ValueError("Invalid restore days")
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        from teledrive.storage.manifest import objects as objects_table
        row = self.db.connection.execute(select(
            archive_versions.c.state,
        ).where(archive_versions.c.object_id == object_id)).first()
        if row is None:
            return "legacy"
        window = self.db.connection.execute(select(
            objects_table.c.restore_until_ns).where(
            objects_table.c.id == object_id)).scalar_one_or_none()
        if window is not None and int(window) > now_ns:
            return "conflict"
        state = row[0]
        if state in ("RESTORING", "RESTORED_TEMP"):
            if state == "RESTORED_TEMP":
                # Window already expired above: settle, then re-queue.
                settle_expired_restore(
                    self.db, object_id, now_ns=now_ns,
                    blob_store=self.blob_store)
                state = ARCHIVED_STATE
            else:
                return "conflict"
        if state != ARCHIVED_STATE:
            # HOT / ARCHING: the physical archive is not verified yet, so
            # there is nothing to retrieve from cold storage - the hot
            # copy is still the authoritative byte store.
            return "legacy"
        changed = self.db.connection.execute(update(archive_versions).where(
            archive_versions.c.object_id == object_id,
            archive_versions.c.state == ARCHIVED_STATE,
        ).values(
            state="RESTORING",
            generation=archive_versions.c.generation + 1,
            restore_days=int(days),
            restore_tier=tier,
            requested_ns=now_ns,
            lease_owner=None, lease_until_ns=None,
            updated_ns=now_ns, error=None))
        if not changed.rowcount:
            self.db.connection.rollback()
            return "conflict"
        self.db.commit()
        return "queued"

    def request_rearchive(self, object_id: str, *,
                          now_ns: int | None = None) -> bool:
        """Repair path: re-seal a corrupt or suspect archive.

        CAS ARCHIVED -> HOT so the next worker pass re-copies and
        re-verifies from the (still present) hot Telegram source. The
        sealed receipt stays until the new pass replaces it, so a failed
        repair never leaves the row less verified than before.
        """
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        changed = self.db.connection.execute(update(archive_versions).where(
            archive_versions.c.object_id == object_id,
            archive_versions.c.state == ARCHIVED_STATE,
        ).values(
            state="HOT",
            generation=archive_versions.c.generation + 1,
            lease_owner=None, lease_until_ns=None,
            updated_ns=now_ns, error=None))
        if not changed.rowcount:
            self.db.connection.rollback()
            return False
        self.db.commit()
        return True

    # -- worker leases -----------------------------------------------------

    def _claim(self, object_id: str, expected_state: str, *,
               lease_seconds: int, now_ns: int) -> int | None:
        """Take the durable lease; returns the NEW generation, or None.

        Portable CAS (no RETURNING / ON CONFLICT, like gc_collect's
        lease): the whole UPDATE-then-SELECT sequence retries when the
        backend picked this transaction as a deadlock victim.
        """
        lease_until = now_ns + int(lease_seconds) * 1_000_000_000

        def _attempt() -> int | None:
            changed = self.db.connection.execute(update(archive_versions).where(
                archive_versions.c.object_id == object_id,
                archive_versions.c.state == expected_state,
                (archive_versions.c.lease_until_ns.is_(None)
                 | (archive_versions.c.lease_until_ns < now_ns)),
            ).values(
                # HOT -> ARCHING happens under the claim; re-claiming an
                # interrupted ARCHING row keeps the state and bumps the
                # generation so the stale worker's completion CAS fails.
                state="ARCHIVING" if expected_state == "HOT" else expected_state,
                lease_owner=self._owner, lease_until_ns=lease_until,
                generation=archive_versions.c.generation + 1,
                updated_ns=now_ns, error=None))
            if not changed.rowcount:
                self.db.connection.rollback()
                return None
            generation = self.db.connection.execute(select(
                archive_versions.c.generation).where(
                archive_versions.c.object_id == object_id)).scalar_one()
            self.db.commit()
            return int(generation)

        return retry_deadlocked_write(self.db, _attempt, attempts=3)

    def _release(self, object_id: str, *, now_ns: int) -> None:
        try:
            self.db.connection.execute(update(archive_versions).where(
                archive_versions.c.object_id == object_id,
                archive_versions.c.lease_owner == self._owner,
            ).values(lease_owner=None, lease_until_ns=None,
                     updated_ns=int(now_ns)))
            self.db.commit()
        except Exception:
            # Best effort: an unreleased lease self-expires, only delaying
            # the next pass on this object.
            _logger.warning("archive lease release failed for %s",
                            object_id, exc_info=True)
            self.db.connection.rollback()

    # -- archive worker ----------------------------------------------------

    async def run_archive_pass(self, transport, *, scratch_directory=None,
                               limit: int = 5,
                               lease_seconds: int = DEFAULT_LEASE_SECONDS,
                               chunk_size: int = 64 * 1024 * 1024,
                               now_ns: int | None = None) -> dict:
        """Archive queued versions: claim, copy, verify, seal, CAS.

        Every failure is recorded on the row and retried on a later pass
        (the lease expires); nothing here ever deletes or moves Telegram
        bytes - the archive is an additional copy.
        """
        from teledrive.storage.engine import TelegramObjectStorage
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        engine = TelegramObjectStorage(
            self.catalog.manifests, transport, chunk_size=chunk_size,
            scratch_directory=scratch_directory)
        candidates = self.db.connection.execute(
            select(archive_versions.c.object_id,
                   archive_versions.c.state)
            .where(archive_versions.c.state.in_(("HOT", "ARCHIVING")),
                   (archive_versions.c.lease_until_ns.is_(None)
                    | (archive_versions.c.lease_until_ns < now_ns)))
            .order_by(archive_versions.c.created_ns)
            .limit(max(1, limit))).all()
        report = {"archived": [], "failed": [], "skipped": []}
        for object_id, state in candidates:
            generation = self._claim(
                object_id, state, lease_seconds=lease_seconds, now_ns=now_ns)
            if generation is None:
                report["skipped"].append(object_id)
                continue
            try:
                await self._archive_one(engine, object_id, generation,
                                        now_ns=now_ns)
                report["archived"].append(object_id)
            except Exception as exc:  # per-object isolation
                _logger.warning("archive pass failed for %s", object_id,
                                exc_info=True)
                try:
                    self.db.connection.execute(update(archive_versions).where(
                        archive_versions.c.object_id == object_id,
                        archive_versions.c.generation == generation,
                    ).values(error=str(exc)[:500], updated_ns=int(time.time_ns())))
                    self.db.commit()
                except Exception:
                    self.db.connection.rollback()
                report["failed"].append(object_id)
            finally:
                self._release(object_id, now_ns=int(time.time_ns()))
        return report

    async def _archive_one(self, engine, object_id: str, generation: int,
                           *, now_ns: int) -> None:
        from teledrive.storage.manifest import objects as objects_table
        item = self.catalog.manifests.get(object_id)  # ready check
        storage_class = self.db.connection.execute(select(
            objects_table.c.storage_class).where(
            objects_table.c.id == object_id)).scalar_one_or_none()
        if storage_class not in ("ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS"):
            # The tier label was reset before this request was claimed;
            # leave the row HOT for a future archive cycle.
            raise ColdStoreError(
                "storage class reset; archive request deferred")
        parts = self.catalog.manifests.parts(object_id)
        info = _encryption_metadata(
            self.catalog.manifests.encryption_info(object_id))
        lineage = []
        stored_offset = 0
        expected_plain = 0
        for part in parts:
            if part.offset != expected_plain:
                raise ColdStoreError("Non-contiguous chunk manifest")
            stored_size = part.ciphertext_size
            lineage.append({
                "ordinal": part.ordinal, "offset": part.offset,
                "size": part.size, "stored_offset": stored_offset,
                "stored_size": stored_size, "sha256": part.sha256,
                "encryption": part.encryption,
            })
            stored_offset += stored_size
            expected_plain += part.size
        if expected_plain != item.size:
            raise ColdStoreError("Chunk journal disagrees with object size")
        # Stream the stored (Telegram-held) bytes into the cold blob,
        # verifying every chunk digest on the way (iter_ciphertext).
        destination = self.blob_store.archive_path(object_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".cold-tmp-",
                                    dir=destination.parent)
        temp = Path(name)
        digest = hashlib.sha256()
        total = 0
        try:
            with os.fdopen(fd, "wb") as handle:
                async for block in engine.iter_ciphertext(object_id):
                    digest.update(block)
                    handle.write(block)
                    total += len(block)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, destination)
            _fsync_directory(destination.parent)
        finally:
            temp.unlink(missing_ok=True)
        whole_sha256 = digest.hexdigest()
        # Hash-verified readback BEFORE anything is marked archived.
        readback_total, readback_digest = self.blob_store._hash_file(
            destination)
        if readback_total != total or readback_digest != whole_sha256:
            destination.unlink(missing_ok=True)
            raise ColdStoreError("Cold archive failed readback verification")
        document = {
            "version": 1,
            "object_id": object_id, "bucket": item.bucket, "key": item.key,
            "size": item.size, "sha256_plaintext": item.sha256,
            "stored_bytes": total, "whole_sha256": whole_sha256,
            "chunk_lineage": lineage, "encryption": info,
            "provider": "local-fs", "root": str(self.blob_store.root),
            "target_uri": self.blob_store.target_uri(object_id),
            "state": ARCHIVED_STATE,
            "created_ns": int(now_ns), "archived_ns": int(time.time_ns()),
            "restored_ns": None,
            "verified": {
                "algorithm": "sha256", "readback": True,
                "at_ns": int(time.time_ns()),
            },
        }
        self.blob_store.write_manifest(object_id, document)
        # Generation-fenced CAS: a worker whose lease expired (and whose
        # row was re-claimed with a new generation) can never complete.
        changed = self.db.connection.execute(update(archive_versions).where(
            archive_versions.c.object_id == object_id,
            archive_versions.c.generation == generation,
            archive_versions.c.state == "ARCHIVING",
        ).values(
            state=ARCHIVED_STATE, whole_sha256=whole_sha256,
            stored_bytes=total, target_uri=document["target_uri"],
            manifest=json.dumps(document, ensure_ascii=False,
                                sort_keys=True, separators=(",", ":")),
            archived_ns=document["archived_ns"],
            lease_owner=None, lease_until_ns=None,
            updated_ns=document["archived_ns"], error=None))
        if not changed.rowcount:
            # The physical blob is idempotent; only our bookkeeping lost.
            self.db.connection.rollback()
            _logger.warning(
                "archive CAS lost for %s (generation fence)", object_id)
            return
        self.db.commit()

    # -- restore worker ----------------------------------------------------

    def run_restore_pass(self, *, limit: int = 10,
                         lease_seconds: int = DEFAULT_LEASE_SECONDS,
                         now_ns: int | None = None) -> dict:
        """Copy verified cold bytes into the bounded staging cache.

        The restore window (``objects.restore_until_ns``) opens in the
        SAME transaction as the RESTORED_TEMP transition, so GET can only
        succeed after whole-SHA256 verification. Scheduling is FIFO by
        request time; the Expedited/Standard/Bulk tier is recorded but
        does not reorder the queue.
        """
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        from teledrive.storage.manifest import objects as objects_table
        candidates = self.db.connection.execute(
            select(archive_versions.c.object_id)
            .where(archive_versions.c.state == "RESTORING",
                   (archive_versions.c.lease_until_ns.is_(None)
                    | (archive_versions.c.lease_until_ns < now_ns)))
            .order_by(archive_versions.c.requested_ns)
            .limit(max(1, limit))).all()
        report = {"restored": [], "failed": [], "skipped": []}
        for (object_id,) in candidates:
            generation = self._claim(
                object_id, "RESTORING", lease_seconds=lease_seconds,
                now_ns=now_ns)
            if generation is None:
                report["skipped"].append(object_id)
                continue
            try:
                row = self.db.connection.execute(select(
                    archive_versions.c.whole_sha256,
                    archive_versions.c.stored_bytes,
                    archive_versions.c.restore_days,
                ).where(archive_versions.c.object_id == object_id)
                ).first()
                if row is None or not row[0]:
                    raise ColdStoreError("Restore row lost its receipt")
                data = self.blob_store.read_archive(
                    object_id, row[0], row[1])
                self.blob_store.write_staged(object_id, data, row[0])
                days = int(row[2] or 1)
                until_ns = int(time.time_ns()) + days * DAY_NS
                changed = self.db.connection.execute(update(
                    archive_versions).where(
                    archive_versions.c.object_id == object_id,
                    archive_versions.c.generation == generation,
                    archive_versions.c.state == "RESTORING",
                ).values(
                    state="RESTORED_TEMP", restored_ns=int(time.time_ns()),
                    restore_until_ns=until_ns,
                    lease_owner=None, lease_until_ns=None,
                    updated_ns=int(time.time_ns()), error=None))
                if not changed.rowcount:
                    self.db.connection.rollback()
                    report["skipped"].append(object_id)
                    continue
                # The gate opens exactly with the verified copy.
                self.db.connection.execute(update(objects_table).where(
                    objects_table.c.id == object_id,
                ).values(restore_until_ns=until_ns))
                self.db.commit()
                report["restored"].append(object_id)
            except Exception as exc:  # per-object isolation
                _logger.warning("restore pass failed for %s", object_id,
                                exc_info=True)
                try:
                    # Back to ARCHIVED with the reason: a corrupt or
                    # missing cold copy must never leave the object in a
                    # permanently unreadable RESTORING state, and the
                    # failed verification also blocks GC deletion.
                    self.db.connection.execute(update(archive_versions).where(
                        archive_versions.c.object_id == object_id,
                        archive_versions.c.generation == generation,
                        archive_versions.c.state == "RESTORING",
                    ).values(state=ARCHIVED_STATE, error=str(exc)[:500],
                             updated_ns=int(time.time_ns())))
                    self.db.commit()
                except Exception:
                    self.db.connection.rollback()
                report["failed"].append(object_id)
            finally:
                self._release(object_id, now_ns=int(time.time_ns()))
        self.purge_expired(now_ns=int(time.time_ns()))
        return report

    # -- expiry / bounds / tiering reset -----------------------------------

    def purge_expired(self, *, now_ns: int | None = None,
                      max_staged: int = DEFAULT_MAX_STAGED) -> int:
        """Settle expired restores and enforce the staging-cache bound.

        The bound evicts the oldest staged copies when the cache exceeds
        ``max_staged`` entries; eviction also closes the restore window so
        the gate never claims a copy the cache no longer holds. Archive
        data is never touched.
        """
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        from teledrive.storage.manifest import objects as objects_table
        settled = 0
        expired = self.db.connection.execute(
            select(archive_versions.c.object_id,
                   archive_versions.c.restore_until_ns)
            .where(archive_versions.c.state == "RESTORED_TEMP")
        ).all()
        for object_id, row_window in expired:
            window = _effective_restore_window(self.db, object_id, row_window)
            if window is not None and int(window) > now_ns:
                continue
            if settle_expired_restore(self.db, object_id, now_ns=now_ns,
                                      blob_store=self.blob_store):
                settled += 1
        live = self.db.connection.execute(
            select(archive_versions.c.object_id)
            .where(archive_versions.c.state == "RESTORED_TEMP")
            .order_by(archive_versions.c.restored_ns.desc())
        ).scalars().all()
        for object_id in live[max_staged:]:
            try:
                changed = self.db.connection.execute(update(
                    archive_versions).where(
                    archive_versions.c.object_id == object_id,
                    archive_versions.c.state == "RESTORED_TEMP",
                ).values(state=ARCHIVED_STATE,
                         generation=archive_versions.c.generation + 1,
                         updated_ns=int(now_ns)))
                if changed.rowcount:
                    self.db.connection.execute(update(objects_table).where(
                        objects_table.c.id == object_id,
                        objects_table.c.restore_until_ns.isnot(None),
                    ).values(restore_until_ns=None))
                    self.db.commit()
                    settled += 1
                else:
                    self.db.connection.rollback()
            except BaseException:
                self.db.connection.rollback()
                raise
            self.blob_store.clear_staged(object_id)
        return settled

    def reset_restore(self, object_ids, *, now_ns: int | None = None) -> int:
        """Tiering reset hook: settle restore state when a version returns
        to STANDARD. The staged copy is cleared; archive data stays."""
        now_ns = time.time_ns() if now_ns is None else int(now_ns)
        from teledrive.storage.manifest import objects as objects_table
        identifiers = [value for value in object_ids if value]
        settled = 0
        if not identifiers:
            return 0
        rows = self.db.connection.execute(select(
            archive_versions.c.object_id,
            archive_versions.c.state).where(
            archive_versions.c.object_id.in_(identifiers),
            archive_versions.c.state.in_(("RESTORING", "RESTORED_TEMP")),
        )).all()
        try:
            for object_id, state in rows:
                changed = self.db.connection.execute(update(
                    archive_versions).where(
                    archive_versions.c.object_id == object_id,
                    archive_versions.c.state == state,
                ).values(state=ARCHIVED_STATE,
                         generation=archive_versions.c.generation + 1,
                         lease_owner=None, lease_until_ns=None,
                         updated_ns=int(now_ns), error=None))
                if not changed.rowcount:
                    continue
                self.db.connection.execute(update(objects_table).where(
                    objects_table.c.id == object_id,
                ).values(restore_until_ns=None))
                settled += 1
            if rows:
                self.db.commit()
        except BaseException:
            self.db.connection.rollback()
            raise
        for object_id, _state in rows:
            self.blob_store.clear_staged(object_id)
        return settled
