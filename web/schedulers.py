"""Background scheduler loops, extracted from ``web.app``.

The long-running loops live here: the durable upload-job worker, the
hourly lifecycle/tiering/report passes, webhook notification delivery,
the optional folder watcher and the folder-scan core they share.
(``telegram_session_health_loop`` stays in ``web.routers.telegram``;
``web.app``'s lifespan still creates and cancels every task.)

Exactly like ``web.settings_runtime``, each loop resolves its
configuration, database connection, transport and helpers through
:func:`_app` at call time. The loops re-read ``JOB_AUTO_RUN``,
``WATCH_*`` and ``STORAGE_SCRATCH_DIR`` every cycle in production, and
the regression suite steers them (and the routers sharing
``_storage_job_root``) with ``monkeypatch.setattr(web.app, ...)`` — the
call-time indirection keeps both working after the split.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from fastapi import HTTPException

from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.jobs import StorageUploadJobs
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from teledrive.stores import sessions as _session_store


def _app():
    """The ``web.app`` module: the owner of the mutable service state.

    Resolved at call time, never at import time, because ``web.app``
    imports this module (a module-level import would be circular) and
    because tests rebind these attributes through
    ``monkeypatch.setattr(web.app, ...)``.
    """
    import web.app as module
    return module


def _storage_job_root() -> Path:
    """Durable jobs may read only an operator-configured local source root."""
    raw = _app().JOB_SOURCE_ROOT.strip()
    if not raw:
        raise HTTPException(503, "Configure TELEDRIVE_JOB_SOURCE_ROOT for local upload jobs")
    try:
        root = Path(raw).resolve(strict=True)
    except OSError as exc:
        raise HTTPException(503, "Upload source root does not exist") from exc
    if not root.is_dir():
        raise HTTPException(503, "Upload source root must be a directory")
    return root


_SCHEDULER_IDLE_NOTICE: dict = {"message": None}


async def upload_job_scheduler_loop() -> None:
    """Opt-in durable job worker; SQL leases prevent duplicate claims.

    Disabled unless jobs.auto_run is enabled in config. Every cycle gets its
    own connection; failures retain job metadata for explicit operator retry.
    """
    while True:
        app = _app()
        conn = None
        try:
            if not app.JOB_AUTO_RUN:
                await asyncio.sleep(10)
                continue
            root = _storage_job_root()
            conn = app.db_connect()
            queue = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
            scratch = Path(app.STORAGE_SCRATCH_DIR)
            app._secure_mkdir(scratch)
            result = await queue.run_next(
                app.storage_transport(conn), allowed_root=root,
                scratch_directory=scratch, chunk_size=RECOMMENDED_CHUNK_SIZE,
            )
            _SCHEDULER_IDLE_NOTICE["message"] = None
            await asyncio.sleep(2 if result else 10)
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            # Expected while no Telegram session or source root is configured;
            # log the state change once instead of spamming every cycle.
            message = f"scheduler idle: {exc.detail}"
            if _SCHEDULER_IDLE_NOTICE["message"] != message:
                app._log(message, "scheduler")
                _SCHEDULER_IDLE_NOTICE["message"] = message
            await asyncio.sleep(60)
        except Exception as exc:
            # Do not log source paths, credentials or Telegram tokens.
            app._log("durable upload job scheduler: " + type(exc).__name__,
                     "scheduler")
            await asyncio.sleep(20)
        finally:
            if conn is not None:
                conn.close()


async def lifecycle_scheduler_loop() -> None:
    """Apply bounded SQL-only lifecycle rules hourly, in this one process."""
    while True:
        app = _app()
        connection = None
        try:
            from teledrive.s3.lifecycle import BucketLifecycleStore
            connection = app.db_connect()
            # Abandoned login sessions otherwise accumulate forever. The
            # purge runs first so a lifecycle failure cannot starve it.
            _session_store.purge_expired(connection, int(time.time()))
            cat = BucketCatalog(ManifestStore(connection))
            BucketLifecycleStore(cat).apply_due(now=int(time.time()), limit=100)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            app._log("lifecycle scheduler: " + type(exc).__name__, "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(3600)


async def tiering_scheduler_loop() -> None:
    """Apply enabled Intelligent-Tiering configurations hourly, bounded.

    The pass updates this catalog's access gate and queues the physical
    cold copy for every transition into an archived class; Telegram
    bytes are never moved or deleted by it. This loop also drains the
    handoff-08 archive/restore worker queues (tiering, lifecycle
    transitions and RestoreObject all enqueue into them), so a queued
    archive or restore progresses without any other process.
    """
    while True:
        app = _app()
        connection = None
        try:
            from teledrive.s3.tiering import TieringStore
            from teledrive.storage.cold_store import (
                ArchiveStore, ColdBlobStore, default_cold_root,
            )
            connection = app.db_connect()
            cat = BucketCatalog(ManifestStore(connection))
            TieringStore(cat).apply_due(now_ns=time.time_ns(), limit=1000)
            # Bounded physical archive/restore passes. The staging cache
            # purge closes expired restore windows and clears their
            # staged copies (never the archive data).
            archive = ArchiveStore(cat, ColdBlobStore(default_cold_root()))
            await archive.run_archive_pass(
                app.storage_transport(connection),
                scratch_directory=Path(app.STORAGE_SCRATCH_DIR), limit=5)
            archive.run_restore_pass(limit=10)
            archive.purge_expired(now_ns=time.time_ns())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            app._log("tiering scheduler: " + type(exc).__name__, "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(3600)


async def notification_scheduler_loop() -> None:
    """Deliver due S3 webhook events with bounded exponential backoff."""
    while True:
        app = _app()
        connection = None
        delivered = 0
        try:
            from teledrive.s3.credentials import load_master_key
            from teledrive.s3.notifications import NotificationDelivery
            connection = app.db_connect()
            cat = BucketCatalog(ManifestStore(connection))
            result = NotificationDelivery(
                cat, master_key=load_master_key(),
            ).deliver_due(now_ns=time.time_ns(), limit=50)
            delivered = result.delivered
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            app._log("notification scheduler: " + type(exc).__name__,
                     "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(30 if delivered else 60)


async def report_scheduler_loop() -> None:
    """Generate due analytics/inventory/metrics report objects hourly.

    The configuration PUTs only store intent; without this pass no report
    object is ever produced. The runner is itself bounded and records a
    per-configuration failure in ``last_error`` instead of raising.
    """
    while True:
        app = _app()
        connection = None
        try:
            from teledrive.s3.report_runner import run_due_reports
            connection = app.db_connect()
            cat = BucketCatalog(ManifestStore(connection))
            scratch = Path(app.STORAGE_SCRATCH_DIR)
            app._secure_mkdir(scratch)
            await run_due_reports(
                cat, int(time.time()),
                transport=app.storage_transport(connection),
                scratch_directory=scratch,
            )
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            # No Telegram session yet: expected on an unconfigured install.
            message = f"report scheduler idle: {exc.detail}"
            if _SCHEDULER_IDLE_NOTICE.get("reports") != message:
                app._log(message, "scheduler")
                _SCHEDULER_IDLE_NOTICE["reports"] = message
        except Exception as exc:
            app._log("report scheduler: " + type(exc).__name__, "scheduler")
        finally:
            if connection is not None:
                connection.close()
        await asyncio.sleep(3600)


def folder_watch_scan() -> dict:
    """One auto-sync pass: enqueue new/changed files from the source root.

    Returns the enqueue_legacy_folder report (queued, already_queued,
    excluded, job_ids). Raises when the source root is not configured.
    """
    app = _app()
    from teledrive.storage.legacy_bridge import enqueue_legacy_folder
    root = _storage_job_root()
    conn = app.db_connect()
    try:
        cfg = app.effective_config()
        source_root = Path(cfg.source_dir).resolve(strict=True)
        if not source_root.is_relative_to(root):
            raise RuntimeError("watch source is outside the job root")
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        report = enqueue_legacy_folder(
            cfg, manager, bucket=app.WATCH_BUCKET, prefix="",
            max_files=100, dry_run=False, lease_heartbeat=None,
        )
        conn.connection.commit()
        return {"queued": report.queued, "already_queued": report.already_queued,
                "excluded": report.excluded, "job_ids": list(report.job_ids)}
    finally:
        conn.close()


async def folder_watch_loop() -> None:
    """Optional folder auto-sync (jobs.watch in config/config.yaml).

    Every jobs.watch_interval_seconds the source root is scanned and
    new/changed files are enqueued as durable upload jobs targeting
    jobs.watch_bucket. Failures never crash the loop; the durable job
    scheduler performs the actual Telegram uploads.
    """
    while True:
        app = _app()
        interval = max(5, int(app.WATCH_INTERVAL))
        try:
            if not app.WATCH_ENABLED:
                await asyncio.sleep(10)
                continue
            if not app.WATCH_BUCKET:
                app._log("folder watch enabled but jobs.watch_bucket is not "
                         "configured; skipping scans", "watcher")
                await asyncio.sleep(60)
                continue
            report = folder_watch_scan()
            if report.get("queued"):
                app._log(f"folder watch queued {report['queued']} file(s)",
                         "watcher")
        except asyncio.CancelledError:
            raise
        except HTTPException as exc:
            # Source root not configured yet — expected on fresh installs.
            message = f"folder watch idle: {exc.detail}"
            if _SCHEDULER_IDLE_NOTICE.get("watch") != message:
                app._log(message, "watcher")
                _SCHEDULER_IDLE_NOTICE["watch"] = message
            interval = max(interval, 60)
        except Exception as exc:
            app._log("folder watch: " + type(exc).__name__, "watcher")
        await asyncio.sleep(interval)
