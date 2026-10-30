"""S3 credential and storage-operations administration.

API key issuance, S3 access-credential CRUD/reveal, multipart and pending
upload recovery, physical GC, and the storage job/recovery admin routes.
Distinct from the WebUI bucket browser in ``web/routers/buckets.py`` and from
the API-key-scoped REST data plane in ``web/routers/rest.py``.

Paths are absolute: ``APIRouter`` has no prefix because ``web.permissions``
matches the full route path. Every secret-bearing credential handler keeps
``_require_interactive_session``; that is the escalation guard, not a nicety.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from teledrive import uploader
from teledrive.api_keys import ApiKeyStore
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.multipart import MultipartStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.gc import StorageGCInventory
from teledrive.storage.gc_collect import RetainedMediaGC
from teledrive.storage.history_inventory import inventory_channel
from teledrive.storage.jobs import (
    StorageUploadJobs, UploadJobError, jobs as storage_job_rows,
)
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.mtproto_rate_guard import MtprotoRateGuard
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from web.deps import (
    _require_interactive_session, _require_within_delegation,
    _require_within_lifetime, _same_origin, permission_registry, require_auth,
)
from web.errors import _credential_error

router = APIRouter()


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


class KeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=20)
    expires_at: int | None = Field(default=None, description="Optional Unix expiry time")


class GCToggleRequest(BaseModel):
    enabled: bool
    confirm: str | None = Field(
        default=None, description='Typed confirmation "PHYSICAL-GC" to enable')
    grace_seconds: int | None = Field(
        default=None, ge=3600, le=90 * 86400,
        description="Grace period for queued physical collections")


class GCCollectRequest(BaseModel):
    scope: str = Field(default="revoked", description="revoked | deleted")
    dry_run: bool = Field(default=True)
    min_age_seconds: int = Field(default=86400, ge=3600, le=90 * 86400)
    limit: int = Field(default=50, ge=1, le=1000)
    confirm: str | None = Field(
        default=None, description='Typed confirmation "DELETE-RETAINED" to execute')


# A new S3 credential with no explicit permission list gets READ-ONLY
# object access. It used to default to every known permission, so an omitted
# field silently produced a credential that could delete buckets and rewrite
# bucket policy -- the opposite of least privilege for the common case.
DEFAULT_NEW_CREDENTIAL_PERMISSIONS = [
    "s3:ListAllMyBuckets", "s3:ListBucket", "s3:GetBucketLocation",
    "s3:GetObject", "s3:GetObjectAttributes",
]


class S3KeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(
        default_factory=lambda: list(DEFAULT_NEW_CREDENTIAL_PERMISSIONS))
    expires_at: int | None = None


class S3CompletionRecoveryRequest(BaseModel):
    execute: bool = False
    min_age_seconds: int = Field(default=3600, ge=60, le=30 * 86400)


class PendingUploadRecoveryRequest(BaseModel):
    execute: bool = False
    min_age_seconds: int = Field(default=3600, ge=60, le=30 * 86400)


class StorageUploadJobRequest(BaseModel):
    bucket: str = Field(min_length=3, max_length=63)
    key: str = Field(min_length=1, max_length=1024)
    source_path: str = Field(min_length=1, max_length=4096)


class LegacyFolderImportRequest(BaseModel):
    bucket: str = Field(min_length=3, max_length=63)
    prefix: str = Field(default="", max_length=512)
    max_files: int = Field(default=100, ge=1, le=1000)
    execute: bool = False


@router.get("/api/v1/admin/keys", tags=["API keys"], summary="List API key metadata; never returns secrets")
def list_api_keys(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        return {"keys": ApiKeyStore(conn).list()}
    finally:
        conn.close()


@router.get("/api/v1/admin/keys/permissions", tags=["API keys"],
         summary="The per-endpoint permission catalog for key issuance")
def list_api_key_permissions(_: None = Depends(require_auth)):
    """EVERY API route is individually permissionable — the catalog is
    derived from the live route table, so it can never drift. The nine
    REST bearer endpoints keep their curated short names; every other
    route carries a canonical "method:path" permission. Legacy grouped
    scopes remain valid as aliases (existing keys keep working)."""
    from teledrive.api_keys import (ENDPOINT_PERMISSIONS,
                                     LEGACY_SCOPE_EXPANSION)
    registry = permission_registry()
    routes = registry.catalog()
    curated = set(ENDPOINT_PERMISSIONS)
    for entry in routes:
        if entry["name"] in curated:
            entry["summary"] = ENDPOINT_PERMISSIONS[entry["name"]]
    return {
        "routes": routes,
        "groups": registry.groups(),
        "legacy_scopes": [
            {"name": name, "expands_to": sorted(expansion)}
            for name, expansion in sorted(LEGACY_SCOPE_EXPANSION.items())],
    }


@router.post("/api/v1/admin/keys", tags=["API keys"], status_code=201, summary="Issue a scoped API key (secret returned once)")
def issue_api_key(request: Request, payload: KeyCreateRequest, _: None = Depends(require_auth)):
    _same_origin(request)
    from teledrive.api_keys import expand_scopes
    # A key may only mint a key whose effective permissions are a subset
    # of its own. The route permission is checked by require_auth; this
    # stops privilege escalation through minting.
    _require_within_delegation(
        request, expand_scopes(payload.scopes), "key creation")
    _require_within_lifetime(request, payload.expires_at)
    conn = _webapp().db_connect()
    try:
        try:
            # Keys may carry ANY single-route permission from the live
            # registry plus the legacy grouped scopes.
            route_permissions = frozenset(
                entry["name"] for entry in permission_registry().catalog())
            key = ApiKeyStore(conn).create(
                payload.name, payload.scopes, expires_at=payload.expires_at,
                extra_allowed=route_permissions)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        # Log AFTER the row exists, with the actor and the new key's id:
        # logging before the store call made a rejected request read as a
        # successful issuance, and "system" made the entry unattributable.
        _webapp()._audit(request, "api_key.issue", target=key.id,
               detail={"prefix": key.prefix, "scopes": list(key.scopes),
                       "expires_at": payload.expires_at})
        _webapp()._log(f"issue api key: id={key.id} prefix={key.prefix} "
             f"scopes={key.scopes} expires_at={payload.expires_at}",
             "api-keys",
             user=(getattr(request.state, "user", None) or {}).get(
                 "username") or "system")
        return {"id": key.id, "token": key.value, "prefix": key.prefix,
                "scopes": key.scopes, "expires_at": payload.expires_at}
    finally:
        conn.close()


@router.delete("/api/v1/admin/keys/{identifier}", tags=["API keys"], summary="Revoke an API key immediately")
def revoke_api_key(identifier: str, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        target_scopes = ApiKeyStore(conn).scopes_for_identifier(identifier)
        # A key may not revoke authority above its own (that is a
        # denial-of-service lever against a more privileged key).
        _require_within_delegation(
            request, frozenset(target_scopes or ()), "key revocation")
        _webapp()._log(f"revoke api key: id={identifier}", "api-keys")
        if not ApiKeyStore(conn).revoke(identifier):
            raise HTTPException(404, "API key not found or already revoked")
        return {"ok": True}
    finally:
        conn.close()


@router.post("/api/v1/admin/keys/{identifier}/rotate", tags=["API keys"], summary="Rotate an API key; secret returned once")
def rotate_api_key(identifier: str, request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        # Rotation returns the NEW SECRET, so rotating a key with more
        # authority than the caller would hand over that authority.
        target_scopes = ApiKeyStore(conn).scopes_for_identifier(identifier)
        _require_within_delegation(
            request, frozenset(target_scopes or ()), "key rotation")
        try:
            key = ApiKeyStore(conn).rotate(identifier)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        _webapp()._audit(request, "api_key.rotate", target=key.id,
               detail={"replaced": str(identifier)})
        _webapp()._log(f"rotate api key: old={identifier} new={key.id} "
             f"prefix={key.prefix}", "api-keys",
             user=(getattr(request.state, "user", None) or {}).get(
                 "username") or "system")
        return {"id": key.id, "token": key.value, "prefix": key.prefix,
                "scopes": key.scopes}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/gc-candidates", tags=["Storage recovery"],
         summary="Retention-aware dry-run FAILED journal planning, never deletion")
def list_storage_gc_candidates(
    min_age_seconds: int = Query(default=7*86400, ge=86400, le=365*86400),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            candidates = StorageGCInventory(catalog.manifests).preview_failed_retention(
                now=int(time.time()), min_age_seconds=min_age_seconds, limit=limit
            )
        except RuntimeError as exc:
            raise HTTPException(409, "Reference graph is inconsistent; GC blocked") from exc
        return {
            "candidates": candidates,
            "dry_run": True, "physical_deletion_enabled": False,
            "remote_history_scan_required": True,
        }
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/gc-audit", tags=["API keys"],
         summary="Audit Telegram object references before any physical cleanup")
def get_storage_gc_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    """Root-admin-only, non-destructive inventory; never authorizes remote deletion."""
    from dataclasses import asdict

    conn = _webapp().db_connect()
    try:
        # Also ensure the bucket/head metadata tables exist on a new DB.
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            inventory = StorageGCInventory(catalog.manifests).inspect()
        except RuntimeError as exc:
            raise HTTPException(409, "Reference graph is inconsistent; GC blocked") from exc
        return {
            "total_manifests": inventory.total_manifests,
            "total_telegram_messages": inventory.total_telegram_messages,
            "unjournaled_mtproto_receipts": inventory.unjournaled_mtproto_receipts,
            "unresolved_mtproto_intents": inventory.unresolved_mtproto_intents,
            "active_upload_jobs": inventory.active_upload_jobs,
            "live_object_heads": inventory.live_object_heads,
            "copy_aliases": inventory.copy_aliases,
            "multipart_parts": inventory.multipart_parts,
            "eligible_for_deletion": 0,
            "dry_run": True,
            "physical_deletion_enabled": False,
            "protected_chunks": [
                asdict(row) for row in inventory.protected_chunks[:limit]
            ],
            "truncated": len(inventory.protected_chunks) > limit,
        }
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/gc", tags=["Storage GC"],
         summary="Physical GC state, logical vs physical metrics (WebUI)")
def gc_status(_: None = Depends(require_auth)):
    """Owner-facing GC view: the toggle state, the split between
    LOGICAL usage (current heads) and PHYSICAL Telegram storage, the
    reclaimable backlog and what previous collections removed. The
    informational gates mirror the GC plan contract."""
    conn = _webapp().db_connect()
    try:
        gcx = RetainedMediaGC(conn)
        return {
            "state": gcx.state(),
            "metrics": gcx.metrics(),
            "gates": {
                "independent_payload_backup_verified": False,
                "restore_drill_verified": False,
                "writer_barrier_verified": True,
                "owner_toggle_required": not gcx.state()["enabled"],
            },
        }
    finally:
        conn.close()


@router.put("/api/v1/admin/storage/gc", tags=["Storage GC"],
         summary="Enable or disable physical GC (owner decision)")
def gc_toggle(request: Request, payload: GCToggleRequest,
              _: None = Depends(require_auth)):
    _same_origin(request)
    if payload.enabled and payload.confirm != "PHYSICAL-GC":
        raise HTTPException(
            422, 'Enabling physical GC requires confirm="PHYSICAL-GC"')
    user = getattr(request.state, "user", {}) or {}
    conn = _webapp().db_connect()
    try:
        gcx = RetainedMediaGC(conn)
        try:
            gcx.set_enabled(payload.enabled, by=str(user.get("username", "?")),
                            grace_seconds=payload.grace_seconds)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        _webapp()._log(f"physical gc {'ENABLED' if payload.enabled else 'disabled'} "
             f"by {user.get('username', '?')} — Telegram media of logically "
             f"deleted objects becomes reclaimable via collect",
             "gc")
        return {"ok": True, "state": gcx.state()}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/gc/collect", tags=["Storage GC"],
          summary="Preview (dry-run) or execute physical collection of retained media")
async def gc_collect(request: Request, payload: GCCollectRequest,
                     _: None = Depends(require_auth)):
    """Dry-run (default) enumerates the fail-closed candidate set.
    Execution additionally requires GC enabled and the typed
    confirmation. Every candidate is re-verified immediately before its
    Telegram messages are deleted; partial failures stay retryable."""
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        gcx = RetainedMediaGC(conn)
        try:
            candidates = gcx.candidates(
                scope=payload.scope, min_age_seconds=payload.min_age_seconds,
                limit=payload.limit)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if payload.dry_run:
            return {"dry_run": True, "scope": payload.scope,
                    "count": len(candidates), "candidates": candidates}
        if payload.confirm != "DELETE-RETAINED":
            raise HTTPException(
                422, 'Executing collection requires confirm="DELETE-RETAINED"')
        if not gcx.state()["enabled"]:
            raise HTTPException(
                409, "Physical GC is disabled; enable it first (owner gate)")
        transport = _webapp().storage_transport(conn)
        user = getattr(request.state, "user", {}) or {}
        # A physical collection is the one irreversible action in the
        # product: it gets a durable trail with the candidate count, the
        # scope and the real actor, before and after.
        _webapp()._audit(request, "gc.collect.start", target=payload.scope,
               detail={"candidates": len(candidates),
                       "min_age_seconds": payload.min_age_seconds})
        _webapp()._log(f"physical gc collect START scope={payload.scope} "
             f"candidates={len(candidates)} by {user.get('username', '?')}",
             "gc")
        report = await gcx.collect(
            transport, scope=payload.scope,
            min_age_seconds=payload.min_age_seconds,
            chunk_refs=candidates)
        _webapp()._audit(request, "gc.collect.done", target=payload.scope,
               outcome="partial" if report["failed"] else "ok",
               detail={"collected": len(report["collected"]),
                       "skipped": len(report["skipped"]),
                       "failed": len(report["failed"]),
                       "bytes": sum(c.get("bytes", 0)
                                    for c in report["collected"])})
        _webapp()._log(f"physical gc collect DONE scope={payload.scope} "
             f"collected={len(report['collected'])} "
             f"skipped={len(report['skipped'])} "
             f"failed={len(report['failed'])}", "gc")
        return {"dry_run": False, "scope": payload.scope, **report,
                "metrics": gcx.metrics()}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/health", tags=["Storage jobs"],
         summary="Read storage jobs, stale leases and protected-media metrics")
def storage_operations_health(_: None = Depends(require_auth)):
    from sqlalchemy import func, select

    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        queue = StorageUploadJobs(catalog)
        counts = conn.connection.execute(
            select(storage_job_rows.c.state, func.count())
            .group_by(storage_job_rows.c.state)
        ).all()
        now = int(time.time())
        pending = catalog.manifests.stale_pending(now=now, limit=1000)
        completing = MultipartStore(catalog).stale_completions(now=now, limit=1000)
        try:
            gc = StorageGCInventory(catalog.manifests).inspect()
        except RuntimeError as exc:
            raise HTTPException(409, "Reference graph is inconsistent; GC blocked") from exc
        states = {state: int(count) for state, count in counts}
        alerts = []
        if gc.unresolved_mtproto_intents:
            alerts.append({
                "code": "unresolved_mtproto_sends", "severity": "critical",
                "count": gc.unresolved_mtproto_intents,
                "message": "MTProto sends have unknown acceptance; do not retry until owner-verified reconciliation",
            })
        if gc.unjournaled_mtproto_receipts:
            alerts.append({
                "code": "unjournaled_mtproto_receipts", "severity": "warning",
                "count": gc.unjournaled_mtproto_receipts,
                "message": "MTProto send receipts not yet linked to a chunk journal; review persistent samples",
            })
        if states.get("failed", 0):
            alerts.append({
                "code": "failed_upload_jobs", "severity": "warning",
                "count": states["failed"],
                "message": "Failed upload jobs require explicit operator retry or cancellation",
            })
        if pending:
            alerts.append({
                "code": "stale_pending_uploads", "severity": "warning",
                "count": len(pending),
                "message": "Expired PENDING writers need dry-run recovery review",
            })
        if completing:
            alerts.append({
                "code": "stale_multipart_completions", "severity": "warning",
                "count": len(completing),
                "message": "Stale multipart completion leases need dry-run review",
            })
        truncated = len(pending) >= 1000 or len(completing) >= 1000
        if truncated:
            alerts.append({
                "code": "sample_limit_reached", "severity": "critical",
                "count": None,
                "message": "Recovery sample limit reached; inventory may be incomplete",
            })
        return {
            "job_states": states,
            "alerts": alerts,
            "unresolved_alert_count": len(alerts),
            "stale_pending_sample_count": len(pending),
            "stale_multipart_sample_count": len(completing),
            "unjournaled_mtproto_receipt_count": gc.unjournaled_mtproto_receipts,
            "unresolved_mtproto_send_count": gc.unresolved_mtproto_intents,
            "mtproto_explicit_flood_total": MtprotoRateGuard(
                conn
            ).total_explicit_flood_observations(),
            "samples_truncated": truncated,
            "telegram_messages_retained": gc.total_telegram_messages,
            "live_object_heads": gc.live_object_heads,
            "copy_aliases": gc.copy_aliases,
            "physical_deletion_enabled": False,
        }
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/mtproto-unresolved", tags=["Storage jobs"],
         summary="Inspect unresolved USER-MTProto send intents without modifying Telegram")
def list_unresolved_mtproto_sends(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    # Operator-only diagnostic: return immutable source identity for
    # independent channel proof. Never accept unverified receipt IDs or
    # perform a retry/deletion as a side effect of inspecting this list.
    from sqlalchemy import func, select
    from teledrive.storage.user_mode import mtproto_send_intents

    conn = _webapp().db_connect()
    try:
        rows = conn.connection.execute(
            select(
                mtproto_send_intents.c.account, mtproto_send_intents.c.chat_id,
                mtproto_send_intents.c.object_id, mtproto_send_intents.c.ordinal,
                mtproto_send_intents.c.sha256, mtproto_send_intents.c.size,
            ).where(mtproto_send_intents.c.message_id.is_(None))
            .order_by(mtproto_send_intents.c.object_id,
                      mtproto_send_intents.c.ordinal)
            .limit(limit)
        ).all()
        total = conn.connection.execute(
            select(func.count()).select_from(mtproto_send_intents).where(
                mtproto_send_intents.c.message_id.is_(None)
            )
        ).scalar_one()
        return {
            "total": int(total),
            "intents": [
                {
                    "account": account, "chat_id": int(chat_id),
                    "object_id": object_id, "ordinal": int(ordinal),
                    "sha256": sha256, "size": int(size),
                }
                for account, chat_id, object_id, ordinal, sha256, size in rows
            ],
            "message": (
                "Possible remotely accepted USER-MTProto sends. Independently "
                "verify the original channel message ID and full Telegram "
                "bytes before recording any recovery receipt. No automatic retry."
            ),
        }
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/jobs", tags=["Storage jobs"],
         summary="Inspect durable local-source upload jobs (no worker tokens)")
def list_storage_upload_jobs(
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = _webapp().db_connect()
    try:
        return {"jobs": StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
                .list_jobs(limit=limit)}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/jobs", tags=["Storage jobs"],
          status_code=201, summary="Queue an allowed-root file for Telegram upload")
def create_storage_upload_job(
    request: Request, payload: StorageUploadJobRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    _webapp()._log(f"queue job: bucket={payload.bucket} key={payload.key} source={payload.source_path}", "jobs")
    root = _webapp()._storage_job_root()
    conn = _webapp().db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        try:
            job_id = manager.enqueue(
                payload.bucket, payload.key, Path(payload.source_path),
                allowed_root=root,
            )
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except (UploadJobError, ValueError, OSError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": job_id, "state": "queued"}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/jobs/import-legacy",
          tags=["Storage jobs"], summary="Preview or queue legacy folder files without uploading")
def import_legacy_folder_jobs(
    request: Request, payload: LegacyFolderImportRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    from teledrive.storage.legacy_bridge import enqueue_legacy_folder
    approved_root = _webapp()._storage_job_root()
    cfg = _webapp().effective_config()
    try:
        source_root = Path(cfg.source_dir).resolve(strict=True)
    except OSError as exc:
        raise HTTPException(503, "Legacy source folder unavailable") from exc
    if not source_root.is_relative_to(approved_root):
        raise HTTPException(403, "Legacy source is outside the configured job root")
    conn = _webapp().db_connect()
    try:
        now = int(time.time())
        holder = "legacy-bridge-" + os.urandom(16).hex()
        if not conn.acquire_lease(
            uploader.LEASE_NAME, holder, now, uploader.LEASE_TTL_SECONDS
        ):
            raise HTTPException(409, "Legacy uploader currently holds a lease")
        try:
            last_renew = time.monotonic()

            def heartbeat():
                nonlocal last_renew
                if time.monotonic() - last_renew < 10:
                    return
                if not conn.renew_lease(
                    uploader.LEASE_NAME, holder,
                    int(time.time()), uploader.LEASE_TTL_SECONDS
                ):
                    raise RuntimeError("Legacy uploader lease lost during import")
                last_renew = time.monotonic()

            manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
            try:
                report = enqueue_legacy_folder(
                    cfg, manager, bucket=payload.bucket, prefix=payload.prefix,
                    max_files=payload.max_files,
                    dry_run=not payload.execute, lease_heartbeat=heartbeat,
                )
            except FileNotFoundError as exc:
                raise HTTPException(404, "Destination object bucket not found") from exc
            except (UploadJobError, ValueError, OSError) as exc:
                raise HTTPException(422, str(exc)) from exc
            return {
                "dry_run": not payload.execute,
                "queued": report.queued if payload.execute else 0,
                "would_queue": report.queued,
                "already_queued": report.already_queued,
                "excluded": report.excluded,
                "job_ids": list(report.job_ids) if payload.execute else [],
                "uploads_started": 0,
            }
        finally:
            conn.release_lease(uploader.LEASE_NAME, holder)
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/jobs/run-next", tags=["Storage jobs"],
          summary="Process one queued upload with SQL lease, checksums and CAS")
async def run_next_storage_upload_job(
    request: Request, _: None = Depends(require_auth),
):
    _same_origin(request)
    _webapp()._log("run-next job triggered", "jobs")
    root = _webapp()._storage_job_root()
    conn = _webapp().db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        transport = _webapp().storage_transport(conn)
        scratch = Path(_webapp().STORAGE_SCRATCH_DIR)
        _webapp()._secure_mkdir(scratch)
        try:
            result = await manager.run_next(
                transport, allowed_root=root, scratch_directory=scratch,
                chunk_size=RECOMMENDED_CHUNK_SIZE,
            )
        except (UploadJobError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(503, "Telegram upload failed; job retained for retry") from exc
        return {"job": result}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/jobs/{job_id}/retry", tags=["Storage jobs"],
          summary="Explicitly retry a failed job; never remove Telegram messages")
def retry_storage_upload_job(
    job_id: str, request: Request, _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        if not manager.retry(job_id):
            raise HTTPException(409, "Job is not failed or does not exist")
        return {"id": job_id, "state": "queued"}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/jobs/{job_id}/cancel", tags=["Storage jobs"],
          summary="Cancel only inactive jobs; preserve all Telegram media")
def cancel_storage_upload_job(
    job_id: str, request: Request, _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        manager = StorageUploadJobs(BucketCatalog(ManifestStore(conn)))
        if not manager.cancel(job_id):
            raise HTTPException(409, "Job is active, completed, cancelled or does not exist")
        return {"id": job_id, "state": "cancelled"}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/pending-stale", tags=["Storage recovery"],
         summary="Preview aged PENDING upload leases; no Telegram deletion")
def list_stale_pending_objects(
    min_age_seconds: int = Query(default=3600, ge=60, le=30 * 86400),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = _webapp().db_connect()
    try:
        items = ManifestStore(conn).stale_pending(
            now=int(time.time()), min_age_seconds=min_age_seconds, limit=limit
        )
        return {"uploads": items, "dry_run": True, "physical_deletion_enabled": False}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/pending-stale/{object_id}/abandon",
          tags=["Storage recovery"],
          summary="Explicitly fence an aged PENDING writer and retain Telegram journal")
def abandon_stale_pending_object(
    object_id: str, request: Request,
    payload: PendingUploadRecoveryRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        manifests = ManifestStore(conn)
        now = int(time.time())
        # A preview never mutates the writer's lease, even after a restart.
        if not payload.execute:
            matches = manifests.stale_pending(
                now=now, min_age_seconds=payload.min_age_seconds, limit=1000
            )
            return {"object_id": object_id,
                    "eligible": any(item["id"] == object_id for item in matches),
                    "abandoned": False, "dry_run": True}
        # Only this object can be transitioned. The SQL conditional update
        # ensures a heartbeat, completed object or another admin wins safely.
        affected = manifests.abandon_stale_pending(
            now=now, min_age_seconds=payload.min_age_seconds,
            limit=1, object_id=object_id,
        )
        return {"object_id": object_id, "eligible": bool(affected),
                "abandoned": bool(affected), "dry_run": False}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/channel-history", tags=["Storage history"],
         summary="Bounded read-only user-MTProto channel history (unverified candidates)")
async def inspect_user_channel_history(
    limit: int = Query(default=100, ge=1, le=1000),
    before_message_id: int | None = Query(default=None, ge=1),
    include_external_markers: bool = Query(default=False),
    _: None = Depends(require_auth),
):
    """Never download media, change catalog mappings or delete channel posts.

    Other senders' markers are NOT trusted ownership/manifest evidence.
    The endpoint deliberately only runs with the already-connected USER
    transport; only an authorized user session can enumerate channel history.
    """
    try:
        runtime = _webapp().mtproto_storage_runtime
        runtime.require()
        target = runtime.transport.accounts[runtime.account][1]
        return await inventory_channel(
            runtime.client, target, account=runtime.account,
            scan_limit=limit, before_message_id=before_message_id,
            include_external_markers=include_external_markers,
        )
    except (ValueError, RuntimeError, OSError):
        raise HTTPException(503, "Authorized channel history inspection unavailable") from None


@router.get("/api/v1/admin/s3-multipart/stale", tags=["API keys"],
         summary="Preview expired multipart completion leases (never deletes chunks)")
def list_stale_s3_completions(
    min_age_seconds: int = Query(default=3600, ge=60, le=30 * 86400),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = _webapp().db_connect()
    try:
        mpu = MultipartStore(BucketCatalog(ManifestStore(conn)))
        return {"uploads": mpu.stale_completions(
            min_age_seconds=min_age_seconds, limit=limit
        )}
    finally:
        conn.close()


@router.post("/api/v1/admin/s3-multipart/{upload_id}/recover", tags=["API keys"],
          summary="Dry-run or explicitly recover an expired multipart completion lease")
def recover_stale_s3_completion(
    request: Request, upload_id: str, payload: S3CompletionRecoveryRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        mpu = MultipartStore(BucketCatalog(ManifestStore(conn)))
        eligible = mpu.recover_stale_completion(
            upload_id, dry_run=not payload.execute,
            min_age_seconds=payload.min_age_seconds,
        )
        return {"upload_id": upload_id, "eligible": eligible,
                "recovered": bool(eligible and payload.execute),
                "dry_run": not payload.execute}
    finally:
        conn.close()


@router.get("/api/v1/admin/s3/credentials", tags=["API keys"],
         summary="List S3 access key metadata (secrets never returned)")
@router.get("/api/v1/admin/s3-credentials", tags=["API keys"],
         include_in_schema=False)
def list_s3_credentials(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        try:
            return {"credentials": S3CredentialStore(conn, _webapp().load_master_key()).list()}
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
    finally:
        conn.close()


@router.post("/api/v1/admin/s3/credentials", tags=["API keys"], status_code=201,
          summary="Issue encrypted S3 access credentials (secret displayed once)")
@router.post("/api/v1/admin/s3-credentials", tags=["API keys"], status_code=201,
          include_in_schema=False)
def issue_s3_credentials(request: Request, payload: S3KeyCreateRequest,
                         _: None = Depends(require_auth)):
    _same_origin(request)
    actor = _require_interactive_session(request, "issue")
    conn = _webapp().db_connect()
    try:
        try:
            key = S3CredentialStore(conn, _webapp().load_master_key()).create(
                payload.name, payload.permissions, expires_at=payload.expires_at
            )
        except (RuntimeError, OSError, ValueError) as exc:
            raise _credential_error(exc) from exc
        _webapp()._log(f"s3 credential issued: id={key.id} access={key.access_key} "
             f"permissions={len(key.permissions)} "
             f"expires_at={payload.expires_at}", "security", user=actor)
        _webapp()._audit(request, "credential.issue", target=key.id,
               detail={"access_key": key.access_key,
                       "permissions": len(key.permissions),
                       "expires_at": payload.expires_at})
        return {"id": key.id, "access_key": key.access_key,
                "secret_key": key.secret_key, "permissions": key.permissions}
    finally:
        conn.close()


@router.get("/api/v1/admin/s3/credentials/{identifier}/secret",
         tags=["API keys"],
         summary="Reveal an S3 credential secret (session only, audit-logged)")
@router.get("/api/v1/admin/s3-credentials/{identifier}/secret",
         tags=["API keys"], include_in_schema=False)
def reveal_s3_credential_secret(request: Request, identifier: str,
                                _: None = Depends(require_auth)):
    """Hand out a decrypted S3 secret. Interactive sessions only.

    Why API keys are refused here: an API key is itself a credential, so
    letting one reveal another credential's secret creates a chain of secret
    holders and bypasses the delegation ceiling that blocks minting or
    rotating a more privileged key. A key scoped to just this route could
    otherwise read the secret of a credential holding s3:PutBucketPolicy,
    which is a privilege escalation with no audit trail tying it to a person.
    A human session is interactive, CSRF-fenced and revocable, so it is the
    only principal allowed to see a secret.
    """
    actor = _require_interactive_session(request, "reveal the secret of")
    if not isinstance(identifier, str) or not 1 <= len(identifier) <= 200:
        raise HTTPException(422, "Invalid credential identifier")
    conn = _webapp().db_connect()
    try:
        try:
            revealed = S3CredentialStore(
                conn, _webapp().load_master_key()).reveal(identifier)
        except RuntimeError as exc:
            # Never echo a path or key state; the audit line carries the
            # reason class only.
            _webapp()._log(f"s3 credential secret reveal failed: id={identifier} "
                 f"reason=runtime", "security", user=actor)
            raise HTTPException(
                503, "Credential secrets are unavailable: the master key "
                     "cannot be loaded") from exc
        except OSError as exc:
            _webapp()._log(f"s3 credential secret reveal failed: id={identifier} "
                 f"reason=master-key-io", "security", user=actor)
            raise HTTPException(
                503, "Credential secrets are unavailable: the master key "
                     "cannot be loaded") from exc
        except ValueError as exc:
            _webapp()._log(f"s3 credential secret reveal failed: id={identifier} "
                 f"reason=invalid-target", "security", user=actor)
            raise HTTPException(422, str(exc)) from exc
        _webapp()._log(f"s3 credential secret revealed: id={identifier} "
             f"access={revealed['access_key']}", "security", user=actor)
        _webapp()._audit(request, "credential.reveal", target=str(identifier),
               detail={"access_key": revealed["access_key"]})
        return revealed
    finally:
        conn.close()


@router.put("/api/v1/admin/s3/credentials/{identifier}", tags=["API keys"],
         summary="Edit an active S3 credential (name, permissions, expiry)")
@router.put("/api/v1/admin/s3-credentials/{identifier}", tags=["API keys"],
         include_in_schema=False)
def update_s3_credentials(request: Request, identifier: str,
                          payload: dict = Body(...),
                          _: None = Depends(require_auth)):
    _same_origin(request)
    actor = _require_interactive_session(request, "edit")
    conn = _webapp().db_connect()
    try:
        try:
            store = S3CredentialStore(conn, _webapp().load_master_key())
            updated = store.update(
                identifier,
                name=payload.get("name"),
                permissions=payload.get("permissions"),
                expires_at=payload.get("expires_at"),
                clear_expiry=payload.get("clear_expiry") is True,
            )
        except (RuntimeError, OSError, ValueError) as exc:
            raise _credential_error(exc) from exc
        _webapp()._audit(request, "credential.edit", target=str(identifier),
               detail={"permissions_changed": payload.get("permissions")
                       is not None,
                       "expires_at": payload.get("expires_at")})
        _webapp()._log(f"s3 credential edited: id={identifier} "
             f"permissions={None if payload.get('permissions') is None else len(payload['permissions'])} "
             f"expires_at={payload.get('expires_at')} "
             f"clear_expiry={payload.get('clear_expiry') is True}",
             "security", user=actor)
        return {"ok": True, "credential": updated}
    finally:
        conn.close()


@router.delete("/api/v1/admin/s3/credentials/{identifier}", tags=["API keys"],
            summary="Revoke an S3 access key immediately")
@router.delete("/api/v1/admin/s3-credentials/{identifier}", tags=["API keys"],
            include_in_schema=False)
def revoke_s3_credentials(request: Request, identifier: str,
                          _: None = Depends(require_auth)):
    _same_origin(request)
    actor = _require_interactive_session(request, "revoke")
    conn = _webapp().db_connect()
    try:
        try:
            changed = S3CredentialStore(conn, _webapp().load_master_key()).revoke(identifier)
        except (RuntimeError, OSError, ValueError) as exc:
            raise _credential_error(exc) from exc
        if not changed:
            raise HTTPException(404, "S3 key not found or already revoked")
        _webapp()._log(f"s3 credential revoked: id={identifier}", "security", user=actor)
        _webapp()._audit(request, "credential.revoke", target=str(identifier))
        return {"ok": True}
    finally:
        conn.close()