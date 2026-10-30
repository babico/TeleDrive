"""The REST data plane: /api/v1/buckets/{bucket}/...

Object and bucket operations authorized by per-route API-key scopes, not by a
session role. Paths are absolute: ``APIRouter`` has no prefix because
``web.permissions`` matches the full route path.

The read/upload cores stay in ``web.app`` because the WebUI download path and
the public site share them; this module reaches app-owned names through
``_webapp()`` so a call resolves at request time.
"""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from sqlalchemy import select as _sa_select

from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.manifest import ManifestStore, objects
from web.deps import require_api_scope
from web.routers.buckets import BucketCreateRequest

router = APIRouter()


def _webapp():
    import web.app as module
    return module

@router.get("/api/v1/buckets", tags=["Object catalog"], summary="List Telegram-backed storage buckets")
def list_storage_buckets(_: None = Depends(require_api_scope("rest:buckets:list"))):
    conn = _webapp().db_connect()
    try:
        return {"buckets": BucketCatalog(ManifestStore(conn)).list_buckets()}
    finally:
        conn.close()


@router.post("/api/v1/buckets", tags=["Object catalog"], status_code=201, summary="Create a bucket")
def create_storage_bucket(payload: BucketCreateRequest,
                          _: None = Depends(require_api_scope("rest:buckets:create"))):
    conn = _webapp().db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).create_bucket(payload.name, int(time.time()))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"name": payload.name}
    finally:
        conn.close()


@router.delete("/api/v1/buckets/{bucket}", tags=["Object catalog"], summary="Remove a physically empty bucket")
def remove_storage_bucket(bucket: str, _: None = Depends(require_api_scope("rest:buckets:delete"))):
    conn = _webapp().db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).delete_bucket(bucket)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ok": True}
    finally:
        conn.close()


@router.get("/api/v1/buckets/{bucket}/versions", tags=["Object catalog"],
         summary="List proven published immutable versions of a key")
def list_published_object_versions(
    bucket: str, key: str = Query(..., min_length=1, max_length=1024),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_api_scope("rest:objects:list-versions")),
):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        return {"bucket": bucket, "key": key,
                "versions": catalog.list_versions(bucket, key, limit=limit)}
    finally:
        conn.close()


@router.get("/api/v1/buckets/{bucket}/objects", tags=["Object catalog"], summary="List current object metadata")
def list_current_objects(bucket: str,
                         prefix: str = Query("", max_length=1024),
                         after: str | None = Query(None, max_length=1024),
                         limit: int = Query(100, ge=1, le=1000),
                         _: None = Depends(require_api_scope("rest:objects:list"))):
    conn = _webapp().db_connect()
    try:
        items = BucketCatalog(ManifestStore(conn)).list_objects(bucket, prefix=prefix, after=after, limit=limit)
        return {"objects": [
            {"id": x.item.id, "key": x.item.key, "bucket": x.item.bucket,
             "size": x.item.size, "sha256": x.item.sha256,
             "created_at": x.item.created_at, "generation": x.generation}
            for x in items
        ]}
    finally:
        conn.close()


@router.delete("/api/v1/buckets/{bucket}/objects", tags=["Object catalog"], summary="Unlink a current object (Telegram data retained)")
def unlink_current_object(bucket: str, key: str = Query(..., min_length=1, max_length=1024),
                          generation: int | None = Query(None, ge=1),
                          _: None = Depends(require_api_scope("rest:objects:delete"))):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        # A legal hold or an open retention window forbids removing the
        # object, and the S3 path already answers AccessDenied for it. The
        # REST unlink only hid the head, so the same logical delete behaved
        # differently depending on which surface it came from.
        try:
            held_item = catalog.get(bucket, key).item
        except FileNotFoundError:
            held_item = None
        if held_item is not None:
            lock_row = catalog.db.connection.execute(
                _sa_select(objects.c.legal_hold,
                           objects.c.retention_until_ns)
                .where(objects.c.id == held_item.id)).first()
            if lock_row is not None:
                if bool(lock_row[0]):
                    raise HTTPException(
                        403, "Object is under legal hold and cannot be "
                             "unlinked")
                if (lock_row[1] is not None
                        and int(lock_row[1]) > time.time_ns()):
                    raise HTTPException(
                        403, "Object is under retention and cannot be "
                             "unlinked")
        try:
            # A versioned bucket must keep history: a permanent head removal
            # there destroys the only record of the previous version, and
            # nothing in storage_removed_versions or the metadata journal
            # would describe what happened. AWS semantics are a delete
            # marker, which is exactly what delete_marker() writes.
            if catalog.versioning_state(bucket) == "Enabled":
                marker = catalog.delete_marker(bucket, key,
                                               expected_generation=generation)
                _webapp()._log(f"unlink {bucket}/{key}: delete marker {marker}", "storage")
                return {"ok": True, "unlinked": True, "delete_marker": marker}
            deleted = catalog.remove_current(
                bucket, key, expected_generation=generation
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(404, "Bucket not found") from exc
        _webapp()._log(f"unlink {bucket}/{key}: removed current head", "storage")
        return {"ok": True, "unlinked": deleted}
    finally:
        conn.close()


async def _stream_object_upload(bucket: str, key: str, request: Request,
                                generation: int | None) -> dict:
    """Shared upload core: validate, stage, enforce quota, upload, publish."""
    # The key must be valid BEFORE a single byte is staged or uploaded.
    # The catalog enforces 1..1024 UTF-8 BYTES, while the query parameter
    # enforces 1024 CHARACTERS, so a multibyte key (e.g. 600 x "é" = 1200
    # bytes) passed validation, uploaded the whole payload to Telegram, and
    # only then failed at publish -- leaving a ready manifest with no
    # published version, which physical GC deliberately never collects.
    # Unreclaimable bytes are worse than a rejected request.
    if not isinstance(key, str) or not (1 <= len(key.encode("utf-8")) <= 1024):
        raise HTTPException(422, "Object key must contain 1..1024 UTF-8 bytes")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/octet-stream":
        raise HTTPException(415, "Content-Type must be application/octet-stream")
    max_size = _webapp().REST_MAX_UPLOAD_BYTES
    if max_size < 1:
        raise HTTPException(503, "REST uploads are disabled by policy")
    stage_root = Path(_webapp().STORAGE_SCRATCH_DIR)
    _webapp()._secure_mkdir(stage_root)
    conn = _webapp().db_connect()
    staged = None
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        if generation is not None:
            try:
                current_generation = catalog.get(bucket, key).generation
            except FileNotFoundError:
                current_generation = 0
            if current_generation != generation:
                # Reject stale conditional writes BEFORE staging/uploading any
                # bytes to Telegram. Recheck atomically at final publication.
                raise HTTPException(409, "Object generation precondition failed")
        transport = _webapp().storage_transport(conn)
        # Verify Telegram access BEFORE consuming a potentially large body.
        await transport.verify_target()
        fd, pathname = tempfile.mkstemp(dir=stage_root, prefix="api-upload-")
        staged = Path(pathname)
        transferred = 0
        with os.fdopen(fd, "wb") as sink:
            async for data in request.stream():
                transferred += len(data)
                if transferred > max_size:
                    raise HTTPException(413, "Upload exceeds configured limit")
                sink.write(data)
            sink.flush()
            os.fsync(sink.fileno())
        # Enforce bucket quota (TeleDrive-level; S3 has no native quota).
        _webapp()._enforce_bucket_quota(conn, bucket, key, transferred)
        engine = TelegramObjectStorage(manifests, transport,
                                       chunk_size=_webapp().RECOMMENDED_CHUNK_SIZE,
                                       scratch_directory=stage_root)
        result = await engine.put_file(bucket, key, staged)
        try:
            head = catalog.publish(result.id, now=int(time.time()),
                                   expected_generation=generation)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"id": result.id, "bucket": bucket, "key": key,
                "size": result.size, "sha256": result.sha256,
                "generation": head.generation}
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
        conn.close()


@router.put("/api/v1/buckets/{bucket}/content", tags=["Uploads"],
         summary="Upload raw binary content to Telegram (synchronous commit)", status_code=201)
async def put_object_content(
    bucket: str, request: Request, key: str = Query(..., min_length=1, max_length=1024),
    generation: int | None = Query(None, ge=0),
    _: None = Depends(require_api_scope("rest:objects:put")),
):
    return await _stream_object_upload(bucket, key, request, generation)


@router.head("/api/v1/buckets/{bucket}/content", tags=["Uploads"],
          summary="Read object headers without downloading Telegram bytes")
def head_object_content(
    bucket: str, key: str = Query(..., min_length=1, max_length=1024),
    _: None = Depends(require_api_scope("rest:objects:head")),
):
    _webapp()._valid_rest_key(key)
    conn = _webapp().db_connect()
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        try:
            item = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        _webapp()._rest_read_gate(manifests, catalog, item)
        return Response(status_code=200, headers={
            "ETag": '"' + item.sha256 + '"',
            "Content-Length": str(item.size),
            "Accept-Ranges": "bytes",
            "X-TeleDrive-Object-ID": item.id,
            "Content-Type": "application/octet-stream",
        })
    finally:
        conn.close()


@router.get("/api/v1/buckets/{bucket}/content", tags=["Uploads"],
         summary="Stream verified object bytes from Telegram; supports HTTP Range")
async def get_object_content(
    bucket: str, request: Request, key: str = Query(..., min_length=1, max_length=1024),
    _: None = Depends(require_api_scope("rest:objects:get")),
):
    return await _webapp()._stream_object_response(bucket, key, request)


