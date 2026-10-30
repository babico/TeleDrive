"""WebUI S3 browser: buckets, objects, quota, pins, CORS, shares, versions.

Session-authenticated admin surface (``Depends(require_auth)``), distinct from
the API-key-scoped REST data plane in ``web/routers/rest.py`` and from the
credential/storage administration in ``web/routers/s3admin.py``. Paths are
absolute: ``APIRouter`` has no prefix because ``web.permissions`` matches the
full route path.

The object read gate (``_rest_read_gate``), the streaming core
(``_stream_object_response``/``_stream_object_upload``) and the quota helpers
are still owned by ``web.app`` while the REST data plane lives there; they are
resolved through ``_webapp()`` at call time so ``webapp.*`` monkeypatching keeps
working.
"""
from __future__ import annotations

import re
import secrets
import shutil
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.website import (
    WebsiteConfigStore, WebsiteError, validate_document_name,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.copy import copy_object, CopyConflict
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from teledrive.stores import content_index as _content_store
from teledrive.stores import pins as _pin_store
from teledrive.stores import shares as _share_store
from web.deps import _require_interactive_session, _same_origin, require_auth

router = APIRouter()


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


# --- S3 bucket browser & quota (WebUI session auth) -------------------------

class BucketCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=63)


class BucketQuotaRequest(BaseModel):
    max_size_bytes: int | None = None
    max_objects: int | None = None


class ObjectCopyRequest(BaseModel):
    destination_bucket: str | None = Field(default=None, min_length=3, max_length=63)
    destination_key: str = Field(min_length=1, max_length=1024)


class VersionRestoreRequest(BaseModel):
    bucket: str = Field(min_length=3, max_length=63)
    key: str = Field(min_length=1, max_length=1024)
    expected_generation: int | None = Field(default=None, ge=0)


class VersionIndexRequest(BaseModel):
    execute: bool = False
    limit: int = Field(default=100, ge=1, le=1000)


def _public_s3_origin(request: Request) -> str:
    """Public base URL of the S3 listener, for presigned links.

    Works in every supported deployment shape, independently:

    * direct mode — the app terminates TLS on the S3 listener (scheme from
      TELEDRIVE_S3_SSL_CERTFILE), or serves plain HTTP;
    * reverse-proxy mode — TLS terminates in front (TRUSTED_PROXY honors
      X-Forwarded-Proto/Host/Port), or the proxy is plain HTTP;
    * both at once — an HTTPS proxy in front of an app that also speaks
      HTTPS.

    In proxy mode the client-facing host/port come from the forwarded
    headers; in direct mode from the Host header plus the S3 listener
    port, with the default port of the scheme elided.
    """
    forwarded = False
    if _webapp().TRUSTED_PROXY:
        forwarded = request.headers.get(
            "x-forwarded-proto", "").lower() == "https"
    scheme = "https" if (_webapp().S3_SSL_CERTFILE or forwarded) else "http"

    host = ""
    if _webapp().TRUSTED_PROXY:
        host = (request.headers.get("x-forwarded-host") or "").strip()
    host = host or (request.headers.get("host") or "").strip()
    host = host.split("/")[0].strip()
    if not host:
        host = "localhost"

    # Split host / port, tolerating bracketed IPv6 literals. In DIRECT mode
    # any port on the Host header is the WebUI's (the admin calls this from
    # the UI), so it is discarded and the S3 listener port is used. In
    # proxy mode the forwarded host's port IS the public S3 port.
    port: int | None = None
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            bracket, tail = host[:end + 1], host[end + 1:]
            if tail.startswith(":"):
                host, port = bracket, int(tail[1:] or 0) or None
    elif host.count(":") == 1:
        name, _, raw_port = host.partition(":")
        host, port = name, int(raw_port or 0) or None
    if not _webapp().TRUSTED_PROXY:
        port = None

    if port is None:
        if _webapp().TRUSTED_PROXY:
            raw_port = request.headers.get("x-forwarded-port", "")
            port = int(raw_port) if raw_port.isdigit() else None
        if port is None:
            port = _webapp().settings_s3_port()

    if (scheme, port) in (("https", 443), ("http", 80)):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


@router.get("/api/v1/admin/storage/buckets", tags=["Object catalog"],
         summary="List buckets with metadata and quota (WebUI)")
def admin_list_buckets(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        buckets = catalog.list_buckets()
        result = []
        for b in buckets:
            # Current object count and total size (heads join).
            count, size = _webapp()._bucket_current_usage(conn, b)
            max_size, max_objects = _webapp()._bucket_quota(conn, b)
            quota = None
            if max_size is not None or max_objects is not None:
                quota = {"max_size_bytes": max_size, "max_objects": max_objects}
            result.append({"name": b, "object_count": count,
                           "total_size": size, "quota": quota})
        return {"buckets": result}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/buckets", tags=["Object catalog"],
          status_code=201, summary="Create a bucket (WebUI session)")
def admin_create_bucket(payload: BucketCreateRequest, request: Request,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).create_bucket(
                payload.name, int(time.time()))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        _webapp()._log(f"create bucket: name={payload.name}", "storage")
        return {"name": payload.name}
    finally:
        conn.close()


@router.delete("/api/v1/admin/storage/buckets/{bucket}", tags=["Object catalog"],
            summary="Remove a physically empty bucket (WebUI session)")
def admin_delete_bucket(bucket: str, request: Request,
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        try:
            BucketCatalog(ManifestStore(conn)).delete_bucket(bucket)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Bucket not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        _webapp()._log(f"delete bucket: name={bucket}", "storage")
        return {"ok": True}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/buckets/{bucket}/objects", tags=["Object catalog"],
         summary="List objects in a bucket (WebUI)")
def admin_list_objects(bucket: str,
                       prefix: str = Query("", max_length=1024),
                       limit: int = Query(100, ge=1, le=1000),
                       _: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        items = catalog.list_objects(bucket, prefix=prefix, limit=limit)
        return {"objects": [
            {"id": x.item.id, "key": x.item.key, "size": x.item.size,
             "sha256": x.item.sha256, "created_at": x.item.created_at,
             "generation": x.generation} for x in items]}
    finally:
        conn.close()


@router.delete("/api/v1/admin/storage/buckets/{bucket}/objects", tags=["Object catalog"],
            summary="Delete an object (WebUI)")
def admin_delete_object(bucket: str, request: Request,
                        key: str = Query(..., min_length=1, max_length=1024),
                        _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        try:
            deleted = BucketCatalog(ManifestStore(conn)).remove_current(bucket, key)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ok": True, "unlinked": deleted}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/buckets/{bucket}/content",
         tags=["Object catalog"],
         summary="Download object bytes through the WebUI session (Range supported)")
async def admin_download_object(bucket: str, request: Request,
                                key: str = Query(..., min_length=1, max_length=1024),
                                _: None = Depends(require_auth)):
    """Stream verified object bytes for the S3 browser's download button.

    Session-authenticated twin of the API-key-scoped
    GET /api/v1/buckets/{bucket}/content. Both delegate to the same core, so
    the archive gate, the SSE-C refusal and the access counter cannot drift
    apart again -- the previous duplicate had none of the three.
    """
    # Only the final path segment becomes the suggested filename; strip
    # everything that could break the header or traverse paths.
    filename = re.sub(r"[^A-Za-z0-9._ -]", "_", key.rsplit("/", 1)[-1]) or "download"
    _webapp()._log(f"download: {bucket}/{key}", "storage",
         user=(getattr(request.state, "user", None) or {}).get(
             "username") or "system")
    return await _webapp()._stream_object_response(
        bucket, key, request,
        content_disposition=f'attachment; filename="{filename}"')


@router.put("/api/v1/admin/storage/buckets/{bucket}/content",
         tags=["Object catalog"], status_code=201,
         summary="Upload object bytes through the WebUI session")
async def admin_upload_object(bucket: str, request: Request,
                              key: str = Query(..., min_length=1, max_length=1024),
                              generation: int | None = Query(None, ge=0),
                              _: None = Depends(require_auth)):
    """Session-authenticated twin of the API-key-scoped content upload."""
    _same_origin(request)
    return await _webapp()._stream_object_upload(bucket, key, request, generation)


@router.get("/api/v1/admin/storage/buckets/{bucket}/cors",
         tags=["Object catalog"],
         summary="Read the bucket CORS rules")
def admin_get_bucket_cors(bucket: str, _: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        from teledrive.s3.cors import BucketCORSStore
        rules = BucketCORSStore(catalog).get(bucket)
        return {"rules": rules or []}
    finally:
        conn.close()


@router.put("/api/v1/admin/storage/buckets/{bucket}/cors",
         tags=["Object catalog"],
         summary="Replace the bucket CORS rules")
def admin_put_bucket_cors(bucket: str, request: Request,
                          payload: dict = Body(...),
                          _: None = Depends(require_auth)):
    _same_origin(request)
    rules = payload.get("rules")
    if not isinstance(rules, list) or len(rules) > 20:
        raise HTTPException(422, "rules must be a list of at most 20")
    allowed_methods = {"GET", "PUT", "POST", "DELETE", "HEAD"}
    origin_re = re.compile(r"\*|https?://[A-Za-z0-9.*-]+(:\d+)?(/\*)?")
    for rule in rules:
        methods = [str(m).upper() for m in rule.get("methods", [])]
        origins = [str(o) for o in rule.get("origins", [])]
        if not methods or not origins:
            raise HTTPException(422, "Each rule needs methods and origins")
        if not set(methods) <= allowed_methods:
            raise HTTPException(422, "Unsupported CORS method")
        if any(not origin_re.fullmatch(o) for o in origins):
            raise HTTPException(422, "Invalid origin (use * or "
                                     "scheme://host[:port])")
        try:
            max_age = int(rule.get("max_age") or 0)
        except (TypeError, ValueError):
            raise HTTPException(422, "max_age must be an integer") from None
        if not 0 <= max_age <= 86400:
            raise HTTPException(422, "max_age must be 0..86400")
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        from teledrive.s3.cors import BucketCORSStore
        BucketCORSStore(catalog).replace(bucket, [
            {"origins": [str(o) for o in r.get("origins", [])],
             "methods": [str(m).upper() for m in r.get("methods", [])],
             "allowed_headers": [str(h) for h in
                                 r.get("allowed_headers", [])],
             "expose_headers": [str(h) for h in
                                r.get("expose_headers", [])],
             "max_age": int(r.get("max_age") or 0),
             "id": r.get("id")}
            for r in rules
        ])
        conn.connection.commit()
    finally:
        conn.close()
    _webapp()._log(f"bucket cors replaced: bucket={bucket} rules={len(rules)}",
         "storage")
    return {"ok": True, "rules": len(rules)}


@router.get("/api/v1/admin/storage/buckets/{bucket}/website",
         tags=["Object catalog"],
         summary="Read the bucket website configuration and public-read gate")
def admin_get_bucket_website(bucket: str, _: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        config = WebsiteConfigStore(catalog).get(bucket)
        return {
            "configured": config is not None,
            "index_document": config["index_document"] if config else None,
            "error_document": config["error_document"] if config else None,
            "public_read": catalog.public_read(bucket),
        }
    finally:
        conn.close()


@router.put("/api/v1/admin/storage/buckets/{bucket}/website",
         tags=["Object catalog"],
         summary="Configure website hosting and the public-read gate")
def admin_put_bucket_website(bucket: str, request: Request,
                             payload: dict = Body(...),
                             _: None = Depends(require_auth)):
    """Owner/admin-only website configuration.

    ``public_read=true`` PUBLISHES the bucket's current objects anonymously
    at ``/site/{bucket}/...``. It is a deliberate public-exposure decision:
    every current ready object becomes readable by anyone who can reach the
    app origin. The flag is stored in bucket metadata, defaults to FALSE,
    and is cleared by DeleteBucketWebsite and bucket deletion.

    The separate S3 PutBucketWebsite API writes only the index/error
    document and never flips this gate.
    """
    _same_origin(request)
    # An API key is not a role: even a key holding this endpoint's
    # permission must not publish a bucket. Public exposure stays an
    # owner/admin session decision.
    role = (getattr(request.state, "user", None) or {}).get("role")
    if role != "admin":
        raise HTTPException(403, "Website public exposure requires admin role")
    index_document = payload.get("index_document")
    error_document = payload.get("error_document")
    public_read = payload.get("public_read")
    if not isinstance(public_read, bool):
        raise HTTPException(422, "public_read must be a boolean")
    try:
        index_document = validate_document_name(index_document, "index_document")
        error_document = (None if error_document in (None, "")
                          else validate_document_name(error_document,
                                                      "error_document"))
    except WebsiteError as exc:
        raise HTTPException(422, str(exc)) from exc
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        WebsiteConfigStore(catalog).replace(bucket, {
            "index_document": index_document,
            "error_document": error_document,
            "enabled": True,
        }, public_read=public_read)
    finally:
        conn.close()
    actor = (getattr(request.state, "user", None) or {}).get(
        "username", "system")
    _webapp()._log(f"bucket website configured: bucket={bucket} "
         f"index={index_document} error={error_document} "
         f"public_read={public_read}", "storage", user=actor)
    result = {
        "ok": True,
        "index_document": index_document,
        "error_document": error_document,
        "public_read": public_read,
    }
    if public_read:
        result["notice"] = (
            "public_read publishes the bucket's current objects anonymously "
            f"at /site/{bucket}/")
    return result


@router.post("/api/v1/admin/storage/buckets/{bucket}/presign",
          tags=["Object catalog"],
          summary="Create a presigned GET URL for one object")
def admin_presign_object(bucket: str, request: Request,
                         payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    """Server-side SigV4 query signing; the credential secret never
    leaves the process, only the signed URL is returned."""
    _same_origin(request)
    # A presigned URL is durable, anonymous authority: it keeps working for
    # up to seven days after the caller's session, API key or role is gone,
    # and only revoking the SIGNING credential ends it. Delegating that from
    # an API key would let a key plant access that outlives its own
    # revocation, so it is an interactive action like share links and
    # credential reveal.
    actor = _require_interactive_session(request, "presign")
    key = str(payload.get("key", "")).strip()
    if len(key.encode("utf-8")) > 1024:
        raise HTTPException(422, "Object key must contain 1..1024 UTF-8 bytes")
    if not key:
        raise HTTPException(422, "key is required")
    try:
        expires = int(payload.get("expires") or 3600)
    except (TypeError, ValueError):
        raise HTTPException(422, "expires must be an integer") from None
    # SigV4 caps a presigned URL at seven days; validate before signing so
    # an out-of-range value is a 422 rather than an unhandled 500.
    if not 1 <= expires <= 604800:
        raise HTTPException(
            422, "expires must be between 1 and 604800 seconds (7 days)")
    credential_id = payload.get("credential_id")
    conn = _webapp().db_connect()
    try:
        if bucket not in BucketCatalog(ManifestStore(conn)).list_buckets():
            raise HTTPException(404, "Bucket not found")
        if not _webapp()._bucket_has_current_key(conn, bucket, key):
            raise HTTPException(404, "Object not found")
        try:
            store = S3CredentialStore(conn, _webapp().load_master_key())
            if credential_id:
                revealed = store.reveal(str(credential_id))
                # A presigned GET needs this exact scope; issuing a URL
                # for a credential that cannot read would fail later and
                # leak a secret for nothing.
                if "s3:GetObject" not in revealed.get("permissions", ()):
                    raise HTTPException(
                        422, "Credential lacks the s3:GetObject permission")
            else:
                candidates = [c for c in store.list() if not c["revoked"]
                              and "s3:GetObject" in c["permissions"]]
                if not candidates:
                    raise HTTPException(
                        422, "No active S3 credential with s3:GetObject")
                revealed = store.reveal(candidates[0]["id"])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        _webapp()._audit(request, "object.presign", target=f"{bucket}/{key}",
               detail={"expires": expires,
                       "credential": revealed["access_key"]})
        _webapp()._log(f"presigned GET: bucket={bucket} key={key} "
             f"expires={expires}s credential={revealed['access_key']}",
             "storage", user=actor)
    finally:
        conn.close()
    from teledrive.s3.sigv4 import presign_get_url
    url = presign_get_url(_public_s3_origin(request),
                          bucket, key, revealed["access_key"],
                          revealed["secret_key"], expires)
    _webapp()._log(f"presigned URL issued: bucket={bucket} key={key} "
         f"expires={expires}s credential={revealed['access_key']}",
         "security")
    return {"url": url, "expires_in": expires}


@router.post("/api/v1/admin/storage/buckets/{bucket}/shares",
          tags=["Object catalog"],
          summary="Create a signed public share link for one object")
def admin_create_share(bucket: str, request: Request,
                       payload: dict = Body(...),
                       _: None = Depends(require_auth)):
    """Unauthenticated URL bounded by expiry, download count and an
    optional password (PBKDF2-hashed; the plaintext is never stored)."""
    _same_origin(request)
    key = str(payload.get("key", "")).strip()
    if not key:
        raise HTTPException(422, "key is required")
    expires_in = payload.get("expires_in")
    if expires_in is not None:
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            raise HTTPException(422, "expires_in must be an integer") from None
        if not 60 <= expires_in <= 30 * 86400:
            raise HTTPException(422, "expires_in must be 60..2592000 seconds")
    max_downloads = payload.get("max_downloads")
    if max_downloads is not None:
        try:
            max_downloads = int(max_downloads)
        except (TypeError, ValueError):
            raise HTTPException(422, "max_downloads must be an integer") from None
        if not 1 <= max_downloads <= 1_000_000:
            raise HTTPException(422, "max_downloads must be 1..1000000")
    password = payload.get("password")
    if password is not None and not (
            isinstance(password, str) and 1 <= len(password) <= 128):
        raise HTTPException(422, "password must be 1..128 characters")

    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        try:
            shared = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        token = secrets.token_urlsafe(24)
        now = int(time.time())
        salt = digest = None
        if password is not None:
            salt, digest = _webapp()._hash_share_password(password)
        _share_store.create(
            conn,
            token=token, bucket=bucket, object_key=key,
            # Pin the exact version. A key-bound link would serve whatever
            # the key pointed at later, and recover after an unlink + re-upload.
            object_id=shared.id,
            created_by=(request.state.user or {}).get("username", "-"),
            created_at=now,
            expires_at=now + expires_in if expires_in else None,
            max_downloads=max_downloads,
            password_salt=salt, password_hash=digest,
        )
    finally:
        conn.close()
    _webapp()._audit(request, "share.create", target=f"{bucket}/{key}",
           detail={"max_downloads": max_downloads,
                   "expires_in": expires_in,
                   "password": password is not None})
    _webapp()._log(f"share link created: bucket={bucket} key={key} token={token[:6]}… "
         f"expires_in={expires_in} max_downloads={max_downloads} "
         f"password={'yes' if password is not None else 'no'}", "share")
    return {"token": token, "path": f"/share/{token}"}


@router.get("/api/v1/admin/storage/shares", tags=["Object catalog"],
         summary="List all share links with live status")
def admin_list_shares(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        rows = _share_store.list(conn)
        now = int(time.time())
        shares = []
        for share in rows:
            expires = share["expires_at"]
            max_downloads = share["max_downloads"]
            count = share["download_count"]
            if share["revoked"]:
                status = "revoked"
            elif expires is not None and expires <= now:
                status = "expired"
            elif max_downloads is not None and count >= max_downloads:
                status = "exhausted"
            else:
                status = "active"
            shares.append({
                "token": share["token"], "bucket": share["bucket"],
                "key": share["object_key"],
                "created_by": share["created_by"],
                "created_at": share["created_at"],
                "expires_at": expires, "max_downloads": max_downloads,
                "download_count": count,
                "password": bool(share["has_password"]),
                "revoked": share["revoked"], "status": status,
            })
        return {"shares": shares, "count": len(shares)}
    finally:
        conn.close()


@router.delete("/api/v1/admin/storage/shares/{token}", tags=["Object catalog"],
            summary="Revoke a share link")
def admin_revoke_share(token: str, request: Request,
                       _: None = Depends(require_auth)):
    _same_origin(request)
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
        raise HTTPException(404, "Unknown share link")
    conn = _webapp().db_connect()
    try:
        deleted = _share_store.revoke(conn, token)
    finally:
        conn.close()
    if not deleted:
        raise HTTPException(404, "Unknown share link")
    _webapp()._log(f"share link revoked: token={token[:6]}…", "share")
    return {"ok": True}


@router.post("/api/v1/admin/storage/buckets/{bucket}/objects/copy",
          tags=["Object catalog"],
          summary="Copy (rename/move) an object at the catalog level")
def admin_copy_object(bucket: str, request: Request,
                      payload: ObjectCopyRequest,
                      key: str = Query(..., min_length=1, max_length=1024),
                      _: None = Depends(require_auth)):
    """Metadata-level copy: no Telegram bytes move, quota is enforced."""
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        destination_bucket = payload.destination_bucket or bucket
        if destination_bucket not in catalog.list_buckets():
            raise HTTPException(404, "Destination bucket not found")
        if destination_bucket == bucket and payload.destination_key == key:
            raise HTTPException(400, "Destination equals source")
        # The copy ADDS the source's full size to the destination, so the
        # quota must be checked with that size -- not 0, which only ever
        # enforced the object count and let a 50-byte bucket accept a
        # 100-byte copy.
        try:
            source_item = catalog.get(bucket, key).item
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        _webapp()._enforce_bucket_quota(conn, destination_bucket,
                              payload.destination_key, source_item.size)
        try:
            dest_head = catalog.get(destination_bucket, payload.destination_key)
            dest_generation = dest_head.generation
            dest_id = dest_head.item.id
        except FileNotFoundError:
            dest_generation, dest_id = 0, None
        try:
            restored = copy_object(
                catalog, bucket, key,
                destination_bucket, payload.destination_key,
                expected_destination_generation=dest_generation,
                expected_destination_object_id=dest_id,
            )
        except FileNotFoundError as exc:
            raise HTTPException(404, "Object not found") from exc
        except (CopyConflict, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        _webapp()._log(f"copy object: {bucket}/{key} -> "
             f"{destination_bucket}/{payload.destination_key} "
             f"id={restored.object_id}", "storage",
             user=(getattr(request.state, "user", None) or {}).get(
                 "username") or "system")
        return {"id": restored.object_id, "bucket": destination_bucket,
                "key": payload.destination_key, "etag": restored.etag,
                "size": restored.size,
                "generation": catalog.get(
                    destination_bucket, payload.destination_key).generation}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/search", tags=["Object catalog"],
         summary="Search object keys or indexed file contents")
def admin_search_objects(q: str = Query(..., min_length=1, max_length=256),
                         mode: str = Query("key"),
                         limit: int = Query(100, ge=1, le=1000),
                         _: None = Depends(require_auth)):
    """mode=key (default): case-insensitive key search over the unified
    catalog. mode=content: full-text search over indexed file contents
    (text-extractable uploads, FTS5/tsvector) with snippets."""
    from sqlalchemy import func, select as _select
    from teledrive.storage.manifest import objects as _objects
    conn = _webapp().db_connect()
    try:
        from teledrive.storage.catalog import heads as _heads
        if mode == "content":
            matches = _content_store.search(conn, q, limit)
            if not matches:
                return {"query": q, "mode": "content", "objects": []}
            by_id = {object_id: snippet for object_id, snippet in matches}
            rows = conn.connection.execute(
                _select(_objects.c.id, _objects.c.bucket,
                        _objects.c.object_key, _objects.c.size,
                        _objects.c.sha256, _objects.c.created_at)
                .select_from(_heads.join(
                    _objects, _objects.c.id == _heads.c.object_id))
                .where(_objects.c.id.in_(list(by_id)))
                .limit(limit)
            ).all()
            return {"query": q, "mode": "content", "objects": [
                {"id": r[0], "bucket": r[1], "key": r[2], "size": r[3],
                 "sha256": r[4], "created_at": r[5],
                 "snippet": by_id.get(r[0], "")} for r in rows]}
        if mode != "key":
            raise HTTPException(422, "mode must be key or content")
        # Escape LIKE wildcards so user input cannot broaden the pattern.
        escaped = (q.replace(chr(92), chr(92) * 2)
                .replace("%", chr(92) + "%")
                .replace("_", chr(92) + "_")).lower()
        pattern = "%" + escaped + "%"
        escape_char = chr(92)
        rows = conn.connection.execute(
            _select(_objects.c.id, _objects.c.bucket, _objects.c.object_key,
                    _objects.c.size, _objects.c.sha256, _objects.c.created_at)
            .select_from(_heads.join(
                _objects, _objects.c.id == _heads.c.object_id))
            .where(func.lower(_objects.c.object_key).like(
                pattern, escape=escape_char))
            .order_by(_objects.c.bucket, _objects.c.object_key)
            .limit(limit)
        ).all()
        return {"query": q, "objects": [
            {"id": r[0], "bucket": r[1], "key": r[2], "size": r[3],
             "sha256": r[4], "created_at": r[5]} for r in rows]}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/search/reindex", tags=["Object catalog"],
          summary="Index file contents of existing objects (backfill)")
async def reindex_object_contents(request: Request,
                                  payload: dict = Body(None),
                                  _: None = Depends(require_auth)):
    """Downloads the head of current, unindexed, text-extractable objects
    and indexes their contents. Bounded per call; repeated calls make
    progress until everything searchable is indexed."""
    _same_origin(request)
    try:
        limit = int((payload or {}).get("limit", 25))
    except (TypeError, ValueError):
        limit = 25
    limit = max(1, min(limit, 100))
    conn = _webapp().db_connect()
    try:
        from teledrive.storage.content_index import (
            MAX_INDEX_BYTES, extract_text, index_object_content)
        # Raw by design: a single read-only candidate query with a portable
        # LIKE-OR chain and a NOT EXISTS; it mutates nothing and no other
        # caller needs the same shape.
        from sqlalchemy import text as _text
        candidates = conn.connection.execute(_text(
            "SELECT o.id, o.bucket, o.object_key FROM storage_objects o "
            "JOIN storage_object_heads h ON h.object_id = o.id "
            "WHERE o.status = 'ready' AND o.size > 0 "
            "AND NOT EXISTS (SELECT 1 FROM object_content_index c "
            "WHERE c.object_id = o.id) "
            "AND (o.object_key LIKE '%.' || :txt OR o.object_key LIKE '%.' || :json "
            "OR o.object_key LIKE '%.' || :csv OR o.object_key LIKE '%.' || :md "
            "OR o.object_key LIKE '%.' || :log OR o.object_key LIKE '%.' || :yaml "
            "OR o.object_key LIKE '%.' || :yml OR o.object_key LIKE '%.' || :xml "
            "OR o.object_key LIKE '%.' || :py OR o.object_key LIKE '%.' || :conf) "
            "LIMIT :n"
        ), {"txt": "txt", "json": "json", "csv": "csv", "md": "md",
            "log": "log", "yaml": "yaml", "yml": "yml", "xml": "xml",
            "py": "py", "conf": "conf", "n": limit}).fetchall()
        if not candidates:
            return {"ok": True, "indexed": 0, "candidates": 0}
        transport = _webapp().storage_transport(conn)
        await transport.verify_target()
        manifests = ManifestStore(conn)
        engine = TelegramObjectStorage(
            manifests, transport, chunk_size=RECOMMENDED_CHUNK_SIZE,
            scratch_directory=Path(_webapp().STORAGE_SCRATCH_DIR))
        indexed = 0
        errors = []
        for object_id, bucket, key in candidates:
            scratch = Path(tempfile.mkdtemp(prefix="reindex-",
                                            dir=_webapp().STORAGE_SCRATCH_DIR))
            try:
                target = scratch / "head"
                # Only the extraction cap is needed, never the whole file.
                obj = manifests.get(object_id)
                end = min(MAX_INDEX_BYTES, obj.size)
                if end > 0:
                    async for piece in engine.iter_bytes(
                            object_id, start=0, end=end):
                        with open(target, "ab") as out:
                            out.write(piece)
                if extract_text(target, key) is None:
                    # Mark non-text objects as examined so they are not
                    # retried forever: an empty index row. The store does the
                    # portable SELECT-then-INSERT (INSERT OR IGNORE is
                    # SQLite-only) and commits.
                    _content_store.ensure_row(
                        conn, object_id, int(time.time()))
                    continue
                if index_object_content(conn, object_id, target, key):
                    indexed += 1
            except Exception as exc:
                errors.append({"object_id": object_id,
                               "error": type(exc).__name__})
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
        _webapp()._log(f"content reindex: indexed={indexed} candidates={len(candidates)}",
             "storage")
        return {"ok": True, "indexed": indexed, "candidates": len(candidates),
                "errors": errors}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/buckets/{bucket}/quota", tags=["Object catalog"],
         summary="Get bucket quota")
def admin_get_quota(bucket: str, _: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        max_size, max_objects = _webapp()._bucket_quota(conn, bucket)
        return {"bucket": bucket, "max_size_bytes": max_size, "max_objects": max_objects}
    finally:
        conn.close()


@router.put("/api/v1/admin/storage/buckets/{bucket}/quota", tags=["Object catalog"],
         summary="Set bucket quota")
def admin_set_quota(bucket: str, payload: BucketQuotaRequest, request: Request,
                    _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        from teledrive.storage import quota as _quota
        _quota.set_bucket_quota(
            conn, bucket, payload.max_size_bytes, payload.max_objects,
            int(time.time()))
        _webapp()._log(f"set quota: bucket={bucket} max_size={payload.max_size_bytes} max_objects={payload.max_objects}", "storage")
    finally:
        conn.close()
    return {"ok": True}


@router.get("/api/v1/admin/storage/buckets/{bucket}/pin",
         tags=["Object catalog"],
         summary="Read the bucket's account pin")
def admin_get_bucket_pin(bucket: str, _: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        pin = _pin_store.get(conn, bucket)
        return {"bucket": bucket, "account": pin}
    finally:
        conn.close()


@router.put("/api/v1/admin/storage/buckets/{bucket}/pin",
         tags=["Object catalog"],
         summary="Pin the bucket's uploads to a Telegram account")
def admin_put_bucket_pin(bucket: str, request: Request,
                         payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    _same_origin(request)
    account = str(payload.get("account", "")).strip()
    if not account:
        raise HTTPException(422, "account is required")
    conn = _webapp().db_connect()
    try:
        from teledrive.stores import telegram_accounts as _accounts
        if not _accounts.has_session(conn, account):
            raise HTTPException(404, "Unknown Telegram session account")
        _pin_store.set(conn, bucket, account, int(time.time()))
    finally:
        conn.close()
    _webapp()._log(f"bucket pin set: bucket={bucket} account={account}", "storage")
    return {"ok": True, "bucket": bucket, "account": account}


@router.delete("/api/v1/admin/storage/buckets/{bucket}/pin",
            tags=["Object catalog"],
            summary="Remove the bucket's account pin")
def admin_delete_bucket_pin(bucket: str, request: Request,
                            _: None = Depends(require_auth)):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        _pin_store.delete(conn, bucket)
    finally:
        conn.close()
    return {"ok": True}


@router.get("/api/v1/admin/storage/version-history", tags=["Object catalog"],
         summary="Object version history incl. delete markers (WebUI)")
def admin_list_object_versions(
        bucket: str | None = Query(None),
        limit: int = Query(200, ge=1, le=1000),
        _: None = Depends(require_auth)):
    """Published versions and delete markers, newest first.

    This is the UI's object-history view: unlike the upload-job history,
    it covers EVERY write path (S3 browser, REST, multipart, copies)
    and shows delete markers, so deleted objects remain traceable until
    physical GC removes their retained media. Distinct from
    /storage/versions, which lists ONE key's versions for restore."""
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        buckets = [bucket] if bucket else catalog.list_buckets()
        entries = []
        for name in buckets:
            try:
                page, _ = catalog.list_bucket_versions(
                    name, prefix="", key_marker="", version_marker="",
                    limit=limit)
            except Exception:
                continue
            for entry in page:
                entries.append({
                    "bucket": name, "key": entry["key"],
                    "version_id": entry["version_id"],
                    "is_current": entry["is_current"],
                    "is_delete_marker": entry["is_delete_marker"],
                    "size": entry.get("size"),
                    "sha256": entry.get("sha256"),
                    "committed_at": entry["committed_ns"] // 1_000_000_000,
                })
        entries.sort(key=lambda e: (e["committed_at"], e["version_id"]),
                     reverse=True)
        return {"versions": entries[:limit], "count": len(entries)}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/usage", tags=["Storage jobs"],
         summary="Daily upload volume (objects, bytes) for the last N days")
def storage_usage_series(days: int = Query(default=30, ge=1, le=365),
                         _: None = Depends(require_auth)):
    """Publication-timestamped usage series for the dashboard chart.

    Aggregation happens in Python: portable across SQLite and
    PostgreSQL, and defensive when the catalog tables live in another
    database.
    """
    cutoff_ns = (int(time.time()) - days * 86400) * 1_000_000_000
    conn = _webapp().db_connect()
    try:
        # Raw by design: a read-only join aggregate for the usage chart.
        from sqlalchemy import text as _text
        try:
            rows = conn.connection.execute(_text(
                "SELECT p.committed_ns, o.size FROM "
                "storage_published_versions p JOIN storage_objects o "
                "ON o.id = p.object_id WHERE p.committed_ns >= :cutoff "
                "ORDER BY p.committed_ns"
            ), {"cutoff": cutoff_ns}).fetchall()
        except Exception:
            rows = []
    finally:
        conn.close()
    daily: dict[str, dict] = {}
    for committed_ns, size in rows:
        day = time.strftime("%Y-%m-%d",
                            time.localtime(int(committed_ns) / 1e9))
        entry = daily.setdefault(day, {"date": day, "objects": 0,
                                       "bytes": 0})
        entry["objects"] += 1
        entry["bytes"] += int(size or 0)
    return {"days": days, "series": [daily[k] for k in sorted(daily)],
            "total_objects": len(rows),
            "total_bytes": sum(int(r[1] or 0) for r in rows)}


@router.post("/api/v1/admin/storage/versions/index-current",
          tags=["Storage versions"],
          summary="Dry-run or explicitly index only verified historical HEAD references")
def index_legacy_current_versions(
    request: Request, payload: VersionIndexRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            registered = catalog.index_legacy_current_heads(
                dry_run=not payload.execute, limit=payload.limit,
            )
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ids": registered, "count": len(registered),
                "dry_run": not payload.execute,
                "indexed": bool(payload.execute and registered)}
    finally:
        conn.close()


@router.get("/api/v1/admin/storage/versions", tags=["Storage versions"],
         summary="Admin listing of published historical versions for restore")
def admin_list_published_versions(
    bucket: str = Query(..., min_length=3, max_length=63),
    key: str = Query(..., min_length=1, max_length=1024),
    limit: int = Query(default=100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        if bucket not in catalog.list_buckets():
            raise HTTPException(404, "Bucket not found")
        try:
            current = catalog.get(bucket, key)
            generation = current.generation
        except FileNotFoundError:
            generation = 0
        return {"bucket": bucket, "key": key, "generation": generation,
                "versions": catalog.list_versions(bucket, key, limit=limit)}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/versions/{version_id}/restore",
          tags=["Storage versions"],
          summary="Restore a previously published immutable version without Telegram uploads")
def restore_published_version(
    version_id: str, request: Request, payload: VersionRestoreRequest,
    _: None = Depends(require_auth),
):
    _same_origin(request)
    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            head = catalog.get(payload.bucket, payload.key)
            generation, current_id = head.generation, head.item.id
        except FileNotFoundError:
            generation, current_id = 0, None
        if payload.expected_generation is not None and (
            payload.expected_generation != generation
        ):
            raise HTTPException(409, "Generation has changed since restore preview")
        try:
            restored = copy_object(
                catalog, payload.bucket, payload.key,
                payload.bucket, payload.key,
                source_version_id=version_id,
                expected_destination_generation=generation,
                expected_destination_object_id=current_id,
            )
        except FileNotFoundError as exc:
            raise HTTPException(404, "Published version does not exist") from exc
        except (CopyConflict, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "id": restored.object_id, "source_version_id": version_id,
            "etag": restored.etag, "size": restored.size,
            "generation": catalog.get(payload.bucket, payload.key).generation,
        }
    finally:
        conn.close()