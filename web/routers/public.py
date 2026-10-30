"""Public surfaces: static UI pages, certificates, share links, websites.

Nothing in this module has an authenticated principal. The HTML page shells
authenticate inside the handler and redirect to /login; the certificate,
share and website routes are deliberately anonymous. Paths are absolute:
``APIRouter`` has no prefix because ``web.permissions`` matches the full
route path.
"""
from __future__ import annotations

import hashlib
import hmac
import html as _html
import re
import secrets
import threading
import time
from collections import deque
from pathlib import Path
import urllib.parse
from urllib.parse import quote as _url_quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import (
    FileResponse, RedirectResponse, Response, StreamingResponse,
)

from teledrive.s3.object_metadata import ObjectMetadataStore
from teledrive.s3.website import WebsiteConfigStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE
from teledrive.stores import shares as _share_store
from web.deps import require_auth

router = APIRouter()


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


def _serve_static_page(page_name: str, request: Request):
    """Serve a static UI page; unauthenticated visitors are sent to /login."""
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=302)
    if page_name == "dashboard":
        page_name = "index"
    candidate = _webapp().STATIC_DIR / f"{page_name}.html"
    if candidate.is_file():
        return FileResponse(candidate)
    raise HTTPException(404, "Page not found")


# --- Nested UI routes (user-facing information architecture) ---------------
# /settings/{general,telegram} and /s3/{credentials,buckets}; the flat
# legacy paths redirect so old bookmarks keep working.


@router.get("/settings/general", include_in_schema=False)
def settings_general_page(request: Request):
    return _serve_static_page("settings", request)


@router.get("/settings/telegram", include_in_schema=False)
def settings_telegram_page(request: Request):
    return _serve_static_page("telegram", request)


@router.get("/s3/credentials", include_in_schema=False)
def s3_credentials_page(request: Request):
    return _serve_static_page("credentials", request)


@router.get("/s3/buckets", include_in_schema=False)
def s3_buckets_page(request: Request):
    return _serve_static_page("buckets", request)


@router.get("/settings", include_in_schema=False)
def settings_legacy_redirect():
    return RedirectResponse(url="/settings/general", status_code=302)


@router.get("/storage", include_in_schema=False)
def storage_legacy_redirect():
    return RedirectResponse(url="/settings/telegram", status_code=302)


@router.get("/s3", include_in_schema=False)
def s3_legacy_redirect():
    return RedirectResponse(url="/s3/buckets", status_code=302)


@router.get("/", include_in_schema=False)
def index(request: Request):
    return _serve_static_page("index", request)


@router.get("/{page_name}.html", include_in_schema=False)
def page_html(page_name: str, request: Request):
    return _serve_static_page(page_name, request)


@router.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(_webapp().STATIC_DIR / "login.html")


# --- public certificate distribution -----------------------------------
# A self-signed deployment needs a way for clients (browsers, S3 Browser,
# rclone, Windows trust store) to obtain the certificate they must trust.
# /server.cer is DER (what Windows imports), /server.crt is the PEM chain.
# Only certificate blocks are emitted — a combined .pem's private key is
# stripped by web.certs. Both are unauthenticated: a certificate is public
# data, and requiring a login over the very TLS connection being
# bootstrapped would be a deadlock.
#
# Declared BEFORE the /{page_name} catch-all, which would otherwise shadow
# these paths and redirect them to /login.


@router.get("/server.cer", include_in_schema=False)
@router.get("/api/v1/certificate.cer", tags=["System"],
         summary="Public TLS certificate (DER/.cer, unauthenticated)")
def public_certificate_der():
    from web import certs
    try:
        payload = certs.public_cert_der()
    except certs.CertError as exc:
        raise HTTPException(404, str(exc)) from exc
    return Response(content=payload,
                    media_type="application/pkix-cert",
                    headers={"Content-Disposition":
                             'attachment; filename="teledrive.cer"'})


@router.get("/server.crt", include_in_schema=False)
@router.get("/api/v1/certificate.pem", tags=["System"],
         summary="Public TLS certificate (PEM chain, unauthenticated)")
def public_certificate_pem():
    from web import certs
    try:
        payload = certs.public_cert_pem()
    except certs.CertError as exc:
        raise HTTPException(404, str(exc)) from exc
    return Response(content=payload,
                    media_type="application/x-pem-file",
                    headers={"Content-Disposition":
                             'attachment; filename="teledrive.crt"'})


@router.get("/{page_name}", include_in_schema=False)
def page_route(page_name: str, request: Request):
    if page_name in {"api", "static", "openapi.json", "docs", "redoc",
                     "__health", "favicon.ico"}:
        raise HTTPException(404, "Not found")
    return _serve_static_page(page_name, request)


# --- Signed public share links -------------------------------------------
#
# An unauthenticated URL streaming exactly one object, bounded by
# expiry, download count and an optional password. Tokens carry 192
# bits of entropy; invalid states answer a uniform 404 so the link's
# existence is never leaked.

_SHARE_RATE_LIMIT = 60          # requests
_SHARE_RATE_WINDOW = 60.0       # seconds
_share_rate: dict[str, deque] = {}
_share_rate_lock = threading.Lock()


def _share_rate_limited(client_ip: str) -> bool:
    """Small in-memory sliding window per client IP (public surface)."""
    now = time.monotonic()
    with _share_rate_lock:
        window = _share_rate.setdefault(client_ip, deque())
        while window and now - window[0] > _SHARE_RATE_WINDOW:
            window.popleft()
        if len(window) >= _SHARE_RATE_LIMIT:
            return True
        window.append(now)
        if len(_share_rate) > 10_000:
            stale = [ip for ip, hits in _share_rate.items()
                     if not hits or now - hits[-1] > _SHARE_RATE_WINDOW]
            for ip in stale:
                del _share_rate[ip]
        return False


def _hash_share_password(password: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt),
        200_000).hex()
    return salt, digest


def _share_html(title: str, body: str, status_code: int = 200) -> Response:
    page = ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_html.escape(title)}</title><style>"
            "body{background:#111827;color:#e5e7eb;font-family:system-ui,"
            "sans-serif;display:flex;align-items:center;justify-content:"
            "center;min-height:100vh;margin:0}"
            ".card{background:#1f2937;border:1px solid #374151;border-radius:"
            "8px;padding:2rem;max-width:24rem;text-align:center}"
            "input{width:100%;box-sizing:border-box;padding:.5rem;margin:"
            ".75rem 0;border-radius:4px;border:1px solid #4b5563;"
            "background:#111827;color:#e5e7eb}"
            "button{background:#2563eb;color:#fff;border:0;border-radius:4px;"
            "padding:.5rem 1.5rem;cursor:pointer;font-weight:600}"
            ".err{color:#f87171;font-size:.9rem}"
            "</style></head><body><div class='card'>" + body +
            "</div></body></html>")
    return Response(page, status_code=status_code,
                    media_type="text/html; charset=utf-8")


def _load_active_share(token: str):
    """Fetch a usable share row; anything else collapses to 404."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", token):
        return None
    conn = _webapp().db_connect()
    try:
        return _share_store.resolve_token(conn, token, int(time.time()))
    except Exception:
        return None
    finally:
        conn.close()


async def _stream_share(row) -> StreamingResponse:
    """Stream the PINNED version, and charge a slot only if it will be sent.

    Two defects the review proved: (1) the counter was incremented BEFORE
    the object was resolved or read, so every 404, every link-preview fetch
    and every failed transfer permanently burned a download slot; (2) the
    link followed the live head by key, so it served replaced content and
    came back to life after an unlink plus a re-upload.
    """
    token, bucket, key = row["token"], row["bucket"], row["object_key"]
    pinned_id = row["object_id"]
    conn = _webapp().db_connect()
    try:
        manifests = ManifestStore(conn)
        catalog = BucketCatalog(manifests)
        # Resolve BEFORE claiming, and refuse anything that cannot be served.
        try:
            item = (manifests.get(pinned_id) if pinned_id
                    else catalog.get(bucket, key).item)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Link not found or expired") from exc
        # A pinned version must still describe the bucket/key it was issued
        # for: if the row no longer does, the link is dead, not re-targeted.
        if item.bucket != bucket or item.key != key:
            raise HTTPException(404, "Link not found or expired")
        if not _share_store.claim_download(conn, token, int(time.time())):
            raise HTTPException(404, "Link not found or expired")
        transport = _webapp().storage_transport(conn)
        root = Path(_webapp().STORAGE_SCRATCH_DIR)
        _webapp()._secure_mkdir(root)
        engine = TelegramObjectStorage(
            ManifestStore(conn), transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=root)
    except BaseException:
        conn.close()
        raise

    async def stream():
        try:
            async for piece in engine.iter_bytes(item.id):
                yield piece
        finally:
            conn.close()

    filename = key.rsplit("/", 1)[-1] or "download"
    quoted = _url_quote(filename)
    return StreamingResponse(stream(), media_type="application/octet-stream",
                             headers={
                                 "Content-Length": str(item.size),
                                 "Content-Disposition":
                                     f"attachment; filename*=UTF-8''{quoted}",
                                 "X-Content-Type-Options": "nosniff",
                                 # A cache could otherwise serve the bytes
                                 # again without consuming a slot.
                                 "Cache-Control": "no-store",
                             })


@router.get("/share/{token}", tags=["Sharing"],
         summary="Public share link: stream the shared object")
async def public_share_get(token: str, request: Request):
    client_ip = request.client.host if request.client else "-"
    if _share_rate_limited(client_ip):
        raise HTTPException(429, "Too many requests")
    row = _load_active_share(token)
    if row is None:
        return _share_html(
            "Link unavailable",
            "<h2>Link not found or expired</h2>", status_code=404)
    if row["password_salt"] is not None:  # password protected
        return _share_html(
            "Protected download",
            "<h2>Protected download</h2>"
            "<p>This link requires a password.</p>"
            f"<form method='post' action='/share/{_html.escape(token)}'>"
            "<input type='password' name='password' placeholder='Password' "
            "autofocus required><button type='submit'>Download</button></form>")
    return await _stream_share(row)


@router.post("/share/{token}", tags=["Sharing"],
          summary="Public share link: unlock a password-protected object")
async def public_share_post(token: str, request: Request):
    client_ip = request.client.host if request.client else "-"
    if _share_rate_limited(client_ip):
        raise HTTPException(429, "Too many requests")
    row = _load_active_share(token)
    if row is None:
        return _share_html(
            "Link unavailable",
            "<h2>Link not found or expired</h2>", status_code=404)
    if row["password_salt"] is None:
        return await _stream_share(row)
    # The share form is always application/x-www-form-urlencoded (our
    # own HTML); parse it directly instead of pulling in python-multipart.
    raw = (await request.body()).decode("utf-8", "replace")
    fields = urllib.parse.parse_qs(raw)
    password = str((fields.get("password") or [""])[0])
    _, candidate = _hash_share_password(password, row["password_salt"])
    if not hmac.compare_digest(candidate, row["password_hash"] or ""):
        _webapp()._log(
            f"share password rejected: token={token[:6]}… ip={client_ip}",
             "share")
        return _share_html(
            "Protected download",
            "<h2>Protected download</h2>"
            "<p class='err'>Incorrect password.</p>"
            f"<form method='post' action='/share/{_html.escape(token)}'>"
            "<input type='password' name='password' placeholder='Password' "
            "autofocus required><button type='submit'>Download</button></form>",
            status_code=401)
    return await _stream_share(row)


# --- Public website hosting (Phase I) ------------------------------------
#
# Website content is served on the APP ORIGIN, so the response must not be
# usable as a same-origin attack surface. Every response carries
# ``Content-Security-Policy: sandbox; default-src 'none'; ...``: the sandbox
# moves the document into an opaque origin (no cookies, no same-origin API
# reads) and default-src 'none' forbids scripts, styles, images and frames.
# The bucket's current ready objects only are addressable: staging manifests,
# delete markers, removed versions and ACL metadata never enter this path.

_SITE_CSP = ("sandbox; default-src 'none'; base-uri 'none'; "
             "form-action 'none'; frame-ancestors 'none'; object-src 'none'")
_SITE_MIME = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")


def _site_not_found() -> Response:
    """Uniform 404: nonexistent bucket, disabled gate and no config look alike."""
    return Response(b"Not Found\n", status_code=404, headers={
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Security-Policy": _SITE_CSP,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


def _site_path(value: str) -> str | None:
    """Decode repeatedly and reject traversal / absolute filesystem paths.

    Starlette already decodes the path parameter once; a second and third
    decode catch ``%252e%252e`` style double encoding. ``..`` and ``.``
    segments, backslashes, NUL/control characters, absolute paths and
    ``scheme://`` values are refused before any key lookup.
    """
    candidate = value
    for _ in range(3):
        if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
            return None
        if "\\" in candidate or "://" in candidate:
            return None
        if candidate.startswith("/") or candidate.startswith("~"):
            return None
        if re.match(r"[A-Za-z]:[/\\]", candidate):
            return None
        # A single trailing slash is the directory form; empty/interior
        # double slashes are ambiguous and refused.
        segments = candidate.split("/") if candidate else []
        if segments and segments[-1] == "":
            segments = segments[:-1]
        if any(segment in {"", ".", ".."} for segment in segments):
            return None
        decoded = urllib.parse.unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    else:
        return None
    return candidate


def _site_content_type(catalog, item) -> str:
    """Stored Content-Type when it is a plain media type, else a safe default."""
    try:
        stored = ObjectMetadataStore(catalog).get(item.id).get("content-type")
    except Exception:
        stored = None
    base = (stored or "").split(";", 1)[0].strip().lower()
    if not _SITE_MIME.fullmatch(base):
        return "application/octet-stream"
    if base.startswith("text/"):
        return base + "; charset=utf-8"
    return base


def _site_headers(catalog, item, status_code: int) -> tuple[dict, int]:
    headers = {
        "Content-Type": _site_content_type(catalog, item),
        "Content-Length": str(item.size),
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": _SITE_CSP,
        "Cache-Control": "no-store",
        "ETag": '"' + item.sha256 + '"',
        "Last-Modified": time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(item.created_at)),
    }
    return headers, status_code


async def _serve_site(bucket: str, path: str, request: Request) -> Response:
    try:
        BucketCatalog.validate_bucket(bucket)
    except ValueError:
        return _site_not_found()
    safe_path = _site_path(path)
    if safe_path is None:
        return _site_not_found()

    conn = _webapp().db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        try:
            config = WebsiteConfigStore(catalog).get(bucket)
            public_read = catalog.public_read(bucket)
        except FileNotFoundError:
            conn.close()
            return _site_not_found()
        if not config or not config.get("enabled", True) or not public_read:
            conn.close()
            return _site_not_found()

        index_document = config["index_document"]
        if safe_path == "" or safe_path.endswith("/"):
            candidates = [safe_path + index_document]
        else:
            candidates = [safe_path, safe_path + "/" + index_document]
        item = None
        status_code = 200
        for key in candidates:
            try:
                item = catalog.get(bucket, key).item
                break
            except FileNotFoundError:
                continue
        if item is None and config.get("error_document"):
            try:
                item = catalog.get(bucket, config["error_document"]).item
                status_code = 404
            except FileNotFoundError:
                item = None
        if item is None:
            conn.close()
            return _site_not_found()

        # The public site is a READ surface, so it must obey the same gate as
        # every other one. Without this, an SSE-C object answered 200 with a
        # non-zero Content-Length and zero body bytes (a client reads that as
        # a successful empty page), and an archived object streamed normally
        # instead of answering InvalidObjectState.
        manifests = ManifestStore(conn)
        try:
            _webapp()._rest_read_gate(manifests, catalog, item)
        except HTTPException:
            # A public site never explains WHY: an anonymous client gets the
            # same uniform 404 as a missing key.
            conn.close()
            return _site_not_found()

        headers, status_code = _site_headers(catalog, item, status_code)
        if request.method == "HEAD":
            conn.close()
            return Response(status_code=status_code, headers=headers)
        transport = _webapp().storage_transport(conn)
        root = Path(_webapp().STORAGE_SCRATCH_DIR)
        _webapp()._secure_mkdir(root)
        engine = TelegramObjectStorage(
            manifests, transport,
            chunk_size=RECOMMENDED_CHUNK_SIZE, scratch_directory=root)
    except BaseException:
        conn.close()
        raise

    async def stream():
        try:
            async for piece in engine.iter_bytes(item.id):
                yield piece
        finally:
            conn.close()

    return StreamingResponse(stream(), status_code=status_code,
                             headers=headers)


@router.get("/site/{bucket}", include_in_schema=False)
async def public_website_root(bucket: str, request: Request):
    return await _serve_site(bucket, "", request)


@router.get("/site/{bucket}/{path:path}", include_in_schema=False)
async def public_website_object(bucket: str, path: str, request: Request):
    return await _serve_site(bucket, path, request)
