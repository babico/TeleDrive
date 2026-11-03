"""Telegram-backed path-style S3 gateway (initial core subset).

Run as a separate ASGI process at port 9000. Shares SQL metadata and Telegram
Bot API credentials with REST; never stores object bodies in another S3 service.
Unimplemented S3 operations explicitly return NotImplemented (501).

Phase O wire shapes implemented here:

* RenameObject: ``PUT /{bucket}/{destination}?renameObject`` with the source in
  signed ``x-amz-rename-source: bucket/source`` header (the AWS directory-bucket
  shape). TeleDrive also accepts standard buckets — a documented SUPERSET of
  AWS, which limits RenameObject to directory buckets — because the rename is a
  single SQL head move with no Telegram byte copy. Overwrite is rejected.
* SelectObjectContent: ``POST /{bucket}/{key}?select&select-type=2`` with the
  AWS XML request and a real AWS event-stream response (see teledrive/s3/select.py).
* RestoreObject: ``POST /{bucket}/{key}?restore`` with strict AWS XML; without
  an archive tier every object is immediately readable, so the truthful answer
  is ``403 InvalidObjectState`` (see teledrive/s3/restore.py).
"""
from __future__ import annotations

import logging

import os
import time
from urllib.parse import unquote

from fastapi import FastAPI, Request
from fastapi.responses import Response

from teledrive.s3.credentials import load_master_key
from teledrive.s3.sigv4 import SigV4Error
from teledrive.s3.cors import (
    BucketCORSStore, matching_rule, response_cors_headers)
from teledrive.s3.notifications import approved_destinations
from teledrive.s3.select import MAX_SCAN_BYTES as MAX_SELECT_SCAN_BYTES
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE

# Set from settings at startup (and by tests). When true, an AES256 bucket
# default or an explicit x-amz-server-side-encryption: AES256 request makes
# the gateway encrypt server-side with a per-object data key wrapped by the
# S3 master key. Read at call time from web.s3 so config reloads and tests
# take effect without re-importing.
ENVELOPE_ENABLED = False
import web.app as _webapp
from web.app import db_connect, storage_transport, _log

from web.s3_gateway.ranges import _page, _virtual_host_bucket

from web.s3_gateway.dispatch import _handle
from web.s3_gateway.xml import _error

_module_logger = logging.getLogger(__name__)

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
app = FastAPI(title="TeleDrive S3 (initial compatibility subset)", docs_url=None,
              redoc_url=None, openapi_url=None)


def _notification_allowlist() -> tuple[str, ...]:
    """Owner-approved webhook destinations (storage.notification_destinations)."""
    raw = os.environ.get("TELEDRIVE_NOTIFICATION_DESTINATIONS", "")
    try:
        storage = getattr(_webapp.effective_config(), "storage", None)
        if isinstance(storage, dict) and storage.get("notification_destinations"):
            raw = str(storage["notification_destinations"])
    except Exception as exc:
        # Falling back to the environment allowlist is the documented
        # behaviour; doing it because of an ERROR rather than an absent
        # setting is worth one debug line.
        _module_logger.debug(
            "notification destinations fell back to the environment: %s",
            exc)
    return approved_destinations(raw)


@app.middleware("http")
async def _s3_audit_log_middleware(request: Request, call_next):
    """Mirror the web http audit log for S3-port traffic.

    S3 client connection attempts — failed signatures, bucket probes,
    even plain browser hits — were previously invisible on the logs
    page because only the web app had an audit middleware. Registered
    after the CORS middleware so it is the OUTERMOST layer and also
    captures its short-circuit responses.
    """
    start = time.time()
    path = request.url.path
    method = request.method
    skip = path == "/__health"
    if not skip:
        client = request.client.host if request.client else "-"
        user = "-"
        auth = request.headers.get("authorization", "")
        if auth.startswith("AWS4-HMAC-SHA256 Credential="):
            # Access key id only; SigV4 never transmits the secret.
            user = auth.split("Credential=", 1)[1].split("/", 1)[0]
        _log(f"{method} {path} from {client}", "http", user=user)
    try:
        response = await call_next(request)
    except Exception as exc:
        if not skip:
            _log(f"{method} {path} -> EXCEPTION: {type(exc).__name__}", "http")
        raise
    elapsed = (time.time() - start) * 1000
    if not skip:
        _log(f"{method} {path} -> {response.status_code} ({elapsed:.0f}ms)",
             "http")
    return response


@app.middleware("http")
async def _route_encoded_control_keys(request: Request, call_next):
    """Preserve S3 opaque keys and enforce bucket CORS independently of SigV4.

    A browser OPTIONS preflight has no AWS signature but cannot read/write
    anything. Actual S3 methods still require the normal signed authorization.
    """
    path = request.scope.get("path", "")
    origin = request.headers.get("origin", "")
    wants_cors = bool(origin and path != "/__health" and path.startswith("/"))
    if wants_cors:
        logical = unquote((request.scope.get("raw_path") or b"/").decode("ascii").lstrip("/"))
        try:
            virtual_bucket = _virtual_host_bucket(request)
        except SigV4Error as exc:
            return _error(exc.code, exc.message, 400)
        bucket = virtual_bucket if virtual_bucket is not None else logical.split("/", 1)[0]
        # The root path (ListBuckets) has no bucket: the lookup below is
        # skipped, but the response still needs a defined "no rule matched".
        matched = None
        if bucket:
            connection = None
            try:
                connection = db_connect()
                catalog = BucketCatalog(ManifestStore(connection))
                if bucket in catalog.list_buckets():
                    rules = BucketCORSStore(catalog).get(bucket) or []
                else:
                    rules = []
                is_preflight = request.method == "OPTIONS"
                cors_method = (request.headers.get("access-control-request-method", "")
                               if is_preflight else request.method)
                headers_string = (request.headers.get("access-control-request-headers", "")
                                  if is_preflight else "")
                requested = ([h.strip() for h in headers_string.split(",") if h.strip()]
                             if headers_string else [])
                # Cross-origin browser clients may send many headers; bound
                # their CORS preflight processing without trusting the Origin.
                if (len(headers_string) > 2048 or len(requested) > 32
                        or any(not h.isascii() for h in requested)):
                    return _error("AccessForbidden", "CORS preflight rejected", 403)
                matched = matching_rule(rules, origin, cors_method, requested)
                if is_preflight:
                    if not matched:
                        return _error("AccessForbidden", "CORS preflight rejected", 403)
                    return Response(status_code=200, headers=response_cors_headers(
                        matched, origin, preflight=True, requested_headers=requested
                    ))
            except Exception:
                if request.method == "OPTIONS":
                    return _error("ServiceUnavailable", "CORS lookup unavailable", 503)
                raise
            finally:
                if connection is not None:
                    connection.close()
            # Do not bypass signature validation for actual HTTP methods.
            if path != "/__health" and any(ord(ch) < 32 for ch in path):
                response = await _handle(request)
            else:
                response = await call_next(request)
            if matched:
                for name, value in response_cors_headers(
                    matched, origin, preflight=False
                ).items():
                    response.headers[name] = value
            return response
    if request.method == "OPTIONS":
        return _error("AccessForbidden", "CORS preflight rejected", 403)
    if path != "/__health" and any(ord(character) < 32 for character in path):
        return await _handle(request)
    return await call_next(request)


@app.middleware("http")
async def _s3_bootstrap_gate_middleware(request: Request, call_next):
    """First-boot gate for the S3 data plane (the ``web.s3`` twin of
    ``web.app._BootstrapGateMiddleware``).

    While the seeded ``admin`` account still uses the shipped default
    password, no credentialed S3 request is authorized -- decided HERE,
    before any SigV4 verification runs. On a legitimate first boot no
    credential can exist (issuing runs through the gated web API), so
    anything that still signs was issued under the default-password
    admin: exactly the delegated authority the bootstrap lock contains.
    Health checks, anonymous preflights and unsigned traffic pass (the
    gateway's own authorization still refuses the latter).

    Registered last, which makes it the OUTERMOST layer: the CORS
    middleware short-circuits some paths directly into ``_handle``,
    bypassing inner layers, so the gate has to wrap it.
    """
    signed = (bool(request.headers.get("authorization"))
              or "X-Amz-Signature" in request.query_params
              or "Signature" in request.query_params)
    if signed and request.url.path != "/__health":
        from web.routers.auth import _bootstrap_gate_active
        # Probe through THIS module's database binding (tests rebind it;
        # production points it at the same database as the web app).
        if _bootstrap_gate_active(db_connect):
            _log("denied: credentialed S3 request while the default admin "
                 "password is still in use", "security")
            return _error(
                "AccessDenied",
                "First-boot setup is incomplete: change the default "
                "administrator password before using the S3 API", 403)
    return await call_next(request)


@app.get("/__health", include_in_schema=False)
def health():
    # Container-local liveness only; no credentials or Telegram calls.
    return {"ok": True}


@app.api_route("/", methods=["GET", "PUT", "POST", "DELETE", "HEAD"])
async def root(request: Request):
    return await _handle(request)


@app.api_route("/{path:path}", methods=["GET", "PUT", "POST", "DELETE", "HEAD"])
async def path_route(request: Request, path: str):
    return await _handle(request)
