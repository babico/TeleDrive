"""Admin WebUI bridge for the S3 governance features.

The S3 gateway already implements bucket policy, ownership controls, public
access block, object lock, website, notifications, replication,
Intelligent-Tiering and storage reports. Those operations are only reachable
through the S3 API with a SigV4 credential, which is the wrong interface for
an operator: this router turns them into point-and-click admin endpoints.

Security model
--------------
* The router requires the ``admin`` role for writes and at least ``operator``
  for reads. The S3 layer only sees an access key, so the role decision has
  to happen here.
* A server-side signer signs the loopback S3 request with an *active* S3
  credential that actually grants the required S3 action. The credential is
  never returned to the browser; only its name/permission metadata is listed.
* Every write is audit-logged through the existing ``_log`` helper.
* ``public_read`` on the website tab is an admin-owned exposure decision and
  requires the explicit ``PUBLISH`` confirmation token, mirroring physical
  GC's confirmation token.

Transport
---------
The WebUI and the S3 gateway are separate listeners, so a direct ASGI call
would bypass the very SigV4 verification this feature is supposed to
exercise. Instead the router signs a real HTTP/1.1 request with a minimal
AWS Signature V4 header signer and sends it to the loopback S3 listener
(``127.0.0.1:<s3_port>``, TLS when an S3 certificate is configured). Only
stdlib ``http.client`` is used: httpx is a test-only dependency.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit
from defusedxml import ElementTree as SafeET
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse

from teledrive.s3.credentials import S3CredentialStore, load_master_key
from teledrive.s3.notifications import (approved_destinations,
                                        notification_xml,
                                        parse_notification_xml)
from teledrive.s3.ownership import (MODELS, ownership_xml,
                                    parse_ownership_xml)
from teledrive.s3.policy import MAX_POLICY_BYTES
from teledrive.s3.public_access import (FIELDS as PAB_FIELDS,
                                        parse_public_access_xml,
                                        public_access_xml)
from teledrive.s3.replication import (parse_replication_xml,
                                      replication_xml)
from teledrive.s3.report_configs import (KINDS as REPORT_KINDS,
                                         parse_document as parse_report)
from teledrive.s3.tiering import (ACCESS_TIERS, STATUSES as TIERING_STATUSES,
                                  config_xml as tiering_config_xml,
                                  parse_document as parse_tiering)
from teledrive.s3.website import (parse_website_xml, website_xml)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore

router = APIRouter(tags=["S3 governance"])

REGION = "us-east-1"
SERVICE = "s3"
TIMEOUT_SECONDS = 15
MAX_BODY_BYTES = 64 * 1024

EVENTS = (
    "s3:ObjectCreated:Put",
    "s3:ObjectCreated:Copy",
    "s3:ObjectCreated:CompleteMultipartUpload",
    "s3:ObjectCreated:Post",
    "s3:ObjectRemoved:Delete",
    "s3:ObjectRemoved:DeleteMarkerCreated",
)
LOCK_MODES = ("COMPLIANCE", "GOVERNANCE")
PUBLISH_CONFIRM = "PUBLISH"

_NOT_CONFIGURED = {
    "policy": {"NoSuchBucketPolicy"},
    "website": {"NoSuchWebsiteConfiguration"},
    "object-lock": {"ObjectLockConfigurationNotFoundError"},
    "replication": {"ReplicationConfigurationNotFoundError"},
}


# ---------------------------------------------------------------------------
# Authentication / authorization
# ---------------------------------------------------------------------------

def _actor(request: Request, *, write: bool) -> dict:
    """Authenticate and enforce the governance role policy.

    Reads need operator (admin included). Writes need admin. API keys are
    deliberately refused: a key is a machine identity, not an owner role.
    """
    import web.app as webapp
    webapp.require_auth(request)
    user = getattr(request.state, "user", None) or {}
    role = user.get("role")
    allowed = {"admin"} if write else {"admin", "operator"}
    if role not in allowed:
        webapp._log(
            f"denied: user={user.get('username')} role={role} "
            f"{request.method} {request.url.path}", "s3-governance")
        raise HTTPException(
            403,
            "S3 governance writes require the admin role" if write
            else "S3 governance reads require the operator role or higher")
    if write:
        webapp._same_origin(request)
    return user


def _audit(request: Request, actor: dict, message: str) -> None:
    import web.app as webapp
    webapp._log(message, "s3-governance",
                user=actor.get("username", "system"))


# ---------------------------------------------------------------------------
# Minimal AWS Signature V4 header signer
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def _encode(value: str) -> str:
    return quote(value, safe="-_.~")


def canonical_query(pairs: list[tuple[str, str]]) -> str:
    encoded = sorted((_encode(key), _encode(value)) for key, value in pairs)
    return "&".join(f"{key}={value}" for key, value in encoded)


def sign_request(*, method: str, host: str, target: str, body: bytes,
                 access_key: str, secret_key: str,
                 now: datetime | None = None) -> dict[str, str]:
    """Sign a request exactly like the gateway's ``verify_header_signature``.

    ``target`` is the already-encoded path plus canonical query (no scheme,
    no host). Returns the headers to send, including ``Host`` so the value
    that was signed is the value on the wire.
    """
    clock = now or datetime.now(timezone.utc)
    stamp = clock.strftime("%Y%m%dT%H%M%SZ")
    date = stamp[:8]
    payload_hash = _sha256(body)
    path, _, query = target.partition("?")
    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{stamp}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical = (
        f"{method}\n{path}\n{query}\n{canonical_headers}\n"
        f"{signed_headers}\n{payload_hash}"
    )
    scope = f"{date}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{_sha256(canonical.encode())}"
    )
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    for word in (REGION, SERVICE, "aws4_request"):
        key = _hmac(key, word)
    signature = hmac.new(key, string_to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return {
        "Host": host,
        "X-Amz-Date": stamp,
        "X-Amz-Content-SHA256": payload_hash,
        "Authorization": authorization,
    }


# ---------------------------------------------------------------------------
# Loopback transport
# ---------------------------------------------------------------------------

@dataclass
class S3Result:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def code(self) -> str:
        return self.error()[0]

    @property
    def message(self) -> str:
        return self.error()[1]

    def error(self) -> tuple[str, str]:
        try:
            root = SafeET.fromstring(self.body)
        except (ET.ParseError, ValueError):
            return ("HTTPError", self.body.decode("utf-8", "replace")[:300])
        code = root.findtext("Code") or root.findtext(
            "{http://s3.amazonaws.com/doc/2006-03-01/}Code") or "HTTPError"
        message = root.findtext("Message") or root.findtext(
            "{http://s3.amazonaws.com/doc/2006-03-01/}Message") or ""
        return (code, message)

    def failure(self) -> JSONResponse:
        code, message = self.error()
        return JSONResponse(
            status_code=self.status,
            content={
                "detail": f"{code}: {message}",
                "code": code,
                "message": message,
                "status": self.status,
            },
        )


def s3_origin() -> str:
    """Base URL of the loopback S3 listener."""
    import web.app as webapp
    cert = (getattr(webapp, "S3_SSL_CERTFILE", "")
            or os.environ.get("TELEDRIVE_S3_SSL_CERTFILE", "")).strip()
    scheme = "https" if cert else "http"
    host = (os.environ.get("TELEDRIVE_S3_INTERNAL_HOST", "127.0.0.1")
            .strip() or "127.0.0.1")
    port = int(webapp.settings_s3_port())
    return f"{scheme}://{host}:{port}"


def _ssl_context() -> ssl.SSLContext:
    import web.app as webapp
    context = ssl.create_default_context()
    cert = (getattr(webapp, "S3_SSL_CERTFILE", "")
            or os.environ.get("TELEDRIVE_S3_SSL_CERTFILE", "")).strip()
    if cert and os.path.isfile(cert):
        context.load_verify_locations(cafile=cert)
        # The loopback listener's certificate may name a hostname other
        # than the IP we dial; the certificate itself is still pinned.
        context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _http_send(origin: str, method: str, target: str, body: bytes,
               headers: dict[str, str]) -> S3Result:
    parts = urlsplit(origin)
    https = parts.scheme == "https"
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if https else 80)
    if https:
        connection = http.client.HTTPSConnection(
            host, port, timeout=TIMEOUT_SECONDS, context=_ssl_context())
    else:
        connection = http.client.HTTPConnection(
            host, port, timeout=TIMEOUT_SECONDS)
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        return S3Result(
            status=int(response.status),
            headers={name.lower(): value
                     for name, value in response.getheaders()},
            body=payload,
        )
    except OSError as exc:
        raise HTTPException(
            502,
            f"S3 gateway unreachable at {origin}: {type(exc).__name__}",
        ) from exc
    finally:
        connection.close()


# Tests replace this with a transport that targets an in-process S3 app.
TRANSPORT = _http_send


# ---------------------------------------------------------------------------
# Credential selection
# ---------------------------------------------------------------------------

def _active_credentials(store: S3CredentialStore) -> list[dict]:
    now = int(datetime.now(timezone.utc).timestamp())
    return [
        row for row in store.list()
        if not row.get("revoked")
        and (row.get("expires_at") is None or int(row["expires_at"]) > now)
    ]


def _signing_credential(store: S3CredentialStore, action: str,
                        credential_id: str | None) -> tuple[str, str]:
    """Return ``(access_key, secret_key)`` for the credential that signs.

    The secret is decrypted in-process and never leaves this function's
    caller; only the access key travels inside a SigV4 header.
    """
    active = _active_credentials(store)
    if credential_id:
        match = next(
            (row for row in active
             if row["id"] == credential_id
             or row["access_key"] == credential_id), None)
        if match is None:
            raise HTTPException(400, "Unknown, revoked or expired credential")
        if action not in match.get("permissions", []):
            raise HTTPException(
                400, f"Credential does not grant {action}")
    else:
        match = next(
            (row for row in active
             if action in row.get("permissions", [])), None)
        if match is None:
            raise HTTPException(
                409,
                f"No active S3 credential grants {action}. Create one under "
                "S3 -> Credentials first.")
    revealed = store.reveal(match["id"])
    return revealed["access_key"], revealed["secret_key"]


# ---------------------------------------------------------------------------
# Request helper
# ---------------------------------------------------------------------------

def _bucket_exists(bucket: str) -> None:
    """Validate the bucket name and its existence (400 for unknown buckets)."""
    try:
        BucketCatalog.validate_bucket(bucket)
    except ValueError as exc:
        raise HTTPException(400, f"InvalidBucketName: {exc}") from exc
    import web.app as webapp
    conn = webapp.db_connect()
    try:
        catalog = BucketCatalog(ManifestStore(conn))
        exists = bucket in catalog.list_buckets()
    finally:
        conn.close()
    if not exists:
        raise HTTPException(400, f"NoSuchBucket: bucket {bucket!r} does not exist")


def call_s3(method: str, bucket: str, query: list[tuple[str, str]],
            action: str, *, body: bytes = b"",
            credential_id: str | None = None,
            content_type: str = "application/xml") -> S3Result:
    """Sign and send one S3 request to the loopback listener."""
    import web.app as webapp
    conn = webapp.db_connect()
    try:
        access_key, secret_key = _signing_credential(
            S3CredentialStore(conn, load_master_key()), action, credential_id)
    finally:
        conn.close()

    origin = s3_origin()
    host = urlsplit(origin).netloc
    path = "/" + _encode(bucket)
    canonical = canonical_query(query)
    target = path + ("?" + canonical if canonical else "")
    headers = sign_request(method=method, host=host, target=target,
                           body=body, access_key=access_key,
                           secret_key=secret_key)
    headers["Content-Length"] = str(len(body))
    if body:
        headers["Content-Type"] = content_type
    return TRANSPORT(origin, method, target, body, headers)


def _require_ok(result: S3Result) -> S3Result:
    if result.status >= 400:
        code, message = result.error()
        raise HTTPException(
            status_code=result.status,
            detail=f"{code}: {message}",
            headers={"X-AWS-Error-Code": code},
        )
    return result


def _not_configured(result: S3Result, kind: str) -> bool:
    return result.status == 404 and result.code in _NOT_CONFIGURED[kind]


def _body_size(body: bytes) -> int:
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "Configuration payload is too large")
    return len(body)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _lock_xml(mode: str | None, days: int | None) -> bytes:
    root = ET.Element("ObjectLockConfiguration", {
        "xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"})
    ET.SubElement(root, "ObjectLockEnabled").text = "Enabled"
    if mode is not None:
        rule = ET.SubElement(root, "Rule")
        retention = ET.SubElement(rule, "DefaultRetention")
        ET.SubElement(retention, "Mode").text = mode
        if days is not None:
            ET.SubElement(retention, "Days").text = str(days)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _parse_lock(body: bytes) -> dict:
    root = SafeET.fromstring(body)
    fields = {node.tag.rsplit("}", 1)[-1]: node for node in root}
    mode = days = None
    rule = fields.get("Rule")
    if rule is not None:
        for node in rule:
            if node.tag.rsplit("}", 1)[-1] != "DefaultRetention":
                continue
            for leaf in node:
                label = leaf.tag.rsplit("}", 1)[-1]
                if label == "Mode":
                    mode = (leaf.text or "").strip() or None
                elif label == "Days" and (leaf.text or "").strip().isdigit():
                    days = int((leaf.text or "").strip())
    return {"enabled": True, "mode": mode, "days": days}


def _tiering_payload(config: dict) -> dict:
    return {
        "id": config["id"],
        "status": config["status"],
        "prefix": (config.get("filter") or {}).get("prefix", ""),
        "tiers": [{"days": tier["days"],
                   "access_tier": tier["access_tier"]}
                  for tier in config.get("tiers", [])],
    }


def _tiering_xml(config_id: str, status: str, prefix: str,
                 tiers: list[dict]) -> bytes:
    normalized = {
        "id": config_id,
        "status": status,
        "filter": {"prefix": prefix, "tag": None},
        "tiers": tiers,
    }
    return tiering_config_xml(normalized)


def _report_xml(kind: str, config_id: str, payload: dict) -> bytes:
    """Build the minimal per-kind document the gateway expects."""
    ns = "http://s3.amazonaws.com/doc/2006-03-01/"
    label = {"analytics": "AnalyticsConfiguration",
             "inventory": "InventoryConfiguration",
             "metrics": "MetricsConfiguration"}[kind]
    root = ET.Element(label, {"xmlns": ns})
    ET.SubElement(root, "Id").text = config_id
    prefix = str(payload.get("prefix") or "")
    if kind == "inventory":
        ET.SubElement(root, "IsEnabled").text = (
            "true" if payload.get("enabled", True) else "false")
    destination = payload.get("destination") or {}
    if kind in {"analytics", "inventory"}:
        if not destination.get("bucket"):
            raise HTTPException(400, "A destination bucket is required")
        container = root
        if kind == "analytics":
            analysis = ET.SubElement(root, "StorageClassAnalysis")
            container = ET.SubElement(analysis, "DataExport")
            ET.SubElement(container, "OutputSchemaVersion").text = "V_1"
        dest = ET.SubElement(container, "Destination")
        s3_dest = ET.SubElement(dest, "S3BucketDestination")
        ET.SubElement(s3_dest, "Bucket").text = (
            "arn:aws:s3:::" + str(destination["bucket"]))
        ET.SubElement(s3_dest, "Format").text = (
            "CSV" if kind == "analytics"
            else str(destination.get("format") or "CSV"))
        if destination.get("prefix"):
            ET.SubElement(s3_dest, "Prefix").text = str(
                destination["prefix"])
    if kind == "inventory":
        schedule = ET.SubElement(root, "Schedule")
        ET.SubElement(schedule, "Frequency").text = str(
            payload.get("schedule") or "Daily")
    if prefix:
        filter_node = ET.SubElement(root, "Filter")
        ET.SubElement(filter_node, "Prefix").text = prefix
    if kind == "inventory":
        ET.SubElement(root, "IncludedObjectVersions").text = "Current"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _report_payload(kind: str, config: dict) -> dict:
    destination = config.get("destination") or {}
    return {
        "id": config["id"],
        "kind": kind,
        "schedule": config.get("schedule"),
        "enabled": bool(config.get("enabled", True)),
        "prefix": (config.get("filter") or {}).get("prefix", ""),
        "destination": {
            "bucket": destination.get("bucket"),
            "prefix": destination.get("prefix", ""),
            "format": destination.get("format"),
        } if destination else None,
        "included_object_versions": config.get("included_object_versions"),
        "optional_fields": config.get("optional_fields") or [],
    }


def _report_list(kind: str, body: bytes) -> list[dict]:
    root = SafeET.fromstring(body)
    documents = [node for node in root
                 if node.tag.rsplit("}", 1)[-1] not in {"IsTruncated"}]
    configs = []
    for node in documents:
        document = ET.tostring(node, encoding="utf-8", xml_declaration=True)
        configs.append(parse_report(kind, document))
    return configs


def _tiering_list(body: bytes) -> list[dict]:
    root = SafeET.fromstring(body)
    return [
        parse_tiering(ET.tostring(node, encoding="utf-8",
                                  xml_declaration=True))
        for node in root
        if node.tag.rsplit("}", 1)[-1] == "IntelligentTieringConfiguration"
    ]


def _destination_labels() -> list[str]:
    """Configured TeleDrive account labels usable as replica destinations."""
    import web.app as webapp
    from sqlalchemy import text
    labels: set[str] = set()
    runtime = getattr(webapp, "mtproto_storage_runtime", None)
    transports = getattr(runtime, "transports", None)
    if callable(transports):
        try:
            labels.update(str(label) for label in transports())
        except Exception:
            pass
    conn = webapp.db_connect()
    try:
        rows = conn.connection.execute(text(
            "SELECT account FROM telegram_sessions WHERE account IS NOT NULL "
            "AND account != ''")).all()
        labels.update(str(row[0]) for row in rows)
    except Exception:
        pass
    finally:
        conn.close()
    return sorted(labels)


# ---------------------------------------------------------------------------
# Page + credential metadata
# ---------------------------------------------------------------------------

@router.get("/s3/governance", include_in_schema=False)
def governance_page(request: Request):
    from web.app import _serve_static_page
    return _serve_static_page("s3-governance", request)


@router.get("/api/v1/admin/s3-governance/signing-credentials")
def list_signing_credentials(request: Request):
    _actor(request, write=False)
    import web.app as webapp
    conn = webapp.db_connect()
    try:
        rows = _active_credentials(S3CredentialStore(conn, load_master_key()))
    finally:
        conn.close()
    return {"credentials": [
        {"id": row["id"], "name": row["name"],
         "access_key": row["access_key"],
         "permissions": row.get("permissions", [])}
        for row in rows
    ]}


# ---------------------------------------------------------------------------
# 1. Bucket policy
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/policy")
def get_policy(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    result = call_s3("GET", bucket, [("policy", "")], "s3:GetBucketPolicy")
    if _not_configured(result, "policy"):
        return {"configured": False, "policy": ""}
    _require_ok(result)
    return {"configured": True,
            "policy": result.body.decode("utf-8", "replace")}


@router.put("/api/v1/admin/s3-governance/{bucket}/policy")
def put_policy(bucket: str, request: Request,
               payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    document = payload.get("policy")
    if isinstance(document, dict):
        document = json.dumps(document)
    if not isinstance(document, str) or not document.strip():
        raise HTTPException(400, "MalformedPolicy: a policy document is required")
    body = document.encode("utf-8")
    if len(body) > MAX_POLICY_BYTES:
        raise HTTPException(400, "MalformedPolicy: bucket policy exceeds 20 KiB")
    result = call_s3("PUT", bucket, [("policy", "")], "s3:PutBucketPolicy",
                     body=body, credential_id=payload.get("credential_id"),
                     content_type="application/json")
    _require_ok(result)
    _audit(request, actor,
           f"bucket policy saved: bucket={bucket} bytes={len(body)}")
    return {"ok": True, "configured": True}


@router.delete("/api/v1/admin/s3-governance/{bucket}/policy")
def delete_policy(bucket: str, request: Request,
                  credential_id: str | None = None):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    result = call_s3("DELETE", bucket, [("policy", "")],
                     "s3:DeleteBucketPolicy",
                     credential_id=credential_id)
    _require_ok(result)
    _audit(request, actor, f"bucket policy deleted: bucket={bucket}")
    return {"ok": True, "configured": False}


# ---------------------------------------------------------------------------
# 2. Ownership controls
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/ownership")
def get_ownership(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    result = call_s3("GET", bucket, [("ownershipControls", "")],
                     "s3:GetOwnershipControls")
    _require_ok(result)
    return {"model": parse_ownership_xml(result.body),
            "models": list(MODELS)}


@router.put("/api/v1/admin/s3-governance/{bucket}/ownership")
def put_ownership(bucket: str, request: Request,
                  payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    model = payload.get("model")
    if model not in MODELS:
        raise HTTPException(400, "InvalidArgument: unknown ObjectOwnership model")
    result = call_s3("PUT", bucket, [("ownershipControls", "")],
                     "s3:PutBucketOwnershipControls",
                     body=ownership_xml(model),
                     credential_id=payload.get("credential_id"))
    _require_ok(result)
    _audit(request, actor,
           f"bucket ownership model set: bucket={bucket} model={model}")
    return {"ok": True, "model": model}


@router.delete("/api/v1/admin/s3-governance/{bucket}/ownership")
def delete_ownership(bucket: str, request: Request,
                     credential_id: str | None = None):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    result = call_s3("DELETE", bucket, [("ownershipControls", "")],
                     "s3:DeleteBucketOwnershipControls",
                     credential_id=credential_id)
    _require_ok(result)
    _audit(request, actor,
           f"bucket ownership controls cleared: bucket={bucket}")
    return {"ok": True, "model": "BucketOwnerEnforced"}


# ---------------------------------------------------------------------------
# 3. Public access block
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/public-access-block")
def get_public_access_block(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    result = call_s3("GET", bucket, [("publicAccessBlock", "")],
                     "s3:GetBucketPublicAccessBlock")
    _require_ok(result)
    return {"flags": parse_public_access_xml(result.body),
            "fields": list(PAB_FIELDS)}


@router.put("/api/v1/admin/s3-governance/{bucket}/public-access-block")
def put_public_access_block(bucket: str, request: Request,
                            payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    flags = payload.get("flags")
    if not isinstance(flags, dict) or set(flags) != set(PAB_FIELDS):
        raise HTTPException(
            400, "InvalidArgument: all four public access flags are required")
    if any(not isinstance(value, bool) for value in flags.values()):
        raise HTTPException(
            400, "InvalidArgument: public access flags must be booleans")
    result = call_s3("PUT", bucket, [("publicAccessBlock", "")],
                     "s3:PutBucketPublicAccessBlock",
                     body=public_access_xml(flags),
                     credential_id=payload.get("credential_id"))
    _require_ok(result)
    disabled = sorted(name for name, value in flags.items() if not value)
    _audit(request, actor,
           f"public access block set: bucket={bucket} "
           f"disabled={','.join(disabled) or 'none'}")
    return {"ok": True, "flags": flags}


# ---------------------------------------------------------------------------
# 4. Object lock
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/object-lock")
def get_object_lock(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    result = call_s3("GET", bucket, [("object-lock", "")],
                     "s3:GetBucketObjectLockConfiguration")
    if _not_configured(result, "object-lock"):
        return {"enabled": False, "mode": None, "days": None,
                "modes": list(LOCK_MODES)}
    _require_ok(result)
    parsed = _parse_lock(result.body)
    parsed["modes"] = list(LOCK_MODES)
    return parsed


@router.put("/api/v1/admin/s3-governance/{bucket}/object-lock")
def put_object_lock(bucket: str, request: Request,
                    payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    mode = payload.get("mode")
    if mode not in LOCK_MODES:
        raise HTTPException(
            400, "InvalidArgument: mode must be COMPLIANCE or GOVERNANCE")
    days = payload.get("days")
    # An omitted `days` used to write a rule with a Mode and NO retention
    # period, which erased an existing default retention entirely, and a mode
    # change could downgrade COMPLIANCE to GOVERNANCE -- the one thing a WORM
    # configuration must never allow. Compare against the stored config.
    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    import web.app as _webapp
    conn = _webapp.db_connect()
    try:
        current = BucketCatalog(ManifestStore(conn)).object_lock_config(bucket) \
            or {}
    finally:
        conn.close()
    if days is None:
        days = current.get("default_days")
    if days is not None and (not isinstance(days, int)
                             or not 1 <= days <= 3650):
        raise HTTPException(
            400, "InvalidArgument: days must be an integer between 1 and 3650")
    if current.get("default_mode") == "COMPLIANCE" and mode != "COMPLIANCE":
        raise HTTPException(
            409, "Compliance-mode retention cannot be downgraded to GOVERNANCE")
    if (days is not None and current.get("default_days") is not None
            and days < int(current["default_days"])):
        raise HTTPException(
            409, "A bucket's default retention period cannot be shortened")
    result = call_s3("PUT", bucket, [("object-lock", "")],
                     "s3:PutBucketObjectLockConfiguration",
                     body=_lock_xml(mode, days),
                     credential_id=payload.get("credential_id"))
    _require_ok(result)
    _audit(request, actor,
           f"object lock ENABLED (one-way): bucket={bucket} "
           f"mode={mode} days={days}")
    return {"ok": True, "enabled": True, "mode": mode, "days": days}


# ---------------------------------------------------------------------------
# 5. Website + public_read gate
# ---------------------------------------------------------------------------

def _public_read(bucket: str) -> bool:
    import web.app as webapp
    conn = webapp.db_connect()
    try:
        return bool(BucketCatalog(ManifestStore(conn)).public_read(bucket))
    finally:
        conn.close()


def _set_public_read(bucket: str, value: bool) -> None:
    """Set the owner-only public exposure gate (no S3 permission can).

    The website XML is written through the real S3 API above; this flag is
    deliberately a separate, admin-only SQL decision, exactly like the
    existing /admin/storage/buckets/{bucket}/website endpoint.
    """
    from sqlalchemy import update

    import web.app as webapp
    from teledrive.storage.catalog import buckets
    conn = webapp.db_connect()
    try:
        changed = conn.connection.execute(
            update(buckets).where(buckets.c.name == bucket)
            .values(public_read=bool(value)))
        if changed.rowcount != 1:
            raise HTTPException(400, f"NoSuchBucket: bucket {bucket!r} "
                                     "does not exist")
        conn.commit()
    except BaseException:
        conn.connection.rollback()
        raise
    finally:
        conn.close()


def _website_state(bucket: str) -> dict:
    state = {
        "configured": False,
        "index_document": None,
        "error_document": None,
        "public_read": _public_read(bucket),
        "site_url": f"/site/{bucket}/",
    }
    result = call_s3("GET", bucket, [("website", "")],
                     "s3:GetBucketWebsite")
    if _not_configured(result, "website"):
        return state
    _require_ok(result)
    config = parse_website_xml(result.body)
    state.update({
        "configured": True,
        "index_document": config.get("index_document"),
        "error_document": config.get("error_document"),
    })
    return state


@router.get("/api/v1/admin/s3-governance/{bucket}/website")
def get_website(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    return _website_state(bucket)


@router.put("/api/v1/admin/s3-governance/{bucket}/website")
def put_website(bucket: str, request: Request,
                payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    # An OMITTED field means "leave it alone", never "turn it off". Defaulting
    # public_read to False meant that editing the index document silently
    # unpublished a live site, and an omitted error_document wiped it.
    current = _website_state(bucket)
    if "public_read" in payload:
        public_read = payload["public_read"]
        if not isinstance(public_read, bool):
            raise HTTPException(422, "public_read must be a boolean")
    else:
        public_read = bool(current.get("public_read"))
    if public_read and not current.get("public_read"):
        if payload.get("confirm") != PUBLISH_CONFIRM:
            raise HTTPException(
                400,
                "public_read publishes every current object in the bucket "
                f"anonymously; send confirm={PUBLISH_CONFIRM!r} to proceed")
    index_document = payload.get("index_document")
    if index_document is None:
        index_document = current.get("index_document")
    if "error_document" in payload:
        error_document = payload.get("error_document") or None
    else:
        error_document = current.get("error_document")
    try:
        body = website_xml({
            "index_document": index_document,
            "error_document": error_document,
            "enabled": True,
        })
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, f"InvalidArgument: {exc}") from exc
    result = call_s3("PUT", bucket, [("website", "")],
                     "s3:PutBucketWebsite", body=body,
                     credential_id=payload.get("credential_id"))
    _require_ok(result)
    _set_public_read(bucket, public_read)
    _audit(request, actor,
           f"bucket website configured: bucket={bucket} "
           f"index={index_document} error={error_document} "
           f"public_read={public_read}")
    state = {"ok": True, "configured": True,
             "index_document": index_document,
             "error_document": error_document,
             "public_read": public_read,
             "site_url": f"/site/{bucket}/"}
    if public_read:
        state["notice"] = (
            "public_read publishes the bucket's current objects anonymously "
            f"at /site/{bucket}/")
    return state


@router.delete("/api/v1/admin/s3-governance/{bucket}/website")
def delete_website(bucket: str, request: Request,
                   credential_id: str | None = None):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    result = call_s3("DELETE", bucket, [("website", "")],
                     "s3:DeleteBucketWebsite", credential_id=credential_id)
    _require_ok(result)
    # S3 DeleteBucketWebsite revokes public_read in the gateway; mirror the
    # state read so the UI never shows a stale gate.
    _audit(request, actor,
           f"bucket website deleted (public_read revoked): bucket={bucket}")
    return {"ok": True, "configured": False,
            "public_read": _public_read(bucket)}


# ---------------------------------------------------------------------------
# 6. Notifications
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/notifications")
def get_notifications(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    result = call_s3("GET", bucket, [("notificationConfiguration", "")],
                     "s3:GetBucketNotification")
    _require_ok(result)
    config = parse_notification_xml(result.body)
    if config is None:
        return {"configured": False, "enabled": False,
                "destination": "", "events": [], "filter_prefix": "",
                "filter_suffix": "", "events_available": list(EVENTS),
                "approved_destinations": sorted(_approved_destinations())}
    return {
        "configured": True,
        "enabled": bool(config.get("enabled", True)),
        "destination": config.get("destination", ""),
        "events": config.get("events", []),
        "filter_prefix": config.get("filter_prefix", ""),
        "filter_suffix": config.get("filter_suffix", ""),
        "events_available": list(EVENTS),
        "approved_destinations": sorted(_approved_destinations()),
    }


def _approved_destinations() -> tuple[str, ...]:
    import web.app as webapp
    raw = os.environ.get("TELEDRIVE_NOTIFICATION_DESTINATIONS", "")
    try:
        storage = getattr(webapp.effective_config(), "storage", None)
        if isinstance(storage, dict) and storage.get("notification_destinations"):
            raw = str(storage["notification_destinations"])
    except Exception:
        pass
    return approved_destinations(raw)


@router.put("/api/v1/admin/s3-governance/{bucket}/notifications")
def put_notifications(bucket: str, request: Request,
                      payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    enabled = payload.get("enabled", True)
    if not isinstance(enabled, bool):
        raise HTTPException(422, "enabled must be a boolean")
    if not enabled:
        result = call_s3("PUT", bucket, [("notificationConfiguration", "")],
                         "s3:PutBucketNotification",
                         body=notification_xml(None),
                         credential_id=payload.get("credential_id"))
        _require_ok(result)
        _audit(request, actor,
               f"bucket notifications disabled: bucket={bucket}")
        return {"ok": True, "configured": False, "enabled": False}
    destination = payload.get("destination")
    events = payload.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 10:
        raise HTTPException(400, "InvalidArgument: select 1 to 10 events")
    unknown = [event for event in events if event not in EVENTS]
    if unknown:
        raise HTTPException(
            400, f"InvalidArgument: unsupported events {unknown}")
    # An omitted secret means "keep the one that is stored", not "remove it":
    # S3 never returns a secret on GET (there is nothing to echo back), so a UI
    # that saves the form again would otherwise silently unsign the webhook.
    # Read the stored secret directly from the store: the S3 GET deliberately
    # omits it, so there is nothing to preserve through the gateway.
    secret = payload.get("secret")
    if secret is None:
        try:
            import web.app as _webapp
            from teledrive.storage.catalog import BucketCatalog
            from teledrive.storage.manifest import ManifestStore
            from teledrive.s3.notifications import NotificationStore
            conn = _webapp.db_connect()
            try:
                store = NotificationStore(
                    BucketCatalog(ManifestStore(conn)),
                    master_key=_webapp.load_master_key())
                stored = store.get_config(bucket, include_secret=True)
                secret = (stored or {}).get("secret") or None
            finally:
                conn.close()
        except Exception:
            secret = None
    elif secret == "":
        secret = None
    config = {
        "id": "",
        "destination": destination,
        "events": events,
        "filter_prefix": str(payload.get("filter_prefix") or ""),
        "filter_suffix": str(payload.get("filter_suffix") or ""),
        "secret": secret,
        "enabled": True,
    }
    # include_secret: this is a server-side write, so the HMAC secret must
    # survive the round trip. The GET response never carries it.
    result = call_s3("PUT", bucket, [("notificationConfiguration", "")],
                     "s3:PutBucketNotification",
                     body=notification_xml(config, include_secret=True),
                     credential_id=payload.get("credential_id"))
    _require_ok(result)
    _audit(request, actor,
           f"bucket notifications configured: bucket={bucket} "
           f"events={len(events)} destination_host="
           f"{urlsplit(str(destination)).hostname or '-'}")
    return {"ok": True, "configured": True, "enabled": True,
            "destination": destination, "events": events,
            "filter_prefix": config["filter_prefix"],
            "filter_suffix": config["filter_suffix"]}


# ---------------------------------------------------------------------------
# 7. Replication
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/replication")
def get_replication(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    destinations = _destination_labels()
    result = call_s3("GET", bucket, [("replication", "")],
                     "s3:GetBucketReplication")
    if _not_configured(result, "replication"):
        return {"configured": False, "rules": [],
                "destinations": destinations}
    _require_ok(result)
    config = parse_replication_xml(result.body)
    rules = [{
        "id": rule["id"],
        "status": rule["status"],
        "prefix": (rule["prefixes"] or [""])[0],
        "destination": rule["destination"],
    } for rule in config["rules"]]
    return {"configured": True, "rules": rules,
            "destinations": destinations}


@router.put("/api/v1/admin/s3-governance/{bucket}/replication")
def put_replication(bucket: str, request: Request,
                    payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise HTTPException(400, "InvalidRequest: at least one rule is required")
    if len(rules) > 10:
        raise HTTPException(400, "InvalidRequest: at most 10 rules are allowed")
    normalized = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise HTTPException(400, "InvalidRequest: invalid rule")
        status = rule.get("status", "Enabled")
        if status not in {"Enabled", "Disabled"}:
            raise HTTPException(400, "InvalidRequest: invalid rule status")
        destination = rule.get("destination")
        if not isinstance(destination, str) or not destination:
            raise HTTPException(
                400, "InvalidRequest: a destination label is required")
        normalized.append({
            "id": str(rule.get("id") or f"rule-{index + 1}"),
            "status": status,
            "prefixes": [str(rule.get("prefix") or "")],
            "destination": destination,
        })
    body = replication_xml({"role": None, "rules": normalized})
    result = call_s3("PUT", bucket, [("replication", "")],
                     "s3:PutBucketReplication", body=body,
                     credential_id=payload.get("credential_id"))
    _require_ok(result)
    _audit(request, actor,
           f"bucket replication configured: bucket={bucket} "
           f"rules={len(normalized)} enabled="
           f"{sum(1 for rule in normalized if rule['status'] == 'Enabled')}")
    return {"ok": True, "configured": True, "rules": [
        {"id": rule["id"], "status": rule["status"],
         "prefix": rule["prefixes"][0],
         "destination": rule["destination"]} for rule in normalized]}


@router.delete("/api/v1/admin/s3-governance/{bucket}/replication")
def delete_replication(bucket: str, request: Request,
                       credential_id: str | None = None):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    result = call_s3("DELETE", bucket, [("replication", "")],
                     "s3:DeleteBucketReplication",
                     credential_id=credential_id)
    _require_ok(result)
    _audit(request, actor,
           f"bucket replication deleted: bucket={bucket}")
    return {"ok": True, "configured": False, "rules": []}


# ---------------------------------------------------------------------------
# 8. Intelligent-Tiering
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/tiering")
def list_tiering(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    result = call_s3("GET", bucket, [("intelligent-tiering", "")],
                     "s3:ListBucketIntelligentTieringConfigurations")
    _require_ok(result)
    return {"configs": [_tiering_payload(config)
                        for config in _tiering_list(result.body)],
            "access_tiers": list(ACCESS_TIERS)}


@router.put("/api/v1/admin/s3-governance/{bucket}/tiering/{config_id}")
def put_tiering(bucket: str, config_id: str, request: Request,
                payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    status = payload.get("status", "Enabled")
    if status not in TIERING_STATUSES:
        raise HTTPException(400, "InvalidArgument: Status must be Enabled or Disabled")
    tiers = payload.get("tiers")
    if not isinstance(tiers, list) or not tiers:
        raise HTTPException(400, "InvalidArgument: at least one tier is required")
    normalized = []
    seen = set()
    for tier in tiers:
        if not isinstance(tier, dict):
            raise HTTPException(400, "InvalidArgument: invalid tier row")
        access = tier.get("access_tier")
        days = tier.get("days")
        if access not in ACCESS_TIERS:
            raise HTTPException(
                400, "InvalidArgument: access tier must be ARCHIVE_ACCESS "
                     "or DEEP_ARCHIVE_ACCESS")
        if access in seen:
            raise HTTPException(400, "InvalidArgument: duplicate access tier")
        if not isinstance(days, int) or not 1 <= days <= 36500:
            raise HTTPException(
                400, "InvalidArgument: Days must be between 1 and 36500")
        seen.add(access)
        normalized.append({"days": days, "access_tier": access})
    body = _tiering_xml(config_id, status,
                        str(payload.get("prefix") or ""), normalized)
    result = call_s3("PUT", bucket,
                     [("intelligent-tiering", ""), ("id", config_id)],
                     "s3:PutBucketIntelligentTieringConfiguration",
                     body=body, credential_id=payload.get("credential_id"))
    _require_ok(result)
    _audit(request, actor,
           f"tiering configuration saved: bucket={bucket} id={config_id} "
           f"status={status} tiers={len(normalized)}")
    return {"ok": True, "config": {
        "id": config_id, "status": status,
        "prefix": str(payload.get("prefix") or ""),
        "tiers": normalized}}


@router.delete("/api/v1/admin/s3-governance/{bucket}/tiering/{config_id}")
def delete_tiering(bucket: str, config_id: str, request: Request,
                   credential_id: str | None = None):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    result = call_s3(
        "DELETE", bucket,
        [("intelligent-tiering", ""), ("id", config_id)],
        "s3:DeleteBucketIntelligentTieringConfiguration",
        credential_id=credential_id)
    _require_ok(result)
    _audit(request, actor,
           f"tiering configuration deleted: bucket={bucket} id={config_id}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# 9. Storage reports
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/s3-governance/{bucket}/reports")
def list_reports(bucket: str, request: Request):
    _actor(request, write=False)
    _bucket_exists(bucket)
    reports = {}
    for kind in REPORT_KINDS:
        result = call_s3(
            "GET", bucket, [(kind, "")],
            f"s3:GetBucket{kind.capitalize()}Configuration")
        _require_ok(result)
        reports[kind] = [_report_payload(kind, config)
                         for config in _report_list(kind, result.body)]
    return {"reports": reports, "kinds": list(REPORT_KINDS)}


@router.put("/api/v1/admin/s3-governance/{bucket}/reports/{kind}/{config_id}")
def put_report(bucket: str, kind: str, config_id: str, request: Request,
               payload: dict = Body(...)):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    if kind not in REPORT_KINDS:
        raise HTTPException(400, "InvalidArgument: unknown report kind")
    body = _report_xml(kind, config_id, payload)
    _body_size(body)
    result = call_s3(
        "PUT", bucket, [(kind, ""), ("id", config_id)],
        f"s3:PutBucket{kind.capitalize()}Configuration",
        body=body, credential_id=payload.get("credential_id"))
    _require_ok(result)
    _audit(request, actor,
           f"report configuration saved: bucket={bucket} kind={kind} "
           f"id={config_id}")
    return {"ok": True, "kind": kind, "id": config_id}


@router.delete("/api/v1/admin/s3-governance/{bucket}/reports/{kind}/{config_id}")
def delete_report(bucket: str, kind: str, config_id: str, request: Request,
                  credential_id: str | None = None):
    actor = _actor(request, write=True)
    _bucket_exists(bucket)
    if kind not in REPORT_KINDS:
        raise HTTPException(400, "InvalidArgument: unknown report kind")
    result = call_s3(
        "DELETE", bucket, [(kind, ""), ("id", config_id)],
        f"s3:DeleteBucket{kind.capitalize()}Configuration",
        credential_id=credential_id)
    _require_ok(result)
    _audit(request, actor,
           f"report configuration deleted: bucket={bucket} kind={kind} "
           f"id={config_id}")
    return {"ok": True}


__all__ = ["router", "sign_request", "canonical_query", "s3_origin",
           "TRANSPORT"]
