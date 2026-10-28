"""Admin S3 governance UI: role policy, confirm token, real SigV4 round-trip.

The most important assertion in this file is that the router's server-side
signer produces requests the gateway's own ``verify_header_signature``
accepts. That is why the fixture starts the real S3 ASGI app on a loopback
socket and points ``web.s3_governance_api.s3_origin`` at it: nothing is
stubbed between signing and verification.
"""
from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import text

import web.app as webapp
import web.s3 as gateway
import web.s3_governance_api as gov
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed  # noqa: F401 (fixture)

ADMIN = ("gov-admin", "admin-password-1")
CSRF = {"x-teledrive-csrf": "1"}
BASE = "/api/v1/admin/s3-governance"
BUCKET = "gov-bucket"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def loopback(service, monkeypatch):
    """Serve the real gateway app on 127.0.0.1 and point the router at it."""
    _, issued, telegram, connection, key = service
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    config = uvicorn.Config(gateway.app, host="127.0.0.1", port=port,
                            log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]},
                              daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    assert server.started, "loopback S3 server did not start"

    monkeypatch.setattr(gov, "s3_origin", lambda: f"http://127.0.0.1:{port}")
    monkeypatch.setattr(gov, "load_master_key", lambda: key)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()


@pytest.fixture
def web(service, loopback, monkeypatch, tmp_path):
    _, issued, telegram, connection, _ = service
    monkeypatch.setattr(webapp, "db_connect", connection)
    monkeypatch.setattr(webapp, "storage_transport", lambda db: telegram)
    monkeypatch.setattr(webapp, "STORAGE_SCRATCH_DIR",
                        str(tmp_path / "governance-staging"))
    monkeypatch.setattr(webapp, "WEB_USER", ADMIN[0])
    monkeypatch.setattr(webapp, "WEB_PASSWORD", ADMIN[1])
    webapp.AUTH_FAILURES.clear()
    client = TestClient(webapp.app, base_url="http://localhost:8080")
    try:
        yield client, connection, issued
    finally:
        client.close()


def _seed_user(connection, username: str, password: str, role: str) -> None:
    db = connection()
    try:
        db.connection.execute(text(
            "INSERT INTO users (username, password_hash, role, enabled, "
            "created_at, updated_at) VALUES (:u, :p, :r, 1, :now, :now)"
        ), {"u": username, "p": webapp._hash_password(password),
            "r": role, "now": int(time.time())})
        db.connection.commit()
    finally:
        db.close()


def _make_bucket(connection, name: str = BUCKET) -> None:
    db = connection()
    try:
        BucketCatalog(ManifestStore(db)).create_bucket(name, int(time.time()))
    finally:
        db.close()


def _login(client, username: str, password: str) -> dict:
    response = client.post("/api/auth/login", headers=CSRF,
                           json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["token"], **CSRF}


def _admin_get(client, path):
    return client.get(path, auth=ADMIN)


def _admin_put(client, path, payload):
    return client.put(path, auth=ADMIN, headers=CSRF, json=payload)


# ---------------------------------------------------------------------------
# Surface
# ---------------------------------------------------------------------------

def test_page_router_and_navigation_exist():
    page = Path("web/static/s3-governance.html")
    assert page.is_file()
    html = page.read_text()
    for marker in ("S3 governance", "Bucket policy", "Ownership controls",
                   "Public access block", "Object lock", "Website",
                   "Notifications", "Replication", "Intelligent-Tiering",
                   "Storage reports", "public_read", "PUBLISH",
                   "InvalidObjectState", "CloudWatch", "not Glacier"):
        assert marker in html, marker
    # Every page with the S3 sidebar carries the nav entry.
    for other in Path("web/static").glob("*.html"):
        if other.name in {"login.html", "s3-governance.html"}:
            continue
        assert 'href="/s3/governance"' in other.read_text(), other
    # The router itself exposes the page + API and exports the signer.
    paths = {getattr(route, "path", "") for route in gov.router.routes}
    assert "/s3/governance" in paths
    assert f"{BASE}/{{bucket}}/policy" in paths
    assert callable(gov.sign_request)


def test_page_is_served_for_admin_and_redirects_anonymous(web):
    client, _, _ = web
    anonymous = client.get("/s3/governance", follow_redirects=False)
    assert anonymous.status_code == 302
    assert anonymous.headers["location"] == "/login"
    served = client.get("/s3/governance", auth=ADMIN)
    assert served.status_code == 200
    assert "S3 governance" in served.text
    assert 'href="/s3/governance"' in served.text


def test_router_is_mounted_once_in_app():
    source = Path("web/app.py").read_text()
    lines = [line for line in source.splitlines()
             if "s3_governance_api" in line]
    assert len(lines) == 2, lines
    assert any("app.include_router" in line for line in lines)


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def test_reads_need_operator_and_writes_need_admin(web):
    client, connection, _ = web
    _make_bucket(connection)
    _seed_user(connection, "gov-operator", "operator-password-1", "operator")
    _seed_user(connection, "gov-viewer", "viewer-password-1", "viewer")

    path = f"{BASE}/{BUCKET}/ownership"
    # Unauthenticated is rejected before any S3 call.
    assert client.get(path).status_code == 401

    viewer = _login(client, "gov-viewer", "viewer-password-1")
    assert client.get(path, headers=viewer).status_code == 403
    assert client.put(path, headers=viewer,
                      json={"model": "ObjectWriter"}).status_code == 403
    client.cookies.clear()

    operator = _login(client, "gov-operator", "operator-password-1")
    allowed = client.get(path, headers=operator)
    assert allowed.status_code == 200, allowed.text
    denied = client.put(path, headers=operator, json={"model": "ObjectWriter"})
    assert denied.status_code == 403
    assert "admin" in denied.json()["detail"]
    client.cookies.clear()

    assert _admin_put(client, path, {"model": "ObjectWriter"}).status_code == 200


def test_write_without_csrf_header_is_rejected(web):
    client, connection, _ = web
    _make_bucket(connection)
    response = client.put(f"{BASE}/{BUCKET}/ownership",
                          auth=ADMIN, json={"model": "ObjectWriter"})
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_unknown_or_invalid_bucket_returns_400(web):
    client, _, _ = web
    unknown = _admin_get(client, f"{BASE}/no-such-bucket/policy")
    assert unknown.status_code == 400
    assert "NoSuchBucket" in unknown.json()["detail"]
    invalid = _admin_get(client, f"{BASE}/Bad_Bucket!/policy")
    assert invalid.status_code == 400
    assert "InvalidBucketName" in invalid.json()["detail"]


# ---------------------------------------------------------------------------
# Website public_read confirmation
# ---------------------------------------------------------------------------

def test_public_read_requires_the_publish_token(web):
    client, connection, _ = web
    _make_bucket(connection)
    path = f"{BASE}/{BUCKET}/website"
    base = {"index_document": "index.html", "error_document": "404.html"}

    refused = _admin_put(client, path, {**base, "public_read": True})
    assert refused.status_code == 400
    assert "PUBLISH" in refused.json()["detail"]
    assert _admin_get(client, path).json()["public_read"] is False

    wrong = _admin_put(client, path,
                       {**base, "public_read": True, "confirm": "publish"})
    assert wrong.status_code == 400

    published = _admin_put(client, path,
                           {**base, "public_read": True, "confirm": "PUBLISH"})
    assert published.status_code == 200, published.text
    assert published.json()["public_read"] is True
    assert published.json()["site_url"] == f"/site/{BUCKET}/"
    state = _admin_get(client, path).json()
    assert state == {
        "configured": True,
        "index_document": "index.html",
        "error_document": "404.html",
        "public_read": True,
        "site_url": f"/site/{BUCKET}/",
    }

    revoked = _admin_put(client, path, {**base, "public_read": False})
    assert revoked.status_code == 200
    assert _admin_get(client, path).json()["public_read"] is False


# ---------------------------------------------------------------------------
# The signing round-trip
# ---------------------------------------------------------------------------

def test_router_signed_requests_round_trip_through_the_gateway(
        web, service, loopback):
    client, connection, issued = web
    _make_bucket(connection)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "RoundTrip",
            "Effect": "Allow",
            "Principal": {"CanonicalUser": [issued.access_key]},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        }],
    }

    saved = _admin_put(client, f"{BASE}/{BUCKET}/policy", {"policy": policy})
    assert saved.status_code == 200, saved.text

    loaded = _admin_get(client, f"{BASE}/{BUCKET}/policy")
    assert loaded.status_code == 200, loaded.text
    assert loaded.json()["configured"] is True
    assert "RoundTrip" in loaded.json()["policy"]

    # The gateway's own verifier accepted the router signature: an
    # independent signed GET returns the exact stored document.
    direct = signed(service, "GET", f"/{BUCKET}?policy")
    assert direct.status_code == 200, direct.text
    assert b"RoundTrip" in direct.content

    # Delete flows through the same signer and is observable on the gateway.
    removed = client.delete(
        f"{BASE}/{BUCKET}/policy", auth=ADMIN, headers=CSRF)
    assert removed.status_code == 200, removed.text
    direct = signed(service, "GET", f"/{BUCKET}?policy")
    assert direct.status_code == 404
    assert b"NoSuchBucketPolicy" in direct.content


def test_policy_validation_errors_are_aws_shaped(web):
    client, connection, _ = web
    _make_bucket(connection)
    response = _admin_put(client, f"{BASE}/{BUCKET}/policy",
                          {"policy": {"Version": "2012-10-17",
                                      "Statement": []}})
    assert response.status_code == 400
    assert response.headers["X-AWS-Error-Code"] == "MalformedPolicy"
    assert "MalformedPolicy" in response.json()["detail"]


def test_ownership_pab_and_object_lock_round_trip(web):
    client, connection, _ = web
    _make_bucket(connection)

    assert _admin_put(client, f"{BASE}/{BUCKET}/ownership",
                      {"model": "BucketOwnerPreferred"}).status_code == 200
    assert _admin_get(client, f"{BASE}/{BUCKET}/ownership"
                      ).json()["model"] == "BucketOwnerPreferred"

    flags = {"BlockPublicAcls": False, "IgnorePublicAcls": False,
             "BlockPublicPolicy": True, "RestrictPublicBuckets": False}
    assert _admin_put(client, f"{BASE}/{BUCKET}/public-access-block",
                      {"flags": flags}).status_code == 200
    assert _admin_get(client, f"{BASE}/{BUCKET}/public-access-block"
                      ).json()["flags"] == flags

    state = _admin_get(client, f"{BASE}/{BUCKET}/object-lock").json()
    assert state["enabled"] is False
    enabled = _admin_put(client, f"{BASE}/{BUCKET}/object-lock",
                         {"mode": "GOVERNANCE", "days": 30})
    assert enabled.status_code == 200, enabled.text
    state = _admin_get(client, f"{BASE}/{BUCKET}/object-lock").json()
    assert state["enabled"] is True
    assert state["mode"] == "GOVERNANCE"
    assert state["days"] == 30

    # Every write is audit-logged under the governance source.
    assert any("[s3-governance]" in entry and "object lock ENABLED"
               in entry for entry in webapp.LOG_BUFFER)


def test_notifications_tiering_and_reports_round_trip(web, monkeypatch):
    client, connection, _ = web
    _make_bucket(connection)
    _make_bucket(connection, "report-dest")
    db = connection()
    try:
        db.connection.execute(text(
            "INSERT INTO telegram_sessions (api_id, api_hash, phone, "
            "session_string, account, channel, strategy, created_at, "
            "updated_at) VALUES (1, 'h', 'p', 's', 'offsite', NULL, "
            "'round_robin', :n, :n)"), {"n": int(time.time())})
        db.connection.commit()
    finally:
        db.close()

    monkeypatch.setattr(gateway, "_notification_allowlist",
                        lambda: ("https://hooks.example.com",))
    events = ["s3:ObjectCreated:Put", "s3:ObjectRemoved:Delete"]
    saved = _admin_put(client, f"{BASE}/{BUCKET}/notifications", {
        "enabled": True,
        "destination": "https://hooks.example.com/teledrive",
        "events": events,
        "filter_prefix": "logs/",
        "filter_suffix": ".json",
    })
    assert saved.status_code == 200, saved.text
    notify = _admin_get(client, f"{BASE}/{BUCKET}/notifications").json()
    assert notify["configured"] is True
    assert notify["events"] == events
    assert notify["filter_prefix"] == "logs/"
    assert notify["filter_suffix"] == ".json"

    tiering = _admin_put(client, f"{BASE}/{BUCKET}/tiering/archive", {
        "status": "Enabled", "prefix": "archive/",
        "tiers": [{"days": 30, "access_tier": "ARCHIVE_ACCESS"},
                  {"days": 90, "access_tier": "DEEP_ARCHIVE_ACCESS"}],
    })
    assert tiering.status_code == 200, tiering.text
    configs = _admin_get(client, f"{BASE}/{BUCKET}/tiering").json()["configs"]
    assert configs[0]["id"] == "archive"
    assert configs[0]["prefix"] == "archive/"
    assert {tier["access_tier"] for tier in configs[0]["tiers"]} == {
        "ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS"}

    for kind, config_id in (("analytics", "analytics-1"),
                            ("inventory", "inventory-1"),
                            ("metrics", "metrics-1")):
        response = _admin_put(
            client, f"{BASE}/{BUCKET}/reports/{kind}/{config_id}", {
                "schedule": "Daily", "enabled": True, "prefix": "data/",
                "destination": {"bucket": "report-dest",
                                "prefix": f"reports/{kind}", "format": "CSV"},
            })
        assert response.status_code == 200, (kind, response.text)
    reports = _admin_get(client, f"{BASE}/{BUCKET}/reports").json()["reports"]
    assert [entry["id"] for entry in reports["analytics"]] == ["analytics-1"]
    assert [entry["id"] for entry in reports["inventory"]] == ["inventory-1"]
    assert [entry["id"] for entry in reports["metrics"]] == ["metrics-1"]
    assert reports["inventory"][0]["destination"]["bucket"] == "report-dest"

    deleted = client.delete(
        f"{BASE}/{BUCKET}/reports/inventory/inventory-1",
        auth=ADMIN, headers=CSRF)
    assert deleted.status_code == 200
    reports = _admin_get(client, f"{BASE}/{BUCKET}/reports").json()["reports"]
    assert reports["inventory"] == []


def test_replication_uses_configured_account_labels(web):
    client, connection, _ = web
    _make_bucket(connection)
    db = connection()
    try:
        db.connection.execute(text(
            "INSERT INTO telegram_sessions (api_id, api_hash, phone, "
            "session_string, account, channel, strategy, created_at, "
            "updated_at) VALUES (1, 'h', 'p', 's', 'offsite', NULL, "
            "'round_robin', :n, :n)"), {"n": int(time.time())})
        db.connection.commit()
    finally:
        db.close()

    state = _admin_get(client, f"{BASE}/{BUCKET}/replication").json()
    assert state["configured"] is False
    assert "offsite" in state["destinations"]

    saved = _admin_put(client, f"{BASE}/{BUCKET}/replication", {
        "rules": [{"id": "logs", "status": "Enabled", "prefix": "logs/",
                   "destination": "offsite"}]})
    assert saved.status_code == 200, saved.text
    rules = _admin_get(client, f"{BASE}/{BUCKET}/replication").json()["rules"]
    assert rules == [{"id": "logs", "status": "Enabled", "prefix": "logs/",
                      "destination": "offsite"}]

    # Overlapping enabled prefixes are rejected by the real XML validator.
    overlap = _admin_put(client, f"{BASE}/{BUCKET}/replication", {
        "rules": [{"id": "a", "status": "Enabled", "prefix": "logs/",
                   "destination": "offsite"},
                  {"id": "b", "status": "Enabled", "prefix": "logs/deep/",
                   "destination": "offsite"}]})
    assert overlap.status_code == 400
    assert overlap.headers["X-AWS-Error-Code"] == "InvalidRequest"
    assert "InvalidRequest" in overlap.json()["detail"]


def test_signing_credentials_never_return_a_secret(web):
    client, connection, issued = web
    _make_bucket(connection)
    response = _admin_get(client, f"{BASE}/signing-credentials")
    assert response.status_code == 200
    text = response.text
    assert issued.secret_key not in text
    for entry in response.json()["credentials"]:
        assert "secret" not in entry and "secret_key" not in entry
        assert entry["id"] and entry["name"] and entry["access_key"]

    # Reads are operator-level; the metadata still never contains a secret.
    _seed_user(connection, "cred-operator", "operator-password-1", "operator")
    operator = _login(client, "cred-operator", "operator-password-1")
    denied = client.get(f"{BASE}/signing-credentials", headers=operator)
    assert denied.status_code == 200  # reads are operator; no secret inside
    assert issued.secret_key not in denied.text
