"""Admin S3 credential issuance contract and immediate revoke with signed S3 calls."""
from __future__ import annotations

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest

import web.app as webapp
import web.s3 as gateway
from teledrive.db import connect_database
from teledrive.s3.credentials import S3CredentialStore


@pytest.fixture
def admin(tmp_path, monkeypatch):
    url = str(tmp_path / "metadata.db")
    key = Fernet.generate_key()
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(url))
    monkeypatch.setattr(gateway, "db_connect", lambda: connect_database(url))
    monkeypatch.setattr(webapp, "load_master_key", lambda: key)
    monkeypatch.setattr(gateway, "load_master_key", lambda: key)
    monkeypatch.setattr(webapp, "WEB_USER", "testadmin")
    monkeypatch.setattr(webapp, "WEB_PASSWORD", "secure-auth-password")
    webapp.AUTH_FAILURES.clear()
    # No ASGI lifespan: endpoint authorization contract is isolated from
    # Docker startup paths (/config, /data) and Telegram scheduler.
    client = TestClient(webapp.app, base_url="http://localhost")
    try:
        yield client, url, key
    finally:
        client.close()


def test_issuance_requires_basic_auth_csrf_and_one_time_secret(admin):
    client, url, master = admin
    path = "/api/v1/admin/s3-credentials"
    payload = {"name": "SDK-backup", "permissions": ["s3:GetObject", "s3:ListBucket"]}
    assert client.post(path, json=payload).status_code == 403 or client.post(path, json=payload).status_code == 401
    assert client.post(path, auth=("testadmin", "secure-auth-password"),
                       json=payload).status_code == 403
    issued = client.post(path, auth=("testadmin", "secure-auth-password"),
                         headers={"x-teledrive-csrf": "1"}, json=payload)
    assert issued.status_code == 201, issued.text
    result = issued.json()
    assert result["secret_key"]
    assert result["access_key"].startswith("TD")
    listing = client.get(path, auth=("testadmin", "secure-auth-password"))
    assert listing.status_code == 200
    rows = listing.json()["credentials"]
    assert rows[0]["access_key"] == result["access_key"]
    assert result["secret_key"] not in listing.text
    connection = connect_database(url)
    try:
        assert S3CredentialStore(connection, master).resolve(
            result["access_key"], "s3:GetObject"
        ) == result["secret_key"]
    finally:
        connection.close()
    revoke_path = f"{path}/{result['id']}"
    assert client.delete(revoke_path, auth=("testadmin", "secure-auth-password")).status_code == 403
    assert client.delete(revoke_path, auth=("testadmin", "secure-auth-password"),
                         headers={"x-teledrive-csrf": "1"}).status_code == 200
    connection = connect_database(url)
    try:
        assert S3CredentialStore(connection, master).resolve(
            result["access_key"], "s3:GetObject"
        ) is None
    finally:
        connection.close()


def test_scope_validation_and_missing_master_key(admin, monkeypatch):
    client, _, _ = admin
    url = "/api/v1/admin/s3-credentials"
    auth = ("testadmin", "secure-auth-password")
    headers = {"x-teledrive-csrf": "1"}
    invalid = client.post(url, auth=auth, headers=headers,
                          json={"name": "bad", "permissions": ["s3:AdminAll"]})
    assert invalid.status_code == 422
    monkeypatch.setattr(webapp, "load_master_key", lambda: (_ for _ in ()).throw(
        RuntimeError("Missing S3 master key")
    ))
    missing = client.get(url, auth=auth)
    assert missing.status_code == 503
    assert "Missing S3 master key" in missing.text


def test_credential_editing(admin):
    """PUT /admin/s3-credentials/{id}: name + permission editing."""
    client, url, master = admin
    auth = ("testadmin", "secure-auth-password")
    csrf = {"X-TeleDrive-CSRF": "1"}

    r = client.post("/api/v1/admin/s3-credentials", auth=auth, headers=csrf,
                    json={"name": "orig", "permissions": ["s3:GetObject",
                                                         "s3:PutObject"]})
    assert r.status_code == 201, r.text
    created = r.json()

    # Edit name and narrow the permissions.
    r = client.put(f"/api/v1/admin/s3-credentials/{created['id']}",
                   auth=auth, headers=csrf,
                   json={"name": "renamed-key",
                         "permissions": ["s3:GetObject", "s3:ListBucket"]})
    assert r.status_code == 200, r.text
    body = r.json()["credential"]
    assert body["name"] == "renamed-key"
    assert body["permissions"] == ["s3:GetObject", "s3:ListBucket"]

    # Access key is unchanged; the edit is visible in the list.
    creds = client.get("/api/v1/admin/s3-credentials", auth=auth).json()["credentials"]
    again = [c for c in creds if c["id"] == created["id"]][0]
    assert again["access_key"] == created["access_key"]
    assert again["name"] == "renamed-key"

    # Invalid permission set and empty updates are rejected.
    assert client.put(f"/api/v1/admin/s3-credentials/{created['id']}",
                      auth=auth, headers=csrf,
                      json={"permissions": ["s3:Nonsense"]}).status_code == 422
    assert client.put(f"/api/v1/admin/s3-credentials/{created['id']}",
                      auth=auth, headers=csrf,
                      json={}).status_code == 422
    # Unknown identifier.
    assert client.put("/api/v1/admin/s3-credentials/nope",
                      auth=auth, headers=csrf,
                      json={"name": "x"}).status_code == 422


def test_credential_secret_reveal(admin):
    """GET /admin/s3-credentials/{id}/secret: admin-only, audit-logged."""
    client, url, master = admin
    auth = ("testadmin", "secure-auth-password")
    csrf = {"X-TeleDrive-CSRF": "1"}

    r = client.post("/api/v1/admin/s3-credentials", auth=auth, headers=csrf,
                    json={"name": "reveal-me",
                          "permissions": ["s3:GetObject"]})
    created = r.json()

    # The revealed secret matches the one shown at creation.
    r = client.get(f"/api/v1/admin/s3-credentials/{created['id']}/secret",
                   auth=auth)
    assert r.status_code == 200
    revealed = r.json()
    assert revealed["access_key"] == created["access_key"]
    assert revealed["secret_key"] == created["secret_key"]

    # Unknown identifier and revoked credentials are rejected.
    assert client.get("/api/v1/admin/s3-credentials/nope/secret",
                      auth=auth).status_code == 422
    client.delete(f"/api/v1/admin/s3-credentials/{created['id']}",
                  auth=auth, headers=csrf)
    r = client.get(f"/api/v1/admin/s3-credentials/{created['id']}/secret",
                   auth=auth)
    assert r.status_code == 422
    assert "Revoked" in r.json()["detail"]
