"""Phase I admin website endpoint: role separation, CSRF and validation.

The endpoint lives on the WebUI origin because ``public_read`` is an explicit
owner decision, not an S3 credential permission.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import web.app as webapp
from tests.s3.test_s3_gateway import service

ADMIN_AUTH = ("testadmin", "secure-auth-password")
CSRF = {"x-teledrive-csrf": "1"}
PATH = "/api/v1/admin/storage/buckets/site-bucket/website"


def seed_user(connection, username: str, password: str, role: str) -> None:
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


@pytest.fixture
def admin_web(service, monkeypatch, tmp_path):
    _, _, telegram, connection, _ = service
    monkeypatch.setattr(webapp, "db_connect", connection)
    monkeypatch.setattr(webapp, "storage_transport", lambda db: telegram)
    monkeypatch.setattr(webapp, "STORAGE_SCRATCH_DIR",
                        str(tmp_path / "website-admin-staging"))
    seed_user(connection, ADMIN_AUTH[0], ADMIN_AUTH[1], "admin")
    webapp.AUTH_FAILURES.clear()
    client = TestClient(webapp.app, base_url="http://localhost:8080")
    try:
        yield client, connection
    finally:
        client.close()


def _login(client, username, password):
    return client.post("/api/auth/login", headers=CSRF,
                       json={"username": username, "password": password})


def _admin_headers(client):
    response = _login(client, *ADMIN_AUTH)
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["token"], **CSRF}


def test_only_admin_role_can_flip_public_read(admin_web):
    web, connection = admin_web
    seed_user(connection, "opuser", "operator-password-1", "operator")
    seed_user(connection, "viewuser", "viewer-password-1", "viewer")
    # A bucket must exist for the role check to be the failing layer.
    db = connection()
    try:
        from teledrive.storage.catalog import BucketCatalog
        from teledrive.storage.manifest import ManifestStore
        BucketCatalog(ManifestStore(db)).create_bucket(
            "site-bucket", int(time.time()))
    finally:
        db.close()

    payload = {"index_document": "index.html", "error_document": None,
               "public_read": True}
    assert web.put(PATH, json=payload).status_code == 401
    for username, password in (("opuser", "operator-password-1"),
                               ("viewuser", "viewer-password-1")):
        login = _login(web, username, password)
        assert login.status_code == 200, login.text
        headers = {"Authorization": "Bearer " + login.json()["token"], **CSRF}
        denied = web.put(PATH, headers=headers, json=payload)
        assert denied.status_code == 403, (username, denied.text)
        web.cookies.clear()

    allowed = web.put(PATH, headers=_admin_headers(web), json=payload)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["public_read"] is True
    assert "publishes" in allowed.json()["notice"]


def test_payload_validation_and_get_observability(admin_web):
    web, connection = admin_web
    db = connection()
    try:
        from teledrive.storage.catalog import BucketCatalog
        from teledrive.storage.manifest import ManifestStore
        BucketCatalog(ManifestStore(db)).create_bucket(
            "site-bucket", int(time.time()))
    finally:
        db.close()

    assert web.put(PATH, headers=_admin_headers(web), json={
        "index_document": "index.html", "error_document": None,
        "public_read": "yes"}).status_code == 422
    for index in ("../index.html", "/index.html", "a\\b.html", "", None):
        invalid = web.put(PATH, headers=_admin_headers(web), json={
            "index_document": index, "error_document": None,
            "public_read": False})
        assert invalid.status_code == 422, (index, invalid.text)
    missing = web.put(
        "/api/v1/admin/storage/buckets/no-such/website",
        headers=_admin_headers(web), json={
            "index_document": "index.html", "error_document": None,
            "public_read": False})
    assert missing.status_code == 404

    ok = web.put(PATH, headers=_admin_headers(web), json={
        "index_document": "index.html", "error_document": "404.html",
        "public_read": False})
    assert ok.status_code == 200
    info = web.get(PATH, headers=_admin_headers(web))
    assert info.status_code == 200
    assert info.json() == {
        "configured": True, "index_document": "index.html",
        "error_document": "404.html", "public_read": False,
    }
