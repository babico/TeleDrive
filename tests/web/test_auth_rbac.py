"""Token auth, RBAC, user management and page-route security tests.

Covers the WebUI security model: PBKDF2 password hashing (with legacy
migration), login/logout session lifecycle, brute-force throttling, disabled
users, role enforcement on /api/v1/admin/*, config secret redaction and
unauthenticated page redirects.
"""
from __future__ import annotations

import hashlib
import secrets
import time

import pytest
from fastapi.testclient import TestClient

import web.app as web
from teledrive.db import connect_database

CSRF = {"X-TeleDrive-CSRF": "1"}


def _seed_user(connect, username: str, password: str, role: str,
               enabled: bool = True, legacy_hash: bool = False) -> None:
    if legacy_hash:
        salt = secrets.token_hex(16)
        stored = salt + ":" + hashlib.sha256(
            (salt + password).encode()).hexdigest()
    else:
        stored = web._hash_password(password)
    db = connect()
    try:
        db.connection.execute(
            __import__("sqlalchemy").text(
                "INSERT INTO users (username, password_hash, role, enabled, "
                "created_at, updated_at) VALUES (:u, :ph, :r, :e, :now, :now)"
            ), {"u": username, "ph": stored, "r": role,
                "e": 1 if enabled else 0, "now": int(time.time())})
        db.connection.commit()
    finally:
        db.close()


@pytest.fixture
def authenv(tmp_path, monkeypatch):
    """SQLite-backed app with admin/operator/viewer/disabled users seeded."""
    path = tmp_path / "auth.sqlite"
    connect = lambda: connect_database(str(path))
    monkeypatch.setattr(web, "db_connect", connect)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "web:\n  user: testadmin\n  password: long-secure-test-password\n"
        "  allowed_hosts: localhost,127.0.0.1,[::1]\n"
        "storage:\n  channel: ''\n  apis: []\n  scratch_dir: "
        + str(tmp_path / "scratch") + "\n"
        "state:\n  database_url: sqlite:////" + str(path) + "\n"
        "jobs:\n  source_root: " + str(tmp_path / "uploads") + "\n"
        "  auto_run: false\n",
        encoding="ascii",
    )
    monkeypatch.setattr(web, "CONFIG_PATH", config_path)
    monkeypatch.setattr(web, "WEB_USER", "testadmin")
    monkeypatch.setattr(web, "WEB_PASSWORD", "long-secure-test-password")
    monkeypatch.setattr(web, "AUTH_DIR", tmp_path / "auth")
    monkeypatch.setattr(web, "STORAGE_SCRATCH_DIR", str(tmp_path / "scratch"))
    (tmp_path / "scratch").mkdir()
    # Fake USER-MTProto transport for the object download path.
    from tests.web.test_rest_transfer import FakeUserTransport
    transport = FakeUserTransport()
    monkeypatch.setattr(web, "storage_transport", lambda db: transport)
    # Redirect hardcoded /data and /uploads paths in ensure_config.
    import pathlib as _pl
    orig_secure_mkdir = web._secure_mkdir

    def patched_secure_mkdir(path):
        ps = str(path)
        if ps.startswith("/data") or ps.startswith("/uploads"):
            path = _pl.Path(str(tmp_path / ps.lstrip("/")))
        return orig_secure_mkdir(path)

    monkeypatch.setattr(web, "_secure_mkdir", patched_secure_mkdir)
    orig_path_mkdir = _pl.Path.mkdir

    def patched_path_mkdir(self, *a, **k):
        s = str(self)
        if s.startswith("/data") or s.startswith("/uploads"):
            return orig_path_mkdir(tmp_path / s.lstrip("/"), *a, **k)
        return orig_path_mkdir(self, *a, **k)

    monkeypatch.setattr(_pl.Path, "mkdir", patched_path_mkdir)
    web.AUTH_FAILURES.clear()
    _seed_user(connect, "admin", "admin-password-1", "admin")
    _seed_user(connect, "opuser", "operator-password-1", "operator")
    _seed_user(connect, "viewuser", "viewer-password-1", "viewer")
    _seed_user(connect, "legacyuser", "legacy-password-1", "viewer",
               legacy_hash=True)
    _seed_user(connect, "disableduser", "disabled-password-1", "viewer",
               enabled=False)
    client = TestClient(web.app, base_url="http://localhost:8080")
    return {"client": client, "connect": connect, "transport": transport,
            "tmp": tmp_path}


def _login(client, username: str, password: str):
    return client.post("/api/auth/login", headers=CSRF,
                       json={"username": username, "password": password})


def _bearer(client, username: str, password: str) -> dict:
    r = _login(client, username, password)
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


# ---------------------------------------------------------------- login/logout

def test_login_sets_token_and_secure_cookie_attributes(authenv):
    client = authenv["client"]
    r = _login(client, "admin", "admin-password-1")
    assert r.status_code == 200
    body = r.json()
    assert body["token"].startswith("td_sess_")
    assert body["user"]["role"] == "admin"
    cookie = r.headers["set-cookie"]
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()


def test_login_wrong_password_and_unknown_user(authenv):
    client = authenv["client"]
    assert _login(client, "admin", "wrong").status_code == 401
    assert _login(client, "ghost", "whatever").status_code == 401


def test_login_requires_csrf_header(authenv):
    r = authenv["client"].post("/api/auth/login",
                               json={"username": "admin",
                                     "password": "admin-password-1"})
    assert r.status_code == 403


def test_login_missing_fields(authenv):
    r = authenv["client"].post("/api/auth/login", headers=CSRF,
                               json={"username": "", "password": ""})
    assert r.status_code == 400


def test_login_brute_force_throttling(authenv):
    client = authenv["client"]
    for _ in range(5):
        assert _login(client, "admin", "wrong").status_code == 401
    # The configured limit (default 5) now blocks further attempts.
    r = _login(client, "admin", "admin-password-1")
    assert r.status_code == 429


def test_disabled_user_cannot_login(authenv):
    r = _login(authenv["client"], "disableduser", "disabled-password-1")
    assert r.status_code == 403


def test_legacy_hash_verified_and_upgraded_on_login(authenv):
    client = authenv["client"]
    r = _login(client, "legacyuser", "legacy-password-1")
    assert r.status_code == 200
    db = authenv["connect"]()
    try:
        stored = db.connection.execute(
            __import__("sqlalchemy").text(
                "SELECT password_hash FROM users WHERE username='legacyuser'")
        ).scalar()
        assert stored.startswith("pbkdf2_sha256$")
    finally:
        db.close()


def test_me_endpoint(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.get("/api/auth/me", headers=auth)
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "admin"
    # Drop the persisted session cookie before the unauthenticated check.
    client.cookies.clear()
    assert client.get("/api/auth/me").status_code == 401


def test_session_token_stored_hashed(authenv):
    client = authenv["client"]
    r = _login(client, "admin", "admin-password-1")
    token = r.json()["token"]
    db = authenv["connect"]()
    try:
        stored = db.connection.execute(
            __import__("sqlalchemy").text(
                "SELECT token FROM user_sessions")
        ).scalar()
        assert stored != token  # raw token must never live in the DB
        assert stored == hashlib.sha256(token.encode()).hexdigest()
    finally:
        db.close()


def test_logout_revokes_bearer_session(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.post("/api/auth/logout", headers={**auth, **CSRF})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=auth).status_code == 401


def test_canonical_v1_paths_work_alongside_legacy_aliases(authenv):
    client = authenv["client"]
    # Canonical /api/v1/auth/login
    r = client.post("/api/v1/auth/login", headers=CSRF,
                    json={"username": "admin", "password": "admin-password-1"})
    assert r.status_code == 200
    # Canonical /api/v1/auth/me and /api/v1/logs
    assert client.get("/api/v1/auth/me").status_code == 200
    r = client.get("/api/v1/logs?limit=10")
    assert r.status_code == 200
    body = r.json()
    # The legacy duplicated `lines` payload is gone; entries only.
    assert "lines" not in body
    assert isinstance(body["entries"], list) and body["entries"]
    # Legacy aliases still resolve.
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/logs?limit=5").status_code == 200


def test_must_change_password_flag(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")

    # Non-default password: no force-change flag.
    r = client.get("/api/v1/auth/me", headers=admin)
    assert r.status_code == 200
    assert r.json()["must_change_password"] is False

    # Reset the admin account to the shipped default credential.
    db = connect()
    try:
        from sqlalchemy import text as _text
        db.connection.execute(_text(
            "UPDATE users SET password_hash = :ph WHERE username = 'admin'"
        ), {"ph": web._hash_password("admin")})
        db.connection.commit()
    finally:
        db.close()
    web._invalidate_default_admin_cache()
    r = client.get("/api/v1/auth/me", headers=admin)
    assert r.json()["must_change_password"] is True

    # Non-admin users are never flagged by the admin's default password.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    r = client.get("/api/v1/auth/me", headers=viewer)
    assert r.json()["must_change_password"] is False

    # Changing the password clears the flag (cache invalidation).
    uid = _user_id(connect, "admin")
    r = client.put(f"/api/v1/admin/users/{uid}/password",
                   headers={**viewer, **CSRF}, json={"password": "whatever"})
    assert r.status_code == 403  # only admins may change passwords
    r = client.put(f"/api/v1/admin/users/{uid}/password",
                   headers={**admin, **CSRF},
                   json={"password": "admin-password-2"})
    assert r.status_code == 200
    # The password change revoked the old session; log in again.
    admin = _bearer(client, "admin", "admin-password-2")
    r = client.get("/api/v1/auth/me", headers=admin)
    assert r.json()["must_change_password"] is False


def test_logout_revokes_cookie_session(authenv):
    client = authenv["client"]
    assert _login(client, "admin", "admin-password-1").status_code == 200
    # TestClient persists the session cookie automatically.
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout", headers=CSRF).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_expired_session_cleaned_up(authenv):
    client = authenv["client"]
    r = _login(client, "admin", "admin-password-1")
    token = r.json()["token"]
    db = authenv["connect"]()
    try:
        db.connection.execute(
            __import__("sqlalchemy").text(
                "UPDATE user_sessions SET expires_at = 1")
        )
        db.connection.commit()
    finally:
        db.close()
    assert client.get("/api/auth/me",
                      headers={"Authorization": "Bearer " + token}
                      ).status_code == 401


# ---------------------------------------------------------------- page routes

@pytest.mark.parametrize("page", ["/", "/dashboard", "/storage", "/s3",
                                  "/users", "/logs", "/settings", "/queue",
                                  "/history", "/api-management"])
def test_pages_redirect_to_login_when_unauthenticated(authenv, page):
    r = authenv["client"].get(page, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].endswith("/login")


def test_login_page_served_unauthenticated(authenv):
    r = authenv["client"].get("/login")
    assert r.status_code == 200


def test_dashboard_alias_serves_index(authenv):
    client = authenv["client"]
    _login(client, "admin", "admin-password-1")
    assert client.get("/dashboard").status_code == 200
    assert client.get("/dashboard.html").status_code == 200


def test_unknown_page_404_when_authenticated(authenv):
    client = authenv["client"]
    _login(client, "admin", "admin-password-1")
    assert client.get("/no-such-page").status_code == 404


# ---------------------------------------------------------------- RBAC

def test_viewer_denied_user_management(authenv):
    client = authenv["client"]
    auth = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/v1/admin/users", headers=auth).status_code == 403
    r = client.post("/api/v1/admin/users", headers={**auth, **CSRF},
                    json={"username": "x2", "password": "longpassword",
                          "role": "viewer"})
    assert r.status_code == 403


def test_viewer_denied_config_write_and_keys(authenv):
    client = authenv["client"]
    auth = _bearer(client, "viewuser", "viewer-password-1")
    assert client.put("/api/config", headers={**auth, **CSRF},
                      json={}).status_code == 403
    assert client.post("/api/v1/admin/keys", headers={**auth, **CSRF},
                       json={"name": "k", "scopes": ["buckets:read"]}
                       ).status_code == 403


def test_viewer_can_read_storage_and_logs(authenv):
    client = authenv["client"]
    auth = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/v1/admin/storage/health",
                      headers=auth).status_code == 200
    assert client.get("/api/v1/admin/storage/jobs", headers=auth).status_code == 200
    assert client.get("/api/logs", headers=auth).status_code == 200
    assert client.get("/api/config", headers=auth).status_code == 200


def test_operator_denied_admin_actions(authenv):
    client = authenv["client"]
    auth = _bearer(client, "opuser", "operator-password-1")
    assert client.put("/api/config", headers={**auth, **CSRF},
                      json={}).status_code == 403
    assert client.get("/api/v1/admin/users", headers=auth).status_code == 403


def test_operator_can_manage_channels(authenv):
    client = authenv["client"]
    auth = _bearer(client, "opuser", "operator-password-1")
    r = client.post("/api/v1/admin/storage/channels", headers={**auth, **CSRF},
                    json={"name": "ch1", "channel_id": "@testchannel"})
    assert r.status_code == 201, r.text


def test_viewer_cannot_manage_channels(authenv):
    client = authenv["client"]
    auth = _bearer(client, "viewuser", "viewer-password-1")
    r = client.post("/api/v1/admin/storage/channels", headers={**auth, **CSRF},
                    json={"name": "ch1", "channel_id": "@testchannel"})
    assert r.status_code == 403


def test_admin_can_create_user(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.post("/api/v1/admin/users", headers={**auth, **CSRF},
                    json={"username": "newuser", "password": "newuserpass1",
                          "role": "operator"})
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "operator"


def test_config_redacts_web_password(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.get("/api/config", headers=auth)
    assert r.status_code == 200
    assert r.json()["web"]["password"] == web.REDACTED


# ---------------------------------------------------------------- user mgmt

def test_create_duplicate_user_conflict(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.post("/api/v1/admin/users", headers={**auth, **CSRF},
                    json={"username": "opuser", "password": "somepassword",
                          "role": "viewer"})
    assert r.status_code == 409


def test_create_user_password_too_short(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.post("/api/v1/admin/users", headers={**auth, **CSRF},
                    json={"username": "shorty", "password": "short",
                          "role": "viewer"})
    assert r.status_code == 400


def _user_id(connect, username: str) -> int:
    db = connect()
    try:
        return db.connection.execute(
            __import__("sqlalchemy").text(
                "SELECT id FROM users WHERE username = :u"), {"u": username}
        ).scalar()
    finally:
        db.close()


def test_change_password_revokes_sessions(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    victim_auth = _bearer(client, "viewuser", "viewer-password-1")
    uid = _user_id(connect, "viewuser")
    r = client.put(f"/api/v1/admin/users/{uid}/password",
                   headers={**admin, **CSRF},
                   json={"password": "brand-new-pass-1"})
    assert r.status_code == 200
    # Old session is revoked.
    assert client.get("/api/auth/me", headers=victim_auth).status_code == 401
    # New password works.
    assert _login(client, "viewuser", "brand-new-pass-1").status_code == 200
    # Old password no longer works.
    assert _login(client, "viewuser", "viewer-password-1").status_code == 401


def test_cannot_demote_or_delete_last_admin(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    uid = _user_id(connect, "admin")
    r = client.put(f"/api/v1/admin/users/{uid}/role", headers={**admin, **CSRF},
                   json={"role": "viewer"})
    assert r.status_code == 409
    r = client.delete(f"/api/v1/admin/users/{uid}", headers={**admin, **CSRF})
    assert r.status_code == 409


def test_demote_admin_allowed_with_second_admin(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    created = client.post("/api/v1/admin/users", headers={**admin, **CSRF},
                          json={"username": "admin2", "password": "admin2pass123",
                                "role": "admin"})
    assert created.status_code == 201
    uid = _user_id(connect, "admin2")
    r = client.put(f"/api/v1/admin/users/{uid}/role", headers={**admin, **CSRF},
                   json={"role": "operator"})
    assert r.status_code == 200
    # And deletion of a non-last admin works.
    r = client.delete(f"/api/v1/admin/users/{uid}", headers={**admin, **CSRF})
    assert r.status_code == 200


def test_disable_user_revokes_sessions(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    victim_auth = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/auth/me", headers=victim_auth).status_code == 200
    uid = _user_id(connect, "viewuser")
    r = client.put(f"/api/v1/admin/users/{uid}", headers={**admin, **CSRF},
                   json={"enabled": False})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=victim_auth).status_code == 401
    assert _login(client, "viewuser", "viewer-password-1").status_code == 403


def test_revoke_user_sessions_endpoint(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    victim_auth = _bearer(client, "viewuser", "viewer-password-1")
    uid = _user_id(connect, "viewuser")
    r = client.delete(f"/api/v1/admin/users/{uid}/sessions",
                      headers={**admin, **CSRF})
    assert r.status_code == 200
    assert r.json()["revoked"] >= 1
    assert client.get("/api/auth/me", headers=victim_auth).status_code == 401


def test_update_user_username_conflict(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    uid = _user_id(connect, "viewuser")
    r = client.put(f"/api/v1/admin/users/{uid}", headers={**admin, **CSRF},
                   json={"username": "opuser"})
    assert r.status_code == 409


def test_user_detail_lists_sessions_without_secrets(authenv):
    client = authenv["client"]
    connect = authenv["connect"]
    admin = _bearer(client, "admin", "admin-password-1")
    _login(client, "viewuser", "viewer-password-1")
    uid = _user_id(connect, "viewuser")
    r = client.get(f"/api/v1/admin/users/{uid}", headers=admin)
    assert r.status_code == 200
    detail = r.json()
    assert detail["username"] == "viewuser"
    assert len(detail["sessions"]) >= 1
    for session in detail["sessions"]:
        assert session["token_prefix"].endswith("...")


def test_list_roles(authenv):
    client = authenv["client"]
    auth = _bearer(client, "viewuser", "viewer-password-1")
    r = client.get("/api/v1/admin/roles", headers=auth)
    assert r.status_code == 200
    assert {x["name"] for x in r.json()["roles"]} == {
        "admin", "operator", "viewer"}


# ---------------------------------------------------------------- hashing

def test_password_hash_format_and_uniqueness():
    h1 = web._hash_password("secret")
    h2 = web._hash_password("secret")
    assert h1.startswith("pbkdf2_sha256$")
    assert h1 != h2  # unique salts
    assert web._verify_password("secret", h1)
    assert not web._verify_password("wrong", h1)


def test_password_verify_legacy_and_garbage():
    salt = secrets.token_hex(16)
    legacy = salt + ":" + hashlib.sha256(
        (salt + "oldpw").encode()).hexdigest()
    assert web._verify_password("oldpw", legacy)
    assert not web._verify_password("other", legacy)
    assert not web._verify_password("x", "garbage-without-separator")
    assert not web._verify_password("x", "a$b$c$d")


# ---------------------------------------------------------------- download

def _publish_object(authenv, bucket: str, key: str, payload: bytes):
    """Stage + publish an object through the real storage engine."""
    import asyncio
    import os
    import tempfile
    from pathlib import Path
    from teledrive.storage.engine import TelegramObjectStorage
    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    from teledrive.storage.telethon_adapter import RECOMMENDED_CHUNK_SIZE

    db = authenv["connect"]()
    try:
        manifests = ManifestStore(db)
        catalog = BucketCatalog(manifests)
        if bucket not in catalog.list_buckets():
            catalog.create_bucket(bucket, int(time.time()))
        fd, staged = tempfile.mkstemp(dir=authenv["tmp"] / "scratch")
        os.write(fd, payload)
        os.close(fd)
        try:
            engine = TelegramObjectStorage(
                manifests, authenv["transport"],
                chunk_size=RECOMMENDED_CHUNK_SIZE,
                scratch_directory=authenv["tmp"] / "scratch")
            result = asyncio.run(engine.put_file(bucket, key, Path(staged)))
            catalog.publish(result.id, now=int(time.time()))
        finally:
            os.unlink(staged)
    finally:
        db.close()


def test_admin_download_object_streams_bytes(authenv):
    client = authenv["client"]
    _publish_object(authenv, "dl-bucket", "reports/file.bin", b"hello-download")
    admin = _bearer(client, "admin", "admin-password-1")
    viewer = _bearer(client, "viewuser", "viewer-password-1")

    r = client.get("/api/v1/admin/storage/buckets/dl-bucket/content",
                   headers=admin,
                   params={"key": "reports/file.bin"})
    assert r.status_code == 200, r.text
    assert r.content == b"hello-download"
    assert r.headers["content-disposition"] == 'attachment; filename="file.bin"'
    assert r.headers["content-length"] == str(len(b"hello-download"))

    # Range requests are honored.
    r = client.get("/api/v1/admin/storage/buckets/dl-bucket/content",
                   headers={**admin, "range": "bytes=0-4"},
                   params={"key": "reports/file.bin"})
    assert r.status_code == 206
    assert r.content == b"hello"

    # Read-only roles may download; unauthenticated may not.
    r = client.get("/api/v1/admin/storage/buckets/dl-bucket/content",
                   headers=viewer, params={"key": "reports/file.bin"})
    assert r.status_code == 200
    client.cookies.clear()
    r = client.get("/api/v1/admin/storage/buckets/dl-bucket/content",
                   params={"key": "reports/file.bin"})
    assert r.status_code == 401

    # Missing bucket / object / traversal-safe filename.
    r = client.get("/api/v1/admin/storage/buckets/nope/content",
                   headers=admin, params={"key": "x"})
    assert r.status_code == 404
    r = client.get("/api/v1/admin/storage/buckets/dl-bucket/content",
                   headers=admin, params={"key": "missing.bin"})
    assert r.status_code == 404
    _publish_object(authenv, "dl-bucket", "weird\"name;.bin", b"x")
    r = client.get("/api/v1/admin/storage/buckets/dl-bucket/content",
                   headers=admin, params={"key": "weird\"name;.bin"})
    assert r.status_code == 200
    suggested = r.headers["content-disposition"].split('filename="')[1].rstrip('"')
    assert '"' not in suggested and ";" not in suggested


# ---------------------------------------------------------------- file manager

def _admin_bucket(client, auth, name):
    r = client.post("/api/v1/admin/storage/buckets", headers={**auth, **CSRF},
                    json={"name": name})
    assert r.status_code == 201, r.text


def test_admin_bucket_create_delete(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    _admin_bucket(client, admin, "bucket-tidy")
    # Duplicate is a conflict.
    r = client.post("/api/v1/admin/storage/buckets", headers={**admin, **CSRF},
                    json={"name": "bucket-tidy"})
    assert r.status_code == 409
    # Viewers may not create or delete buckets.
    assert client.post("/api/v1/admin/storage/buckets",
                       headers={**viewer, **CSRF},
                       json={"name": "nope"}).status_code == 403
    assert client.delete("/api/v1/admin/storage/buckets/bucket-tidy",
                         headers={**viewer, **CSRF}).status_code == 403
    # Empty bucket deletion works; missing bucket is a 404.
    assert client.delete("/api/v1/admin/storage/buckets/bucket-tidy",
                         headers={**admin, **CSRF}).status_code == 200
    assert client.delete("/api/v1/admin/storage/buckets/bucket-tidy",
                         headers={**admin, **CSRF}).status_code == 404


def test_admin_upload_download_round_trip(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    _admin_bucket(client, admin, "upload-bucket")

    r = client.put("/api/v1/admin/storage/buckets/upload-bucket/content",
                   headers={**admin, **CSRF,
                            "content-type": "application/octet-stream"},
                   params={"key": "docs/readme.txt"}, content=b"round-trip-bytes")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["key"] == "docs/readme.txt"

    # Download through the session-authenticated reader.
    r = client.get("/api/v1/admin/storage/buckets/upload-bucket/content",
                   headers=admin, params={"key": "docs/readme.txt"})
    assert r.status_code == 200 and r.content == b"round-trip-bytes"

    # CSRF is required; viewers cannot upload; wrong content-type rejected.
    assert client.put("/api/v1/admin/storage/buckets/upload-bucket/content",
                      headers={**admin, "content-type": "application/octet-stream"},
                      params={"key": "x"}, content=b"y").status_code == 403
    assert client.put("/api/v1/admin/storage/buckets/upload-bucket/content",
                      headers={**viewer, **CSRF,
                               "content-type": "application/octet-stream"},
                      params={"key": "x"}, content=b"y").status_code == 403
    assert client.put("/api/v1/admin/storage/buckets/upload-bucket/content",
                      headers={**admin, **CSRF, "content-type": "text/plain"},
                      params={"key": "x"}, content=b"y").status_code == 415

    # Quota enforcement on the session upload path.
    r = client.put("/api/v1/admin/storage/buckets/upload-bucket/quota",
                   headers={**admin, **CSRF},
                   json={"max_size_bytes": 4, "max_objects": None})
    assert r.status_code == 200
    r = client.put("/api/v1/admin/storage/buckets/upload-bucket/content",
                   headers={**admin, **CSRF,
                            "content-type": "application/octet-stream"},
                   params={"key": "big.bin"}, content=b"too-many-bytes")
    assert r.status_code == 413


def test_admin_copy_object_and_search(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    _admin_bucket(client, admin, "copy-bucket")
    _publish_object(authenv, "copy-bucket", "reports/Annual Summary.txt", b"data")
    _publish_object(authenv, "copy-bucket", "notes.txt", b"notes")

    # Rename-style copy within the bucket.
    r = client.post("/api/v1/admin/storage/buckets/copy-bucket/objects/copy",
                    headers={**admin, **CSRF},
                    params={"key": "reports/Annual Summary.txt"},
                    json={"destination_key": "reports/Annual_Summary_v2.txt"})
    assert r.status_code == 200, r.text
    # Original still exists.
    assert client.get("/api/v1/admin/storage/buckets/copy-bucket/content",
                      headers=admin,
                      params={"key": "reports/Annual Summary.txt"}
                      ).status_code == 200

    # Destination equals source is rejected.
    r = client.post("/api/v1/admin/storage/buckets/copy-bucket/objects/copy",
                    headers={**admin, **CSRF}, params={"key": "notes.txt"},
                    json={"destination_key": "notes.txt"})
    assert r.status_code == 400
    # Missing source is a 404.
    r = client.post("/api/v1/admin/storage/buckets/copy-bucket/objects/copy",
                    headers={**admin, **CSRF}, params={"key": "ghost.txt"},
                    json={"destination_key": "any.txt"})
    assert r.status_code == 404

    # Search: case-insensitive match across the catalog.
    r = client.get("/api/v1/admin/storage/search", headers=admin,
                   params={"q": "annual"})
    assert r.status_code == 200
    keys = {o["key"] for o in r.json()["objects"]}
    assert "reports/Annual Summary.txt" in keys
    assert "reports/Annual_Summary_v2.txt" in keys
    # LIKE wildcards are escaped: '%' and '_' never broaden the query.
    r = client.get("/api/v1/admin/storage/search", headers=admin,
                   params={"q": "%"})
    assert r.status_code == 200 and r.json()["objects"] == []
    r = client.get("/api/v1/admin/storage/search", headers=admin,
                   params={"q": "notes.tx_"})
    assert r.status_code == 200 and r.json()["objects"] == []


def test_folder_watch_scan_enqueues_new_files(authenv, monkeypatch):
    root = authenv["tmp"] / "uploads"
    root.mkdir(exist_ok=True)
    monkeypatch.setattr(web, "JOB_SOURCE_ROOT", str(root))
    monkeypatch.setattr(web, "WATCH_BUCKET", "watch-bucket")
    monkeypatch.setattr(web, "WATCH_ENABLED", True)
    # Point the parsed config's upload.source_dir at the test root.
    config_path = authenv["tmp"] / "config.yaml"
    config_path.write_text(
        config_path.read_text(encoding="ascii")
        + "upload:\n  source_dir: " + str(root) + "\n",
        encoding="ascii")

    db = authenv["connect"]()
    try:
        from teledrive.storage.catalog import BucketCatalog
        from teledrive.storage.manifest import ManifestStore
        from teledrive.storage.jobs import StorageUploadJobs
        catalog = BucketCatalog(ManifestStore(db))
        catalog.create_bucket("watch-bucket", int(time.time()))
    finally:
        db.close()

    (root / "watched-file.bin").write_bytes(b"watched")
    report = web.folder_watch_scan()
    assert report["queued"] == 1

    db = authenv["connect"]()
    try:
        jobs = StorageUploadJobs(
            BucketCatalog(ManifestStore(db))).list_jobs(limit=10)
    finally:
        db.close()
    assert any(j["source_path"].endswith("watched-file.bin") for j in jobs)

    # Idempotent: the same file is never re-queued.
    report2 = web.folder_watch_scan()
    assert report2["queued"] == 0
    assert report2["already_queued"] >= 1


# ---------------------------------------------------------------- floodwait

def test_flood_wait_status_lifecycle(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")

    # No FloodWait recorded yet.
    r = client.get("/api/v1/admin/storage/telegram-session/floodwait",
                   headers=admin)
    assert r.status_code == 200
    assert r.json() == {"active": False, "remaining_seconds": 0, "last": None}

    # Record an active wait; the endpoint reports the live countdown.
    info = web._record_flood_wait("send_code", 3600, "test wait")
    r = client.get("/api/v1/admin/storage/telegram-session/floodwait",
                   headers=admin)
    body = r.json()
    assert body["active"] is True
    assert 3500 < body["remaining_seconds"] <= 3600
    assert body["last"]["scope"] == "send_code"
    assert body["last"]["wait_seconds"] == 3600
    assert body["last"]["detail"] == "test wait"

    # An already-expired wait is inactive but still reported as the last one.
    db = authenv["connect"]()
    try:
        from sqlalchemy import text as _text
        db.connection.execute(_text(
            "UPDATE flood_waits SET expires_at = 1"))
        db.connection.commit()
    finally:
        db.close()
    r = client.get("/api/v1/admin/storage/telegram-session/floodwait",
                   headers=admin)
    body = r.json()
    assert body["active"] is False
    assert body["remaining_seconds"] == 0
    assert body["last"]["scope"] == "send_code"

    # Any authenticated role may read the status.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/v1/admin/storage/telegram-session/floodwait",
                      headers=viewer).status_code == 200


def test_telegram_error_response_maps_and_logs(authenv):
    from telethon.errors import PhoneCodeInvalidError
    from fastapi import HTTPException

    exc = PhoneCodeInvalidError(request=None)
    try:
        raise web._telegram_error_response(exc, "verify-code")
    except HTTPException as e:
        assert e.status_code == 400
        assert "code is invalid" in str(e.detail).lower()
        assert "PhoneCodeInvalidError" in str(e.detail)

    # The failure reason must land in the log buffer (visible on the logs
    # page right next to the -> 400 http line).
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    r = client.get("/api/v1/logs?limit=50", headers=admin)
    joined = " ".join(e.get("message", "") for e in r.json()["entries"])
    assert "verify-code FAILED: PhoneCodeInvalidError" in joined

    # Unknown errors fall back to the scrubbed text and are still logged.
    try:
        raise web._telegram_error_response(RuntimeError("boom http://x:secret@h/"), "request-code")
    except HTTPException as e:
        assert "RuntimeError" in str(e.detail)
        assert "secret" not in str(e.detail)


def test_pending_session_string_migration_and_legacy_row(authenv):
    """The login-flow fix: pending rows must carry the requesting session.

    1) Old rows without session_string get a clean 410 instead of a
       doomed Telethon round-trip.
    2) The engine build adds the column to databases created before it
       existed (dialect-aware ALTER).
    """
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    db = authenv["connect"]()
    now = int(time.time())
    try:
        from sqlalchemy import text as _text
        db.connection.execute(_text(
            "INSERT INTO telegram_session_pending (token, api_id, api_hash, "
            "phone, phone_code_hash, session_string, channel, strategy, "
            "created_at) VALUES (:t, 1, 'h', '+900', 'pch', NULL, NULL, "
            "'round_robin', :now)"), {"t": "legacy-token", "now": now})
        db.connection.commit()
    finally:
        db.close()

    r = client.post("/api/v1/admin/storage/telegram-session/verify-code",
                    headers={**admin, **CSRF},
                    json={"token": "legacy-token", "code": "12345"})
    assert r.status_code == 410
    assert "predates" in r.json()["detail"]

    # The legacy token was consumed, not left to age out.
    db = authenv["connect"]()
    try:
        from sqlalchemy import text as _text
        left = db.connection.execute(_text(
            "SELECT COUNT(*) FROM telegram_session_pending "
            "WHERE token = 'legacy-token'")).fetchone()[0]
    finally:
        db.close()
    assert left == 0

    # Dialect-aware migration: an old-schema database gains the column.
    import sqlalchemy as sa
    import teledrive.db as tdb
    with sa.create_engine(
            f"sqlite:////tmp/opencode/old_schema_test.db").connect() as oc:
        oc.exec_driver_sql(
            "CREATE TABLE telegram_session_pending (token VARCHAR(64) "
            "PRIMARY KEY, api_id BIGINT NOT NULL, api_hash VARCHAR(128) "
            "NOT NULL, phone VARCHAR(64) NOT NULL, phone_code_hash "
            "VARCHAR(255), channel VARCHAR(255), strategy VARCHAR(32) "
            "DEFAULT 'round_robin', created_at BIGINT NOT NULL)")
        oc.commit()
    eng = tdb._build_engine("sqlite:////tmp/opencode/old_schema_test.db")
    cols = {c["name"] for c in sa.inspect(eng).get_columns(
        "telegram_session_pending")}
    eng.dispose()
    assert "session_string" in cols
