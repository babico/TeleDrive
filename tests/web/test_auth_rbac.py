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

@pytest.mark.parametrize("page", ["/", "/dashboard", "/users", "/logs",
                                  "/queue", "/history", "/api-management",
                                  "/settings/general", "/settings/telegram",
                                  "/s3/credentials", "/s3/buckets"])
def test_pages_redirect_to_login_when_unauthenticated(authenv, page):
    r = authenv["client"].get(page, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].endswith("/login")


@pytest.mark.parametrize("legacy,new", [("/settings", "/settings/general"),
                                        ("/storage", "/settings/telegram"),
                                        ("/s3", "/s3/buckets")])
def test_legacy_page_paths_redirect(authenv, legacy, new):
    client = authenv["client"]
    r = client.get(legacy, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == new
    # Unauthenticated visitors ultimately land on /login.
    r = client.get(legacy, follow_redirects=True)
    assert r.url.path.endswith("/login")


def test_nested_pages_served_when_authenticated(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    for path, marker in [("/settings/general", "Source directory"),
                         ("/settings/telegram", "Telegram session"),
                         ("/s3/credentials", "S3-compatible gateway"),
                         ("/s3/buckets", "Bucket browser")]:
        r = client.get(path, headers=admin)
        assert r.status_code == 200, (path, r.status_code)
        assert marker in r.text, (path, marker)


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


def test_physical_gc_is_admin_only(authenv):
    """Irreversible Telegram media deletion is an owner decision.

    The GC toggle and the collect trigger must not be reachable by an
    operator — the documents call this an owner gate, so the role policy
    has to match: operator 403, admin allowed.
    """
    client = authenv["client"]
    op = _bearer(client, "opuser", "operator-password-1")
    admin = _bearer(client, "admin", "admin-password-1")
    assert client.put("/api/v1/admin/storage/gc", headers={**op, **CSRF},
                      json={"enabled": False}).status_code == 403
    assert client.post("/api/v1/admin/storage/gc/collect",
                       headers={**op, **CSRF},
                       json={"scope": "retained", "confirm": "PHYSICAL-GC"}
                       ).status_code == 403
    # Admin passes the role gate (the request may still fail on its own
    # preconditions, but never with 403 from the role policy).
    assert client.put("/api/v1/admin/storage/gc", headers={**admin, **CSRF},
                      json={"enabled": False}).status_code != 403


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


def test_config_never_exposes_or_keeps_retired_auth_keys(authenv):
    client = authenv["client"]
    auth = _bearer(client, "admin", "admin-password-1")
    r = client.get("/api/config", headers=auth)
    assert r.status_code == 200
    # The upgrade-era password is neither exposed nor kept as a setting.
    assert "password" not in r.json()["web"]
    assert "user" not in r.json()["web"]


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


def test_pending_session_string_migration_and_legacy_row(authenv, tmp_path):
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
    db_file = tmp_path / "old_schema.db"
    url = f"sqlite:///{db_file}"
    eng0 = sa.create_engine(url)
    with eng0.connect() as oc:
        oc.exec_driver_sql(
            "CREATE TABLE telegram_session_pending (token VARCHAR(64) "
            "PRIMARY KEY, api_id BIGINT NOT NULL, api_hash VARCHAR(128) "
            "NOT NULL, phone VARCHAR(64) NOT NULL, phone_code_hash "
            "VARCHAR(255), channel VARCHAR(255), strategy VARCHAR(32) "
            "DEFAULT 'round_robin', created_at BIGINT NOT NULL)")
        oc.commit()
    eng0.dispose()
    eng = tdb._build_engine(url)
    cols = {c["name"] for c in sa.inspect(eng).get_columns(
        "telegram_session_pending")}
    eng.dispose()
    assert "session_string" in cols


# ------------------------------------------------- multi-account sessions

def _insert_session(db, account, phone="+905551112233"):
    from sqlalchemy import text as _text
    db.connection.execute(_text(
        "INSERT INTO telegram_sessions (api_id, api_hash, phone, "
        "session_string, account, channel, strategy, created_at, updated_at) "
        "VALUES (1, 'h', :phone, 'sess', :account, NULL, 'round_robin', "
        ":now, :now)"),
        {"phone": phone, "account": account, "now": int(time.time())})
    db.connection.commit()


def test_telegram_sessions_list_and_delete(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    db = authenv["connect"]()
    try:
        _insert_session(db, "user-1001")
        _insert_session(db, "user-2002", "+905559998877")
    finally:
        db.close()

    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    accounts = {s["account"] for s in body["sessions"]}
    assert accounts == {"user-1001", "user-2002"}
    for s in body["sessions"]:
        assert s["phone"].startswith("+905***") or "***" in s["phone"]
        assert "session_string" not in s and "api_hash" not in s
        assert s["objects"] == 0 and s["bytes"] == 0
        assert s["cooldown_remaining_s"] == 0

    # Viewer may read but not delete.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/v1/admin/storage/telegram-sessions",
                      headers=viewer).status_code == 200
    assert client.delete("/api/v1/admin/storage/telegram-sessions/user-1001",
                         headers={**viewer, **CSRF}).status_code == 403

    # Delete one account; the other survives.
    r = client.delete("/api/v1/admin/storage/telegram-sessions/user-1001",
                      headers={**admin, **CSRF})
    assert r.status_code == 200 and r.json()["deleted"] == 1
    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    assert {s["account"] for s in r.json()["sessions"]} == {"user-2002"}


def test_telegram_session_delete_soft_guard(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    db = authenv["connect"]()
    try:
        _insert_session(db, "user-3003")
        from sqlalchemy import text as _text
        db.connection.execute(_text(
            "INSERT INTO storage_chunks (object_id, ordinal, offset, size, "
            "sha256, account, chat_id, message_id) VALUES "
            "('obj-1',0,0,100,'h1','user-3003',1,1),"
            "('obj-1',1,100,200,'h2','user-3003',1,2)"))
        db.connection.commit()
    finally:
        db.close()

    # Soft-guard: 409 with usage details while chunks reference the account.
    r = client.delete("/api/v1/admin/storage/telegram-sessions/user-3003",
                      headers={**admin, **CSRF})
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["objects"] == 1 and detail["bytes"] == 300
    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    assert {s["account"] for s in r.json()["sessions"]} == {"user-3003"}

    # force=true deletes anyway.
    r = client.delete(
        "/api/v1/admin/storage/telegram-sessions/user-3003?force=true",
        headers={**admin, **CSRF})
    assert r.status_code == 200
    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    assert r.json()["sessions"] == []


def test_telegram_session_health_check(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    db = authenv["connect"]()
    try:
        _insert_session(db, "user-4004")
    finally:
        db.close()

    # Unknown account.
    r = client.post(
        "/api/v1/admin/storage/telegram-sessions/nobody/health-check",
        headers={**admin, **CSRF})
    assert r.status_code == 404

    # A garbage session string fails the probe locally (StringSession
    # raises before any network traffic) and marks the account dead.
    r = client.post(
        "/api/v1/admin/storage/telegram-sessions/user-4004/health-check",
        headers={**admin, **CSRF})
    assert r.status_code == 200
    body = r.json()
    assert body["authorized"] is False
    assert body["health_checked_at"] > 0

    # The verdict and timestamp persist into the sessions list.
    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    entry = next(s for s in r.json()["sessions"] if s["account"] == "user-4004")
    assert entry["authorized"] is False
    assert entry["health_checked_at"] > 0

    # Viewer may read the list but cannot trigger a probe.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.post(
        "/api/v1/admin/storage/telegram-sessions/user-4004/health-check",
        headers={**viewer, **CSRF}).status_code == 403

    # The unauthorized verdict lands in the log buffer.
    r = client.get("/api/v1/logs?limit=50", headers=admin)
    joined = " ".join(e.get("message", "") for e in r.json()["entries"])
    assert "user-4004 UNAUTHORIZED" in joined


def test_prometheus_metrics(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")

    # The schema coordinator creates storage_upload_jobs on connect; seed it
    # with the real column set instead of a pre-schema copy.
    db = authenv["connect"]()
    try:
        from sqlalchemy import text as _text
        now = int(time.time())
        db.connection.execute(_text(
            "INSERT INTO storage_upload_jobs (id, bucket, object_key, "
            "source_path, source_size, source_device, source_inode, "
            "source_mtime_ns, expected_generation, state, attempts, "
            "created_at, updated_at) VALUES "
            "('j1','b','k','p',1,0,0,0,1,'queued',0,:now,:now),"
            "('j2','b','k2','p2',1,0,0,0,1,'queued',0,:now,:now),"
            "('j3','b','k3','p3',1,0,0,0,1,'failed',0,:now,:now)"),
            {"now": now})
        db.connection.commit()
    finally:
        db.close()

    r = client.get("/api/v1/metrics", headers=admin)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert "teledrive_up 1" in body
    assert "# TYPE teledrive_storage_jobs gauge" in body
    assert 'teledrive_storage_jobs{state="queued"} 2' in body
    assert 'teledrive_storage_jobs{state="failed"} 1' in body

    # Anonymous access is rejected (fail-closed); drop the login
    # cookie the bearer helper left on this client first.
    client.cookies.clear()
    assert client.get("/api/v1/metrics").status_code == 401

    # Viewer role may scrape.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/v1/metrics", headers=viewer).status_code == 200

    # Sessions appear with their health verdict; label values are escaped.
    db = authenv["connect"]()
    try:
        _insert_session(db, 'weird"account')
        from sqlalchemy import text as _text
        db.connection.execute(_text(
            "UPDATE telegram_sessions SET authorized = 1 "
            "WHERE account = 'weird\"account'"))
        db.connection.commit()
    finally:
        db.close()
    body = client.get("/api/v1/metrics", headers=admin).text
    assert 'teledrive_telegram_session_authorized{account="weird\\"account"}' in body


def test_storage_strategy_endpoint(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")

    # The sessions list reports the active cross-account strategy.
    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    assert r.status_code == 200
    assert r.json()["strategy"] in ("single", "round_robin", "failover",
                                    "parallel")

    # Operator/admin may set it; the change persists in the config.
    r = client.put("/api/v1/admin/storage/strategy",
                   headers={**admin, **CSRF},
                   json={"strategy": "failover"})
    assert r.status_code == 200 and r.json()["strategy"] == "failover"
    cfg = client.get("/api/v1/config", headers=admin).json()
    assert cfg["storage"]["strategy"] == "failover"
    r = client.get("/api/v1/admin/storage/telegram-sessions", headers=admin)
    assert r.json()["strategy"] == "failover"

    # Invalid values and viewer role are rejected.
    assert client.put("/api/v1/admin/storage/strategy",
                      headers={**admin, **CSRF},
                      json={"strategy": "wild"}).status_code == 400
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.put("/api/v1/admin/storage/strategy",
                      headers={**viewer, **CSRF},
                      json={"strategy": "parallel"}).status_code == 403

    # Restore the default for other tests.
    assert client.put("/api/v1/admin/storage/strategy",
                      headers={**admin, **CSRF},
                      json={"strategy": "round_robin"}).status_code == 200


def test_bucket_cors_management(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    csrf = {"X-TeleDrive-CSRF": "1"}

    r = client.post("/api/v1/admin/storage/buckets", headers={**admin, **CSRF},
                    json={"name": "cors-bucket"})
    assert r.status_code in (200, 201), r.text

    # Empty by default.
    r = client.get("/api/v1/admin/storage/buckets/cors-bucket/cors",
                   headers=admin)
    assert r.status_code == 200 and r.json() == {"rules": []}

    # Replace with one rule.
    r = client.put("/api/v1/admin/storage/buckets/cors-bucket/cors",
                   headers={**admin, **CSRF},
                   json={"rules": [{"origins": ["https://example.com"],
                                    "methods": ["GET", "HEAD"],
                                    "allowed_headers": ["*"],
                                    "max_age": 3600}]})
    assert r.status_code == 200, r.text
    r = client.get("/api/v1/admin/storage/buckets/cors-bucket/cors",
                   headers=admin)
    rules = r.json()["rules"]
    assert rules[0]["origins"] == ["https://example.com"]
    assert rules[0]["methods"] == ["GET", "HEAD"]
    assert rules[0]["max_age"] == 3600

    # Validation: bad method, bad origin, bad max_age.
    base = "/api/v1/admin/storage/buckets/cors-bucket/cors"
    assert client.put(base, headers={**admin, **CSRF},
                      json={"rules": [{"origins": ["*"], "methods": ["PATCH"]}]}) \
        .status_code == 422
    assert client.put(base, headers={**admin, **CSRF},
                      json={"rules": [{"origins": ["no-scheme"],
                                      "methods": ["GET"]}]}) \
        .status_code == 422
    assert client.put(base, headers={**admin, **CSRF},
                      json={"rules": [{"origins": ["*"], "methods": ["GET"],
                                       "max_age": 99999}]}) \
        .status_code == 422
    # Viewer cannot write.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.put(base, headers={**viewer, **CSRF},
                      json={"rules": []}).status_code == 403


def test_logs_websocket_stream(authenv):
    """Live log stream: cookie-authenticated sockets receive the backlog
    and new entries; unauthenticated ones close with 4401."""
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")

    web.LOG_BUFFER.clear()
    with client.websocket_connect(
            "/api/v1/logs/stream",
            cookies={"teledrive_session": client.cookies.get(
                "teledrive_session", "")}) as ws:
        # A fresh entry must arrive on the stream (bounded drain loop in
        # case anything was logged between clear and connect).
        web._log("ws-probe-message", "test")
        pushed = ""
        for _ in range(50):
            pushed = ws.receive_text()
            if "ws-probe-message" in pushed:
                break
        assert "ws-probe-message" in pushed

    # Unauthenticated handshake: close code 4401 before accept.
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/logs/stream") as ws:
            ws.receive_text()


def test_storage_usage_series(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")

    # Without catalog tables the endpoint degrades to an empty series.
    r = client.get("/api/v1/admin/storage/usage", headers=admin)
    assert r.status_code == 200
    assert r.json()["series"] == []

    # Seed publications on two consecutive days.
    db = authenv["connect"]()
    try:
        from sqlalchemy import text as _text
        now = int(time.time())
        day = 86_400
        db.connection.execute(_text(
            "INSERT INTO storage_objects (id, bucket, object_key, status, "
            "size, sha256, created_at, updated_at) VALUES "
            "('o1','b','k1','ready',100,'x',:n,:n),"
            "('o2','b','k2','ready',50,'x',:n,:n)"), {"n": now})
        db.connection.execute(_text(
            "INSERT INTO storage_published_versions (object_id, bucket, "
            "key_hash, committed_ns) VALUES "
            "('o1','b','h1',:ns1),('o2','b','h2',:ns2)"),
            {"ns1": now * 1_000_000_000,
             "ns2": (now - day) * 1_000_000_000})
        db.connection.commit()
    finally:
        db.close()

    r = client.get("/api/v1/admin/storage/usage?days=7", headers=admin)
    body = r.json()
    assert body["total_objects"] == 2 and body["total_bytes"] == 150
    assert len(body["series"]) == 2
    assert body["series"][0]["bytes"] == 50   # older day first
    assert body["series"][1]["objects"] == 1

    # Viewer may read.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.get("/api/v1/admin/storage/usage",
                      headers=viewer).status_code == 200


def test_account_soft_quota(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    db = authenv["connect"]()
    try:
        _insert_session(db, "quota-user")
    finally:
        db.close()

    # Set, read back through the sessions list.
    r = client.put(
        "/api/v1/admin/storage/telegram-sessions/quota-user/quota",
        headers={**admin, **CSRF}, json={"soft_quota_bytes": 1073741824})
    assert r.status_code == 200
    body = client.get("/api/v1/admin/storage/telegram-sessions",
                      headers=admin).json()
    entry = next(s for s in body["sessions"]
                 if s["account"] == "quota-user")
    assert entry["soft_quota_bytes"] == 1073741824

    # Unlimited via null; validation and 404 paths.
    assert client.put(
        "/api/v1/admin/storage/telegram-sessions/quota-user/quota",
        headers={**admin, **CSRF},
        json={"soft_quota_bytes": None}).status_code == 200
    assert client.put(
        "/api/v1/admin/storage/telegram-sessions/quota-user/quota",
        headers={**admin, **CSRF},
        json={"soft_quota_bytes": "garbage"}).status_code == 422
    assert client.put(
        "/api/v1/admin/storage/telegram-sessions/ghost/quota",
        headers={**admin, **CSRF},
        json={"soft_quota_bytes": 1}).status_code == 404
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.put(
        "/api/v1/admin/storage/telegram-sessions/quota-user/quota",
        headers={**viewer, **CSRF},
        json={"soft_quota_bytes": 1}).status_code == 403


def test_bucket_account_pin_api(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")
    db = authenv["connect"]()
    try:
        _insert_session(db, "pin-target")
    finally:
        db.close()

    r = client.post("/api/v1/admin/storage/buckets", headers={**admin, **CSRF},
                    json={"name": "pinned-bucket"})
    assert r.status_code in (200, 201)

    base = "/api/v1/admin/storage/buckets/pinned-bucket/pin"
    assert client.get(base, headers=admin).json()["account"] is None
    r = client.put(base, headers={**admin, **CSRF},
                   json={"account": "pin-target"})
    assert r.status_code == 200
    assert client.get(base, headers=admin).json()["account"] == "pin-target"

    # Unknown account rejected; empty account rejected; viewer blocked.
    assert client.put(base, headers={**admin, **CSRF},
                      json={"account": "ghost"}).status_code == 404
    assert client.put(base, headers={**admin, **CSRF},
                      json={}).status_code == 422
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.put(base, headers={**viewer, **CSRF},
                      json={"account": "pin-target"}).status_code == 403

    # Delete clears the pin.
    assert client.delete(base, headers={**admin, **CSRF}).status_code == 200
    assert client.get(base, headers=admin).json()["account"] is None


def test_replication_endpoints(authenv):
    client = authenv["client"]
    admin = _bearer(client, "admin", "admin-password-1")

    # Status: disabled by default, zero coverage, no runtime account.
    r = client.get("/api/v1/admin/storage/replication", headers=admin)
    assert r.status_code == 200
    status = r.json()
    assert status["enabled"] is False
    assert status["runtime_account"] is None
    assert status["coverage"]["objects"] == 0

    # Unknown accounts are rejected before any config write.
    assert client.put("/api/v1/admin/storage/replication",
                      headers={**admin, **CSRF},
                      json={"account": "ghost"}).status_code == 404
    # Viewer role is blocked.
    viewer = _bearer(client, "viewuser", "viewer-password-1")
    assert client.put("/api/v1/admin/storage/replication",
                      headers={**viewer, **CSRF},
                      json={"account": "repl-target"}).status_code == 403

    # A real session account is accepted and persists in the config.
    db = authenv["connect"]()
    try:
        _insert_session(db, "repl-target")
    finally:
        db.close()
    r = client.put("/api/v1/admin/storage/replication",
                   headers={**admin, **CSRF},
                   json={"account": "repl-target"})
    assert r.status_code == 200 and r.json()["account"] == "repl-target"
    cfg = client.get("/api/v1/config", headers=admin).json()
    assert cfg["storage"]["replica_account"] == "repl-target"
    status = client.get("/api/v1/admin/storage/replication",
                        headers=admin).json()
    assert status["account"] == "repl-target"

    # Repair with nothing to do reports zero work (and needs no session).
    r = client.post("/api/v1/admin/storage/replication/repair",
                    headers={**admin, **CSRF}, json={"limit": 3})
    assert r.status_code == 200
    assert r.json()["repaired_objects"] == 0

    # Empty account disables replication again.
    assert client.put("/api/v1/admin/storage/replication",
                      headers={**admin, **CSRF},
                      json={"account": ""}).status_code == 200
    status = client.get("/api/v1/admin/storage/replication",
                        headers=admin).json()
    assert status["account"] is None


def test_basic_header_is_ignored_by_the_audit_identity(authenv):
    """A Basic header is no longer a credential claim at all."""
    from starlette.requests import Request

    from tests import basic_header

    def build(header: str) -> Request:
        return Request({"type": "http", "method": "GET", "path": "/api/v1/x",
                        "headers": [(b"authorization", header.encode()),
                                    (b"host", b"localhost")],
                        "query_string": b"", "server": ("127.0.0.1", 80),
                        "scheme": "http", "client": ("127.0.0.1", 1)})

    # Even a valid local username/password over Basic is anonymous.
    header = basic_header("admin", "admin-password-1")["Authorization"]
    assert web._extract_user(build(header)) == "anonymous"

    # A real session still resolves to the username.
    login = _login(authenv["client"], "admin", "admin-password-1")
    assert login.status_code == 200, login.text
    assert web._extract_user(
        build("Bearer " + login.json()["token"])) == "admin"
