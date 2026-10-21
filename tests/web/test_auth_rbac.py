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
    return {"client": client, "connect": connect}


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
