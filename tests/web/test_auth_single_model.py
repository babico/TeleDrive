"""One permission model for sessions and roles (review P5/P6).

HTTP Basic is gone: only the login form (session cookie) and API keys
authenticate. The first-boot admin is hardcoded as admin/admin and is
never configurable or overwritten. Session users are the subjects of the
role->permission map; API keys keep their per-route scopes.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import web.app as web
from teledrive.db import connect_database
from tests import basic_header, login_headers, seed_local_user
from web.permissions import PermissionRegistry

CSRF = {"X-TeleDrive-CSRF": "1"}
ADMIN_PASSWORD = "admin-password-1"
OPERATOR_PASSWORD = "operator-password-1"
VIEWER_PASSWORD = "viewer-password-1"
DISABLED_PASSWORD = "disabled-password-1"


@pytest.fixture()
def appenv(tmp_path, monkeypatch):
    """Isolated SQLite app with one local user per role, no lifespan."""
    path = tmp_path / "single-model.sqlite"
    connect = lambda: connect_database(str(path))
    monkeypatch.setattr(web, "db_connect", connect)
    monkeypatch.setattr(web, "AUTH_DIR", tmp_path / "auth")
    web.AUTH_FAILURES.clear()
    seed_local_user(connect, "admin", ADMIN_PASSWORD, "admin")
    seed_local_user(connect, "opuser", OPERATOR_PASSWORD, "operator")
    seed_local_user(connect, "viewuser", VIEWER_PASSWORD, "viewer")
    seed_local_user(connect, "disableduser", DISABLED_PASSWORD, "viewer",
                    enabled=False)
    client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        yield {"client": client, "connect": connect}
    finally:
        client.close()


def _admin_rows(connect):
    import sqlalchemy
    db = connect()
    try:
        return db.connection.execute(sqlalchemy.text(
            "SELECT username, password_hash, role, enabled FROM users "
            "WHERE username = 'admin'")).fetchall()
    finally:
        db.close()


# --------------------------------------------------------------- bootstrap

def test_first_boot_creates_admin_admin_and_the_login_form_accepts_it(
        tmp_path, monkeypatch):
    path = tmp_path / "bootstrap.sqlite"
    connect = lambda: connect_database(str(path))
    monkeypatch.setattr(web, "db_connect", connect)
    web.AUTH_FAILURES.clear()

    web._create_default_admin()

    rows = _admin_rows(connect)
    assert len(rows) == 1
    username, password_hash, role, enabled = rows[0]
    assert (username, role, enabled) == ("admin", "admin", 1)
    assert web._verify_password("admin", password_hash)

    client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        headers = login_headers(client, "admin", "admin")
        assert client.get("/api/v1/admin/users",
                          headers=headers).status_code == 200
    finally:
        client.close()


def test_restart_does_not_reset_a_changed_admin_password(
        tmp_path, monkeypatch):
    path = tmp_path / "restart.sqlite"
    connect = lambda: connect_database(str(path))
    monkeypatch.setattr(web, "db_connect", connect)
    web.AUTH_FAILURES.clear()

    web._create_default_admin()
    import sqlalchemy
    db = connect()
    try:
        db.connection.execute(sqlalchemy.text(
            "UPDATE users SET password_hash = :ph WHERE username = 'admin'"
        ), {"ph": web._hash_password("changed-admin-password")})
        db.connection.commit()
    finally:
        db.close()

    # Two more "starts" must leave the changed hash exactly as it was.
    before = _admin_rows(connect)[0]
    web._create_default_admin()
    web._create_default_admin()
    assert _admin_rows(connect)[0] == before
    assert web._verify_password("changed-admin-password", before[1])
    assert not web._verify_password("admin", before[1])

    client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        headers = login_headers(client, "admin", "changed-admin-password")
        assert client.get("/api/v1/admin/users",
                          headers=headers).status_code == 200
        # The old default password is no longer a credential either.
        assert client.post("/api/v1/auth/login", headers=CSRF,
                           json={"username": "admin", "password": "admin"}
                           ).status_code == 401
    finally:
        client.close()


def test_preexisting_admin_row_keeps_custom_hash_role_and_enabled(
        tmp_path, monkeypatch):
    path = tmp_path / "existing.sqlite"
    connect = lambda: connect_database(str(path))
    monkeypatch.setattr(web, "db_connect", connect)
    web.AUTH_FAILURES.clear()
    seed_local_user(connect, "admin", "custom-password", "viewer",
                    enabled=False)
    before = _admin_rows(connect)[0]

    web._create_default_admin()

    after = _admin_rows(connect)[0]
    assert after == before          # hash, role and enabled untouched
    assert after[2] == "viewer"
    assert after[3] == 0


def test_bootstrap_adds_admin_when_only_other_users_exist(
        tmp_path, monkeypatch):
    """A database without an ``admin`` row still gets the recovery account."""
    path = tmp_path / "no-admin.sqlite"
    connect = lambda: connect_database(str(path))
    monkeypatch.setattr(web, "db_connect", connect)
    seed_local_user(connect, "someone", "someone-password", "operator")

    web._create_default_admin()

    rows = _admin_rows(connect)
    assert len(rows) == 1 and rows[0][0] == "admin"
    assert web._verify_password("admin", rows[0][1])


# ------------------------------------------------------- Basic is not a thing

def test_basic_header_is_rejected_exactly_like_no_credential(appenv):
    client = appenv["client"]
    valid = basic_header("admin", ADMIN_PASSWORD)

    # A valid local username/password over Basic is still anonymous.
    with_basic = client.get("/api/v1/admin/users", headers=valid)
    without = client.get("/api/v1/admin/users")
    assert with_basic.status_code == without.status_code == 401
    assert with_basic.json() == without.json()

    # The same applies to a normal read route and to bad credentials.
    assert client.get("/api/v1/admin/storage/buckets",
                      headers=valid).status_code == 401
    assert client.get("/api/v1/admin/storage/buckets",
                      headers=basic_header("admin", "wrong")).status_code == 401


def test_extract_user_ignores_basic_and_reports_anonymous(appenv):
    from starlette.requests import Request

    def build(header: str) -> Request:
        return Request({"type": "http", "method": "GET", "path": "/api/v1/x",
                        "headers": [(b"authorization", header.encode()),
                                    (b"host", b"localhost")],
                        "query_string": b"", "server": ("127.0.0.1", 80),
                        "scheme": "http", "client": ("127.0.0.1", 1)})

    header = basic_header("admin", ADMIN_PASSWORD)["Authorization"]
    assert web._extract_user(build(header)) == "anonymous"
    assert web._extract_user(build("Basic not-even-base64")) == "anonymous"


def test_no_code_path_reads_web_password_as_an_authenticator():
    roots = [Path("web"), Path("teledrive")]
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for root in roots for path in root.rglob("*.py"))
    assert "WEB_PASSWORD" not in sources
    assert "TELEDRIVE_WEB_PASSWORD" not in sources
    assert "Authorization: Basic" not in sources
    assert "_verify_basic_credentials" not in sources
    assert "unverified-basic" not in sources


# ------------------------------------------------------ sessions use the map

def test_viewer_session_cannot_reach_admin_only_get(appenv):
    client = appenv["client"]
    viewer = login_headers(client, "viewuser", VIEWER_PASSWORD)
    assert client.get("/api/v1/admin/users", headers=viewer).status_code == 403
    # Previously this GET slipped past the role gate.
    assert client.get("/api/v1/admin/storage/buckets/any/quota",
                      headers=viewer).status_code == 403
    assert client.get("/api/v1/admin/keys",
                      headers=viewer).status_code == 403
    assert client.get("/api/v1/admin/storage/buckets",
                      headers=viewer).status_code == 200


def test_operator_can_write_storage_but_not_users_or_keys(appenv):
    client = appenv["client"]
    operator = login_headers(client, "opuser", OPERATOR_PASSWORD)
    created = client.post("/api/v1/admin/storage/buckets",
                          headers={**operator, **CSRF},
                          json={"name": "operator-bucket"})
    assert created.status_code == 201, created.text
    assert client.get("/api/v1/admin/users",
                      headers=operator).status_code == 403
    assert client.post("/api/v1/admin/users", headers={**operator, **CSRF},
                       json={"username": "new", "password": "password-123",
                             "role": "viewer"}).status_code == 403
    assert client.get("/api/v1/admin/keys",
                      headers=operator).status_code == 403
    assert client.post("/api/v1/admin/s3/credentials",
                       headers={**operator, **CSRF},
                       json={"name": "nope",
                             "permissions": ["s3:GetObject"]}).status_code == 403


def test_api_keys_keep_their_own_route_scopes(appenv):
    client = appenv["client"]
    session = login_headers(client, "admin", ADMIN_PASSWORD)
    issued = client.post("/api/v1/admin/keys",
                         headers={**session, **CSRF},
                         json={"name": "map-check",
                               "scopes": ["get:/api/v1/admin/users"]})
    assert issued.status_code == 201, issued.text
    key = {"Authorization": "Bearer " + issued.json()["token"]}
    # A key is not a role: the granted route works, an ungranted one does not.
    assert client.get("/api/v1/admin/users", headers=key).status_code == 200
    assert client.get("/api/v1/admin/storage/buckets",
                      headers=key).status_code == 403


# --------------------------------------------------------------- role/permission map

def test_role_permission_map_covers_every_registry_permission():
    registry = PermissionRegistry(web.app.routes)
    catalog = {entry["name"] for entry in registry.catalog()}
    admin = registry.permissions_for_role("admin")
    operator = registry.permissions_for_role("operator")
    viewer = registry.permissions_for_role("viewer")

    assert admin == catalog
    assert admin > operator > viewer
    assert viewer, "viewer must keep read access"
    assert operator, "operator must keep storage access"

    # No admin-only route leaks into a lower role.
    for permission, (method, template) in registry._by_permission.items():
        if template.startswith(("/api/v1/admin/users",
                                "/api/v1/admin/keys",
                                "/api/v1/admin/s3/credentials",
                                "/api/v1/admin/s3-credentials",
                                "/api/v1/admin/storage/gc")):
            assert permission not in operator
            assert permission not in viewer
        if (template.startswith("/api/v1/admin/storage/buckets")
                and (template.endswith("/quota")
                     or template.endswith("/website"))):
            assert permission not in operator
            assert permission not in viewer

    # Read-only means GET/HEAD or the curated read names.
    for permission in viewer:
        assert (permission.startswith(("get:", "head:"))
                or permission.startswith("rest:")
                and permission.split(":")[-1] in {
                    "list", "list-versions", "get", "head"})
