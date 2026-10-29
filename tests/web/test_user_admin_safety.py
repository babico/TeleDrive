"""Account-privilege safety, found by the third API-review wave.

The critical one: ``user_sessions`` has no foreign key to ``users`` and an
Integer primary key reuses rowids on SQLite, so deleting a user left their
session behind and a later account could inherit it. The review proved a
deleted viewer's token authenticating as a freshly created ADMIN.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
from teledrive.db import connect_database


@pytest.fixture()
def api(tmp_path, monkeypatch):
    path = tmp_path / "users.sqlite"
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(path)))
    webapp.AUTH_FAILURES.clear()
    webapp._create_default_admin()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    yield client, path
    client.close()


def _login(client, username, password):
    """Log in and return a BEARER header, leaving the cookie jar untouched.

    The cookie jar is shared by the whole TestClient, so a second login would
    silently replace the admin session every later request uses.
    """
    reply = client.post("/api/v1/auth/login",
                        headers={"x-teledrive-csrf": "1"},
                        json={"username": username, "password": password})
    assert reply.status_code == 200, reply.text
    client.cookies.clear()
    return {"x-teledrive-csrf": "1",
            "Authorization": f"Bearer {reply.json()['token']}"}


def _admin(client):
    return _login(client, "admin", "admin")


def test_deleted_users_session_never_authenticates_as_a_recreated_user(api):
    client, path = api
    admin = _admin(client)

    victim = client.post("/api/v1/admin/users", headers=admin,
                         json={"username": "victim", "password": "victim-pass-1",
                               "role": "viewer"})
    assert victim.status_code == 201, victim.text
    victim_id = victim.json()["id"]
    stale = _login(client, "victim", "victim-pass-1")
    assert client.get("/api/auth/me", headers=stale).status_code == 200

    assert client.delete(f"/api/v1/admin/users/{victim_id}",
                         headers=admin).status_code == 200

    # A NEW account, deliberately an admin, may reuse the integer id.
    created = client.post("/api/v1/admin/users", headers=admin,
                          json={"username": "newadmin",
                                "password": "new-admin-pass-1",
                                "role": "admin"})
    assert created.status_code == 201, created.text

    # The old token must be dead, not reborn as the new account.
    assert client.get("/api/auth/me", headers=stale).status_code == 401
    assert client.get("/api/v1/admin/keys", headers=stale).status_code == 401

    db = connect_database(str(path))
    try:
        from sqlalchemy import text
        leftovers = db.connection.execute(text(
            "SELECT COUNT(*) FROM user_sessions WHERE user_id = :i"),
            {"i": victim_id}).scalar_one()
        assert leftovers == 0, "a session outlived the account it belonged to"
    finally:
        db.close()


def test_the_last_enabled_admin_cannot_be_disabled(api):
    """Disabling the last admin locks everyone out with no recovery path."""
    client, _ = api
    admin = _admin(client)

    # Disabling ourselves is the last-admin case.
    reply = client.put("/api/v1/admin/users/1", headers=admin,
                       json={"enabled": False})
    assert reply.status_code == 409, reply.text
    assert "last admin" in reply.text

    # With a second enabled admin it becomes allowed.
    second = client.post("/api/v1/admin/users", headers=admin,
                         json={"username": "second", "password": "second-pass-1",
                               "role": "admin"})
    assert second.status_code == 201, second.text
    assert client.put("/api/v1/admin/users/1", headers=admin,
                      json={"enabled": False}).status_code == 200


def test_the_bootstrap_admin_cannot_be_renamed(api):
    """Renaming admin re-seeds admin/admin on the next restart."""
    client, _ = api
    admin = _admin(client)
    reply = client.put("/api/v1/admin/users/1", headers=admin,
                       json={"username": "root"})
    assert reply.status_code == 400, reply.text
    assert "bootstrap" in reply.text


@pytest.mark.parametrize("bad", [
    "a" * 65,
    "admin\n[2026-01-01 00:00:00] [system] [users] forged",
    "admin ",
    " аdmin",
    "Admin",
    "",
])
def test_username_validation_rejects_hostile_names(api, bad):
    """Usernames are login identifiers AND log fields."""
    client, _ = api
    admin = _admin(client)
    reply = client.post("/api/v1/admin/users", headers=admin,
                        json={"username": bad, "password": "password-1234",
                              "role": "viewer"})
    assert reply.status_code in (400, 422), reply.text
