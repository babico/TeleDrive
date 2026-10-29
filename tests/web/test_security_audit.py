"""Durable security trail.

The review's open finding: security events existed only in a bounded
in-memory buffer, so nothing could answer "who revealed that secret last
week", and every role could read the buffer.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
from teledrive.db import connect_database
from teledrive.storage import audit


@pytest.fixture()
def api(tmp_path, monkeypatch):
    path = tmp_path / "audit.sqlite"
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(path)))
    webapp.AUTH_FAILURES.clear()
    webapp._create_default_admin()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    yield client, path
    client.close()


def _login(client, username="admin", password="admin"):
    reply = client.post("/api/v1/auth/login",
                        headers={"x-teledrive-csrf": "1"},
                        json={"username": username, "password": password})
    assert reply.status_code == 200, reply.text
    client.cookies.clear()
    return {"x-teledrive-csrf": "1",
            "Authorization": f"Bearer {reply.json()['token']}"}


def test_a_privileged_action_survives_a_restart(api):
    """The event is in the DATABASE, not the buffer."""
    client, path = api
    admin = _login(client)
    created = client.post("/api/v1/admin/users", headers=admin,
                          json={"username": "audited", "password": "audited-pass-1",
                                "role": "viewer"})
    assert created.status_code == 201, created.text

    # A fresh connection with an empty in-process buffer sees the event.
    webapp.LOG_BUFFER.clear()
    db = connect_database(str(path))
    try:
        events = audit.recent(db, action="user.create")
    finally:
        db.close()
    assert len(events) == 1, events
    assert events[0]["actor"] == "admin"
    assert events[0]["target"] == "audited"


def test_the_trail_never_contains_a_secret(api):
    client, path = api
    admin = _login(client)
    db = connect_database(str(path))
    try:
        audit.record(db, action="probe", actor="admin",
                     detail={"token": "td_live_abcdefghijklmnop",
                             "sess": "td_sess_abcdefghijklmnop",
                             "fernet": "gAAAAAB" + "x" * 40,
                             "access": "TD7B67BD1ABE1D21E7768F0A23"})
        row = audit.recent(db, limit=1)[0]
    finally:
        db.close()
    assert "td_live_" not in row["detail"]
    assert "td_sess_" not in row["detail"]
    assert "gAAAA" not in row["detail"]
    assert "TD7B67" not in row["detail"]


def test_only_an_admin_can_read_the_trail(api):
    client, _ = api
    admin = _login(client)
    assert client.post("/api/v1/admin/users", headers=admin,
                       json={"username": "op2", "password": "operator-pass-1",
                             "role": "operator"}).status_code == 201
    operator = _login(client, "op2", "operator-pass-1")
    assert client.get("/api/v1/admin/audit",
                      headers=operator).status_code == 403
    assert client.get("/api/v1/admin/audit",
                      headers=admin).status_code == 200
