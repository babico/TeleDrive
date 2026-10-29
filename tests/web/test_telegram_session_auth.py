"""Binding a Telegram account is an owner (admin) decision, and a login code
cannot be brute-forced.

Both come from the API review: an operator could attach their own Telegram
account and thereby own every future upload, and verify-code had no attempt
cap -- a five-digit code with unlimited retries.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
from teledrive.db import connect_database


@pytest.fixture()
def api(tmp_path, monkeypatch):
    path = tmp_path / "telegram-auth.sqlite"
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(path)))
    webapp.AUTH_FAILURES.clear()
    webapp._create_default_admin()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    yield client, path
    client.close()


def _session(client, username, password):
    reply = client.post("/api/v1/auth/login",
                        headers={"x-teledrive-csrf": "1"},
                        json={"username": username, "password": password})
    assert reply.status_code == 200, reply.text
    return {"x-teledrive-csrf": "1"}


def _operator(api):
    client, _ = api
    admin = _session(client, "admin", "admin")
    created = client.post("/api/v1/admin/users", headers=admin,
                          json={"username": "op", "password": "operator-pass-1",
                                "role": "operator"})
    assert created.status_code == 201, created.text
    return _session(client, "op", "operator-pass-1")


def test_operator_cannot_bind_a_telegram_session(api):
    """An operator who can bind an account owns the backend."""
    client, _ = api
    op = _operator(api)
    body = {"api_id": 123456, "api_hash": "x" * 32, "phone": "+15550001111"}
    request = client.post("/api/v1/admin/storage/telegram-session/request-code",
                          headers=op, json=body)
    assert request.status_code == 403, request.text
    verify = client.post("/api/v1/admin/storage/telegram-session/verify-code",
                         headers=op, json={"token": "x" * 32, "code": "12345"})
    assert verify.status_code == 403, verify.text


def test_operator_keeps_read_access_to_the_session_listing(api):
    """Making binding admin-only must not close the read-only listing.

    ``/telegram-session`` is a prefix of ``/telegram-sessions``, so the gate
    matches exact paths and child segments only.
    """
    client, _ = api
    op = _operator(api)
    assert client.get("/api/v1/admin/storage/telegram-sessions",
                      headers=op).status_code == 200


def test_verify_code_attempt_budget_destroys_the_pending_request(api):
    """A 5-digit code must not be brute-forceable."""
    client, path = api
    admin = _session(client, "admin", "admin")
    conn = connect_database(str(path))
    token = "probe-token-" + "a" * 20
    try:
        from sqlalchemy import text
        conn.connection.execute(text(
            "INSERT INTO telegram_session_pending (token, api_id, api_hash, "
            "phone, phone_code_hash, session_string, created_at, attempts) "
            "VALUES (:t, 1, 'h', '+15550001111', 'hash', 'sess', :now, 0)"
        ), {"t": token, "now": int(time.time())})
        conn.connection.commit()
    finally:
        conn.close()

    # Exhaust the budget through the real failure path. Each call is a wrong
    # code; Telethon is not reached because the stored session is invalid, so
    # the exception path records the attempt.
    for _ in range(webapp._MAX_VERIFY_ATTEMPTS):
        client.post("/api/v1/admin/storage/telegram-session/verify-code",
                    headers=admin, json={"token": token, "code": "00000"})

    # The next attempt is refused outright, and the row is gone.
    blocked = client.post("/api/v1/admin/storage/telegram-session/verify-code",
                          headers=admin, json={"token": token, "code": "00000"})
    assert blocked.status_code in (404, 429), blocked.text
    conn = connect_database(str(path))
    try:
        from sqlalchemy import text
        remaining = conn.connection.execute(text(
            "SELECT COUNT(*) FROM telegram_session_pending WHERE token = :t"),
            {"t": token}).scalar_one()
    finally:
        conn.close()
    assert remaining == 0, "the pending request must be destroyed"
