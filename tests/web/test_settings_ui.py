"""Tests for the WebUI settings surface: channels and Telegram session endpoints."""
from __future__ import annotations

import pytest

from web import app as webapp


AUTH = ("testadmin", "long-secure-test-password")
CSRF = {"X-TeleDrive-CSRF": "1"}


@pytest.fixture
def admin(monkeypatch, tmp_path):
    monkeypatch.setattr(webapp, "WEB_USER", "testadmin")
    monkeypatch.setattr(webapp, "WEB_PASSWORD", "long-secure-test-password")
    monkeypatch.setattr(webapp, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "[::1]"])
    monkeypatch.setattr(webapp, "AUTH_DIR", tmp_path / "auth")
    db_path = tmp_path / "test.db"
    from teledrive.db import connect_database
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(db_path)))
    webapp.AUTH_FAILURES.clear()
    from fastapi.testclient import TestClient
    client = TestClient(webapp.app, base_url="http://localhost:8080")
    return client


def test_channels_crud(admin):
    client = admin
    # Create
    r = client.post("/api/v1/admin/storage/channels",
                    auth=AUTH, headers=CSRF,
                    json={"name": "ch1", "channel_id": "TeleDriveStorage",
                          "strategy": "single", "scratch_dir": "/data/tmp"})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert cid is not None

    # List
    r = client.get("/api/v1/admin/storage/channels", auth=AUTH)
    assert r.status_code == 200
    channels = r.json()["channels"]
    assert any(c["id"] == cid for c in channels)

    # Activate
    r = client.post(f"/api/v1/admin/storage/channels/{cid}/activate",
                    auth=AUTH, headers=CSRF)
    assert r.status_code == 200, r.text

    # Active channel
    r = client.get("/api/v1/admin/storage/active-channel", auth=AUTH)
    assert r.status_code == 200
    assert r.json()["active"]["id"] == cid

    # Delete
    r = client.delete(f"/api/v1/admin/storage/channels/{cid}",
                      auth=AUTH, headers=CSRF)
    assert r.status_code == 200, r.text


def test_telegram_session_status(admin):
    client = admin
    r = client.get("/api/v1/admin/storage/telegram-session", auth=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert "configured" in data


def test_request_code_validation(admin):
    client = admin
    # Missing fields
    r = client.post("/api/v1/admin/storage/telegram-session/request-code",
                    auth=AUTH, headers=CSRF, json={})
    assert r.status_code in (400, 422)

    r = client.post("/api/v1/admin/storage/telegram-session/request-code",
                    auth=AUTH, headers=CSRF,
                    json={"api_id": 0, "api_hash": "", "phone": ""})
    assert r.status_code in (400, 422)


def test_verify_code_requires_pending(admin):
    client = admin
    r = client.post("/api/v1/admin/storage/telegram-session/verify-code",
                    auth=AUTH, headers=CSRF,
                    json={"token": "nonexistent", "code": "12345"})
    assert r.status_code == 404


def test_delete_session(admin):
    client = admin
    r = client.delete("/api/v1/admin/storage/telegram-session",
                      auth=AUTH, headers=CSRF)
    assert r.status_code == 200


def test_settings_page_contains_ui_elements():
    """Verify the settings HTML contains the new UI cards and elements."""
    from pathlib import Path
    html = Path("web/static/index.html").read_text(encoding="utf-8")
    assert "Telegram session (USER MTProto)" in html
    assert "Channels" in html
    assert 'addChannel()' in html
    assert 'sendTgCode()' in html
    assert 'verifyTgCode()' in html
    assert 'tgSessionStatus' in html
    assert 'activeChannelId' in html
    assert 'channelEditors' in html


def test_app_js_valid_syntax():
    """Verify app.js has no syntax errors (checked via node if available)."""
    import shutil, subprocess
    if not shutil.which("node"):
        pytest.skip("node not installed")
    result = subprocess.run(["node", "--check", "web/static/app.js"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
