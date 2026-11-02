"""Tests for the WebUI settings surface: channels and Telegram session endpoints."""
from __future__ import annotations

import pytest

from web import app as webapp


ADMIN = ("testadmin", "long-secure-test-password")
CSRF = {"X-TeleDrive-CSRF": "1"}


@pytest.fixture
def admin(monkeypatch, tmp_path):
    monkeypatch.setattr(webapp, "ALLOWED_HOSTS", ["localhost", "127.0.0.1", "[::1]"])
    monkeypatch.setattr(webapp, "AUTH_DIR", tmp_path / "auth")
    db_path = tmp_path / "test.db"
    from teledrive.db import connect_database
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(db_path)))
    from tests import seed_local_user
    seed_local_user(lambda: connect_database(str(db_path)),
                    "testadmin", "long-secure-test-password", "admin")
    webapp.AUTH_FAILURES.clear()
    from fastapi.testclient import TestClient
    client = TestClient(webapp.app, base_url="http://localhost:8080")
    # This suite exercises the browser cookie flow, so keep the cookie.
    login = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": ADMIN[0], "password": ADMIN[1]})
    assert login.status_code == 200, login.text
    return client


def test_channels_crud(admin):
    client = admin
    # Create
    r = client.post("/api/v1/admin/storage/channels",
                    headers=CSRF,
                    json={"name": "ch1", "channel_id": "TeleDriveStorage",
                          "strategy": "single", "scratch_dir": "/data/tmp"})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert cid is not None

    # List
    r = client.get("/api/v1/admin/storage/channels")
    assert r.status_code == 200
    channels = r.json()["channels"]
    assert any(c["id"] == cid for c in channels)

    # Activate
    r = client.post(f"/api/v1/admin/storage/channels/{cid}/activate",
                    headers=CSRF)
    assert r.status_code == 200, r.text

    # Active channel
    r = client.get("/api/v1/admin/storage/active-channel")
    assert r.status_code == 200
    assert r.json()["active"]["id"] == cid

    # Delete
    r = client.delete(f"/api/v1/admin/storage/channels/{cid}",
                      headers=CSRF)
    assert r.status_code == 200, r.text


def test_active_channel_without_any_channel(admin):
    """Regression: the no-channel branch answers 200/None, never a 500.

    A removed raw-SQL import once left a NameError on exactly this path
    (dashboard and settings pages both call the endpoint), so the empty
    table is pinned here.
    """
    client = admin
    r = client.get("/api/v1/admin/storage/active-channel")
    assert r.status_code == 200, r.text
    assert r.json() == {"active": None}


def test_active_channel_falls_back_to_first_inactive_channel(admin):
    """Channels exist but none is flagged active: the first one is served."""
    client = admin
    first = client.post("/api/v1/admin/storage/channels",
                        headers=CSRF,
                        json={"name": "alpha", "channel_id": "ChAlpha",
                              "strategy": "single", "scratch_dir": "/data/tmp"})
    assert first.status_code == 201, first.text
    second = client.post("/api/v1/admin/storage/channels",
                         headers=CSRF,
                         json={"name": "beta", "channel_id": "ChBeta",
                               "strategy": "single", "scratch_dir": "/data/tmp"})
    assert second.status_code == 201, second.text
    # New channels are created inactive, so the fallback branch runs.
    r = client.get("/api/v1/admin/storage/active-channel")
    assert r.status_code == 200, r.text
    active = r.json()["active"]
    assert active["id"] == first.json()["id"]
    assert active["name"] == "alpha"


def test_telegram_session_status(admin):
    client = admin
    r = client.get("/api/v1/admin/storage/telegram-session")
    assert r.status_code == 200
    data = r.json()
    assert "configured" in data


def test_request_code_validation(admin):
    client = admin
    # Missing fields
    r = client.post("/api/v1/admin/storage/telegram-session/request-code",
                    headers=CSRF, json={})
    assert r.status_code in (400, 422)

    r = client.post("/api/v1/admin/storage/telegram-session/request-code",
                    headers=CSRF,
                    json={"api_id": 0, "api_hash": "", "phone": ""})
    assert r.status_code in (400, 422)


def test_verify_code_requires_pending(admin):
    client = admin
    r = client.post("/api/v1/admin/storage/telegram-session/verify-code",
                    headers=CSRF,
                    json={"token": "nonexistent", "code": "12345"})
    assert r.status_code == 404


def test_delete_session(admin):
    client = admin
    r = client.delete("/api/v1/admin/storage/telegram-session",
                      headers=CSRF)
    assert r.status_code == 200


def test_settings_page_contains_ui_elements():
    """Verify the settings HTML contains the new UI cards and elements."""
    from pathlib import Path
    html = Path("web/static/telegram.html").read_text(encoding="utf-8")
    assert "Telegram session (USER MTProto)" in html
    assert "Channels" in html
    assert 'addChannel()' in html
    assert 'sendTgCode()' in html
    assert 'verifyTgCode()' in html
    assert 'tgSessionStatus' in html
    assert 'activeChannelId' in html
    assert 'showAddChannel' in html


def test_general_settings_page_tells_the_truth():
    """The Automation card binds the setting the durable worker reads.

    jobs.auto_run (teledrive/settings.py job_auto_run, live-reloaded on
    every config save) gates the worker loop. The legacy app.* section
    drives nothing, so a checkbox or interval field bound to config.app.*
    was UI that saved values nothing consumed. The page also must not
    point users at a "Storage page" that does not exist.
    """
    from pathlib import Path
    html = Path("web/static/settings.html").read_text(encoding="utf-8")
    assert 'x-model="config.jobs.auto_run"' in html
    assert "config.app.auto_run" not in html
    assert "config.app.run_interval_minutes" not in html
    assert "Storage page" not in html
    assert "Telegram settings page" in html


def test_telegram_js_normalizes_jobs_auto_run():
    """loadSettings() must normalize the jobs section, not the dead app one."""
    from pathlib import Path
    js = Path("web/static/telegram.js").read_text(encoding="utf-8")
    assert "this.config.jobs.auto_run = !!jobs.auto_run;" in js
    assert "config.app.auto_run" not in js
    assert "config.app.run_interval_minutes" not in js


def test_app_js_valid_syntax():
    """Verify app.js has no syntax errors (checked via node if available)."""
    import shutil, subprocess
    if not shutil.which("node"):
        pytest.skip("node not installed")
    result = subprocess.run(["node", "--check", "web/static/app.js"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
