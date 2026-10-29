"""Config is a credential document and a deployment control surface.

Both criticals from the fifth review wave were reproduced over HTTP before
these tests were written.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
from teledrive.db import connect_database


@pytest.fixture()
def api(tmp_path, monkeypatch):
    """web.app pointed at a throwaway config file, database and scratch dir."""
    import yaml

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    db_path = tmp_path / "app.db"
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    config_path.write_text(yaml.safe_dump({
        "web": {"allowed_hosts": "localhost",
                "auth_dir": str(tmp_path / "auth")},
        "state": {"database_url": f"sqlite:///{db_path}"},
        "upload": {"source_dir": str(tmp_path / "uploads")},
        "storage": {"scratch_dir": str(scratch)},
        "logging": {"log_path": str(tmp_path / "uploader.log")},
        "paths": {"source_roots": str(tmp_path),
                  "session_roots": str(tmp_path),
                  "log_roots": str(tmp_path),
                  "split_dir": str(scratch),
                  "lock_dir": str(scratch)},
    }), encoding="utf-8")

    monkeypatch.setenv("TELEDRIVE_CONFIG", str(config_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_SQLITE_ROOTS", str(tmp_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_SESSION_ROOTS", str(tmp_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_LOG_ROOTS", str(tmp_path))
    monkeypatch.setattr(webapp, "CONFIG_PATH", config_path)
    monkeypatch.setattr(webapp, "AUTH_DIR", tmp_path / "auth")
    monkeypatch.setattr(webapp, "STORAGE_SCRATCH_DIR", str(scratch))
    monkeypatch.setattr(webapp, "_CONFIG_CACHE", {"mtime": None, "config": None})
    monkeypatch.setattr(webapp, "db_connect",
                        lambda: connect_database(str(db_path)))
    monkeypatch.setattr(webapp, "_settings_store", lambda: None)
    webapp.AUTH_FAILURES.clear()
    webapp._create_default_admin()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    yield client, db_path
    client.close()


def _login(client, username="admin", password="admin"):
    reply = client.post("/api/v1/auth/login",
                        headers={"x-teledrive-csrf": "1"},
                        json={"username": username, "password": password})
    assert reply.status_code == 200, reply.text
    client.cookies.clear()
    return {"x-teledrive-csrf": "1",
            "Authorization": f"Bearer {reply.json()['token']}"}


def test_get_config_never_returns_a_session_string_or_api_hash(api):
    """A live Telethon StringSession is full storage-account control.

    Redaction used to be a two-key denylist (telegram.api_hash), so
    storage.apis[*].session_string and an account's api_hash went out
    verbatim to a viewer.
    """
    client, _ = api
    headers = _login(client)
    secret_session = "1BVtsOK4Bu-SESSION-STRING-THAT-MUST-NOT-LEAK"
    secret_hash = "0123456789abcdef0123456789abcdef"

    current = webapp.read_raw_config()
    document = dict(current)
    document["telegram"] = {**current.get("telegram", {}),
                            "api_hash": secret_hash,
                            "accounts": [{"name": "primary",
                                          "api_hash": secret_hash}]}
    document["storage"] = {**current.get("storage", {}),
                           "scratch_dir": str(webapp.STORAGE_SCRATCH_DIR),
                           "apis": [{"name": "primary",
                                     "session_string": secret_session}]}
    reply = client.put("/api/v1/config", headers=headers, json=document)
    assert reply.status_code == 200, reply.text

    shown = client.get("/api/v1/config", headers=headers)
    assert shown.status_code == 200
    body = shown.text
    assert secret_session not in body, "the Telegram session string leaked"
    assert secret_hash not in body, "the api_hash leaked"
    # The value is still there for the loader, just not over HTTP.
    assert webapp.read_raw_config()["storage"]["apis"][0]["session_string"] == secret_session


def test_config_save_cannot_redirect_the_database(api):
    """Redirecting the DB is admin-creation plus data orphaning.

    The save used to be accepted, the application switched databases, and the
    bootstrap created admin/admin in the new one -- verified end to end.
    """
    client, path = api
    headers = _login(client)
    current = webapp.read_raw_config()
    original_url = (current.get("state") or {}).get("database_url")

    document = dict(current)
    document["state"] = {**(current.get("state") or {}),
                         "database_url": "sqlite:////tmp/opencode/evil.db"}
    reply = client.put("/api/v1/config", headers=headers, json=document)
    assert reply.status_code == 400, reply.text
    assert "config.yaml" in reply.text
    assert (webapp.read_raw_config().get("state") or {}).get(
        "database_url") == original_url


def test_config_save_cannot_add_a_boot_installed_package(api):
    """db_extra_packages is pip-installed at boot: arbitrary code."""
    client, _ = api
    headers = _login(client)
    current = webapp.read_raw_config()
    document = dict(current)
    document["state"] = {**(current.get("state") or {}),
                         "db_extra_packages": ["evil-package==1.0"]}
    reply = client.put("/api/v1/config", headers=headers, json=document)
    assert reply.status_code == 400, reply.text


def test_config_write_requires_an_interactive_session(api):
    """An API key must not be able to rewrite the deployment."""
    client, _ = api
    headers = _login(client)
    key = client.post("/api/v1/admin/keys", headers=headers,
                      json={"name": "cfg", "scopes": ["put:/api/v1/config"]})
    assert key.status_code == 201, key.text
    bearer = {"x-teledrive-csrf": "1",
              "Authorization": f"Bearer {key.json()['token']}"}
    reply = client.put("/api/v1/config", headers=bearer,
                       json=webapp.read_raw_config())
    assert reply.status_code == 403, reply.text
    assert "interactive session" in reply.text
