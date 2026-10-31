"""The startup path, actually executed.

Every other web test builds ``TestClient(web.app)`` without a context
manager, which in Starlette means the ASGI lifespan NEVER runs -- so the
first-boot bootstrap, config parsing, file-logging setup and scheduler
startup were covered only by the Docker smoke job. A regression that crashed
startup would have left this whole suite green.

This test runs the real lifespan once with the background loops and the
MTProto runtime replaced by inert stand-ins (they are not what is being
verified here), and asserts the two things startup must guarantee: the app
serves traffic afterwards, and the documented admin account exists.
"""
from __future__ import annotations

import time

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

import web.app as web
from teledrive.db import connect_database


LOOPS = (
    "upload_job_scheduler_loop",
    "lifecycle_scheduler_loop",
    "tiering_scheduler_loop",
    "notification_scheduler_loop",
    "report_scheduler_loop",
    "folder_watch_loop",
    "telegram_session_health_loop",
)


@pytest.fixture
def lifespan_app(tmp_path, monkeypatch):
    database = tmp_path / "lifespan.sqlite"
    connect = lambda: connect_database(str(database))
    monkeypatch.setattr(web, "db_connect", connect)
    monkeypatch.setattr(web, "AUTH_DIR", tmp_path / "auth")
    monkeypatch.setattr(web, "STORAGE_SCRATCH_DIR", str(tmp_path / "scratch"))
    (tmp_path / "scratch").mkdir()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "web:\n  allowed_hosts: localhost,127.0.0.1,[::1]\n"
        "storage:\n  channel: ''\n  apis: []\n"
        f"  scratch_dir: {tmp_path / 'scratch'}\n"
        "state:\n"
        f"  database_url: sqlite:///{database}\n"
        f"jobs:\n  source_root: {tmp_path / 'uploads'}\n  auto_run: false\n"
        f"logging:\n  log_path: {tmp_path / 'teledrive.log'}\n  level: INFO\n",
        encoding="ascii",
    )
    monkeypatch.setenv("TELEDRIVE_CONFIG", str(config_path))
    monkeypatch.setattr(web, "CONFIG_PATH", config_path)
    monkeypatch.setattr(web, "DB_EXTRA_PACKAGES", [])

    # Startup calls these with the real /data and /uploads roots, which do not
    # exist for an unprivileged test user; redirect rather than skip startup.
    import pathlib as _pl
    orig_path_mkdir = _pl.Path.mkdir

    def patched_path_mkdir(self, *args, **kwargs):
        raw = str(self)
        if raw.startswith("/data") or raw.startswith("/uploads"):
            return orig_path_mkdir(tmp_path / raw.lstrip("/"), *args, **kwargs)
        return orig_path_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(_pl.Path, "mkdir", patched_path_mkdir)

    async def no_loop():
        return None

    for name in LOOPS:
        monkeypatch.setattr(web, name, no_loop, raising=False)

    async def no_start():
        return None

    async def no_stop():
        return None

    monkeypatch.setattr(web.mtproto_storage_runtime, "start", no_start)
    monkeypatch.setattr(web.mtproto_storage_runtime, "stop", no_stop)
    return {"config": config_path, "connect": connect}


def test_lifespan_bootstraps_the_admin_account_and_serves_health(lifespan_app):
    with TestClient(web.app, base_url="http://localhost:8080") as client:
        health = client.get("/api/health")
        assert health.status_code == 200, health.text
        assert health.json()["ok"] is True

        db = lifespan_app["connect"]()
        try:
            row = db.connection.execute(text(
                "SELECT username, role, enabled FROM users "
                "WHERE username = 'admin'")).fetchone()
        finally:
            db.close()
        assert row is not None, "first boot must create the admin account"
        assert tuple(row) == ("admin", "admin", 1)


def test_lifespan_never_overwrites_an_existing_admin(lifespan_app):
    # A previous install has an admin whose password the operator changed.
    db = lifespan_app["connect"]()
    try:
        web._create_default_admin()  # first boot, through the same helper
        stored = web._hash_password("operator-chosen-password")
        db.connection.execute(text(
            "UPDATE users SET password_hash = :h WHERE username = 'admin'"),
            {"h": stored})
        db.connection.commit()
    finally:
        db.close()

    with TestClient(web.app, base_url="http://localhost:8080"):
        pass

    db = lifespan_app["connect"]()
    try:
        row = db.connection.execute(text(
            "SELECT password_hash FROM users WHERE username = 'admin'"
        )).fetchone()
    finally:
        db.close()
    assert web._verify_password("operator-chosen-password", row[0]), (
        "startup must never reset an existing admin credential")
