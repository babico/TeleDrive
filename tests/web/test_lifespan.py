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

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

import web.app as web


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
def lifespan_app(make_app_env, monkeypatch):
    # Same MonkeyPatch instance pytest hands to make_app_env, so the
    # loop/runtime stubs below sit next to the factory's patches.
    env = make_app_env(db_name="lifespan.sqlite", set_env_config=True,
                       db_extra_packages=[])

    # The background loops and the MTProto runtime are not what this
    # test verifies; make_app_env deliberately leaves them alone.
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
    return {"config": env.config_path, "connect": env.connect}


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
