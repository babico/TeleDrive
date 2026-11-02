"""One factory for the throwaway app environments the web tests use.

Four test modules (auth/rbac, REST transfer, unified service, lifespan)
each re-implemented the same tmp-app scaffolding -- SQLite database,
config file, patched ``CONFIG_PATH``/``AUTH_DIR``/``STORAGE_SCRATCH_DIR``,
a fake USER-MTProto transport, cleared ``AUTH_FAILURES`` -- and drifted
apart. They now build on :func:`make_app_env` instead.

Every root the app would create is pointed at ``tmp_path`` through the
config file itself (``upload.source_dir``, ``storage.scratch_dir``,
``web.auth_dir``, ``logging.log_path``), which is why no test here needs
to monkeypatch ``pathlib.Path.mkdir`` globally anymore.

The factory rebinds the module attributes on ``web.app`` with
``monkeypatch``; the extracted runtime modules
(``web.settings_runtime``, ``web.schedulers``) resolve their state
through ``web.app`` at call time, so those patches steer them too.
"""
from __future__ import annotations

import hashlib
import secrets
import time

import pytest

import web.app as web
from teledrive.db import connect_database


def seed_user(connect, username: str, password: str, role: str,
              *, enabled: bool = True, legacy_hash: bool = False) -> None:
    """Insert a local user row for session-cookie tests.

    ``legacy_hash`` stores the pre-PBKDF2 SHA-256 format so login can
    exercise the migration path; ``enabled=False`` seeds a disabled row.
    """
    if legacy_hash:
        salt = secrets.token_hex(16)
        stored = salt + ":" + hashlib.sha256(
            (salt + password).encode()).hexdigest()
    else:
        stored = web._hash_password(password)
    db = connect()
    try:
        import sqlalchemy
        db.connection.execute(sqlalchemy.text(
            "INSERT INTO users (username, password_hash, role, enabled, "
            "created_at, updated_at) VALUES (:u, :ph, :r, :e, :now, :now)"
        ), {"u": username, "ph": stored, "r": role,
            "e": 1 if enabled else 0, "now": int(time.time())})
        db.connection.commit()
    finally:
        db.close()


@pytest.fixture
def make_app_env(tmp_path, monkeypatch):
    """Build a hermetic TeleDrive app environment under ``tmp_path``.

    Returns a namespace with ``connect`` (tmp SQLite), ``transport``
    (FakeUserTransport), ``config_path``, ``db_path``, ``scratch``,
    ``uploads``, ``auth_dir`` and ``tmp``. The returned ``connect`` and
    the module-level patches are reverted by monkeypatch.
    """
    def factory(*, db_name: str = "state.db", transport=None,
                patch_transport: bool = True, config_extra: str = "",
                include_auth_keys: bool = True,
                rest_max_upload_bytes: int | None = None,
                job_source_root: str | None = None,
                set_env_config: bool = False,
                db_extra_packages=None):
        from tests.web.test_rest_transfer import FakeUserTransport

        db_path = tmp_path / db_name
        connect = lambda: connect_database(str(db_path))
        scratch = tmp_path / "scratch"
        uploads = tmp_path / "uploads"
        auth_dir = tmp_path / "auth"
        scratch.mkdir(exist_ok=True)
        uploads.mkdir(exist_ok=True)
        if transport is None and patch_transport:
            transport = FakeUserTransport()

        # The retired web.user/web.password keys stay in two configs on
        # purpose: their strip-on-read is itself under test.
        auth_keys = ("  user: testadmin\n"
                     "  password: long-secure-test-password\n"
                     ) if include_auth_keys else ""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "web:\n" + auth_keys +
            "  allowed_hosts: localhost,127.0.0.1,[::1]\n"
            f"  auth_dir: {auth_dir}\n"
            "storage:\n"
            "  channel: ''\n"
            "  apis: []\n"
            f"  scratch_dir: {scratch}\n"
            "state:\n"
            f"  database_url: sqlite:///{db_path}\n"
            "jobs:\n"
            f"  source_root: {uploads}\n"
            "  auto_run: false\n"
            "upload:\n"
            f"  source_dir: {uploads}\n"
            "logging:\n"
            f"  log_path: {tmp_path / 'teledrive.log'}\n"
            "  level: INFO\n"
            + config_extra,
            encoding="ascii",
        )

        monkeypatch.setattr(web, "CONFIG_PATH", config_path)
        monkeypatch.setattr(web, "AUTH_DIR", auth_dir)
        monkeypatch.setattr(web, "STORAGE_SCRATCH_DIR", str(scratch))
        monkeypatch.setattr(web, "db_connect", connect)
        if patch_transport:
            monkeypatch.setattr(web, "storage_transport",
                                lambda db: transport)
        if rest_max_upload_bytes is not None:
            monkeypatch.setattr(web, "REST_MAX_UPLOAD_BYTES",
                                rest_max_upload_bytes)
        if job_source_root is not None:
            monkeypatch.setattr(web, "JOB_SOURCE_ROOT", job_source_root)
        if db_extra_packages is not None:
            monkeypatch.setattr(web, "DB_EXTRA_PACKAGES", db_extra_packages)
        if set_env_config:
            # The lifespan re-reads the environment path; monkeypatch
            # restores it so a later test cannot inherit this database.
            monkeypatch.setenv("TELEDRIVE_CONFIG", str(config_path))
        web.AUTH_FAILURES.clear()

        import types
        return types.SimpleNamespace(
            connect=connect, transport=transport, tmp=tmp_path,
            config_path=config_path, db_path=db_path, scratch=scratch,
            uploads=uploads, auth_dir=auth_dir)

    return factory
