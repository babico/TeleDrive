"""Settings persistence: the SQL document is authoritative, config.yaml
is the bootstrap and recovery source.

Rules under test:
* first boot seeds SQL from the file and keeps working;
* a save writes BOTH the file and the SQL row;
* the SQL document wins when the file behind it is stale;
* an undecryptable row (master-key change) falls back to the file instead
  of breaking startup, and the next save re-seeds;
* redacted secrets survive a UI round-trip unchanged.
"""
from __future__ import annotations

import yaml
import pytest

from teledrive.db import connect_database
from teledrive.settings_store import SettingsStore, SettingsStoreError


@pytest.fixture
def store(tmp_path):
    from cryptography.fernet import Fernet
    db = connect_database(str(tmp_path / "settings.db"))
    try:
        yield SettingsStore(db, Fernet.generate_key()), db
    finally:
        db.close()


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    """A web.app pointed at a throwaway config file and database."""
    from cryptography.fernet import Fernet
    import web.app as webapp

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    db_path = tmp_path / "app.db"
    config_path.write_text(yaml.safe_dump({
        "web": {"allowed_hosts": "localhost",
                "password": "supersecret-password-1",
                "auth_dir": str(tmp_path / "auth")},
        "state": {"database_url": f"sqlite:///{db_path}"},
        "upload": {"source_dir": str(tmp_path / "uploads")},
        "storage": {"scratch_dir": str(tmp_path / "scratch")},
        "logging": {"log_path": str(tmp_path / "uploader.log")},
        "paths": {"source_roots": str(tmp_path),
                  "session_roots": str(tmp_path),
                  "log_roots": str(tmp_path),
                  "split_dir": str(tmp_path / "scratch"),
                  "lock_dir": str(tmp_path / "scratch")},
    }, sort_keys=False), encoding="utf-8")

    key = Fernet.generate_key()
    monkeypatch.setenv("TELEDRIVE_ALLOWED_SQLITE_ROOTS", str(tmp_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_SESSION_ROOTS", str(tmp_path))
    monkeypatch.setenv("TELEDRIVE_ALLOWED_LOG_ROOTS", str(tmp_path))
    monkeypatch.setattr(webapp, "CONFIG_PATH", config_path)
    monkeypatch.setattr(webapp, "load_master_key", lambda: key)
    monkeypatch.setattr(webapp, "AUTH_DIR", tmp_path / "auth")
    monkeypatch.setattr(webapp, "STORAGE_SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr(webapp, "_CONFIG_CACHE",
                        {"mtime": None, "config": None})
    webapp._SETTINGS_CACHE.update({"document": None, "generation": 0})
    return {"webapp": webapp, "config_path": config_path, "db_path": db_path,
            "key": key}


def test_first_read_seeds_the_document_from_the_file(app_env):
    webapp = app_env["webapp"]
    first = webapp.read_raw_config()
    assert first["web"]["allowed_hosts"] == "localhost"

    db = connect_database(f"sqlite:///{app_env['db_path']}")
    try:
        stored = SettingsStore(db, app_env["key"]).load()
    finally:
        db.close()
    assert stored is not None
    assert stored.updated_by == "bootstrap:config.yaml"
    assert stored.document["web"]["allowed_hosts"] == "localhost"
    # Secrets are stored encrypted, never as readable text.
    raw_row = connect_database(f"sqlite:///{app_env['db_path']}")
    try:
        from sqlalchemy import text
        payload = raw_row.connection.execute(text(
            "SELECT payload FROM service_settings")).scalar_one()
    finally:
        raw_row.close()
    assert "supersecret-password-1" not in payload


def test_save_writes_both_file_and_sql_and_sql_wins(app_env):
    webapp = app_env["webapp"]
    webapp.read_raw_config()  # seed
    document = webapp.read_raw_config()
    document["upload"]["max_files_per_run"] = 42
    webapp.validate_and_write_config(document, by="admin")

    # The file mirrors the change...
    on_disk = yaml.safe_load(app_env["config_path"].read_text("utf-8"))
    assert on_disk["upload"]["max_files_per_run"] == 42

    # ...and the SQL document carries it too.
    db = connect_database(f"sqlite:///{app_env['db_path']}")
    try:
        stored = SettingsStore(db, app_env["key"]).load()
    finally:
        db.close()
    assert stored.document["upload"]["max_files_per_run"] == 42
    assert stored.updated_by == "admin"

    # Make the FILE stale (an old mounted copy) and prove SQL is the
    # authoritative source.
    stale = yaml.safe_load(app_env["config_path"].read_text("utf-8"))
    stale["upload"]["max_files_per_run"] = 7
    app_env["config_path"].write_text(yaml.safe_dump(stale), encoding="utf-8")
    assert webapp.read_raw_config()["upload"]["max_files_per_run"] == 42


def test_undecryptable_document_falls_back_to_the_file(app_env):
    webapp = app_env["webapp"]
    webapp.read_raw_config()  # seed with key A
    # Rotate the master key: the stored row can no longer be decrypted.
    from cryptography.fernet import Fernet
    app_env["webapp"].load_master_key = lambda: Fernet.generate_key()
    rotated = Fernet.generate_key()
    import web.app as webapp_module
    webapp_module.load_master_key = lambda: rotated

    document = webapp.read_raw_config()
    # It still answers, using the file, and re-seeds under the new key.
    assert document["web"]["allowed_hosts"] == "localhost"
    db = connect_database(f"sqlite:///{app_env['db_path']}")
    try:
        stored = SettingsStore(db, rotated).load()
    finally:
        db.close()
    assert stored is not None and stored.document["web"][
        "allowed_hosts"] == "localhost"


def test_retired_auth_settings_never_round_trip(app_env):
    """Upgrade-era auth keys are stripped, not treated as settings."""
    webapp = app_env["webapp"]
    current = webapp.read_raw_config()
    assert "password" not in current.get("web", {})
    assert "user" not in current.get("web", {})
    webapp.validate_and_write_config(webapp._redacted_config(current),
                                     by="admin")
    webapp.read_raw_config()  # invalidate the cache
    assert "password" not in webapp.read_raw_config()["web"]


def test_store_rejects_oversized_documents(store):
    settings, _ = store
    with pytest.raises(ValueError, match="1 MiB"):
        settings.save({"blob": "x" * (1024 * 1024 + 10)}, by="test")


def test_store_requires_a_master_key(tmp_path):
    db = connect_database(str(tmp_path / "nokey.db"))
    try:
        settings = SettingsStore(db, None)
        with pytest.raises(SettingsStoreError):
            settings.save({"web": {}}, by="test")
    finally:
        db.close()


def test_load_returns_none_before_any_save(store):
    settings, _ = store
    assert settings.load() is None
