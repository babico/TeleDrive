#!/usr/bin/env python3
import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .db import Database, connect_database, normalize_database_url, sqlite_database_path

import yaml


ACCOUNT_STRATEGIES = {"single", "round_robin", "failover", "parallel"}
# The lease the legacy import shares with the real legacy uploader. This used
# to be "" with a TTL of 0, which made the mutual-exclusion gate dead code:
# the name never collided with the uploader the message talks about, and
# lease_until == now meant a second request a second later stole it. The first
# heartbeat at +10 s then always failed, raising a 500 mid-import.
LEASE_NAME = "legacy-uploader"
LEASE_TTL_SECONDS = 120


@dataclass
class AppConfig:
    strategy: str
    web: dict
    jobs: dict
    storage: dict
    state: dict
    source_dir: str
    allowed_extensions: list[str]
    max_file_size_mb: int
    db_path: str
    log_path: str
    log_level: str




def _safe_account_token(name: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip()).strip("._-")
    return token or "account"


def load_config(path: str) -> AppConfig:
    config_dir = Path(path).expanduser().resolve().parent

    def config_path(value: object) -> str:
        candidate = Path(str(value)).expanduser()
        return str(candidate if candidate.is_absolute() else config_dir / candidate)

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    tg = raw.get("telegram") or {}
    up = raw.get("upload") or {}
    st = raw.get("state") or {}
    lg = raw.get("logging") or {}
    web_section = raw.get("web") or {}
    jobs_section = raw.get("jobs") or {}
    storage_section = raw.get("storage") or {}

    strategy = str(tg.get("strategy", "single")).strip().lower()

    # Legacy direct-send scanner is gone; the unified service uses
    # storage.apis for credentials. Tolerate a legacy telegram: section but
    # do not parse accounts. Only source_dir and the file-allowed filter are
    # still consumed (by the legacy bridge and cutover checks).
    return AppConfig(
        strategy=strategy,
        source_dir=config_path(up.get("source_dir", "/uploads")),
        allowed_extensions=[str(x).lower() for x in up.get("allowed_extensions", [])],
        max_file_size_mb=int(up.get("max_file_size_mb", 0)),
        db_path=normalize_database_url(
            st.get("database_url") or st.get("db_path", "data/state.db"),
            config_dir=config_dir,
        ),
        log_path=config_path(lg.get("log_path", "/data/uploader.log")),
        log_level=str(lg.get("level", "INFO")),
        web=web_section,
        jobs=jobs_section,
        storage=storage_section,
        state=st,
    )


_LOG_SECRET_URL_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:)[^@\s]+(@)")
_LOG_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:password|passwd|pwd|token|access_token|secret|api_key|apikey)=)[^&#\s]+"
)


def _scrub_log_text(value: str) -> str:
    value = _LOG_SECRET_URL_RE.sub(r"\1***\2", value)
    return _LOG_QUERY_SECRET_RE.sub(r"\1***", value)


def connect_db(db_path: str) -> Database:
    return connect_database(db_path)



def _path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:
        return False


def _validate_allowed_roots(path: str, env_name: str) -> None:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return
    roots = [item.strip() for item in raw.split(os.pathsep) if item.strip()]
    if not roots or not any(_path_within(path, root) for root in roots):
        raise ValueError(f"{path} is outside allowed roots configured by {env_name}")


def iter_source_files(source_dir: str) -> Iterable[str]:
    source_real = os.path.realpath(source_dir)
    for root, dirs, files in os.walk(source_real, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for name in files:
            path = os.path.abspath(os.path.join(root, name))
            if os.path.islink(path):
                logging.warning("Skipping symlink: %r", path)
                continue
            if not _path_within(path, source_real):
                logging.warning("Skipping path outside source root: %r", path)
                continue
            try:
                file_stat = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                logging.warning("Skipping non-regular file: %r", path)
                continue
            yield path


def file_allowed(path: str, cfg: AppConfig) -> bool:
    if cfg.allowed_extensions:
        ext = os.path.splitext(path)[1].lower()
        if ext not in cfg.allowed_extensions:
            return False
    if cfg.max_file_size_mb > 0:
        max_bytes = cfg.max_file_size_mb * 1024 * 1024
        try:
            if os.path.getsize(path) > max_bytes:
                return False
        except OSError:
            return False
    return True




def validate_config(cfg: AppConfig) -> None:
    # The legacy upload scanner (sleep/retry/file-count/caption/send-mode
    # knobs) is gone: chunk I/O lives in storage/telethon_adapter.py. Only
    # the settings the legacy import path still reads are validated here.
    if cfg.strategy not in ACCOUNT_STRATEGIES:
        raise ValueError("telegram.strategy must be single, round_robin, failover, or parallel")
    if cfg.max_file_size_mb < 0:
        raise ValueError("max_file_size_mb cannot be negative")
    validate_storage_paths(cfg)


def validate_storage_paths(cfg: AppConfig) -> None:
    if not os.path.isdir(cfg.source_dir):
        raise ValueError(f"source_dir not found: {cfg.source_dir}")
    _validate_allowed_roots(cfg.source_dir, "TELEDRIVE_ALLOWED_SOURCE_ROOTS")
    _validate_allowed_roots(cfg.log_path, "TELEDRIVE_ALLOWED_LOG_ROOTS")
    sqlite_path = sqlite_database_path(cfg.db_path)
    if sqlite_path is not None:
        _validate_allowed_roots(sqlite_path, "TELEDRIVE_ALLOWED_SQLITE_ROOTS")

