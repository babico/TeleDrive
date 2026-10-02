from __future__ import annotations

import asyncio
import hmac
import os
import re
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import Body, Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

import uploader

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("TELEDRIVE_CONFIG", "/config/config.yaml"))
AUTH_DIR = Path(os.environ.get("TELEDRIVE_AUTH_DIR", "/data/auth"))
STATIC_DIR = BASE_DIR / "static"
WEB_USER = os.environ.get("TELEDRIVE_WEB_USER", "admin")
WEB_PASSWORD = os.environ.get("TELEDRIVE_WEB_PASSWORD", "")
LOG_BUFFER: deque[str] = deque(maxlen=1500)
PROMPT_RE = re.compile(r"Please enter the (code|password) for account '([^']+)':", re.I)

security = HTTPBasic(auto_error=False)
process_lock = asyncio.Lock()
current_process: asyncio.subprocess.Process | None = None
current_mode: str | None = None
current_started_at: int | None = None
current_prompt: dict[str, str] | None = None
scheduler_task: asyncio.Task | None = None


def require_auth(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    if not WEB_PASSWORD:
        return
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})
    if not (
        hmac.compare_digest(credentials.username, WEB_USER)
        and hmac.compare_digest(credentials.password, WEB_PASSWORD)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})


def default_config() -> dict[str, Any]:
    return {
        "telegram": {
            "strategy": "parallel",
            "api_id": 0,
            "api_hash": "",
            "target": "me",
            "accounts": [{
                "name": "primary",
                "enabled": True,
                "phone": "",
                "session_path": "/data/sessions/primary",
            }],
        },
        "upload": {
            "source_dir": "/uploads",
            "allowed_extensions": [],
            "max_file_size_mb": 0,
            "sleep_min_seconds": 60,
            "sleep_max_seconds": 90,
            "max_files_per_run": 12,
            "max_files_per_day": 100,
            "retry_attempts": 5,
            "backoff_base_seconds": 10,
            "floodwait_buffer_seconds": 5,
            "caption_template": "{name}",
            "send_mode": "document",
        },
        "state": {"database_url": "sqlite:////data/state.db"},
        "logging": {"log_path": "/data/uploader.log", "level": "INFO"},
        "app": {"auto_run": False, "run_interval_minutes": 60},
    }


def ensure_config() -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    Path("/data/sessions").mkdir(parents=True, exist_ok=True)
    Path("/uploads").mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(yaml.safe_dump(default_config(), sort_keys=False), encoding="utf-8")


def read_raw_config() -> dict[str, Any]:
    ensure_config()
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


def effective_config():
    ensure_config()
    return uploader.load_config(str(CONFIG_PATH))


def validate_and_write_config(raw: dict[str, Any]) -> None:
    tmp = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    tmp.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    try:
        cfg = uploader.load_config(str(tmp))
        uploader.validate_config(cfg)
        conn = uploader.connect_db(cfg.db_path)
        conn.close()
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(CONFIG_PATH)


def db_connect():
    cfg = effective_config()
    return uploader.connect_db(cfg.db_path)


def process_snapshot() -> dict[str, Any]:
    proc = current_process
    return {
        "running": proc is not None and proc.returncode is None,
        "pid": proc.pid if proc is not None and proc.returncode is None else None,
        "mode": current_mode,
        "started_at": current_started_at,
        "auth_prompt": current_prompt,
    }


async def _capture_process(proc: asyncio.subprocess.Process) -> None:
    global current_process, current_mode, current_started_at, current_prompt
    assert proc.stdout is not None
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            message = line.decode("utf-8", errors="replace").rstrip()
            if message:
                LOG_BUFFER.append(message)
                match = PROMPT_RE.search(message)
                if match:
                    current_prompt = {"kind": match.group(1).lower(), "account": match.group(2)}
        await proc.wait()
        LOG_BUFFER.append(f"[web] uploader exited with code {proc.returncode}")
    finally:
        async with process_lock:
            if current_process is proc:
                current_process = None
                current_mode = None
                current_started_at = None
                current_prompt = None


async def start_uploader(mode: str) -> dict[str, Any]:
    global current_process, current_mode, current_started_at, current_prompt
    if mode not in {"run-once", "scan-only", "connect"}:
        raise HTTPException(400, "mode must be run-once, scan-only, or connect")
    async with process_lock:
        if current_process is not None and current_process.returncode is None:
            raise HTTPException(409, "Uploader is already running")
        args = ["python", str(BASE_DIR / "uploader.py"), "--config", str(CONFIG_PATH), "--auth-dir", str(AUTH_DIR)]
        if mode == "scan-only":
            args.append("--scan-only")
        elif mode == "connect":
            args.extend(["--run-once", "--no-scan"])
        else:
            args.append("--run-once")
        current_prompt = None
        current_mode = mode
        current_started_at = int(time.time())
        LOG_BUFFER.append("[web] $ " + " ".join(args))
        current_process = await asyncio.create_subprocess_exec(
            *args, cwd=str(BASE_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        asyncio.create_task(_capture_process(current_process))
        return process_snapshot()


async def stop_uploader() -> dict[str, Any]:
    proc = current_process
    if proc is None or proc.returncode is not None:
        return process_snapshot()
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
    return process_snapshot()


async def scheduler_loop() -> None:
    last_launch = 0.0
    while True:
        try:
            app_cfg = read_raw_config().get("app", {})
            enabled = bool(app_cfg.get("auto_run", False))
            interval = max(1, int(app_cfg.get("run_interval_minutes", 60))) * 60
            now = time.time()
            running = current_process is not None and current_process.returncode is None
            if enabled and not running and now - last_launch >= interval:
                await start_uploader("run-once")
                last_launch = now
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG_BUFFER.append(f"[web] scheduler error: {exc}")
            await asyncio.sleep(10)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global scheduler_task
    ensure_config()
    try:
        conn = db_connect()
        conn.close()
    except Exception as exc:
        LOG_BUFFER.append(f"[web] startup database warning: {exc}")
    scheduler_task = asyncio.create_task(scheduler_loop())
    yield
    if scheduler_task:
        scheduler_task.cancel()
    await stop_uploader()


app = FastAPI(title="TeleDrive Web UI", version="2.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index(_: None = Depends(require_auth)):
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config")
def get_config(_: None = Depends(require_auth)):
    return read_raw_config()


@app.put("/api/config")
def put_config(payload: dict[str, Any] = Body(...), _: None = Depends(require_auth)):
    try:
        validate_and_write_config(payload)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@app.get("/api/dashboard")
def dashboard(_: None = Depends(require_auth)):
    cfg = effective_config()
    conn = db_connect()
    try:
        counts = conn.dashboard_counts()
        uploaded_today = uploader.uploaded_today(conn)
        statuses = conn.all_account_states()
        account_counts = conn.uploaded_counts_by_account()
    finally:
        conn.close()

    accounts = []
    for account in cfg.accounts:
        state = statuses.get(account.name, {})
        accounts.append({
            "name": account.name,
            "enabled": account.enabled,
            "phone": account.phone or "",
            "target": account.target,
            "session_path": account.session_path,
            "state": state.get("state", "unknown"),
            "last_error": state.get("last_error"),
            "cooldown_until": state.get("cooldown_until"),
            "last_success_ts": state.get("last_success_ts"),
            "last_update_ts": state.get("last_update_ts"),
            "uploaded_count": account_counts.get(account.name, 0),
        })

    return {
        "strategy": cfg.strategy,
        "database_url": cfg.db_path,
        "queue": {
            "pending": counts.get("pending", 0),
            "failed": counts.get("failed", 0),
            "uploaded": counts.get("uploaded", 0),
            "uploaded_today": uploaded_today,
        },
        "accounts": accounts,
        "process": process_snapshot(),
    }


@app.get("/api/files")
def files_endpoint(
    kind: str = Query("queue", pattern="^(queue|history)$"),
    limit: int = Query(100, ge=1, le=1000),
    _: None = Depends(require_auth),
):
    conn = db_connect()
    try:
        return conn.list_files(kind, limit)
    finally:
        conn.close()


@app.post("/api/process/start")
async def process_start(payload: dict[str, Any] = Body(default={}), _: None = Depends(require_auth)):
    return await start_uploader(str(payload.get("mode", "run-once")))


@app.post("/api/process/stop")
async def process_stop(_: None = Depends(require_auth)):
    return await stop_uploader()


@app.post("/api/auth")
def submit_auth(payload: dict[str, Any] = Body(...), _: None = Depends(require_auth)):
    global current_prompt
    account = str(payload.get("account", "")).strip()
    kind = str(payload.get("kind", "")).strip().lower()
    value = str(payload.get("value", "")).strip()
    if not account or kind not in {"code", "password"} or not value:
        raise HTTPException(400, "account, kind(code/password), and value are required")
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    token = uploader._safe_account_token(account)
    path = AUTH_DIR / f"{token}_{kind}.txt"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(value, encoding="utf-8")
    tmp.replace(path)
    if current_prompt and current_prompt.get("account") == account and current_prompt.get("kind") == kind:
        current_prompt = None
    return {"ok": True}


@app.get("/api/logs")
def logs(limit: int = Query(300, ge=1, le=1500), _: None = Depends(require_auth)):
    cfg = effective_config()
    combined = list(LOG_BUFFER)[-limit:]
    log_path = Path(cfg.log_path)
    if log_path.exists():
        try:
            combined = (log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:] + combined)[-limit:]
        except OSError:
            pass
    return {"lines": combined, "process": process_snapshot()}


@app.get("/api/health")
def health():
    return {"ok": True, "password_protected": bool(WEB_PASSWORD)}
