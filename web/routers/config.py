"""Deployment configuration, logs and health.

Paths are absolute: ``APIRouter`` has no prefix because ``web.permissions``
matches the full route path.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from fastapi import (
    APIRouter, Body, Depends, HTTPException, Query, Request, WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel

from web.deps import _require_interactive_session, _same_origin, require_auth
from web.errors import _scrub_text

router = APIRouter()


class OKResponse(BaseModel):
    ok: bool = True


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


@router.get("/api/v1/config", tags=["Configuration"], summary="Read configuration (secrets redacted)")
@router.get("/api/config", tags=["Configuration"], include_in_schema=False)
def get_config(_: None = Depends(require_auth)):
    return _webapp()._redacted_config(_webapp().read_raw_config())


# Settings that can only be changed by editing config.yaml on disk, as a
# deployment decision made by someone with filesystem access. Exposing them
# over HTTP is a takeover primitive, not a feature:
#
#   state.database_url   redirects the whole application at a fresh database,
#                        after which the startup bootstrap creates
#                        admin/admin there -- verified end to end: a session
#                        save, then /api/v1/auth/login with admin/admin on the
#                        new DB. It also orphans the real data.
#   state.db_extra_packages
#                        is pip-installed at every boot (settings.py), so it
#                        is arbitrary code execution that survives restarts.
_FILE_ONLY_STATE_KEYS = ("database_url", "db_path", "db_extra_packages")


def _reject_file_only_settings(payload: dict[str, Any]) -> None:
    submitted = (payload or {}).get("state") or {}
    if not isinstance(submitted, dict):
        raise HTTPException(400, "state must be an object")
    current = (_webapp().read_raw_config() or {}).get("state") or {}
    for key in _FILE_ONLY_STATE_KEYS:
        if key not in submitted:
            continue
        if submitted[key] == _webapp().REDACTED:
            continue
        if submitted[key] != current.get(key):
            raise HTTPException(
                400,
                f"state.{key} cannot be changed from the API; edit "
                f"config.yaml on the server instead")


@router.put("/api/v1/config", tags=["Configuration"], response_model=OKResponse, summary="Validate and save configuration")
@router.put("/api/config", tags=["Configuration"], include_in_schema=False)
def put_config(request: Request, payload: dict[str, Any] = Body(...), _: None = Depends(require_auth)):
    _same_origin(request)
    # A configuration write can change allowed hosts, filesystem roots and
    # the job watcher, so it is a human/operator decision -- never something
    # a stored API key performs on its holder's behalf.
    actor = _require_interactive_session(request, "change the deployment "
                                                   "configuration")
    _webapp()._log(
        f"settings save requested by {actor}", "config", user=actor)
    _reject_file_only_settings(payload)
    try:
        _webapp().validate_and_write_config(payload, by=actor)
        _webapp()._log("settings saved successfully", "config", user=actor)
        _webapp()._audit(
            request, "config.write",
               detail={"sections": sorted(k for k in payload if k != "state")})
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(400, _scrub_text(str(exc))) from exc
    except Exception as exc:
        raise HTTPException(400, "Configuration/database validation failed") from exc
    return {"ok": True}


@router.websocket("/api/v1/logs/stream")
async def logs_stream(websocket: WebSocket):
    """Live log stream: the initial backlog plus every new entry.

    Authentication mirrors the REST API (session cookie on the
    handshake, Bearer via query is NOT offered — tokens must not live
    in URLs). Unauthenticated sockets close before accepting.
    """
    token = websocket.cookies.get("teledrive_session") if websocket.cookies else None
    user = None
    if token:
        class _Shim:
            headers = {}
            cookies = {"teledrive_session": token}
        user = _webapp()._get_current_user(_Shim())  # type: ignore[arg-type]
    if user is None:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    # Bootstrap the main-loop reference when lifespan did not run (e.g.
    # test harnesses): the push path in _log needs it for the
    # thread-safe handoff.
    if _webapp()._main_event_loop is None:
        _webapp()._main_event_loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    _webapp()._LOG_WAITERS.add(queue)
    try:
        for entry in list(_webapp().LOG_BUFFER)[-200:]:
            await websocket.send_text(entry)
        while True:
            entry = await queue.get()
            await websocket.send_text(entry)
    except WebSocketDisconnect:
        pass
    finally:
        _webapp()._LOG_WAITERS.discard(queue)


@router.get("/api/v1/logs", tags=["System"], summary="Read recent redacted activity logs")
@router.get("/api/logs", tags=["System"], include_in_schema=False)
def logs(limit: int = Query(default=1000, ge=1, le=1500),
         _: None = Depends(require_auth)):
    combined = list(_webapp().LOG_BUFFER)[-limit:]
    combined = list(reversed(combined))
    entries = []
    for line in combined:
        # Parse "[ts] [user] [source] msg" format.
        m = re.match(r"^\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)$", line)
        if m:
            entries.append({"ts": m.group(1), "user": m.group(2),
                           "source": m.group(3), "message": m.group(4)})
        else:
            entries.append({"ts": "", "user": "", "source": "", "message": line})
    return {"entries": entries}


@router.get("/api/health", tags=["System"], response_model=OKResponse, summary="Liveness health check (unauthenticated)")
def health():
    return {"ok": True}
