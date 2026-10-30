"""Telegram session and channel management.

Paths are absolute: ``APIRouter`` has no prefix because ``web.permissions``
matches the full route path.

App-owned state is read through ``_webapp()`` at call time so the existing
monkeypatch-based tests (``webapp.db_connect``, ``webapp._log``,
``webapp.mtproto_storage_runtime``) still take effect, and because importing
``web.app`` at module scope would be a cycle: ``web.app`` imports this module
at the end of its own body.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel

from teledrive.stores import telegram_accounts as _accounts
from teledrive.stores import telegram_pending as _pending_store
from web.deps import _same_origin, require_auth
from web.errors import _telegram_error_response

router = APIRouter()


def _webapp():
    """Resolve app-owned state at call time (monkeypatch-friendly)."""
    import web.app as module
    return module


# --- Telegram session management (WebUI-driven) -----------------------------

def _mask_phone(phone: str | None) -> str:
    if not phone:
        return "-"
    digits = str(phone).strip()
    if len(digits) <= 6:
        return "***"
    return digits[:4] + "***" + digits[-2:]


async def _probe_telegram_session(api_id: int, api_hash: str,
                                  session_string: str) -> bool:
    """One lightweight authorization probe: connect + is_authorized."""
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    try:
        client = TelegramClient(StringSession(session_string), api_id,
                                api_hash, receive_updates=False,
                                flood_sleep_threshold=0)
    except Exception:
        return False
    try:
        await client.connect()
        return bool(await client.is_user_authorized())
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def _store_session_health(account: str, authorized: bool) -> None:
    conn = _webapp().db_connect()
    try:
        _accounts.record_health(conn, account, authorized)
    finally:
        conn.close()


def _probe_account_now(account: str) -> dict:
    """Probe one account synchronously (endpoint context)."""
    import asyncio
    conn = _webapp().db_connect()
    try:
        row = _accounts.get_session(conn, account)
    finally:
        conn.close()
    if row is None:
        raise HTTPException(404, "Unknown Telegram session account")
    api_id, api_hash, session_string = (row["api_id"], row["api_hash"],
                                       row["session_string"])
    try:
        authorized = asyncio.run(
            _probe_telegram_session(api_id, api_hash, session_string))
    except Exception as exc:
        _webapp()._log(f"session health: account={account} probe error "
             f"{type(exc).__name__}", "telegram-session")
        authorized = False
    _store_session_health(account, authorized)
    if not authorized:
        _webapp()._log(f"session health: account={account} UNAUTHORIZED "
             "(expired/revoked); re-login required", "telegram-session")
    return {"account": account, "authorized": authorized,
            "health_checked_at": int(time.time())}


async def telegram_session_health_loop() -> None:
    """Probe every Telegram session for expiry/revocation, periodically.

    A dead session silently turns uploads into failures; the probe keeps
    an explicit authorized flag on every account row and logs a warning
    the moment a previously-healthy session dies.
    """
    while True:
        try:
            conn = _webapp().db_connect()
            try:
                rows = [
                    (r["account"], r["api_id"], r["api_hash"],
                     r["session_string"], r["authorized"])
                    for r in _accounts.all_session_credentials(conn)]
            finally:
                conn.close()
            for account, api_id, api_hash, session_string, previous in rows:
                try:
                    authorized = await _probe_telegram_session(
                        int(api_id), str(api_hash), str(session_string))
                except Exception as exc:
                    _webapp()._log(f"session health: account={account} probe error "
                         f"{type(exc).__name__}", "telegram-session")
                    continue
                _store_session_health(str(account), authorized)
                if not authorized and previous not in (0, None):
                    _webapp()._log(f"session health: account={account} UNAUTHORIZED "
                         "(expired/revoked); re-login required",
                         "telegram-session")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _webapp()._log("session health scheduler: " + type(exc).__name__,
                 "scheduler")
        await asyncio.sleep(1800)


@router.put("/api/v1/admin/storage/telegram-sessions/{account}/quota",
         tags=["Storage jobs"],
         summary="Set an account's soft quota (preferred routing headroom)")
def set_telegram_session_quota(account: str, request: Request,
                               payload: dict = Body(...),
                               _: None = Depends(require_auth)):
    _same_origin(request)
    account = account.strip()
    if not account:
        raise HTTPException(400, "account is required")
    raw = payload.get("soft_quota_bytes")
    if raw is not None:
        try:
            quota = int(raw)
        except (TypeError, ValueError):
            raise HTTPException(422, "soft_quota_bytes must be an integer "
                                     "or null") from None
        if not 0 <= quota <= 2**63 - 1:
            raise HTTPException(422, "soft_quota_bytes out of range")
    else:
        quota = None
    conn = _webapp().db_connect()
    try:
        changed = _accounts.set_soft_quota(conn, account, quota)
    finally:
        conn.close()
    if not changed:
        raise HTTPException(404, "Unknown Telegram session account")
    _webapp()._log(f"account soft quota set: account={account} "
         f"quota={quota if quota is not None else 'unlimited'}", "storage")
    return {"ok": True, "account": account, "soft_quota_bytes": quota}


@router.post("/api/v1/admin/storage/telegram-sessions/{account}/health-check",
          tags=["Storage jobs"],
          summary="Probe one Telegram session for authorization now")
def telegram_session_health_check(account: str, request: Request,
                                  _: None = Depends(require_auth)):
    _same_origin(request)
    account = account.strip()
    if not account:
        raise HTTPException(400, "account is required")
    result = _probe_account_now(account)
    return {"ok": True, **result}


@router.get("/api/v1/admin/storage/telegram-sessions", tags=["Storage jobs"],
         summary="List all Telegram sessions with per-account health")
def list_telegram_sessions(_: None = Depends(require_auth)):
    now_ms = int(time.time() * 1000)
    conn = _webapp().db_connect()
    try:
        rows = [(r["account"], r["api_id"], r["phone"], r["channel"],
                 r["strategy"], r["created_at"], r["updated_at"],
                 r["authorized"], r["health_checked_at"],
                 r["soft_quota_bytes"])
                for r in _accounts.list_sessions(conn)]
        # Usage, cooldowns and flood observations live in the storage
        # catalog tables; degrade gracefully when this deployment's web
        # database does not carry them.
        #
        # Raw by design: four read-only GROUP BY aggregates (current usage,
        # retained backlog, cooldowns, flood observations) over tables owned
        # by the storage and MTProto layers. Nothing mutates here, and each
        # query is tolerant of a table this deployment does not carry.
        from sqlalchemy import text as _text
        # CURRENT usage joins the object heads: deleted-but-retained
        # objects (physical GC is owner-gated) do NOT count. The
        # physical chunk totals are reported separately as the retained
        # backlog the owner could eventually reclaim through GC.
        usage: dict[str, tuple[int, int]] = {}
        retained: dict[str, tuple[int, int]] = {}
        cooldowns: dict[str, int] = {}
        floods: dict[str, int] = {}
        try:
            for acct, objects, total in conn.connection.execute(_text(
                    "SELECT c.account, COUNT(DISTINCT c.object_id), "
                    "SUM(c.size) FROM storage_chunks c "
                    "JOIN storage_object_heads h "
                    "ON h.object_id = c.object_id GROUP BY c.account")):
                usage[str(acct)] = (int(objects or 0), int(total or 0))
        except Exception:
            pass
        try:
            for acct, objects, total in conn.connection.execute(_text(
                    "SELECT account, COUNT(DISTINCT object_id), SUM(size) "
                    "FROM storage_chunks GROUP BY account")):
                retained[str(acct)] = (int(objects or 0), int(total or 0))
        except Exception:
            pass
        try:
            for acct, until in conn.connection.execute(_text(
                    "SELECT account, MAX(cooldown_until_ms) FROM "
                    "storage_mtproto_chat_cooldowns GROUP BY account")):
                cooldowns[str(acct)] = int(until or 0)
        except Exception:
            pass
        try:
            for acct, obs in conn.connection.execute(_text(
                    "SELECT account, SUM(observations) FROM "
                    "storage_mtproto_flood_observations GROUP BY account")):
                floods[str(acct)] = int(obs or 0)
        except Exception:
            pass
    finally:
        conn.close()
    sessions = []
    for account, api_id, phone, channel, strategy, created, updated, \
            authorized, checked, soft_quota in rows:
        objects, total = usage.get(str(account), (0, 0))
        retained_objects, retained_total = retained.get(str(account), (0, 0))
        remaining_ms = max(0, cooldowns.get(str(account), 0) - now_ms)
        sessions.append({
            "account": account, "api_id": api_id,
            "phone": _mask_phone(phone), "channel": channel,
            "strategy": strategy or "round_robin",
            "created_at": created, "updated_at": updated,
            "objects": objects, "bytes": total,
            # Physical Telegram storage per account. The difference to
            # the current numbers is the retained (GC-reclaimable)
            # backlog: deleted objects whose media survives until the
            # owner authorizes physical GC.
            "retained_objects": retained_objects,
            "retained_bytes": retained_total,
            "cooldown_remaining_s": remaining_ms // 1000,
            "flood_observations": floods.get(str(account), 0),
            "authorized": None if authorized is None else bool(authorized),
            "health_checked_at": checked,
            "soft_quota_bytes": soft_quota,
        })
    try:
        active_strategy = str(((_webapp().read_raw_config() or {})
                               .get("storage") or {})
                               .get("strategy") or "round_robin")
    except Exception:
        active_strategy = "round_robin"
    return {"sessions": sessions, "count": len(sessions),
            "strategy": active_strategy}


@router.delete("/api/v1/admin/storage/telegram-sessions/{account}",
            tags=["Storage jobs"],
            summary="Delete one account's Telegram session")
def delete_telegram_session_account(account: str, request: Request,
                                    force: bool = False,
                                    _: None = Depends(require_auth)):
    _same_origin(request)
    account = account.strip()
    if not account:
        raise HTTPException(400, "account is required")
    # Soft-guard: an account that still stores chunks must be deleted
    # explicitly with force=true. The catalog rows survive either way,
    # but reads of those objects need the session re-authorized first.
    conn = _webapp().db_connect()
    try:
        # Deliberately raw: this is a read-only aggregate (COUNT DISTINCT +
        # SUM) over storage_chunks, a table owned by the storage layer. It
        # has no store because nothing mutates it here and a typed function
        # would only wrap one SUM that no other caller needs.
        from sqlalchemy import text as _text
        objects, total = 0, 0
        try:
            guard = conn.connection.execute(_text(
                "SELECT COUNT(DISTINCT object_id), SUM(size) FROM "
                "storage_chunks WHERE account = :account"
            ), {"account": account}).fetchone()
            if guard is not None:
                objects, total = int(guard[0] or 0), int(guard[1] or 0)
        except Exception:
            pass
        if objects and not force:
            raise HTTPException(409, {
                "message": "This account still stores objects in the "
                           "catalog. Deleting the session stops new "
                           "uploads from using it, but reading those "
                           "objects requires re-authorizing the account.",
                "account": account, "objects": objects, "bytes": total,
            })
        deleted = conn.connection.execute(_text(
            "DELETE FROM telegram_sessions WHERE account = :account"
        ), {"account": account}).rowcount
        conn.connection.commit()
    finally:
        conn.close()
    _webapp()._log(f"telegram session deleted: account={account} rows={deleted}",
         "storage")
    _webapp()._schedule_storage_runtime_reload()
    return {"ok": True, "deleted": deleted, "account": account}


@router.get("/api/v1/admin/storage/telegram-session", tags=["Storage jobs"],
         summary="Read the active Telegram USER session status")
def get_telegram_session(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        latest = _accounts.latest_session(conn)
        row = (None if latest is None else
               (latest["id"], latest["api_id"], latest["phone"],
                latest["account"], latest["channel"], latest["strategy"],
                latest["created_at"], latest["updated_at"]))
        if row is None:
            return {"configured": False, "session": None}
        return {
            "configured": True,
            "session": {
                "id": row[0], "api_id": row[1], "phone": row[2],
                "account": row[3], "channel": row[4], "strategy": row[5],
                "created_at": row[6], "updated_at": row[7],
            },
        }
    finally:
        conn.close()


class TelegramSessionRequestCode(BaseModel):
    api_id: int
    api_hash: str
    phone: str
    channel: str | None = None
    strategy: str | None = None


# Wrong-code budget per pending login. Five-digit codes: 5 tries leaves a
# 1-in-2000 chance of a blind guess, and Telegram's own FloodWait makes the
# real attack far slower than that.
_MAX_VERIFY_ATTEMPTS = 5


def _record_verify_attempt(token: str) -> None:
    """Count one failed verification without extending the request's life."""
    conn = _webapp().db_connect()
    try:
        _pending_store.bump_attempts(conn, token)
    except Exception:
        pass
    finally:
        conn.close()


def _consume_pending_session_token(token: str) -> None:
    conn = _webapp().db_connect()
    try:
        _pending_store.consume(conn, token)
    finally:
        conn.close()


def _record_flood_wait(scope: str, seconds: int, detail: str = "") -> dict:
    """Persist a Telegram FloodWait and log the full countdown picture."""
    now = int(time.time())
    seconds = max(1, int(seconds))
    expires = now + seconds
    conn = _webapp().db_connect()
    try:
        _accounts.record_flood_wait(conn, scope=scope, wait_seconds=seconds,
                                    detail=detail, now=now)
    finally:
        conn.close()
    _webapp()._log(
        f"FLOODWAIT scope={scope} wait={seconds}s "
        f"({seconds // 3600}h {(seconds % 3600) // 60}m) "
        f"started={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))} "
        f"expires={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires))}",
        "telegram-session",
    )
    return {"scope": scope, "started_at": now, "wait_seconds": seconds,
            "expires_at": expires, "remaining_seconds": seconds,
            "detail": detail}


def _flood_wait_status() -> dict:
    """Latest FloodWait record with the live remaining countdown."""
    conn = _webapp().db_connect()
    try:
        last = _accounts.last_flood_wait(conn)
        row = (None if last is None else
               (last["scope"], last["started_at"], last["wait_seconds"],
                last["expires_at"], last["detail"]))
    finally:
        conn.close()
    if row is None:
        return {"active": False, "remaining_seconds": 0, "last": None}
    now = int(time.time())
    remaining = max(0, int(row[3]) - now)
    return {
        "active": remaining > 0,
        "remaining_seconds": remaining,
        "now": now,
        "last": {"scope": row[0], "started_at": row[1],
                 "wait_seconds": row[2], "expires_at": row[3],
                 "remaining_seconds": remaining, "detail": row[4]},
    }


@router.get("/api/v1/admin/storage/telegram-session/floodwait",
         tags=["Storage jobs"],
         summary="Read the current Telegram FloodWait status and countdown")
def telegram_floodwait_status(_: None = Depends(require_auth)):
    return _flood_wait_status()


@router.post("/api/v1/admin/storage/telegram-session/request-code",
          tags=["Storage jobs"], summary="Send a Telegram login code to the phone")
def request_telegram_session_code(payload: TelegramSessionRequestCode,
                                 request: Request,
                                 _: None = Depends(require_auth)):
    from telethon.errors import FloodWaitError
    _same_origin(request)
    _webapp()._log(f"request-code: api_id={payload.api_id} channel={payload.channel}", "telegram-session")
    if payload.api_id <= 0 or not payload.api_hash or not payload.phone:
        raise HTTPException(400, "api_id, api_hash and phone are required")
    import secrets as _secrets
    token = _secrets.token_urlsafe(16)
    now = int(time.time())
    # Resolve active channel if not provided.
    channel = payload.channel
    if not channel:
        try:
            conn_ch = _webapp().db_connect()
            try:
                from sqlalchemy import text as _t
                row = conn_ch.connection.execute(_t(
                    "SELECT channel_id FROM telegram_channels WHERE is_active=1 LIMIT 1"
                )).fetchone()
                if row is None:
                    row = conn_ch.connection.execute(_t(
                        "SELECT channel_id FROM telegram_channels ORDER BY id LIMIT 1"
                    )).fetchone()
                if row is not None:
                    channel = row[0]
            finally:
                conn_ch.close()
        except Exception:
            pass
    # Send the code via Telethon (synchronously).
    phone_code_hash = None
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        import asyncio

        async def _send():
            client = TelegramClient(StringSession(), payload.api_id, payload.api_hash,
                                    receive_updates=False, flood_sleep_threshold=0)
            await client.connect()
            result = await client.send_code_request(payload.phone)
            h = result.phone_code_hash
            # The unauthorized session carries the auth key that
            # phone_code_hash is bound to. verify-code MUST sign in with
            # this exact session; a fresh one always gets
            # PHONE_CODE_EXPIRED from Telegram.
            sess = client.session.save()
            await client.disconnect()
            return h, sess

        phone_code_hash, request_session = asyncio.run(_send())
    except FloodWaitError as exc:
        info = _record_flood_wait(
            "send_code", int(getattr(exc, "seconds", 0)),
            "Telegram login code request")
        raise HTTPException(429, {
            "message": "Telegram FloodWait: too many code requests. "
                       "The code request is rate-limited by Telegram.",
            **info,
        }) from exc
    except Exception as exc:
        raise _telegram_error_response(exc, "request-code") from exc

    # Store pending state in DB (persistent across restarts).
    conn = _webapp().db_connect()
    try:
        # One transaction: the stale-row purge and the new request commit
        # together when create() commits.
        _pending_store.purge_older_than(conn, now - 300, commit=False)
        _pending_store.create(
            conn, token=token, api_id=payload.api_id,
            api_hash=payload.api_hash, phone=payload.phone,
            phone_code_hash=phone_code_hash, session_string=request_session,
            channel=channel, strategy=payload.strategy or "round_robin",
            created_at=now)
    finally:
        conn.close()

    return {"token": token, "phone": payload.phone,
            "expires_in": 300}


class TelegramSessionVerifyCode(BaseModel):
    token: str
    code: str
    password: str | None = None


@router.post("/api/v1/admin/storage/telegram-session/verify-code",
          tags=["Storage jobs"], summary="Verify the code and save the session")
def verify_telegram_session_code(payload: TelegramSessionVerifyCode,
                                request: Request,
                                _: None = Depends(require_auth)):
    from telethon.errors import FloodWaitError, PhoneCodeExpiredError
    _same_origin(request)
    _webapp()._log(f"verify-code: token={payload.token[:8]}...", "telegram-session")

    conn = _webapp().db_connect()
    try:
        pending = _pending_store.get(conn, payload.token)
    finally:
        conn.close()
    if pending is None:
        raise HTTPException(404, "No pending code request (expired, invalid "
                                 "token, or already used). Request a new code.")
    api_id, api_hash, phone = (pending["api_id"], pending["api_hash"],
                               pending["phone"])
    phone_code_hash = pending["phone_code_hash"]
    request_session = pending["session_string"]
    channel, strategy = pending["channel"], pending["strategy"]
    created_at, attempts = pending["created_at"], pending["attempts"]
    # A Telegram login code is five digits. Telegram throttles the send, but
    # not the verify side reliably, so cap wrong attempts here: past the
    # budget the pending request is destroyed and a fresh code is required.
    if int(attempts or 0) >= _MAX_VERIFY_ATTEMPTS:
        _consume_pending_session_token(payload.token)
        _webapp()._log(f"verify-code BLOCKED: {int(attempts)} failed attempts; "
             f"pending request destroyed", "telegram-session")
        raise HTTPException(
            429,
            "Too many incorrect codes for this request. Request a new code.",
        )
    _webapp()._log(f"verify-code: token={payload.token[:8]}... request_age="
         f"{int(time.time()) - int(created_at)}s", "telegram-session")
    if int(time.time()) - int(created_at) > 300:
        _consume_pending_session_token(payload.token)
        raise HTTPException(410, "Code request expired; request a new one")
    if not request_session:
        # Pending row from before the session-binding fix: the hash can
        # never be verified without the requesting session.
        _consume_pending_session_token(payload.token)
        raise HTTPException(410, "This code request predates a server fix; "
                                 "request a new code")
    if not payload.code:
        raise HTTPException(400, "code is required")
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        import asyncio

        async def _verify():
            # Reuse the code-REQUEST session: phone_code_hash is bound to
            # its auth key. A fresh session here is the classic cause of
            # PhoneCodeExpiredError on a brand-new code.
            client = TelegramClient(StringSession(request_session), api_id, api_hash,
                                    receive_updates=False, flood_sleep_threshold=0)
            await client.connect()
            # Telethon's sign_in IGNORES `password` when a `code` is given
            # (elif code: branch in telethon/client/auth.py). The 2FA step
            # is a second, separate sign_in(password=...) call after
            # SessionPasswordNeededError — exactly what client.start()
            # does internally. One code attempt only; Telegram allows ~3.
            from telethon.errors import SessionPasswordNeededError
            try:
                await client.sign_in(phone, code=payload.code,
                                     phone_code_hash=phone_code_hash)
            except SessionPasswordNeededError:
                if not payload.password:
                    raise
                await client.sign_in(password=payload.password)
            if not await client.is_user_authorized():
                raise RuntimeError("Sign-in did not authorize the user")
            me = await client.get_me()
            if me is None or getattr(me, "bot", False):
                raise RuntimeError("Use a real Telegram USER session, not a bot token")
            session_string = client.session.save()
            await client.disconnect()
            return session_string, me

        session_string, me = asyncio.run(_verify())
    except FloodWaitError as exc:
        info = _record_flood_wait(
            "sign_in", int(getattr(exc, "seconds", 0)),
            "Telegram login verification")
        raise HTTPException(429, {
            "message": "Telegram FloodWait: the verification is "
                       "rate-limited by Telegram.",
            **info,
        }) from exc
    except PhoneCodeExpiredError as exc:
        # The hash is burned for good: retrying with this token can never
        # succeed, so consume it and force a fresh code request.
        _consume_pending_session_token(payload.token)
        _webapp()._log("verify-code FAILED: PhoneCodeExpiredError: the code has "
             "expired", "telegram-session")
        raise HTTPException(410, "The code has expired. Request a new code "
                                 "and use the code from the NEWEST Telegram "
                                 "message (each request invalidates all "
                                 "previous codes).") from exc
    except Exception as exc:
        # A wrong code must NOT consume the pending request outright -- the
        # user can retry -- but the attempt is counted, and the counter is
        # what eventually destroys it (see _MAX_VERIFY_ATTEMPTS).
        _record_verify_attempt(payload.token)
        raise _telegram_error_response(exc, "verify-code") from exc
    # Success: consume the pending token.
    _consume_pending_session_token(payload.token)

    # Resolve the channel (optional).
    account = getattr(me, "username", None) or f"user-{me.id}"
    strategy = strategy or "round_robin"
    now = int(time.time())
    conn = _webapp().db_connect()
    try:
        # One row per account: the store updates in place, which is what the
        # previous delete-then-insert achieved without the window in between.
        _accounts.upsert_session(
            conn, api_id=api_id, api_hash=api_hash, phone=phone,
            session_string=session_string, account=account,
            channel=channel, strategy=strategy, now=now)
    finally:
        conn.close()

    # Create or activate a channel entry for this session.
    if channel:
        conn2 = _webapp().db_connect()
        try:
            _accounts.upsert_channel_by_channel_id(
                conn2, name=channel, channel_id=channel, strategy=strategy,
                scratch_dir="/data/tmp", active=True)
        finally:
            conn2.close()

    # Also write the session file so the existing file-based runtime works.
    sessions_dir = _webapp().AUTH_DIR.parent / "sessions"
    session_file = f"{sessions_dir}/{account}.session"
    try:
        _webapp()._secure_mkdir(sessions_dir)
        _webapp()._secure_write(Path(session_file), session_string + "\n")
    except Exception:
        pass

    _webapp()._log(f"session verified and saved: account={account} user_id={me.id} channel={channel}", "telegram-session")
    _webapp()._schedule_storage_runtime_reload()
    return {
        "ok": True,
        "account": account,
        "user_id": me.id,
        "session_file": session_file,
    }


@router.delete("/api/v1/admin/storage/telegram-session", tags=["Storage jobs"],
            summary="Revoke the stored Telegram session")
def delete_telegram_session(request: Request, _: None = Depends(require_auth)):
    _same_origin(request)
    _webapp()._log("revoke telegram session", "storage")
    conn = _webapp().db_connect()
    try:
        for existing in _accounts.list_sessions(conn):
            _accounts.delete_session(conn, existing["account"])
    finally:
        conn.close()
    _webapp()._schedule_storage_runtime_reload()
    return {"ok": True}


# --- Telegram channel management (multi-channel) ----------------------------

@router.get("/api/v1/admin/storage/channels", tags=["Storage jobs"],
         summary="List configured Telegram storage channels")
def list_telegram_channels(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        rows = [(r["id"], r["name"], r["channel_id"], r["strategy"],
                 r["scratch_dir"], 1 if r["is_active"] else 0,
                 r["created_at"], r["updated_at"])
                for r in _accounts.list_channels(conn)]
        return {"channels": [
            {"id": r[0], "name": r[1], "channel_id": r[2], "strategy": r[3],
             "scratch_dir": r[4], "is_active": bool(r[5]),
             "created_at": r[6], "updated_at": r[7]} for r in rows]}
    finally:
        conn.close()


class TelegramChannelCreate(BaseModel):
    name: str
    channel_id: str
    strategy: str | None = None
    scratch_dir: str | None = None


@router.post("/api/v1/admin/storage/channels", tags=["Storage jobs"],
          status_code=201, summary="Add a Telegram storage channel")
def create_telegram_channel(payload: TelegramChannelCreate, request: Request,
                           _: None = Depends(require_auth)):
    _same_origin(request)
    _webapp()._log(f"create channel: name={payload.name} channel_id={payload.channel_id}", "storage")
    if not payload.name or not payload.channel_id:
        raise HTTPException(400, "name and channel_id are required")
    strategy = (payload.strategy or "round_robin").strip().lower()
    if strategy not in ("single", "round_robin", "failover", "parallel"):
        raise HTTPException(400, "invalid strategy")
    now = int(time.time())
    conn = _webapp().db_connect()
    try:
        new_id = _accounts.create_channel(
            conn, name=payload.name, channel_id=payload.channel_id,
            strategy=strategy,
            scratch_dir=payload.scratch_dir or "/data/tmp", now=now)
    finally:
        conn.close()
    return {"id": new_id, "name": payload.name, "channel_id": payload.channel_id}


@router.delete("/api/v1/admin/storage/channels/{channel_id}", tags=["Storage jobs"],
            summary="Remove a Telegram storage channel")
def delete_telegram_channel(channel_id: int, request: Request,
                           _: None = Depends(require_auth)):
    _same_origin(request)
    _webapp()._log(f"delete channel: id={channel_id}", "storage")
    conn = _webapp().db_connect()
    try:
        _accounts.delete_channel(conn, channel_id)
    finally:
        conn.close()
    return {"ok": True}


@router.put("/api/v1/admin/storage/strategy", tags=["Storage jobs"],
         summary="Set the cross-account upload routing strategy")
def set_storage_strategy(request: Request, payload: dict = Body(...),
                         _: None = Depends(require_auth)):
    _same_origin(request)
    strategy = str(payload.get("strategy", "")).strip().lower()
    if strategy not in ("single", "round_robin", "failover", "parallel"):
        raise HTTPException(400, "Strategy must be one of single, "
                                 "round_robin, failover, parallel")
    cfg = _webapp().read_raw_config()
    if not isinstance(cfg, dict):
        raise HTTPException(400, "Configuration is not readable")
    # Surgical single-key update: a full config validation would also
    # demand an existing upload source_dir, which is unrelated to the
    # routing strategy. The value itself is whitelisted above.
    cfg.setdefault("storage", {})["strategy"] = strategy
    tmp = _webapp().CONFIG_PATH.with_suffix(_webapp().CONFIG_PATH.suffix + ".tmp")
    _webapp()._secure_write(tmp, yaml.safe_dump(cfg, sort_keys=False))
    os.replace(tmp, _webapp().CONFIG_PATH)
    _webapp()._reload_service_settings()
    _webapp()._log(f"storage strategy set: {strategy} (runtime reloaded)", "config")
    _webapp()._schedule_storage_runtime_reload()
    return {"ok": True, "strategy": strategy}


@router.get("/api/v1/admin/storage/replication", tags=["Storage jobs"],
         summary="Cross-account replication status and coverage")
def get_replication_status(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        coverage = _webapp().BucketCatalog(_webapp().ManifestStore(conn)).manifests.replica_coverage()
    finally:
        conn.close()
    try:
        account = str(((_webapp().read_raw_config() or {}).get("storage") or {})
                      .get("replica_account") or "").strip() or None
    except Exception:
        account = None
    runtime_account = getattr(_webapp().mtproto_storage_runtime, "replica_account", None)
    return {
        "account": account,
        "runtime_account": runtime_account,
        "enabled": bool(runtime_account),
        "coverage": coverage,
    }


@router.put("/api/v1/admin/storage/replication", tags=["Storage jobs"],
         summary="Set or disable the cross-account replication target")
def set_replication_account(request: Request, payload: dict = Body(...),
                            _: None = Depends(require_auth)):
    _same_origin(request)
    account = str(payload.get("account", "")).strip()
    if account:
        conn = _webapp().db_connect()
        try:
            if not _accounts.has_session(conn, account):
                raise HTTPException(404, "Unknown Telegram session account")
        finally:
            conn.close()
    cfg = _webapp().read_raw_config()
    if not isinstance(cfg, dict):
        raise HTTPException(400, "Configuration is not readable")
    # Surgical single-key update, mirroring the strategy setter. An
    # account that is not among the loaded credential sets degrades to
    # disabled at runtime (with a log) rather than failing startup.
    cfg.setdefault("storage", {})["replica_account"] = account
    tmp = _webapp().CONFIG_PATH.with_suffix(_webapp().CONFIG_PATH.suffix + ".tmp")
    _webapp()._secure_write(tmp, yaml.safe_dump(cfg, sort_keys=False))
    os.replace(tmp, _webapp().CONFIG_PATH)
    _webapp()._reload_service_settings()
    _webapp()._log(f"storage replica account set: {account or '(disabled)'} "
         "(runtime reloaded)", "config")
    _webapp()._schedule_storage_runtime_reload()
    return {"ok": True, "account": account or None}


@router.post("/api/v1/admin/storage/replication/repair", tags=["Storage jobs"],
          summary="Re-send missing replica chunks for under-replicated objects")
async def repair_replication(request: Request, payload: dict = Body(None),
                             _: None = Depends(require_auth)):
    _same_origin(request)
    try:
        limit = int((payload or {}).get("limit", 5))
    except (TypeError, ValueError):
        limit = 5
    limit = max(1, min(limit, 25))
    conn = _webapp().db_connect()
    try:
        manifests = _webapp().BucketCatalog(_webapp().ManifestStore(conn)).manifests
        missing = manifests.objects_missing_replicas(limit=limit)
        if not missing:
            return {"ok": True, "repaired_objects": 0, "chunks": 0}
        transport = _webapp().storage_transport(conn)
        await transport.verify_target()
        engine = _webapp().TelegramObjectStorage(
            manifests, transport, chunk_size=_webapp().RECOMMENDED_CHUNK_SIZE)
        repaired_objects = 0
        total_chunks = 0
        errors = []
        for object_id in missing:
            try:
                count = await engine.repair_replicas(object_id)
                if count:
                    repaired_objects += 1
                    total_chunks += count
            except Exception as exc:
                errors.append({"object_id": object_id,
                               "error": type(exc).__name__})
        if errors:
            _webapp()._log(f"replica repair finished with {len(errors)} object "
                 "error(s)", "storage")
        return {"ok": True, "repaired_objects": repaired_objects,
                "chunks": total_chunks, "errors": errors}
    finally:
        conn.close()


@router.post("/api/v1/admin/storage/channels/{channel_id}/activate",
          tags=["Storage jobs"], summary="Set the active write channel")
def activate_telegram_channel(channel_id: int, request: Request,
                             _: None = Depends(require_auth)):
    _same_origin(request)
    _webapp()._log(f"activate channel: id={channel_id}", "storage")
    conn = _webapp().db_connect()
    try:
        _accounts.activate_channel(conn, channel_id)
    finally:
        conn.close()
    _webapp()._schedule_storage_runtime_reload()
    return {"ok": True}


@router.get("/api/v1/admin/storage/active-channel", tags=["Storage jobs"],
         summary="Read the active write channel")
def get_active_channel(_: None = Depends(require_auth)):
    conn = _webapp().db_connect()
    try:
        active = _accounts.list_channels(conn, active_only=True)
        row = (None if not active else
               (active[0]["id"], active[0]["name"], active[0]["channel_id"],
                active[0]["strategy"], active[0]["scratch_dir"]))
        if row is None:
            # Fall back to first channel
            row = conn.connection.execute(_text(
                "SELECT id, name, channel_id, strategy, scratch_dir FROM "
                "telegram_channels ORDER BY id LIMIT 1"
            )).fetchone()
        if row is None:
            return {"active": None}
        return {"active": {"id": row[0], "name": row[1], "channel_id": row[2],
                           "strategy": row[3], "scratch_dir": row[4]}}
    finally:
        conn.close()
