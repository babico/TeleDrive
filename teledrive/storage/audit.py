"""Durable security audit trail.

The in-memory ``LOG_BUFFER`` is a debugging aid: bounded at 1500 entries and
lost on restart, so an investigation could not answer "who revealed this
secret three days ago" or even "who revealed it before the last deploy". The
API review flagged this on the credential-reveal endpoint, and the same
weakness applied to every security-relevant action.

This module is deliberately narrow. It records **security events** only --
actions that change or expose authority -- with the actor, the target and a
small JSON detail blob. It is not a general request log; that stays in the
buffer.

Rules:

* Append-only. There is no update or delete path, by design.
* Never store a secret. A detail value is a name, an id, a count or a
  reason class -- never a key, a token or a password. ``record`` rejects
  values that look like the app's own secret formats.
* Bounded growth: the caller prunes by age; nothing prunes automatically
  during a request, because a write that can block on a DELETE is a write
  that can fail in an incident.
"""
from __future__ import annotations

import json
import re
import time

from sqlalchemy import (BigInteger, Column, Index, Integer, String, Table,
                        Text, delete, insert, select)

from teledrive.db import metadata

audit_events = Table(
    "security_audit_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("occurred_ns", BigInteger, nullable=False),
    Column("actor", String(128), nullable=False),
    Column("action", String(64), nullable=False),
    Column("target", String(512)),
    Column("outcome", String(16), nullable=False),
    Column("detail", Text),
    Column("client_ip", String(64)),
)
Index("ix_security_audit_occurred", audit_events.c.occurred_ns)
Index("ix_security_audit_action", audit_events.c.action,
      audit_events.c.occurred_ns)

# Anything that looks like a credential this application issues or stores.
_SECRET_SHAPES = (
    re.compile(r"td_live_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"td_sess_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bTD[0-9A-F]{20,}\b"),
    re.compile(r"gAAAAA[A-Za-z0-9_\-]{20,}"),          # Fernet token
    re.compile(r"pbkdf2_sha256\$"),
    re.compile(r"1BVts[A-Za-z0-9_\-]{10,}"),           # Telethon session
)

REDACTED = "[redacted]"


def _scrub(value: str) -> str:
    cleaned = value
    for pattern in _SECRET_SHAPES:
        cleaned = pattern.sub(REDACTED, cleaned)
    return cleaned.replace("\n", " ").replace("\r", " ")[:500]


def record(db, *, action: str, actor: str, outcome: str = "ok",
           target: str | None = None, detail: dict | None = None,
           client_ip: str | None = None) -> None:
    """Append one security event. Never raises.

    An audit write must not be able to fail the operation it describes: a
    refused reveal that crashed the endpoint would itself be a denial of
    service. Failures are swallowed and the caller keeps the in-memory line.
    """
    payload = None
    if detail:
        try:
            payload = _scrub(json.dumps(detail, sort_keys=True,
                                        default=str))[:4000]
        except Exception:
            payload = None
    try:
        db.connection.execute(insert(audit_events).values(
            occurred_ns=time.time_ns(),
            actor=_scrub(str(actor))[:128] or "unknown",
            action=_scrub(str(action))[:64],
            target=(_scrub(str(target))[:512] if target is not None else None),
            outcome=_scrub(str(outcome))[:16],
            detail=payload,
            client_ip=(str(client_ip)[:64] if client_ip else None),
        ))
        db.commit()
    except Exception:
        try:
            db.connection.rollback()
        except Exception:
            pass


def recent(db, *, limit: int = 100, action: str | None = None,
           actor: str | None = None) -> list[dict]:
    """Newest-first window, for the admin UI and for tests."""
    statement = select(
        audit_events.c.occurred_ns, audit_events.c.actor,
        audit_events.c.action, audit_events.c.target,
        audit_events.c.outcome, audit_events.c.detail,
        audit_events.c.client_ip,
    ).order_by(audit_events.c.occurred_ns.desc()).limit(max(1, min(limit, 1000)))
    if action is not None:
        statement = statement.where(audit_events.c.action == action)
    if actor is not None:
        statement = statement.where(audit_events.c.actor == actor)
    rows = db.connection.execute(statement).mappings().all()
    return [dict(row) for row in rows]


def prune(db, *, older_than_ns: int) -> int:
    """Delete events older than a cutoff. Called by an operator, not a request."""
    result = db.connection.execute(delete(audit_events).where(
        audit_events.c.occurred_ns < int(older_than_ns)))
    db.commit()
    return result.rowcount or 0
