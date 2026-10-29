"""A credential is a secret: only an interactive session may manage one.

Found by the third API-review wave. ``POST /api/v1/admin/s3/credentials`` was
reachable by an API key holding only that route's permission, and the handler
passed the permission list straight through. A key with no S3 authority
could therefore mint a credential with all 90 permissions (including
s3:PutBucketPolicy and s3:DeleteBucket) and receive its secret -- a complete
bypass of the delegation ceiling that guards API-key minting. ``PUT`` had the
same hole: a least-privilege credential could be edited to add destructive
permissions.
"""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import web.app as webapp
import web.s3 as gateway
from teledrive.db import connect_database
from teledrive.s3.credentials import S3CredentialStore


@pytest.fixture()
def api(tmp_path, monkeypatch):
    url = str(tmp_path / "credentials.sqlite")
    key = Fernet.generate_key()
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(url))
    monkeypatch.setattr(gateway, "db_connect", lambda: connect_database(url))
    monkeypatch.setattr(webapp, "load_master_key", lambda: key)
    monkeypatch.setattr(gateway, "load_master_key", lambda: key)
    from tests import seed_local_user
    seed_local_user(lambda: connect_database(url),
                    "admin-x", "admin-x-password", "admin")
    webapp.AUTH_FAILURES.clear()
    client = TestClient(webapp.app, base_url="http://localhost")
    yield client, url, key
    client.close()


def _session(client):
    from tests import login_headers
    return {**login_headers(client, "admin-x", "admin-x-password"),
            "x-teledrive-csrf": "1"}


def _mint_key(client, session, scopes):
    reply = client.post("/api/v1/admin/keys", headers=session,
                        json={"name": "narrow", "scopes": scopes})
    assert reply.status_code == 201, reply.text
    return {"Authorization": f"Bearer {reply.json()['token']}",
            "x-teledrive-csrf": "1"}


def test_api_key_cannot_issue_or_edit_s3_credentials(api):
    client, url, master = api
    session = _session(client)

    # A credential to attack with least privilege.
    created = client.post("/api/v1/admin/s3/credentials", headers=session,
                          json={"name": "reader",
                                "permissions": ["s3:GetObject"]})
    assert created.status_code == 201, created.text
    target = created.json()

    key = _mint_key(client, session, [
        "post:/api/v1/admin/s3/credentials",
        "put:/api/v1/admin/s3/credentials/{identifier}",
    ])
    # The listing is admin-only too: names and access keys are metadata an
    # impersonating key should not be able to enumerate.
    assert client.get("/api/v1/admin/s3-credentials",
                      headers=key).status_code == 403

    # Minting a full-power credential is refused and writes nothing.
    escalated = client.post("/api/v1/admin/s3/credentials", headers=key,
                            json={"name": "escalated"})
    assert escalated.status_code == 403, escalated.text
    assert "interactive session" in escalated.text
    assert "secret_key" not in escalated.text

    db = connect_database(url)
    try:
        store = S3CredentialStore(db, master)
        assert not any(c["name"] == "escalated" for c in store.list())
    finally:
        db.close()

    # Editing a read-only credential into a destructive one is refused, and
    # the stored permissions are untouched.
    edited = client.put(f"/api/v1/admin/s3/credentials/{target['id']}",
                        headers=key,
                        json={"permissions": ["s3:GetObject",
                                              "s3:DeleteBucket"]})
    assert edited.status_code == 403, edited.text
    db = connect_database(url)
    try:
        row = [c for c in S3CredentialStore(db, master).list()
               if c["id"] == target["id"]][0]
        assert row["permissions"] == ["s3:GetObject"]
    finally:
        db.close()


def test_omitting_permissions_yields_a_read_only_credential(api):
    """Least privilege by default: an omitted field must not mean "all"."""
    client, url, master = api
    session = _session(client)
    reply = client.post("/api/v1/admin/s3/credentials", headers=session,
                        json={"name": "defaulted"})
    assert reply.status_code == 201, reply.text
    granted = reply.json()["permissions"]
    assert "s3:DeleteBucket" not in granted
    assert "s3:PutBucketPolicy" not in granted
    assert "s3:GetObject" in granted


def test_update_cannot_revive_an_expired_credential(api):
    """Expiry is enforced at SigV4 time, so editing it back is real access."""
    client, url, master = api
    session = _session(client)
    import time
    created = client.post("/api/v1/admin/s3/credentials", headers=session,
                          json={"name": "short-lived",
                                "permissions": ["s3:GetObject"],
                                "expires_at": int(time.time()) + 60})
    assert created.status_code == 201, created.text
    ident = created.json()["id"]

    db = connect_database(url)
    try:
        from sqlalchemy import text
        db.connection.execute(text(
            "UPDATE storage_s3_credentials SET expires_at = 1 WHERE id = :i"),
            {"i": ident})
        db.connection.commit()
    finally:
        db.close()

    revived = client.put(f"/api/v1/admin/s3/credentials/{ident}",
                         headers=session,
                         json={"expires_at": int(time.time()) + 3600})
    assert revived.status_code == 422, revived.text
    assert "Expired" in revived.text

    # And a past or absurd expiry is rejected outright on an active one.
    past = client.put(f"/api/v1/admin/s3/credentials/{ident}",
                      headers=session, json={"name": "x"})
    assert past.status_code in (200, 422)
