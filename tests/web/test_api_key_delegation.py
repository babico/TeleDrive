"""Delegation is a real ceiling: scope AND lifetime.

Found by the API review wave. Two defects are pinned here:

* ``admin:*`` expanded to only the nine curated REST names, so a key issued
  with the "full access" preset was rejected on every admin route -- the
  preset was dead.
* a key could mint a descendant with no expiry (or a longer one) and the
  descendant kept working after the parent was revoked, so revoking the
  parent did not end the authority it had delegated.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
from teledrive.db import connect_database


@pytest.fixture()
def api(tmp_path, monkeypatch):
    path = tmp_path / "delegation.sqlite"
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(path)))
    webapp.AUTH_FAILURES.clear()
    # The bootstrap administrator is created at startup, which a TestClient
    # without a lifespan does not run.
    webapp._create_default_admin()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    yield client
    client.close()


def _session(client):
    """Log in as the hardcoded bootstrap admin and return CSRF headers."""
    reply = client.post("/api/v1/auth/login",
                        headers={"x-teledrive-csrf": "1"},
                        json={"username": "admin", "password": "admin"})
    assert reply.status_code == 200, reply.text
    return {"x-teledrive-csrf": "1"}


def _mint(client, session, scopes, expires_at=None, name="k"):
    body = {"name": name, "scopes": scopes}
    if expires_at is not None:
        body["expires_at"] = expires_at
    reply = client.post("/api/v1/admin/keys", headers=session, json=body)
    assert reply.status_code == 201, reply.text
    return reply.json()


def test_admin_star_covers_the_live_route_table(api):
    """``admin:*`` must be a wildcard over every API route, not nine names."""
    from teledrive.api_keys import expand_scopes
    from web.permissions import PermissionRegistry, route_views

    webapp.permission_registry()
    granted = expand_scopes(["admin:*"])
    live = {entry["name"]
            for entry in PermissionRegistry(route_views(webapp.app)).catalog()}
    assert live, "registry is empty"
    assert live <= granted, sorted(live - granted)


def test_admin_star_key_can_use_an_admin_route(api):
    """The "full access" preset must actually work."""
    session = _session(api)
    key = _mint(api, session, ["admin:*"], name="root")
    headers = {"Authorization": f"Bearer {key['token']}"}
    # Rotating itself is an admin route that needs a route permission.
    reply = api.post(f"/api/v1/admin/keys/{key['id']}/rotate",
                     headers={**headers, "x-teledrive-csrf": "1"})
    assert reply.status_code == 200, reply.text


def test_child_key_cannot_outlive_its_parent(api):
    session = _session(api)
    expires = int(time.time()) + 60
    parent = _mint(api, session, ["post:/api/v1/admin/keys"],
                   expires_at=expires, name="parent")
    headers = {"Authorization": f"Bearer {parent['token']}",
               "x-teledrive-csrf": "1"}

    # A descendant with no expiry would outlive the parent: refused.
    refused = api.post("/api/v1/admin/keys", headers=headers,
                       json={"name": "forever",
                             "scopes": ["post:/api/v1/admin/keys"]})
    assert refused.status_code == 403, refused.text
    assert "expires no later" in refused.text

    # A descendant valid for nine years is equally refused.
    refused = api.post("/api/v1/admin/keys", headers=headers,
                       json={"name": "long", "expires_at": int(time.time())
                             + 9 * 365 * 86400,
                             "scopes": ["post:/api/v1/admin/keys"]})
    assert refused.status_code == 403, refused.text

    # One that expires no later than the parent is allowed.
    allowed = api.post("/api/v1/admin/keys", headers=headers,
                       json={"name": "child", "expires_at": expires - 5,
                             "scopes": ["post:/api/v1/admin/keys"]})
    assert allowed.status_code == 201, allowed.text


def test_revoking_the_parent_ends_the_family(api):
    """A revoked parent's key must not mint anything, ever."""
    session = _session(api)
    parent = _mint(api, session, ["post:/api/v1/admin/keys"], name="parent")
    headers = {"Authorization": f"Bearer {parent['token']}",
               "x-teledrive-csrf": "1"}
    assert api.post("/api/v1/admin/keys", headers=headers,
                    json={"name": "child",
                          "scopes": ["post:/api/v1/admin/keys"]}
                    ).status_code == 201
    assert api.delete(f"/api/v1/admin/keys/{parent['id']}",
                      headers=session).status_code == 200
    denied = api.post("/api/v1/admin/keys", headers=headers,
                      json={"name": "grandchild",
                            "scopes": ["post:/api/v1/admin/keys"]})
    assert denied.status_code == 403, denied.text


def test_never_expiring_parent_may_mint_anything(api):
    """No expiry on the parent means a child cannot outlive it."""
    session = _session(api)
    parent = _mint(api, session, ["post:/api/v1/admin/keys"], name="forever")
    headers = {"Authorization": f"Bearer {parent['token']}",
               "x-teledrive-csrf": "1"}
    reply = api.post("/api/v1/admin/keys", headers=headers,
                     json={"name": "child",
                           "scopes": ["post:/api/v1/admin/keys"]})
    assert reply.status_code == 201, reply.text
