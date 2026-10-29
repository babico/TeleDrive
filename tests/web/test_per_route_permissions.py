"""Unified per-endpoint permissions: every API route is individually
permissionable and bearer keys work on ANY route, not just the REST
object surface. Session role behaviour is covered by test_auth_rbac.py
and test_auth_single_model.py."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from teledrive.db import connect_database
import web.app as webapp
from web.permissions import CURATED_PERMISSIONS, PermissionRegistry


@pytest.fixture()
def api(tmp_path, monkeypatch):
    path = tmp_path / "per-route.sqlite"
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(path)))
    from tests import seed_local_user
    seed_local_user(lambda: connect_database(str(path)),
                    "ci-admin", "ci-local-password-1234", "admin")
    webapp.AUTH_FAILURES.clear()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    yield client, path
    client.close()


def _admin_headers(client):
    from tests import login_headers
    return login_headers(client, "ci-admin", "ci-local-password-1234")


def create_key(client, scopes):
    res = client.post("/api/v1/admin/keys",
        headers={**_admin_headers(client), "x-teledrive-csrf": "1"},
        json={"name": "per-route", "scopes": scopes})
    assert res.status_code == 201, res.text
    return res.json()


def test_registry_covers_every_api_route_and_never_drifts():
    registry = PermissionRegistry(webapp.app.routes)
    catalog = registry.catalog()
    assert catalog, "registry is empty"
    names = [entry["name"] for entry in catalog]
    assert len(names) == len(set(names)), "duplicate permission names"
    # The curated short names must survive as the permissions of their
    # exact routes (issued keys depend on them).
    for (method, path), name in CURATED_PERMISSIONS.items():
        assert registry.permission_for(method, path) == name
    # Concrete requests resolve to exactly one route permission.
    assert registry.permission_for(
        "GET", "/api/v1/admin/storage/buckets") == \
        "get:/api/v1/admin/storage/buckets"
    assert registry.permission_for(
        "GET", "/api/v1/admin/storage/buckets/some-bucket/quota") == \
        "get:/api/v1/admin/storage/buckets/{bucket}/quota"
    # Params with special characters still match the template.
    assert registry.permission_for(
        "GET", "/api/v1/admin/storage/versions") is not None
    # Non-API paths carry no permission.
    assert registry.permission_for("GET", "/static/app.js") is None


def test_bearer_key_hits_admin_route_only_with_its_permission(api):
    client, _ = api
    # A key scoped to ONE admin route: listing keys.
    key = create_key(client, ["get:/api/v1/admin/keys"])
    headers = {"Authorization": f"Bearer {key['token']}"}

    # Granted route passes without any session credential.
    listed = client.get("/api/v1/admin/keys", headers=headers)
    assert listed.status_code == 200, listed.text
    assert any(k["prefix"] == key["prefix"] for k in listed.json()["keys"])

    # Every OTHER route is denied — no groups left to over-grant.
    assert client.get("/api/v1/admin/storage/health",
                      headers=headers).status_code == 403
    assert client.get("/api/v1/admin/storage/usage?days=1",
                      headers=headers).status_code == 403
    assert client.get("/api/v1/admin/keys/permissions",
                      headers=headers).status_code == 403

    # Invalid tokens are rejected before any handler logic.
    assert client.get("/api/v1/admin/keys",
                      headers={"Authorization": "Bearer td_live_forged"}
                      ).status_code == 403


def test_write_route_key_still_needs_the_csrf_header(api):
    client, _ = api
    # Granting a key the power to mint keys is an owner decision; when
    # granted, the write still goes through the CSRF fence.
    key = create_key(client, ["post:/api/v1/admin/keys", "get:/api/v1/admin/keys"])
    headers = {"Authorization": f"Bearer {key['token']}"}
    body = {"name": "minted", "scopes": ["get:/api/v1/admin/keys"]}
    assert client.post("/api/v1/admin/keys", headers=headers,
                       json=body).status_code == 403
    minted = client.post("/api/v1/admin/keys",
                         headers={**headers, "x-teledrive-csrf": "1"},
                         json=body)
    assert minted.status_code == 201, minted.text
    # The minted key is scoped to exactly what it was granted.
    assert client.get("/api/v1/admin/keys", headers={
        "Authorization": f"Bearer {minted.json()['token']}"
    }).status_code == 200
    assert client.get("/api/v1/admin/storage/health", headers={
        "Authorization": f"Bearer {minted.json()['token']}"
    }).status_code == 403


def _mint(client, scopes):
    res = client.post(
        "/api/v1/admin/keys",
        headers={**_admin_headers(client), "x-teledrive-csrf": "1"},
        json={"name": "delegator", "scopes": scopes},
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_api_key_cannot_mint_beyond_its_own_permissions(api):
    """Delegation ceiling: a key may only create authority it holds.

    Without this, a key scoped to just the mint endpoint could issue
    itself (or anyone) a fully privileged key — total escalation.
    """
    client, _ = api
    delegator = _mint(client, ["post:/api/v1/admin/keys"])
    headers = {"Authorization": f"Bearer {delegator['token']}",
               "x-teledrive-csrf": "1"}

    # A privilege above the caller's own set is refused.
    escalated = client.post("/api/v1/admin/keys", headers=headers, json={
        "name": "escalated",
        "scopes": ["delete:/api/v1/admin/users/{user_id}"],
    })
    assert escalated.status_code == 403, escalated.text
    assert "only delegate" in escalated.json()["detail"]

    # admin:* is far above a single-route key.
    assert client.post("/api/v1/admin/keys", headers=headers, json={
        "name": "root", "scopes": ["admin:*"],
    }).status_code == 403

    # Delegating a permission the caller DOES hold is allowed.
    allowed = client.post("/api/v1/admin/keys", headers=headers, json={
        "name": "same", "scopes": ["post:/api/v1/admin/keys"],
    })
    assert allowed.status_code == 201, allowed.text


def test_api_key_rotation_cannot_steal_a_more_privileged_key(api):
    """Rotation returns the new secret, so rotating upward is theft."""
    client, _ = api
    # A privileged key exists (minted by the session admin).
    privileged = _mint(client, ["admin:*"])
    listed = client.get("/api/v1/admin/keys",
                        headers=_admin_headers(client)).json()
    target = next(k for k in listed["keys"]
                  if k["prefix"] == privileged["prefix"])

    delegator = _mint(client, ["post:/api/v1/admin/keys/{identifier}/rotate"])
    headers = {"Authorization": f"Bearer {delegator['token']}",
               "x-teledrive-csrf": "1"}
    stolen = client.post(f"/api/v1/admin/keys/{target['id']}/rotate",
                         headers=headers)
    assert stolen.status_code == 403, stolen.text
    assert "only delegate" in stolen.json()["detail"]


def test_api_key_cannot_revoke_above_its_own_authority(api):
    client, _ = api
    privileged = _mint(client, ["get:/api/v1/admin/keys"])
    listed = client.get("/api/v1/admin/keys",
                        headers=_admin_headers(client)).json()
    target = next(k for k in listed["keys"]
                  if k["prefix"] == privileged["prefix"])
    delegator = _mint(client, ["delete:/api/v1/admin/keys/{identifier}"])
    headers = {"Authorization": f"Bearer {delegator['token']}",
               "x-teledrive-csrf": "1"}
    denied = client.delete(f"/api/v1/admin/keys/{target['id']}",
                          headers=headers)
    assert denied.status_code == 403, denied.text
    # The privileged key still works.
    assert client.get("/api/v1/admin/keys", headers={
        "Authorization": f"Bearer {privileged['token']}"}).status_code == 200


def test_catalog_endpoint_exposes_the_full_registry(api):
    client, _ = api
    catalog = client.get("/api/v1/admin/keys/permissions",
                         headers=_admin_headers(client))
    assert catalog.status_code == 200
    body = catalog.json()
    names = {entry["name"] for entry in body["routes"]}
    # Curated REST names plus canonical method:path names are present.
    assert "rest:objects:get" in names
    assert "get:/api/v1/admin/keys" in names
    assert any(n.startswith("post:/api/v1/admin/") for n in names)
    # Groups carry curated descriptions and routes carry summaries.
    groups = {g["name"]: g for g in body.get("groups", [])}
    assert groups, "permission groups are missing"
    assert groups["/api/v1/admin/storage/gc"]["description"]
    assert "Physical GC" in groups["/api/v1/admin/storage/gc"]["description"]
    assert any(r.get("summary") for r in body["routes"]), \
        "route summaries are missing"
    # Only the JSON API surface is permissionable (no HTML pages).
    assert all(r["path"].startswith("/api/") for r in body["routes"])
    # Legacy aliases documented with their expansions.
    legacy = {entry["name"]: entry["expands_to"] for entry in body["legacy_scopes"]}
    assert legacy["objects:read"] == [
        "rest:objects:get", "rest:objects:head",
        "rest:objects:list", "rest:objects:list-versions"]
