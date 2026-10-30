"""API key integration tests against persisted SQLite; no bearer secrets leaked."""
from __future__ import annotations

import time

import pytest

from teledrive.api_keys import ApiKeyStore
from teledrive.db import connect_database


@pytest.fixture
def keys(tmp_path):
    connection = connect_database(str(tmp_path / "auth.db"))
    try:
        yield ApiKeyStore(connection)
    finally:
        connection.close()


def test_credentials_are_hashed_never_listed_and_persisted(keys):
    created = keys.create("Backup client", ["objects:write", "objects:read"], now=100)
    assert created.value.startswith("td_live_")
    assert len(created.value) >= 40
    row = keys.list()[0]
    assert row["name"] == "Backup client"
    assert row["prefix"] == created.value[:16]
    assert "value" not in row and "digest" not in row
    assert created.value not in str(keys.list())
    assert keys.authorize(created.value, "rest:objects:get", now=101)
    assert keys.authorize(created.value, "rest:objects:put", now=102)
    assert not keys.authorize(created.value, "rest:objects:delete", now=103)
    assert keys.list()[0]["last_used_at"] == 102


def test_read_only_and_wrong_key_do_not_escalate(keys):
    key = keys.create("read", ["objects:read"], now=100)
    assert not keys.authorize(key.value, "rest:objects:put", now=101)
    assert not keys.authorize(key.value + "x", "rest:objects:get", now=101)
    assert not keys.authorize("not-a-token", "rest:objects:get", now=101)
    assert keys.authorize(key.value, "rest:objects:get", now=101)


def test_expiry_and_revoke_fence_future_requests(keys):
    token = keys.create("short", ["objects:read"], now=100, expires_at=150)
    assert keys.authorize(token.value, "rest:objects:get", now=149)
    assert not keys.authorize(token.value, "rest:objects:get", now=150)
    assert keys.revoke(token.id)
    assert not keys.revoke(token.id)
    assert not keys.authorize(token.value, "rest:objects:get", now=101)


def test_rotation_invalidates_old_token_and_preserves_policy(keys):
    previous = keys.create("bot", ["buckets:manage"], now=100, expires_at=500)
    rotated = keys.rotate(previous.id, now=200)
    assert rotated.id != previous.id and rotated.value != previous.value
    assert keys.list()[0]["name"] == "bot"
    assert not keys.authorize(previous.value, "rest:buckets:create", now=201)
    assert keys.authorize(rotated.value, "rest:buckets:create", now=201)
    assert not keys.authorize(rotated.value, "rest:objects:get", now=201)
    with pytest.raises(FileNotFoundError):
        keys.rotate(previous.id, now=202)


def test_input_validation_rejects_bad_scopes_and_lifetime(keys):
    with pytest.raises(ValueError):
        keys.create("empty", [], now=100)
    with pytest.raises(ValueError):
        keys.create("invalid", ["root"], now=100)
    with pytest.raises(ValueError):
        keys.create("mixed", ["admin:*", "objects:read"], now=100)
    with pytest.raises(ValueError):
        keys.create("", ["objects:read"], now=100)
    with pytest.raises(ValueError):
        keys.create("expired", ["objects:read"], now=100, expires_at=100)
    with pytest.raises(ValueError):
        keys.create("too long", ["objects:read"], now=100, expires_at=100 + 11 * 365 * 86400)
    assert keys.list() == []


def test_admin_wildcard_and_scope_distinctions(keys):
    key = keys.create("admin service", ["admin:*"], now=100)
    for scope in ["rest:buckets:create", "rest:objects:delete",
                  "rest:objects:put", "rest:buckets:list"]:
        assert keys.authorize(key.value, scope, now=110)
    assert not keys.authorize("", "rest:objects:get", now=110)


def test_per_endpoint_permissions(keys):
    """Every REST endpoint is individually permissionable, and legacy
    grouped scopes expand to exactly their endpoint sets."""
    from teledrive.api_keys import (ENDPOINT_PERMISSIONS,
                                     LEGACY_SCOPE_EXPANSION, expand_scopes)

    # A key with ONE endpoint permission can use that endpoint only.
    writer = keys.create("put-only", ["rest:objects:put"], now=200)
    assert keys.authorize(writer.value, "rest:objects:put", now=201)
    assert not keys.authorize(writer.value, "rest:objects:get", now=202)
    assert not keys.authorize(writer.value, "rest:objects:head", now=203)
    assert not keys.authorize(writer.value, "rest:buckets:list", now=204)

    # Legacy groups keep working through expansion.
    legacy_reader = keys.create("legacy-reader", ["objects:read"], now=210)
    for endpoint in LEGACY_SCOPE_EXPANSION["objects:read"]:
        assert keys.authorize(legacy_reader.value, endpoint, now=211), endpoint
    assert not keys.authorize(legacy_reader.value, "rest:objects:put", now=212)
    assert not keys.authorize(legacy_reader.value, "rest:objects:delete", now=213)

    # admin:* expands to every endpoint permission.
    admin = keys.create("admin", ["admin:*"], now=220)
    for endpoint in ENDPOINT_PERMISSIONS:
        assert keys.authorize(admin.value, endpoint, now=221), endpoint

    # Expansion is a pure function of the scope list.
    assert expand_scopes(["objects:read", "rest:buckets:list"]) == frozenset(
        {"rest:objects:list", "rest:objects:list-versions",
         "rest:objects:get", "rest:objects:head", "rest:buckets:list"})
    assert expand_scopes(["jobs:read"]) == frozenset()
    assert expand_scopes([]) == frozenset()

    # Mixing legacy and endpoint names on one key is allowed.
    mixed = keys.create("mixed", ["buckets:manage", "rest:objects:get"], now=230)
    assert keys.authorize(mixed.value, "rest:buckets:create", now=231)
    assert keys.authorize(mixed.value, "rest:buckets:delete", now=232)
    assert keys.authorize(mixed.value, "rest:objects:get", now=233)
    assert not keys.authorize(mixed.value, "rest:objects:put", now=234)


def test_endpoint_catalog_covers_every_bearer_route(keys):
    """Every require_api_scope call site uses a registered endpoint
    permission — the catalog can never drift from the routes."""
    import re
    from pathlib import Path
    from teledrive.api_keys import ENDPOINT_PERMISSIONS

    # Bearer routes live in web/app.py and in any router module (rest.py
    # holds the whole /api/v1/buckets data plane). Scan every Python file
    # under web/ so a future extraction cannot make this pass vacuously.
    used = set()
    for path in Path("web").rglob("*.py"):
        used |= set(re.findall(r'require_api_scope\("([^"]+)"\)',
                               path.read_text(encoding="utf-8")))
    assert used, "no bearer routes found"
    assert used <= set(ENDPOINT_PERMISSIONS), (
        f"Routes with unregistered permissions: {used - set(ENDPOINT_PERMISSIONS)}")
