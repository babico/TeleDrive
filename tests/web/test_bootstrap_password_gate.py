"""The first-boot bootstrap gate, end to end.

While the seeded ``admin`` account still authenticates with the shipped
``admin``/``admin`` password, the server refuses every authenticated
operation except the flow that completes setup: login, current-user info,
logout, the self-service password change, and the health/static/certificate
surfaces a browser needs to reach them. The condition is ACCOUNT STATE (a
cached PBKDF2 probe of the stored hash), never a browser flag; it applies to
session cookies, session bearers, API keys and the SigV4 S3 data plane
alike, because on a legitimate first boot none of those credentials can
exist yet -- anything that still answers was issued under the
default-password admin.

``web.app._BootstrapGateMiddleware`` is the web gate; ``web.s3`` carries the
S3-port twin. The self-service rotation endpoint this gate exists to
enable is ``POST /api/v1/auth/password``.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
import sqlalchemy
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import web.app as web
import web.s3 as gateway
from teledrive.api_keys import ApiKeyStore
from teledrive.s3.credentials import S3CredentialStore, DEFAULT_PERMISSIONS
from tests import seed_local_user
from tests.s3.test_s3_gateway import signed as s3_signed

CSRF = {"X-TeleDrive-CSRF": "1"}
GATE_CODE = "bootstrap_password_change_required"
ROTATED = "rotated-admin-pass-1"


@pytest.fixture()
def gated(make_app_env):
    """A first-boot environment: the seeded admin still uses admin/admin."""
    env = make_app_env(db_name="gate.sqlite")
    connect = env.connect
    web._invalidate_default_admin_cache()
    web._create_default_admin()
    client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        yield SimpleNamespace(client=client, connect=connect, env=env)
    finally:
        client.close()


def _login(client, username="admin", password="admin") -> dict:
    """Log in and return a Bearer header (cookie jar left untouched)."""
    reply = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": username, "password": password})
    assert reply.status_code == 200, reply.text
    return {"Authorization": "Bearer " + reply.json()["token"]}


def _rotate_via_endpoint(client, current="admin", new=ROTATED) -> dict:
    """Complete the bootstrap rotation through the self-service route."""
    session = _login(client, "admin", current)
    reply = client.post("/api/v1/auth/password",
                        headers={**CSRF, **session},
                        json={"current_password": current,
                              "new_password": new})
    assert reply.status_code == 200, reply.text
    return {"Authorization": "Bearer " + reply.json()["token"]}


def _set_admin_hash(connect, password: str) -> None:
    db = connect()
    try:
        db.connection.execute(sqlalchemy.text(
            "UPDATE users SET password_hash = :ph WHERE username = 'admin'"),
            {"ph": web._hash_password(password)})
        db.connection.commit()
    finally:
        db.close()


# ------------------------------------------------------------ first boot

def test_first_boot_gates_every_authenticated_operation(gated):
    client = gated.client
    assert _login(client)  # the shipped credential still logs in

    login_reply = client.post(
        "/api/v1/auth/login", headers=CSRF,
        json={"username": "admin", "password": "admin"})
    assert login_reply.json()["must_change_password"] is True

    admin = _login(client)
    me = client.get("/api/v1/auth/me", headers=admin)
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True

    for method, path, kwargs in [
        ("GET", "/api/v1/admin/users", {}),
        ("GET", "/api/v1/admin/storage/buckets", {}),
        ("GET", "/api/v1/buckets", {}),
        ("POST", "/api/v1/admin/users",
         {"json": {"username": "x", "password": "password-1234",
                   "role": "viewer"}}),
        # S3 credential issue and presign via the web API.
        ("POST", "/api/v1/admin/s3/credentials",
         {"json": {"name": "nope", "permissions": ["s3:GetObject"]}}),
        ("POST", "/api/v1/admin/storage/buckets/b/presign",
         {"json": {"key": "k", "expires_in": 300}}),
        # API key minting.
        ("POST", "/api/v1/admin/keys",
         {"json": {"name": "nope", "scopes": ["admin:*"]}}),
    ]:
        denied = client.request(method, path, headers={**CSRF, **admin},
                                **kwargs)
        assert denied.status_code == 403, (method, path, denied.text)
        assert denied.json()["code"] == GATE_CODE
        assert "password" in denied.json()["detail"]


def test_rotation_through_the_endpoint_lifts_the_gate(gated):
    client = gated.client
    old_session = _login(client)
    rotated = _rotate_via_endpoint(client)

    # Session rotation: the pre-change token is revoked, the fresh one
    # works, and the cookie jar carries the new session.
    assert client.get("/api/v1/admin/users",
                      headers=old_session).status_code == 401
    assert client.get("/api/v1/admin/users",
                      headers=rotated).status_code == 200
    # The rotation response replaced the cookie: the jar alone (what a
    # browser sends) now carries the fresh session.
    assert client.get("/api/v1/admin/users").status_code == 200

    # The old default is no longer a credential and the flag is gone.
    reply = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": "admin", "password": "admin"})
    assert reply.status_code == 401
    me = client.get("/api/v1/auth/me", headers=rotated)
    assert me.json()["must_change_password"] is False


# ------------------------------------------------- custom password: no gate

def test_custom_admin_password_means_no_gate(make_app_env):
    env = make_app_env(db_name="gate-custom.sqlite")
    seed_local_user(env.connect, "admin", "operator-chosen-pass-1", "admin")
    client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        admin = _login(client, "admin", "operator-chosen-pass-1")
        assert client.get("/api/v1/admin/users",
                          headers=admin).status_code == 200
    finally:
        client.close()


def test_another_user_with_the_default_password_does_not_arm_the_gate(
        make_app_env):
    """The gate reads the SEEDED ADMIN's row, nobody else's password."""
    env = make_app_env(db_name="gate-collision.sqlite")
    seed_local_user(env.connect, "admin", "operator-chosen-pass-1", "admin")
    # A different account whose (weak) password happens to be "admin".
    seed_local_user(env.connect, "bob", "admin", "viewer")
    client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        bob = _login(client, "bob", "admin")
        assert client.get("/api/v1/auth/me", headers=bob).status_code == 200
        assert client.get("/api/v1/admin/storage/buckets",
                          headers=bob).status_code == 200
    finally:
        client.close()


# ------------------------------------------------------- session vs bearer

def test_cookie_and_bearer_sessions_are_gated_identically(gated):
    client = gated.client
    token = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": "admin",
                              "password": "admin"}).json()["token"]
    # Bearer form.
    assert client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"}).status_code == 403
    # Cookie form (what a browser actually sends).
    client.cookies.set("teledrive_session", token)
    denied = client.get("/api/v1/admin/users")
    assert denied.status_code == 403
    assert denied.json()["code"] == GATE_CODE
    client.cookies.clear()


def test_revoked_and_expired_sessions_answer_401_not_403(gated):
    """Unauthenticated is unauthenticated: the gate only bites principals."""
    client, connect = gated.client, gated.connect
    token = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": "admin",
                              "password": "admin"}).json()["token"]

    # Expire the session row, then ask again: 401 from require_auth.
    db = connect()
    try:
        db.connection.execute(sqlalchemy.text(
            "UPDATE user_sessions SET expires_at = 1 WHERE token = :t"),
            {"t": web._session_token_digest(token)})
        db.connection.commit()
    finally:
        db.close()
    assert client.get("/api/v1/admin/users",
                      headers={"Authorization": f"Bearer {token}"}
                      ).status_code == 401

    # A revoked token (logout) behaves the same way.
    fresh = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": "admin",
                              "password": "admin"}).json()["token"]
    assert client.post("/api/v1/auth/logout",
                       headers={**CSRF,
                                "Authorization": f"Bearer {fresh}"}
                       ).status_code == 200
    assert client.get("/api/v1/admin/users",
                      headers={"Authorization": f"Bearer {fresh}"}
                      ).status_code == 401


def test_anonymous_requests_are_untouched_by_the_gate(gated):
    client = gated.client
    assert client.get("/api/v1/admin/users").status_code == 401
    # Page shell -> /login redirect for an unauthenticated visitor.
    assert client.get("/", follow_redirects=False).status_code == 302


# --------------------------------------------------------- API keys denied

def test_api_key_issued_under_the_default_password_is_denied_until_rotation(
        gated):
    """The safer rule: while the gate is up, bearer keys are refused.

    A key cannot be minted through the gated API, so any key that still
    answers was issued by the default-password admin; refusing it costs
    nothing on a real first boot and contains exactly that delegated
    authority. Rotation re-enables it unchanged.
    """
    client, connect = gated.client, gated.connect
    db = connect()
    try:
        key = ApiKeyStore(db).create(
            "issued-under-default", ["get:/api/v1/admin/users"],
            extra_allowed={"get:/api/v1/admin/users"})
    finally:
        db.close()
    headers = {"Authorization": "Bearer " + key.value}
    denied = client.get("/api/v1/admin/users", headers=headers)
    assert denied.status_code == 403
    assert denied.json()["code"] == GATE_CODE

    _rotate_via_endpoint(client)
    assert client.get("/api/v1/admin/users",
                      headers=headers).status_code == 200


# ------------------------------------------------------------- websocket

def test_websocket_admin_logs_are_denied_while_gated(gated):
    client = gated.client
    token = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": "admin",
                              "password": "admin"}).json()["token"]
    client.cookies.set("teledrive_session", token)
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/v1/logs/stream") as ws:
            ws.receive_text()
    assert excinfo.value.code == 4403

    # Anonymous sockets keep the handler's own 4401.
    client.cookies.clear()
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/v1/logs/stream") as ws:
            ws.receive_text()
    assert excinfo.value.code == 4401

    # After rotation the same cookie may subscribe again (a denial
    # raises WebSocketDisconnect before the handshake completes).
    rotated_token = _rotate_via_endpoint(client)["Authorization"][7:]
    client.cookies.set("teledrive_session", rotated_token)
    with client.websocket_connect("/api/v1/logs/stream"):
        pass


# ------------------------------------------------------ no deadlock

def test_no_bootstrap_deadlock_the_flow_can_complete(gated):
    """Everything a browser needs to finish setup stays reachable."""
    client = gated.client
    admin = _login(client)
    assert client.get("/api/health").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/vendor/alpine.min.js").status_code == 200
    # Certificates: public data; 404 only because no TLS cert is
    # configured here -- the point is the gate does not answer them.
    for path in ("/server.cer", "/server.crt",
                 "/api/v1/certificate.cer", "/api/v1/certificate.pem"):
        assert client.get(path, headers=admin).status_code in (200, 404)
    # And the rotation itself works, proving the loop closes.
    assert _rotate_via_endpoint(client)


# ------------------------------------------------------- allowed-path list

def test_every_allowlisted_path_stays_reachable_while_gated(gated):
    """The frozen allowlist: each entry reaches its HANDLER, not the gate."""
    client = gated.client
    # (method, path, body-or-None, expected statuses)
    cases = {
        ("POST", "/api/v1/auth/login"): ({"username": "admin",
                                          "password": "admin"}, {200}),
        ("POST", "/api/auth/login"): ({"username": "admin",
                                       "password": "admin"}, {200}),
        ("GET", "/api/v1/auth/me"): (None, {200}),
        ("GET", "/api/auth/me"): (None, {200}),
        ("POST", "/api/v1/auth/logout"): (None, {200}),
        ("POST", "/api/auth/logout"): (None, {200}),
        # Reaches the handler's validation (400), proving the gate let
        # it through without performing a real rotation.
        ("POST", "/api/v1/auth/password"): (
            {"current_password": "admin", "new_password": "short"}, {400}),
        ("POST", "/api/auth/password"): (
            {"current_password": "admin", "new_password": "short"}, {400}),
        ("GET", "/api/health"): (None, {200}),
        ("GET", "/__health"): (None, {200, 404}),  # served on the S3 port
        ("GET", "/login"): (None, {200}),
        ("GET", "/server.cer"): (None, {200, 404}),
        ("GET", "/server.crt"): (None, {200, 404}),
        ("GET", "/api/v1/certificate.cer"): (None, {200, 404}),
        ("GET", "/api/v1/certificate.pem"): (None, {200, 404}),
    }
    from web.app import _BootstrapGateMiddleware
    allowlisted = {(method, path) for method, path in
                   _BootstrapGateMiddleware.ALLOWED}
    assert allowlisted == set(cases), (
        "the gate allowlist changed without a test row: "
        f"{sorted(allowlisted ^ set(cases))}")

    for (method, path), (body, expected) in cases.items():
        session = _login(client)  # fresh session: logout cases revoke theirs
        headers = {**CSRF, **session}
        reply = client.request(method, path, headers=headers, json=body)
        assert reply.status_code in expected, (method, path, reply.text)
    # HEAD reaches the ROUTER (405: the route has no HEAD binding), not
    # the gate -- which is the property that matters.
    assert client.head("/api/v1/auth/me",
                       headers=_login(client)).status_code == 405
    # The static prefix is allowlisted too.
    assert client.get("/static/app.js").status_code == 200
    # A gated session must still see 403-from-gate everywhere else.
    gate_403 = client.get("/api/v1/admin/users", headers=_login(client))
    assert gate_403.json()["code"] == GATE_CODE


# ------------------------------------------------------ restart semantics

def test_restart_keeps_the_rotated_admin_row_and_the_gate_stays_off(gated):
    client, connect = gated.client, gated.connect
    # Rotate at the database level WITHOUT touching the invalidation
    # hook: the hash-keyed probe cache must notice on its own.
    _set_admin_hash(connect, ROTATED)

    # Two more "starts" must leave the changed hash exactly as it was.
    web._create_default_admin()
    web._create_default_admin()
    db = connect()
    try:
        row = db.connection.execute(sqlalchemy.text(
            "SELECT password_hash FROM users WHERE username = 'admin'")
        ).fetchone()
    finally:
        db.close()
    assert web._verify_password(ROTATED, row[0])

    admin = _login(client, "admin", ROTATED)
    assert client.get("/api/v1/admin/users", headers=admin).status_code == 200


def test_probe_failure_directions(tmp_path, monkeypatch):
    """The gate fails closed; the UI nudge fails open."""
    import web.routers.auth as auth
    path = tmp_path / "probe.sqlite"
    monkeypatch.setattr(web, "db_connect", lambda: (_ for _ in ()).throw(
        RuntimeError("database unreachable")))
    web._invalidate_default_admin_cache()
    assert auth._bootstrap_gate_active() is True
    assert auth._default_admin_password_in_use() is False


def test_probe_cache_is_keyed_by_the_stored_hash(gated):
    """A password change misses the cache automatically."""
    from web.routers.auth import _DEFAULT_ADMIN_PW_CACHE
    connect = gated.connect
    assert gated.client.get("/api/v1/admin/users",
                            headers=_login(gated.client)).status_code == 403
    assert True in _DEFAULT_ADMIN_PW_CACHE.values()
    _set_admin_hash(connect, ROTATED)
    assert gated.client.get("/api/v1/admin/users",
                            headers=_login(gated.client,
                                           "admin", ROTATED)).status_code == 200


# ------------------------------------------------------------- concurrency

def test_concurrent_requests_all_meet_the_same_gate(gated):
    """Parallel traffic must not deadlock or leak past the gate."""
    client = gated.client
    token = client.post("/api/v1/auth/login", headers=CSRF,
                        json={"username": "admin",
                              "password": "admin"}).json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    work = []

    def probe(index):
        if index % 3 == 0:
            return client.get("/api/v1/auth/me", headers=auth).status_code
        if index % 3 == 1:
            reply = client.get("/api/v1/admin/users", headers=auth)
            return reply.status_code, reply.json().get("code")
        return client.get("/static/app.js").status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        work = list(pool.map(probe, range(24)))
    assert all(w == 200 for w in work[0::3]), work[0::3]
    assert all(w == (403, GATE_CODE) for w in work[1::3]), work[1::3]
    assert all(w == 200 for w in work[2::3]), work[2::3]


# --------------------------------------------------------- proxy headers

def test_gate_and_login_work_behind_a_trusted_proxy(gated, monkeypatch):
    monkeypatch.setattr(web, "TRUSTED_PROXY", True)
    client = gated.client
    proxied = {**CSRF, "X-Forwarded-For": "203.0.113.9",
               "X-Forwarded-Proto": "https"}
    reply = client.post("/api/v1/auth/login", headers=proxied,
                        json={"username": "admin", "password": "admin"})
    assert reply.status_code == 200
    assert "secure" in reply.headers["set-cookie"].lower()
    denied = client.get("/api/v1/admin/users",
                        headers={"Authorization":
                                 "Bearer " + reply.json()["token"],
                                 "X-Forwarded-For": "203.0.113.9"})
    assert denied.status_code == 403
    assert denied.json()["code"] == GATE_CODE


# ------------------------------------------------- self-service endpoint

def test_password_change_rejects_weak_or_wrong_input(gated):
    client = gated.client
    session = _login(client)
    cases = [
        ({"current_password": "admin", "new_password": "admin"},
         "shipped default"),
        ({"current_password": "admin", "new_password": "Admin"},
         "shipped default"),
        ({"current_password": "admin", "new_password": "short"}, "8 characters"),
        ({"current_password": "admin", "new_password": "onlyletters"},
         "letters with digits"),
        ({"current_password": "wrong-password-1",
          "new_password": "another-pass-2"}, "incorrect"),
    ]
    for body, fragment in cases:
        reply = client.post("/api/v1/auth/password",
                            headers={**CSRF, **session}, json=body)
        assert reply.status_code in (400, 403), (body, reply.text)
        assert fragment in reply.json()["detail"]

    # Re-using the CURRENT (already rotated) password is refused too.
    _rotate_via_endpoint(client)
    rotated_session = _login(client, "admin", ROTATED)
    reply = client.post("/api/v1/auth/password",
                        headers={**CSRF, **rotated_session},
                        json={"current_password": ROTATED,
                              "new_password": ROTATED})
    assert reply.status_code == 400
    assert "differ from the current" in reply.json()["detail"]


def test_password_change_requires_csrf_and_same_origin(gated):
    client = gated.client
    session = _login(client)
    body = {"current_password": "admin", "new_password": "another-pass-2"}
    # Missing CSRF header.
    assert client.post("/api/v1/auth/password", headers=session,
                       json=body).status_code == 403
    # Cross-origin state change.
    assert client.post("/api/v1/auth/password",
                       headers={**CSRF, **session,
                                "Origin": "http://evil.example"},
                       json=body).status_code == 403
    # Unauthenticated (the jar is cleared so no cookie rides along).
    client.cookies.clear()
    assert client.post("/api/v1/auth/password", headers=CSRF,
                       json=body).status_code == 401


def test_an_api_key_cannot_change_the_password(gated):
    client, connect = gated.client, gated.connect
    db = connect()
    try:
        key = ApiKeyStore(db).create(
            "rotation-attempt", ["post:/api/v1/auth/password"],
            extra_allowed={"post:/api/v1/auth/password"})
    finally:
        db.close()
    reply = client.post("/api/v1/auth/password",
                        headers={**CSRF,
                                 "Authorization": "Bearer " + key.value},
                        json={"current_password": "admin",
                              "new_password": "stolen-password-1"})
    assert reply.status_code == 403
    assert "interactive" in reply.json()["detail"]
    # The default password still verifies: no rotation happened.
    assert _login(client)


def test_non_admin_self_change_is_allowed_but_lifts_nothing(gated):
    """Another account may rotate ITS OWN password; only the admin's
    rotation ends first-boot."""
    client, connect = gated.client, gated.connect
    seed_local_user(connect, "opuser", "operator-pass-1", "operator")
    session = _login(client, "opuser", "operator-pass-1")
    # Gated like everyone else...
    assert client.get("/api/v1/admin/storage/buckets",
                      headers=session).status_code == 403
    # ...may still complete its own rotation...
    reply = client.post("/api/v1/auth/password",
                        headers={**CSRF, **session},
                        json={"current_password": "operator-pass-1",
                              "new_password": "operator-pass-2"})
    assert reply.status_code == 200, reply.text
    # ...which does not disarm the gate for the deployment.
    assert client.get("/api/v1/admin/storage/buckets", headers={
        "Authorization": "Bearer " + reply.json()["token"]}).status_code == 403
    assert _login(client)  # admin/admin still logs in


def test_rotation_sets_a_fresh_secure_cookie_session(gated):
    client = gated.client
    session = _login(client)
    reply = client.post("/api/v1/auth/password",
                        headers={**CSRF, **session},
                        json={"current_password": "admin",
                              "new_password": ROTATED})
    assert reply.status_code == 200
    assert reply.json()["token"].startswith("td_sess_")
    cookie = reply.headers["set-cookie"]
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    # The new cookie session carries the caller straight into the app.
    client.cookies.set("teledrive_session", reply.json()["token"])
    assert client.get("/api/v1/admin/users").status_code == 200


# --------------------------------------------------------- S3 data plane

def test_s3_data_plane_is_gated_until_rotation(make_app_env, monkeypatch):
    env = make_app_env(db_name="gate-s3.sqlite")
    connect = env.connect
    secret = Fernet.generate_key()
    db = connect()
    try:
        creds = S3CredentialStore(db, secret).create(
            "gate", list(DEFAULT_PERMISSIONS))
    finally:
        db.close()
    monkeypatch.setattr(gateway, "db_connect", connect)
    monkeypatch.setattr(gateway, "storage_transport",
                        lambda db: env.transport)
    monkeypatch.setattr(gateway, "load_master_key", lambda: secret)
    web._invalidate_default_admin_cache()
    web._create_default_admin()

    s3_client = TestClient(gateway.app, base_url="http://localhost:9000")
    web_client = TestClient(web.app, base_url="http://localhost:8080")
    try:
        service = (s3_client, creds, env.transport, connect, secret)
        # A validly signed request is refused BEFORE S3 authorization,
        # with the required action named.
        denied = s3_signed(service, "PUT", "/gate-bucket")
        assert denied.status_code == 403, denied.text
        assert "AccessDenied" in denied.text
        assert "default administrator password" in denied.text
        # Health and unsigned traffic keep the gateway's own behaviour.
        assert s3_client.get("/__health").status_code == 200
        unsigned = s3_client.get("/gate-bucket")
        assert unsigned.status_code == 403
        assert "administrator" not in unsigned.text

        # Complete the rotation through the WEB app; the S3 port needs
        # no restart and immediately serves the same signature.
        _rotate_via_endpoint(web_client)
        assert s3_signed(service, "PUT", "/gate-bucket").status_code == 200
        put = s3_signed(service, "PUT", "/gate-bucket/hello.txt", b"gate")
        assert put.status_code == 200, put.text
        got = s3_signed(service, "GET", "/gate-bucket/hello.txt")
        assert got.status_code == 200 and got.content == b"gate"
    finally:
        s3_client.close()
        web_client.close()


def test_s3_port_stays_open_when_no_admin_row_exists(make_app_env,
                                                     monkeypatch):
    """The S3 gate keys on the admin account, not on S3 credentials."""
    env = make_app_env(db_name="gate-s3-noadmin.sqlite")
    connect = env.connect
    secret = Fernet.generate_key()
    db = connect()
    try:
        creds = S3CredentialStore(db, secret).create(
            "noadmin", list(DEFAULT_PERMISSIONS))
    finally:
        db.close()
    monkeypatch.setattr(gateway, "db_connect", connect)
    monkeypatch.setattr(gateway, "storage_transport",
                        lambda db: env.transport)
    monkeypatch.setattr(gateway, "load_master_key", lambda: secret)
    web._invalidate_default_admin_cache()
    s3_client = TestClient(gateway.app, base_url="http://localhost:9000")
    try:
        service = (s3_client, creds, env.transport, connect, secret)
        assert s3_signed(service, "PUT",
                         "/noadmin-bucket").status_code == 200
    finally:
        s3_client.close()
