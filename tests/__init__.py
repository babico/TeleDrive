"""TeleDrive regression suite package."""
from __future__ import annotations

CSRF = {"X-TeleDrive-CSRF": "1"}


def seed_local_user(connect, username: str, password: str,
                    role: str = "admin", enabled: bool = True) -> None:
    """Insert a real local user for tests that authenticate with Basic.

    HTTP Basic is verified against the users table (there is no
    config-password fallback), so a fixture must seed the principal it
    intends to use.
    """
    import time

    import sqlalchemy

    import web.app as web

    db = connect()
    try:
        db.connection.execute(sqlalchemy.text(
            "INSERT INTO users (username, password_hash, role, enabled, "
            "created_at, updated_at) VALUES (:u, :ph, :r, :e, :now, :now)"
        ), {"u": username, "ph": web._hash_password(password), "r": role,
            "e": 1 if enabled else 0, "now": int(time.time())})
        db.connection.commit()
    finally:
        db.close()


def basic_header(username: str, password: str) -> dict:
    """Build an HTTP Basic header for a local user."""
    import base64

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": "Basic " + token}


def login_headers(client, username: str, password: str) -> dict:
    """Log in through the real form endpoint and return a Bearer header.

    The session cookie is cleared afterwards so a test that header-hops
    still exercises the unauthenticated path where it expects to. Tests
    that want the browser cookie flow should call the login endpoint
    themselves.
    """
    response = client.post("/api/v1/auth/login", headers=CSRF,
                           json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.cookies.clear()
    return {"Authorization": "Bearer " + response.json()["token"]}
