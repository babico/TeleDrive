"""OpenAPI contract tests independent of Starlette's optional HTTP test client."""
from __future__ import annotations

from fastapi import HTTPException
from starlette.requests import Request
import pytest

import web.app as webapp


def request():
    return Request({
        "type": "http", "method": "GET", "path": "/openapi.json",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8080),
        "scheme": "http", "query_string": b"",
    })


def test_api_schema_exposes_typed_requests_and_security():
    schema = webapp.app.openapi()
    assert schema["info"]["title"] == "TeleDrive API"
    paths = schema["paths"]
    # Canonical API namespace; legacy /api/config is an undocumented alias.
    for endpoint in ["/api/v1/config", "/api/v1/auth/login", "/api/health"]:
        assert endpoint in paths
    assert "/api/config" not in paths
    assert "/docs" not in paths
    assert "HTTPBearer" in schema["components"]["securitySchemes"]


def test_docs_routes_return_official_swagger_redoc_html():
    assert "Swagger" in webapp.swagger_docs(None).body.decode()
    assert "ReDoc" in webapp.redoc_docs(None).body.decode()
    assert "TeleDrive API" in webapp.openapi_schema(None).body.decode()


def test_documentation_requires_auth():
    webapp.AUTH_FAILURES.clear()
    with pytest.raises(HTTPException) as exc:
        webapp.require_auth(request())
    assert exc.value.status_code == 401


def test_health_is_public():
    assert webapp.health() == {"ok": True}
