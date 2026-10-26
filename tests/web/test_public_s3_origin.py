"""Public S3 origin for presigned links across every deployment shape.

TLS is deployment plumbing and the two modes are independent:

* direct   — the app terminates TLS on the S3 listener (or sends HTTP);
* proxied  — TLS terminates in front (or the proxy is plain HTTP);
* both at once — an HTTPS proxy in front of an app that also speaks HTTPS.
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

import web.app as webapp


def _request(headers: dict[str, str]) -> Request:
    raw = [(key.lower().encode(), value.encode())
           for key, value in headers.items()]
    return Request({
        "type": "http", "method": "POST", "path": "/api/v1/x",
        "headers": raw, "query_string": b"",
        "server": ("127.0.0.1", 8080), "scheme": "http",
        "client": ("127.0.0.1", 12345),
    })


@pytest.fixture
def origin(monkeypatch):
    def build(*, s3_cert: str, trusted: bool, headers: dict[str, str],
              s3_port: int = 9000) -> str:
        monkeypatch.setattr(webapp, "S3_SSL_CERTFILE", s3_cert)
        monkeypatch.setattr(webapp, "TRUSTED_PROXY", trusted)
        monkeypatch.setattr(webapp, "settings_s3_port", lambda: s3_port)
        return webapp._public_s3_origin(_request(headers))
    return build


def test_direct_plain_http_uses_the_s3_listener_port(origin):
    # The admin calls the API through the WebUI port; the link must point
    # at the S3 listener, not echo the WebUI port back.
    assert origin(s3_cert="", trusted=False,
                  headers={"host": "drive.local:8088"}) == \
        "http://drive.local:9000"


def test_direct_tls_uses_https_and_discards_the_webui_port(origin):
    assert origin(s3_cert="/config/ssl/server.crt", trusted=False,
                  headers={"host": "drive.local:8088"}) == \
        "https://drive.local:9000"


def test_direct_mode_custom_s3_port(origin):
    assert origin(s3_cert="", trusted=False,
                  headers={"host": "drive.local:8088"}, s3_port=9443) == \
        "http://drive.local:9443"


def test_proxy_tls_with_plain_app(origin):
    # TLS ends at the proxy, the app speaks HTTP: X-Forwarded-Proto wins.
    assert origin(s3_cert="", trusted=True, headers={
        "host": "internal:8088",
        "x-forwarded-proto": "https",
        "x-forwarded-host": "s3.example.com",
        "x-forwarded-port": "9088",
    }) == "https://s3.example.com:9088"


def test_proxy_tls_already_forwarded_on_default_https_port(origin):
    assert origin(s3_cert="", trusted=True, headers={
        "host": "internal:8088",
        "x-forwarded-proto": "https",
        "x-forwarded-host": "s3.example.com",
        "x-forwarded-port": "443",
    }) == "https://s3.example.com"


def test_proxy_tls_in_front_of_app_tls(origin):
    # Both layers terminate TLS — legal and supported.
    assert origin(s3_cert="/config/ssl/server.crt", trusted=True, headers={
        "host": "internal:9088",
        "x-forwarded-proto": "https",
        "x-forwarded-host": "drive.example.com",
        "x-forwarded-port": "443",
    }) == "https://drive.example.com"


def test_proxy_plain_http_keeps_the_forwarded_port(origin):
    assert origin(s3_cert="", trusted=True, headers={
        "host": "internal:8088",
        "x-forwarded-proto": "http",
        "x-forwarded-host": "lan.local:9088",
    }) == "http://lan.local:9088"


def test_forwarded_headers_are_ignored_without_trusted_proxy(origin):
    # Header spoofing must not change the origin when the proxy mode is off.
    assert origin(s3_cert="", trusted=False, headers={
        "host": "drive.local:8088",
        "x-forwarded-proto": "https",
        "x-forwarded-host": "attacker.example.com",
        "x-forwarded-port": "443",
    }) == "http://drive.local:9000"


def test_ipv6_literal_host(origin):
    assert origin(s3_cert="", trusted=False,
                  headers={"host": "[::1]:8088"}) == "http://[::1]:9000"
