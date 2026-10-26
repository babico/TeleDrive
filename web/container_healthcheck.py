"""Container healthcheck for both listeners, env-driven.

The WebUI and S3 listeners are configured by docker-compose environment
variables (TELEDRIVE_WEB_PORT / TELEDRIVE_S3_PORT) and may each serve
TLS. This probe derives scheme + port from the same variables the service
itself reads, so the healthcheck can never check a port the app stopped
listening on.

TLS handling: the probe talks to loopback and, when a certificate file is
configured, verifies the chain against that very certificate. Hostname
verification is disabled because the probe connects to 127.0.0.1, which a
deployment certificate need not list — the listener's identity is already
established by the configured file, and this is a liveness check, not a
public trust decision.
"""
from __future__ import annotations

import http.client
import os
import ssl
import sys


def _context(cert_path: str) -> ssl.SSLContext:
    """Chain-verifying context that tolerates a loopback hostname."""
    if cert_path and os.path.isfile(cert_path):
        context = ssl.create_default_context(cafile=cert_path)
    else:
        # No file readable: still require encryption, but there is no
        # anchor to pin against. Matches the app's own startup behavior
        # (it would have failed to serve TLS without a certificate).
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    context.check_hostname = False
    return context


def _probe(port_var: str, default_port: str, path: str,
           cert_var: str) -> None:
    port = int(os.environ.get(port_var) or default_port)
    cert_path = os.environ.get(cert_var, "").strip()
    if cert_path:
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=5, context=_context(cert_path))
    else:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        response.read(1024)
        if response.status >= 500:
            raise RuntimeError(f"{path} returned HTTP {response.status}")
    finally:
        connection.close()


def main() -> int:
    try:
        _probe("TELEDRIVE_WEB_PORT", "8080", "/api/health",
               "TELEDRIVE_SSL_CERTFILE")
        _probe("TELEDRIVE_S3_PORT", "9000", "/__health",
               "TELEDRIVE_S3_SSL_CERTFILE")
    except Exception as exc:  # noqa: BLE001 - healthcheck reports, never raises
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
