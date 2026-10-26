"""Public certificate distribution for client trust bootstrap.

A self-signed deployment has a chicken-and-egg problem: clients must
trust the certificate before they can talk TLS to fetch it. This module
turns the configured listener certificate into a downloadable public
artifact (PEM and DER/.cer) that the management UI serves over plain
HTTP on a dedicated bootstrap port.

Security rules:
* ONLY the certificate blocks are ever emitted. A combined .pem holds
  the private key too — the key block is stripped and never rendered.
* Nothing here is secret: the certificate is public by definition.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_CERT_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


class CertError(RuntimeError):
    """The configured certificate cannot be read or parsed."""


def certificate_path() -> str:
    """The certificate a client should trust.

    Prefers the WebUI certificate; falls back to the S3 listener's (a
    deployment may run only the S3 gateway over TLS). Empty when neither
    listener terminates TLS — there is then nothing to distribute.
    """
    for name in ("TELEDRIVE_SSL_CERTFILE", "TELEDRIVE_S3_SSL_CERTFILE"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def _certificate_pem(path: str) -> bytes:
    """Extract the certificate chain from a PEM, discarding any key."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise CertError(f"cannot read certificate: {exc}") from exc
    blocks = _CERT_BLOCK.findall(raw)
    if not blocks:
        raise CertError("no CERTIFICATE block found in the configured file")
    return b"".join(block if block.endswith(b"\n") else block + b"\n"
                    for block in blocks)


def public_cert_pem() -> bytes:
    path = certificate_path()
    if not path:
        raise CertError("no TLS certificate is configured")
    return _certificate_pem(path)


def public_cert_der() -> bytes:
    """DER (a.k.a. .cer/.crt) form, what Windows trust stores import."""
    pem = public_cert_pem()
    try:
        # PEM is exactly base64 over the DER body between the armor lines.
        import base64
        body = b"".join(
            line for line in pem.splitlines()
            if not line.startswith(b"-----")
        )
        return base64.b64decode(body)
    except Exception as exc:  # noqa: BLE001 - surface a typed error
        raise CertError(f"cannot decode certificate: {exc}") from exc


def certificate_fingerprint_sha256() -> str:
    """Lowercase hex SHA-256 of the DER body (stable identity)."""
    import hashlib
    return hashlib.sha256(public_cert_der()).hexdigest()
