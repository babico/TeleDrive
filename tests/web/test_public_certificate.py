"""Public certificate distribution from the management interface.

A self-signed deployment must be able to hand out the certificate clients
need to trust it. The routes are unauthenticated (a certificate is public
data, and a login over the untrusted TLS connection would deadlock) and
must never leak the private key, even when the configured file is a
combined .pem.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
from web import certs


@pytest.fixture
def client():
    return TestClient(webapp.app, base_url="http://localhost:8080")


@pytest.fixture
def cert_file(tmp_path, monkeypatch):
    """A self-signed certificate generated for the test."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "teledrive.test"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    split = tmp_path / "server.crt"
    split.write_bytes(cert_pem)
    combined = tmp_path / "server.pem"
    combined.write_bytes(key_pem + cert_pem)
    monkeypatch.setenv("TELEDRIVE_SSL_CERTFILE", str(split))
    monkeypatch.delenv("TELEDRIVE_S3_SSL_CERTFILE", raising=False)
    return {"split": split, "combined": combined, "cert_pem": cert_pem,
            "key_pem": key_pem}


def test_cer_is_downloadable_without_authentication(client, cert_file):
    reply = client.get("/server.cer")
    assert reply.status_code == 200, reply.text
    assert reply.headers["content-type"] == "application/pkix-cert"
    assert "teledrive.cer" in reply.headers["content-disposition"]
    # DER starts with a SEQUENCE tag and decodes back to the same cert.
    assert reply.content[:1] == b"\x30"
    from cryptography import x509
    parsed = x509.load_der_x509_certificate(reply.content)
    assert parsed.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME)[0].value == "teledrive.test"


def test_pem_is_downloadable_without_authentication(client, cert_file):
    reply = client.get("/server.crt")
    assert reply.status_code == 200, reply.text
    assert b"BEGIN CERTIFICATE" in reply.content
    assert b"PRIVATE KEY" not in reply.content
    assert reply.content == cert_file["cert_pem"].rstrip(b"\n") + b"\n"


def test_api_namespaced_aliases_match(client, cert_file):
    assert client.get("/api/v1/certificate.cer").content == \
        client.get("/server.cer").content
    assert client.get("/api/v1/certificate.pem").content == \
        client.get("/server.crt").content


def test_combined_pem_never_leaks_the_private_key(client, cert_file,
                                                  monkeypatch):
    monkeypatch.setenv("TELEDRIVE_SSL_CERTFILE", str(cert_file["combined"]))
    for path in ("/server.cer", "/server.crt"):
        reply = client.get(path)
        assert reply.status_code == 200, reply.text
        assert b"PRIVATE KEY" not in reply.content, path
        assert b"BEGIN CERTIFICATE" in certs.public_cert_pem() or path.endswith(".cer")


def test_no_certificate_configured_is_an_honest_404(client, monkeypatch):
    monkeypatch.delenv("TELEDRIVE_SSL_CERTFILE", raising=False)
    monkeypatch.delenv("TELEDRIVE_S3_SSL_CERTFILE", raising=False)
    assert client.get("/server.cer").status_code == 404
    assert client.get("/server.crt").status_code == 404


def test_s3_certificate_is_the_fallback(client, cert_file, monkeypatch):
    monkeypatch.delenv("TELEDRIVE_SSL_CERTFILE", raising=False)
    monkeypatch.setenv("TELEDRIVE_S3_SSL_CERTFILE", str(cert_file["split"]))
    reply = client.get("/server.crt")
    assert reply.status_code == 200
    assert b"BEGIN CERTIFICATE" in reply.content


def test_missing_file_surfaces_as_404(client, monkeypatch, tmp_path):
    monkeypatch.setenv("TELEDRIVE_SSL_CERTFILE", str(tmp_path / "absent.crt"))
    assert client.get("/server.cer").status_code == 404


def test_der_and_pem_agree(cert_file):
    der = certs.public_cert_der()
    pem_body = b"".join(
        line for line in cert_file["cert_pem"].splitlines()
        if not line.startswith(b"-----"))
    assert der == base64.b64decode(pem_body)
