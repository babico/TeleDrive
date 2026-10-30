#!/usr/bin/env python3
"""Generate a self-signed TLS certificate for the TeleDrive service.

The unified service serves HTTPS when the deployment environment sets
TELEDRIVE_SSL_CERTFILE / TELEDRIVE_SSL_KEYFILE (WebUI/REST) or
TELEDRIVE_S3_SSL_CERTFILE / TELEDRIVE_S3_SSL_KEYFILE (S3 gateway).
TLS is ENV-ONLY by owner policy: it is never configured in
config/config.yaml. This script generates a self-signed pair and prints
the exact environment lines to add, and can verify a running instance
over HTTPS with the generated certificate.

Certificates belong under the ./data mount (e.g. /data/tls) so they
need no extra container volume.

Examples:
    python scripts/ops/generate_ssl.py --out ./data/tls
    python scripts/ops/generate_ssl.py --out ./data/tls \
        --test https://127.0.0.1:8443 --insecure --days 365
"""
from __future__ import annotations

import argparse
import shutil
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path


def generate(target: Path, *, days: int, hostname: str) -> dict:
    target.mkdir(parents=True, exist_ok=True)
    cert = target / "server.crt"
    key = target / "server.key"
    if cert.exists() or key.exists():
        raise FileExistsError("Refusing to overwrite existing TLS material")
    if shutil.which("openssl"):
        command = [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert), "-days", str(days),
            "-subj", f"/CN={hostname}",
            "-addext", f"subjectAltName=DNS:{hostname},IP:127.0.0.1",
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError("openssl failed: " + completed.stderr[-800:])
    else:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=days)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(hostname), x509.IPAddress(
                        __import__("ipaddress").ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(private, hashes.SHA256())
        )
        with key.open("wb") as stream:
            stream.write(private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with cert.open("wb") as stream:
            stream.write(certificate.public_bytes(serialization.Encoding.PEM))
    key.chmod(0o600)
    cert.chmod(0o644)
    return {
        "certfile": str(cert),
        "keyfile": str(key),
        # TLS is env-only: never write certificate paths into config.yaml.
        "env_snippet": (
            "# WebUI/REST listener\n"
            f"TELEDRIVE_SSL_CERTFILE={cert}\n"
            f"TELEDRIVE_SSL_KEYFILE={key}\n"
            "# S3 gateway listener (independent pair; same files work)\n"
            f"TELEDRIVE_S3_SSL_CERTFILE={cert}\n"
            f"TELEDRIVE_S3_SSL_KEYFILE={key}\n"
        ),
    }


def test_https(url: str, cert: Path, *, insecure: bool) -> None:
    # Only ever probe an HTTPS listener; the URL comes from the operator's
    # own command line, and a file:// read here would be a surprise.
    if not url.startswith("https://"):
        raise ValueError("test_https only accepts an https:// URL")
    context = ssl.create_default_context(cafile=str(cert))
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(  # nosec B310 -- https:// checked above
            url, context=context, timeout=10) as response:
        body = response.read(256)
    print(f"HTTPS OK: {url} responded with HTTP {response.status}")
    if not body:
        raise RuntimeError("Empty HTTPS response")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True,
                        help="Directory for server.crt and server.key")
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--hostname", default="localhost")
    parser.add_argument("--test", default="",
                        help="Verify a running instance, e.g. https://127.0.0.1:8443")
    parser.add_argument("--insecure", action="store_true",
                        help="Accept the self-signed chain without hostname checks")
    args = parser.parse_args()
    try:
        if args.test:
            cert = args.out / "server.crt"
            if not cert.is_file():
                parser.error(f"{cert} missing; generate it first")
            test_https(args.test, cert, insecure=args.insecure)
            return 0
        result = generate(args.out, days=args.days, hostname=args.hostname)
        print("TLS material generated:")
        print("  cert:", result["certfile"])
        print("  key: ", result["keyfile"])
        print()
        print("TLS is ENV-ONLY. Add to the docker-compose environment")
        print("(or .env), then restart the service:")
        print(result["env_snippet"])
        return 0
    except Exception as exc:
        print("SSL tool failed: " + type(exc).__name__ + ": " + str(exc),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
