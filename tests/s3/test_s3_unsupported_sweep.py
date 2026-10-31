"""P2 adversarial sweep: every manifest-unsupported operation fails closed.

Driven directly by teledrive/s3/operation_manifest.json: for each
operation still marked unsupported, the mapped AWS-shaped request is
sent with a VALID signature against a live gateway listener. The
contract: no accidental 2xx, no mutation of the existing bucket or
object, and zero Telegram traffic. This closes the spec checklist item
"for unsupported operations, add adversarial selector/HTTP method
tests: no accidental HTTP 200 or mutation".

Implemented operations are covered by their own suites and are not
listed here; this sweep only maps what the manifest still reports as
unsupported, so no entry is skipped on every run.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.s3.test_s3_gateway import service, signed

ROOT = Path(__file__).resolve().parents[2]

# Unsupported operation -> the AWS-shaped request that names it.
# Selector ops map to their subresource; endpoint-shaped ops
# (WriteGetObjectResponse) map to their documented URI shapes.
REQUESTS = {
    # AWS-specific object retrieval and event-driven responses.
    "GetObjectTorrent": ("GET", "/sweep-bucket/asset.bin?torrent"),
    "WriteGetObjectResponse": ("POST", "/WriteGetObjectResponse"),
}


def _unsupported_operations() -> list[str]:
    manifest = json.loads(
        (ROOT / "teledrive/s3/operation_manifest.json").read_text())
    return [op["name"] for op in manifest["operations"]
            if op.get("status") == "unsupported"]


def test_every_unsupported_operation_is_mapped_by_the_sweep():
    """The sweep cannot silently skip a newly unsupported operation."""
    unmapped = [name for name in _unsupported_operations()
                if name not in REQUESTS]
    extra = [name for name in REQUESTS
             if name not in set(_unsupported_operations())]
    assert not unmapped, f"Unmapped unsupported operations: {unmapped}"
    assert not extra, f"Sweep maps supported/renamed operations: {extra}"


@pytest.mark.parametrize("operation", sorted(REQUESTS))
def test_unsupported_operation_never_succeeds_or_mutates(service, operation):
    method, path = REQUESTS[operation]
    assert signed(service, "PUT", "/sweep-bucket").status_code == 200
    assert signed(service, "PUT", "/sweep-bucket/asset.bin",
                  b"sweep-protected-bytes").status_code == 200
    telegram = service[2]
    uploads_before = telegram.uploads

    reply = signed(service, method, path, b"<configuration/>"
                   if method in ("PUT", "POST") else b"")

    # Fail closed: never a success status, never a redirect-to-2xx.
    assert reply.status_code not in (200, 201, 204, 206, 301, 302), (
        operation, reply.status_code, reply.text[:200])

    # The existing bucket and object are untouched, and not one byte
    # moved to Telegram for an unsupported control operation.
    assert signed(service, "HEAD", "/sweep-bucket").status_code == 200
    head = signed(service, "HEAD", "/sweep-bucket/asset.bin")
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(b"sweep-protected-bytes"))
    assert telegram.uploads == uploads_before
