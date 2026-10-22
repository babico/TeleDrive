"""Real rclone binary compatibility against the S3 gateway listener.

The P2 client matrix (boto3 already covered by test_s3_gateway) is
extended with the actual rclone binary: bucket creation, upload, tree
listing, byte-identical readback, size accounting and deletion — all
through rclone's own SigV4 signing and its S3 protocol expectations.

Skipped when no rclone binary is available (CI installs it explicitly).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

import web.s3 as gateway
from tests.s3.test_s3_gateway import service

RCLONE = shutil.which("rclone")


@pytest.mark.skipif(RCLONE is None, reason="rclone binary is required")
def test_real_rclone_binary_round_trip(service, tmp_path):
    import uvicorn

    _, issued, bot, _, _ = service
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port,
        log_level="error", lifespan="off"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]},
                              daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "ASGI S3 server did not start"

        env = dict(os.environ)
        env.update({
            "RCLONE_CONFIG_SWEEP_TYPE": "s3",
            "RCLONE_CONFIG_SWEEP_PROVIDER": "Other",
            "RCLONE_CONFIG_SWEEP_ACCESS_KEY_ID": issued.access_key,
            "RCLONE_CONFIG_SWEEP_SECRET_ACCESS_KEY": issued.secret_key,
            "RCLONE_CONFIG_SWEEP_ENDPOINT": f"http://127.0.0.1:{port}",
            "RCLONE_CONFIG_SWEEP_REGION": "us-east-1",
            # Keep test runs hermetic: no update checks, no config dir.
            "RCLONE_CONFIG_DIR": str(tmp_path / "rclone-config"),
        })

        def rclone(*args, check=True):
            result = subprocess.run(
                [RCLONE, *args], env=env, capture_output=True,
                timeout=120)
            if check and result.returncode != 0:
                raise AssertionError(
                    f"rclone {' '.join(args)} failed: "
                    f"{result.stderr.decode('utf-8', 'replace')}")
            return result

        # Bucket creation and listing.
        rclone("mkdir", "sweep:rclone-bucket")
        assert b"rclone-bucket" in rclone("lsd", "sweep:").stdout

        # Upload with a nested key, then verify tree listing + size.
        payload = os.urandom(77_777)
        source = Path(tempfile.mkstemp(dir=tmp_path)[1])
        source.write_bytes(payload)
        rclone("copyto", str(source), "sweep:rclone-bucket/nested/file.bin")
        listing = rclone("ls", "sweep:rclone-bucket").stdout.decode()
        assert "nested/file.bin" in listing
        assert str(len(payload)) in listing.split()

        # Byte-identical readback through rclone's own GET path.
        assert rclone("cat", "sweep:rclone-bucket/nested/file.bin"
                      ).stdout == payload

        # Size accounting sees exactly one object with the right size.
        size_out = rclone("size", "sweep:rclone-bucket").stdout.decode()
        assert "1" in size_out and str(len(payload)) in size_out

        # Delete and confirm the listing is empty again.
        rclone("delete", "sweep:rclone-bucket/nested/file.bin")
        assert rclone("ls", "sweep:rclone-bucket").stdout.strip() == b""

        assert bot.uploads >= 1 and bot.downloads >= 1
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "ASGI S3 server did not stop"
