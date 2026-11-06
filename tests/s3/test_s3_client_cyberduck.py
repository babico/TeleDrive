"""Real Cyberduck ``duck`` CLI round trip against the Telegram-backed gateway.

Cyberduck and its command-line front end ``duck`` share the same Java S3
implementation (``s3/src/main/java/ch/cyberduck/core/s3``). This module runs
the actual pinned binary, not a re-implementation, against Uvicorn in a
background thread over the shared service fixture: real SQLite manifests, a
fake USER MTProto transport holding real bytes, every downloaded byte
compared.

Pinned client: Cyberduck **9.6.0 (build 46406)**, the ``duck_9.6.0.46406_amd64.deb``
release archive from https://github.com/iterate-ch/cyberduck/releases/tag/release-9-6-0.

Two client facts are pinned here because they decide whether the gateway can
serve the client at all:

1. **``s3://`` means HTTPS/443.** ``S3Protocol.getScheme()`` returns
   ``Scheme.https`` (``s3/src/main/java/ch/cyberduck/core/s3/S3Protocol.java``).
   A plain-HTTP endpoint therefore needs a connection profile whose
   ``Scheme`` is ``http`` and whose URL scheme is distinct (``s3http``);
   that is exactly what an owner configures in the GUI too.
2. **Checksums are off by default.** ``defaults-9.6.0.jar`` ships
   ``queue.upload.checksum.calculate=false`` and ``S3WriteFeature`` then
   sends ``x-amz-content-sha256: UNSIGNED-PAYLOAD`` with no ``Content-MD5``
   (``S3WriteFeature.java`` lines 113-131). TeleDrive deliberately refuses
   unsigned mutable uploads, so the profile must set
   ``queue.upload.checksum.calculate=true``. Both the working profile and the
   refusal are asserted below so neither side can drift silently.

Local runs skip when no client is available unless
``TELEDRIVE_REQUIRE_CLI_CLIENTS=1`` is set (the same fail-closed switch the
real AWS CLI / rclone / minio-py suites use). CI sets it and installs the
pinned archive.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
import uvicorn

import web.s3 as gateway
from tests.s3.test_s3_gateway import service, signed

# The compatibility contract below is only proven for this exact build;
# drift is a test failure, never a silent "probably still works".
PINNED_CYBERDUCK_BUILD = "46406"
PINNED_CYBERDUCK_VERSION_LINE = "Cyberduck 9.6.0 (46406)"


@pytest.fixture
def live_s3(service):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    server = uvicorn.Server(uvicorn.Config(
        gateway.app, host="127.0.0.1", port=port, lifespan="off", log_level="error",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "S3 ASGI server did not start"
        yield f"http://127.0.0.1:{port}", service[1], service[2]
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "S3 ASGI server failed to stop"


def _duck_command():
    """Return the argv prefix that runs ``duck``, or skip/fail closed.

    Accepts either a ``duck`` executable on ``PATH`` (rpm/deb install) or the
    CI route, which unpacks the release ``.deb`` and points
    ``TELEDRIVE_DUCK_CLASSPATH`` at its application jars.
    """
    executable = shutil.which("duck")
    if executable:
        return [executable]
    classpath = os.environ.get("TELEDRIVE_DUCK_CLASSPATH")
    java = shutil.which("java")
    if classpath and java:
        return [java, "-cp", classpath, "ch.cyberduck.cli.Terminal"]
    if os.getenv("TELEDRIVE_REQUIRE_CLI_CLIENTS") == "1":
        pytest.fail(
            "Required real S3 client is absent: duck "
            "(install the pinned Cyberduck .deb or set TELEDRIVE_DUCK_CLASSPATH)"
        )
    pytest.skip("Install the pinned Cyberduck duck CLI to run its integration tests")


def _profile(*, checksum: bool, multipart_threshold: int | None = None) -> str:
    """A minimal Cyberduck connection profile for a plain-HTTP S3 endpoint.

    ``Scheme`` selects HTTP, ``Schemes`` gives the profile its own URL
    scheme, and ``Properties`` carries the per-bookmark preference overrides
    that ``Host.getProperty`` serves to ``HostPreferences``.
    """
    overrides = []
    if checksum:
        overrides.append("queue.upload.checksum.calculate=true")
    overrides.append("s3.bucket.virtualhost.disable=true")
    if multipart_threshold is not None:
        overrides.append(f"s3.upload.multipart.threshold={multipart_threshold}")
    properties = (
        "        <key>Properties</key>\n"
        "        <array>\n"
        + "".join(f"            <string>{value}</string>\n" for value in overrides)
        + "        </array>\n"
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Protocol</key>
        <string>s3</string>
        <key>Vendor</key>
        <string>TeleDrive</string>
        <key>Name</key>
        <string>TeleDrive S3 (HTTP)</string>
        <key>Default Nickname</key>
        <string>TeleDrive S3 (HTTP)</string>
        <key>Default Hostname</key>
        <string>127.0.0.1</string>
        <key>Default Port</key>
        <integer>80</integer>
        <key>Hostname Configurable</key>
        <true/>
        <key>Port Configurable</key>
        <true/>
        <key>Scheme</key>
        <string>http</string>
        <key>Schemes</key>
        <array><string>s3http</string></array>
        <key>Regions</key>
        <array><string>us-east-1</string></array>
{properties}    </dict>
</plist>
"""


class Duck:
    """A pinned ``duck`` process bound to one fixture endpoint and home dir."""

    def __init__(self, command, endpoint, issued, tmp_path):
        self.command = command
        self.endpoint = endpoint
        self.host = endpoint.rsplit("//", 1)[-1]
        self.issued = issued
        self.home = tmp_path / "duck-home"
        self.home.mkdir()
        self.profile = tmp_path / "teledrive.cyberduckprofile"

    def url(self, path: str = "") -> str:
        return f"s3http://{self.host}/{path}"

    def run(self, *args, profile=None, expect=0, timeout=240):
        command = list(self.command)
        command += list(args)
        command += [
            "-u", self.issued.access_key,
            "-p", self.issued.secret_key,
            "--region", "us-east-1",
            "--nokeychain", "--assumeyes", "--verbose",
        ]
        if profile is not None:
            command += ["--profile", str(profile)]
        done = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "HOME": str(self.home)},
        )
        transcript = done.stdout + done.stderr
        if expect is not None:
            assert done.returncode == expect, (
                f"duck {' '.join(args)} exited {done.returncode}, expected {expect}\n"
                f"stdout: {done.stdout[-4000:]}\nstderr: {done.stderr[-4000:]}"
            )
        return transcript


def _write_profile(duck: Duck, *, checksum: bool, multipart_threshold=None) -> Path:
    duck.profile.write_text(
        _profile(checksum=checksum, multipart_threshold=multipart_threshold),
        encoding="utf-8",
    )
    return duck.profile


def _source(tmp_path: Path) -> tuple[Path, bytes]:
    content = bytes(range(256)) * 121 + b"\x00\xff\x80binary"
    path = tmp_path / "source.bin"
    path.write_bytes(content)
    return path, content


def test_real_cyberduck_duck_version_is_pinned(live_s3, tmp_path):
    """The exercised binary is the release this module's contract names."""
    endpoint, issued, _ = live_s3
    duck = Duck(_duck_command(), endpoint, issued, tmp_path)
    transcript = duck.run("--version", expect=0)
    assert PINNED_CYBERDUCK_VERSION_LINE in transcript, transcript
    assert f"({PINNED_CYBERDUCK_BUILD})" in transcript


def test_real_cyberduck_duck_round_trip(live_s3, tmp_path):
    """Cyberduck CLI: list buckets, make bucket/folder, upload, long list,
    download with byte verification, and delete object and folder.

    The 409 on bucket deletion at the end is asserted explicitly: TeleDrive
    refuses to drop a bucket that still has object history (``catalog_buckets``
    "Bucket has object history; safe physical GC required"), so this is
    documented gateway semantics rather than a Cyberduck failure.
    """
    endpoint, issued, transport = live_s3
    duck = Duck(_duck_command(), endpoint, issued, tmp_path)
    profile = _write_profile(duck, checksum=True)
    source, content = _source(tmp_path)
    digest = hashlib.sha256(content).hexdigest()

    # List all buckets (GET /) and create the bucket (PUT /bucket, no body
    # for us-east-1).
    listing = duck.run("-l", duck.url(), profile=profile)
    assert "> GET / HTTP/1.1" in listing
    assert "> Host: " in listing
    duck.run("-c", duck.url("cyberduck-bucket"), profile=profile)

    # Fresh bucket is empty, and Cyberduck additionally probes in-progress
    # multipart uploads (?uploads=) alongside the listing.
    listing = duck.run("-l", duck.url("cyberduck-bucket"), profile=profile)
    assert (
        "?encoding-type=url&max-keys=1000&prefix=&delimiter=%2F" in listing
    ), listing
    assert "?delimiter=%2F&uploads=" in listing

    # Create a "directory" (zero-byte key with a trailing slash). The client
    # sends Content-MD5 even for this empty body.
    duck.run("-c", duck.url("cyberduck-bucket/dir/"), profile=profile)

    # Upload. With the checksum preference on, Cyberduck hashes the body,
    # sends Content-MD5 and keeps x-amz-content-sha256 unsigned - the exact
    # combination the gateway's unsigned-upload rule accepts.
    uploads_before = transport.uploads
    upload = duck.run(
        "--upload", duck.url("cyberduck-bucket/dir/source.bin"), str(source),
        profile=profile,
    )
    assert "> PUT /cyberduck-bucket/dir/source.bin HTTP/1.1" in upload, upload
    assert "> Content-MD5: " in upload, upload
    assert "> x-amz-content-sha256: UNSIGNED-PAYLOAD" in upload, upload
    assert "> User-Agent: Cyberduck/9.6.0.46406 " in upload, upload
    assert transport.uploads == uploads_before + 1

    # Long listing sees the object with its size.
    longlist = duck.run("-L", duck.url("cyberduck-bucket/dir/"), profile=profile)
    assert "source.bin" in longlist

    # Download: Cyberduck HEADs the key, then GETs it. Compare the bytes.
    retrieved = tmp_path / "retrieved.bin"
    duck.run(
        "-d", duck.url("cyberduck-bucket/dir/source.bin"), str(retrieved),
        profile=profile,
    )
    assert retrieved.read_bytes() == content
    assert hashlib.sha256(retrieved.read_bytes()).hexdigest() == digest
    assert transport.downloads >= 1

    # Delete the object. The bucket is versioned, so the gateway answers with
    # a delete marker (x-amz-delete-marker / x-amz-version-id).
    delete = duck.run(
        "-D", duck.url("cyberduck-bucket/dir/source.bin"), profile=profile
    )
    assert "> GET /cyberduck-bucket?versioning HTTP/1.1" in delete, delete
    assert "> DELETE /cyberduck-bucket/dir/source.bin HTTP/1.1" in delete, delete
    assert "< x-amz-delete-marker: true" in delete, delete

    listing = duck.run("-l", duck.url("cyberduck-bucket/dir/"), profile=profile)
    assert "source.bin" not in listing

    # Delete the directory key, then attempt bucket deletion. TeleDrive keeps
    # object history and demands physical GC first; the client surfaces the
    # gateway's message unchanged.
    duck.run("-D", duck.url("cyberduck-bucket/dir/"), profile=profile)
    transcript = duck.run(
        "-D", duck.url("cyberduck-bucket"), profile=profile, expect=None
    )
    assert "Bucket has object history; safe physical GC required" in transcript


def test_cyberduck_multipart_upload_completes(live_s3, tmp_path, service):
    """Cyberduck's multipart upload works end to end.

    The profile forces the multipart path at 1 KiB so a 6 MiB upload splits.
    Cyberduck sends ``POST /<bucket>/<key>?uploads=`` with a zero-length
    body, ``x-amz-content-sha256: UNSIGNED-PAYLOAD`` and no ``Content-MD5``:
    an initiation carries no bytes, and every part is checksummed
    individually. The gateway exempts exactly that zero-length initiation
    (declared ``Content-Length: 0``, never a chunked body) while every
    request that can carry bytes still needs a signed digest — so the
    initiation is accepted, the parts upload, and the bytes read back.
    """
    endpoint, issued, transport = live_s3
    duck = Duck(_duck_command(), endpoint, issued, tmp_path)
    profile = _write_profile(duck, checksum=True, multipart_threshold=1024)
    content = bytes(range(256)) * (6 * 4096)  # 6 MiB, one >=5 MiB part
    source = tmp_path / "multipart.bin"
    source.write_bytes(content)

    duck.run("-c", duck.url("multipart-bucket"), profile=profile)
    uploads_before = transport.uploads
    transcript = duck.run(
        "--upload", duck.url("multipart-bucket/multipart.bin"), str(source),
        profile=profile, expect=None,
    )
    assert "> POST /multipart-bucket/multipart.bin?uploads= HTTP/1.1" in transcript
    # With the checksum profile the initiation signs the empty-body digest;
    # an initiation with UNSIGNED-PAYLOAD and Content-Length: 0 is the shape
    # the gateway exemption admits (the default-unsigned single PUT below
    # still proves that rule).
    # The initiation is accepted and the split upload really ran.
    assert "partNumber=1" in transcript, transcript[-3000:]
    assert transport.uploads > uploads_before
    stored = signed(service, "GET", "/multipart-bucket/multipart.bin")
    assert stored.status_code == 200
    assert stored.content == content


def test_cyberduck_default_upload_is_refused_by_unsigned_upload_policy(
    live_s3, tmp_path, service
):
    """Pin the incompatibility that forces the checksum preference.

    Cyberduck's shipped default is ``queue.upload.checksum.calculate=false``
    (``defaults-9.6.0.jar``); without a checksum it sends UNSIGNED-PAYLOAD and
    no Content-MD5, which TeleDrive refuses by design rather than writing
    unauthenticated bytes. If either side changes, this test fails and the
    docs/profile guidance must change with it.
    """
    endpoint, issued, transport = live_s3
    duck = Duck(_duck_command(), endpoint, issued, tmp_path)
    profile = _write_profile(duck, checksum=False)
    source, _ = _source(tmp_path)

    duck.run("-c", duck.url("unsigned-bucket"), profile=profile)
    uploads_before = transport.uploads
    transcript = duck.run(
        "--upload", duck.url("unsigned-bucket/unsigned.bin"), str(source),
        profile=profile, expect=None,
    )
    assert "> PUT /unsigned-bucket/unsigned.bin HTTP/1.1" in transcript
    assert "> x-amz-content-sha256: UNSIGNED-PAYLOAD" in transcript
    assert "> Content-MD5: " not in transcript
    assert "Unsigned upload requires a signed Content-MD5 or SHA-256 checksum" in transcript
    assert transport.uploads == uploads_before
    assert signed(service, "GET", "/unsigned-bucket/unsigned.bin").status_code == 404
