"""The Telegram DR rehearsal proves its own machinery offline.

The self-test mode of ``scripts/ops/rehearse_telegram_dr.py`` builds a
synthetic sealed snapshot plus a synthetic byte backend and drives the
whole verification path, including every documented failure mode and
exit code. These tests invoke that mode exactly the way an owner would,
plus focused checks on the exit-code map, range planning, redaction and
the redacted evidence record. Nothing here needs Telegram, the network
or the live service.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ops" / "rehearse_telegram_dr.py"

EXPECTED_SCENARIOS = {
    "sample-object-verified",
    "encrypted-key-restore-verified",
    "snapshot-digest-refused",
    "missing-object",
    "missing-remote-chunk",
    "scope-refused",
    "corrupt-chunk",
    "encrypted-without-key",
}


def _run_cli(argv: list[str]) -> subprocess.CompletedProcess:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("TELEDRIVE")
    }
    return subprocess.run(
        [sys.executable, str(SCRIPT), *argv],
        capture_output=True, text=True, timeout=300,
        cwd=str(ROOT), env=environment,
    )


def test_self_test_passes_with_every_failure_mode():
    completed = _run_cli(["--self-test"])
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["self_test"] == "PASS"
    scenarios = {entry["name"]: entry for entry in payload["scenarios"]}
    assert EXPECTED_SCENARIOS <= set(scenarios)
    assert all(entry["outcome"] == "PASS" for entry in scenarios.values())
    # The documented exit codes were actually exercised, not just listed.
    assert scenarios["snapshot-digest-refused"]["exit"] == 2
    assert scenarios["missing-object"]["exit"] == 3
    assert scenarios["scope-refused"]["exit"] == 4
    assert scenarios["corrupt-chunk"]["exit"] == 5
    assert scenarios["encrypted-without-key"]["exit"] == 6


def test_self_test_never_mutates_its_synthetic_sources():
    completed = _run_cli(["--self-test"])
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["read_only_invariants"] == {
        "source_database_modified": False,
        "archive_modified": False,
        "telegram_uploads": 0,
        "telegram_deletions": 0,
    }


def test_help_documents_the_owner_contract():
    completed = _run_cli(["--help"])
    assert completed.returncode == 0
    assert not completed.stderr
    for flag in ("--snapshot", "--sha256", "--bucket", "--key", "--account",
                 "--chat-id", "--target", "--version-id", "--object-sha256",
                 "--object-size", "--master-key-file", "--evidence-dir",
                 "--max-bytes", "--self-test"):
        assert flag in completed.stdout
    for code in ("0", "1", "2", "3", "4", "5", "6"):
        assert f"  {code} " in completed.stdout


def test_owner_arguments_are_required_outside_self_test():
    completed = _run_cli([])
    assert completed.returncode == 2
    assert "--snapshot" in completed.stderr and "--chat-id" in completed.stderr


def test_missing_environment_fails_closed_without_touching_the_snapshot(
        tmp_path):
    sentinel = tmp_path / "sealed-snapshot.db"
    completed = _run_cli([
        "--snapshot", str(sentinel),
        "--sha256", "0" * 64,
        "--bucket", "evidence-fixture-bucket",
        "--key", "original/one.bin",
        "--account", "api-bot",
        "--chat-id", "-1001234567890",
    ])
    assert completed.returncode == 1
    assert "DR rehearsal failed" in completed.stderr
    # Failed closed before reading anything: the snapshot was never opened.
    assert not sentinel.exists()


def test_exit_code_map_is_exhaustive_for_documented_failures():
    from scripts.ops.rehearse_telegram_dr import (
        AttestationError, KeyMaterialError, ScopeError, exit_code_for)
    from scripts.ops.verify_metadata_backup import InvalidSnapshot
    from teledrive.storage.engine import IntegrityError
    from teledrive.storage.sse import SSECError

    assert exit_code_for(InvalidSnapshot("receipt")) == 2
    assert exit_code_for(FileNotFoundError("key")) == 3
    assert exit_code_for(ScopeError("scope")) == 4
    assert exit_code_for(ValueError("budget")) == 1
    assert exit_code_for(IntegrityError("chunk")) == 5
    assert exit_code_for(AttestationError("digest")) == 5
    assert exit_code_for(KeyMaterialError("kek")) == 6
    assert exit_code_for(SSECError("InvalidRequest", "key")) == 6
    assert exit_code_for(RuntimeError("unexpected")) == 1


def test_planned_ranges_cover_first_middle_boundary_and_last():
    from scripts.ops.rehearse_telegram_dr import _planned_ranges

    assert _planned_ranges(0, []) == []
    single = _planned_ranges(1, [])
    assert single == [("first", 0, 1)]
    ranges = _planned_ranges(150_003, [65_536, 131_072])
    labels = [label for label, _, _ in ranges]
    assert labels[0] == "first"
    assert "middle" in labels and "last" in labels
    assert "cross-boundary-1" in labels and "cross-boundary-2" in labels
    for _, start, end in ranges:
        assert 0 <= start < end <= 150_003
    windows = {(start, end) for _, start, end in ranges}
    assert len(windows) == len(ranges)  # no duplicated windows
    # A snapshot with thousands of tiny chunks stays bounded.
    huge = _planned_ranges(70_000_000, [i * 1_000 for i in range(1, 70_000)])
    assert sum(1 for label, _, _ in huge
               if label.startswith("cross-boundary-")) <= 16


def test_redaction_strips_operator_private_values():
    from scripts.ops.rehearse_telegram_dr import redact

    secrets = ["evidence-fixture-bucket", "original/one.bin", "owner-user",
               "a" * 32]
    text = ("bucket=evidence-fixture-bucket key=original/one.bin "
            "hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
            "channel=-1001234567890 size=65537")
    scrubbed = redact(text, secrets)
    assert "evidence-fixture-bucket" not in scrubbed
    assert "original/one.bin" not in scrubbed
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in scrubbed
    assert "-1001234567890" not in scrubbed
    assert "[REDACTED]" in scrubbed and "[REDACTED:channel-id]" in scrubbed
    # Evidence the owner may share survives: sizes and receipts.
    assert "size=65537" in scrubbed


def _patched_rehearsal(monkeypatch, tmp_path, outcome):
    import scripts.ops.rehearse_telegram_dr as rehearse

    session_file = tmp_path / "mtproto-user.session"
    session_file.write_text("private-session-string\n", encoding="ascii")
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_API_ID", "12345")
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_API_HASH", "b" * 32)
    monkeypatch.setenv("TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE",
                       str(session_file))

    async def fake_verify(snapshot, receipt, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        print("stdout mentions evidence-fixture-bucket", file=sys.stderr)
        return outcome

    monkeypatch.setattr(rehearse, "verify_original_user_channel", fake_verify)
    return rehearse


def _evidence_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("dr-rehearsal-*.json"))


def test_main_writes_redacted_owner_only_evidence_record(
        monkeypatch, tmp_path, capsys):
    report = {
        "verified": True, "claim": "sample DR (one object)",
        "archive_sha256": "0" * 64, "object_id": "id", "version_id": None,
        "size": 65537, "sha256": "1" * 64, "verified_object_count": 1,
        "verified_ranges": [["first", 0, 37]], "chunk_count": 2,
        "encryption_mode": "plaintext",
        "encrypted_key_restore_verified": False,
        "independent_attestation_checked": True, "readback_bytes": 65537,
        "telegram_uploads": 0, "telegram_deletions": 0,
        "source_database_modified": False,
    }
    rehearse = _patched_rehearsal(
        monkeypatch, tmp_path, report)
    evidence_dir = tmp_path / "evidence"
    snapshot = tmp_path / "sealed.db"
    snapshot.write_bytes(b"synthetic")
    code = rehearse.main([
        "--snapshot", str(snapshot), "--sha256", "0" * 64,
        "--bucket", "evidence-fixture-bucket",
        "--key", "original/one.bin", "--account", "owner-user",
        "--chat-id", "-1001234567890",
        "--object-sha256", "1" * 64,
        "--evidence-dir", str(evidence_dir),
    ])
    assert code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["verified"] is True
    records = _evidence_files(evidence_dir)
    assert len(records) == 1
    assert stat.S_IMODE(records[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(evidence_dir.stat().st_mode) == 0o700
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["status"] == "PASS"
    assert record["verified_object_count"] == 1
    assert record["object_size"] == 65537 and record["object_sha256"] == "1" * 64
    assert record["commit_sha"] == rehearse._commit_sha()
    assert record["tool_versions"]["python"] == sys.version.split()[0]
    assert record["telegram_deletions"] == 0
    assert record["source_database_modified"] is False
    # Redaction: none of the operator-private values survive anywhere.
    serialized = json.dumps(record)
    for secret in ("evidence-fixture-bucket", "original/one.bin",
                   "owner-user", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                   "private-session-string", "-1001234567890"):
        assert secret not in serialized
    assert "[REDACTED]" in record["stderr_redacted"]


def test_main_records_failures_and_exit_code_in_evidence(
        monkeypatch, tmp_path, capsys):
    from teledrive.storage.engine import IntegrityError

    rehearse = _patched_rehearsal(
        monkeypatch, tmp_path, IntegrityError("chunk checksum mismatch"))
    evidence_dir = tmp_path / "evidence"
    snapshot = tmp_path / "sealed.db"
    snapshot.write_bytes(b"synthetic")
    code = rehearse.main([
        "--snapshot", str(snapshot), "--sha256", "0" * 64,
        "--bucket", "evidence-fixture-bucket",
        "--key", "original/one.bin", "--account", "owner-user",
        "--chat-id", "-1001234567890",
        "--evidence-dir", str(evidence_dir),
    ])
    assert code == 5
    record = json.loads(
        _evidence_files(evidence_dir)[0].read_text(encoding="utf-8"))
    assert record["status"] == "FAIL"
    assert record["failure"] == {"exit_code": 5, "error_type": "IntegrityError"}
    assert record["verified_object_count"] == 0
    assert "DR rehearsal failed: IntegrityError (exit 5)" in (
        capsys.readouterr().err)


def test_missing_environment_is_reported_not_crashed(monkeypatch, tmp_path):
    rehearse = _patched_rehearsal(monkeypatch, tmp_path, None)
    for name in ("TELEDRIVE_STORAGE_MTPROTO_API_ID",
                 "TELEDRIVE_STORAGE_MTPROTO_API_HASH"):
        monkeypatch.delenv(name, raising=False)
    snapshot = tmp_path / "sealed.db"
    snapshot.write_bytes(b"synthetic")
    code = rehearse.main([
        "--snapshot", str(snapshot), "--sha256", "0" * 64,
        "--bucket", "evidence-fixture-bucket",
        "--key", "original/one.bin", "--account", "owner-user",
        "--chat-id", "-1001234567890",
    ])
    assert code == 1
