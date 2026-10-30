"""Signed production evidence alone never asserts deployment acceptance."""
from __future__ import annotations
import base64
import copy
from hashlib import sha256
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts.ops.verify_production_bundle import canonical_payload, verify_bundle

COMMIT = "a" * 40


def fixture():
    one, two = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pubs = tuple(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                 for k in (one, two))
    hashed = lambda text: sha256(text.encode()).hexdigest()
    report = {
        "release_sha": COMMIT,
        "original_telegram_data_attested": True,
        "no_legacy_source_attested": True,
        "topology": {
            "independent_hosts_owner_attested": True,
            "hosts": [
                {"label": label, "machine_id_sha256": hashed(label),
                 "shared_database_sha256": hashed("same-sql-db")}
                for label in ("host-a", "host-b")
            ],
        },
        "soak": {
            "telemetry_gate_passed": True, "duration_seconds": 3600,
            "host_labels": ["host-a", "host-b"],
            "final_shared_counter_agreement": True,
            "explicit_429_deltas_by_host": {"host-a": 1, "host-b": 1},
            "telegram_mutations_performed": 0,
        },
        "dr": {
            "verified": True, "source_database_modified": False,
            "telegram_uploads": 0, "telegram_deletions": 0,
            "archive_sha256": hashed("backup"), "sha256": hashed("original"),
            "size": 100, "readback_bytes": 100,
        },
        "cutover": {"not_applicable": True},
    }
    def sign(entry):
        entry = copy.deepcopy(entry)
        raw = canonical_payload(entry)
        entry["approvals"] = {
            role: base64.b64encode(key.sign(raw)).decode()
            for role, key in (("owner", one), ("operator", two))
        }
        return entry
    return report, pubs, sign


def test_complete_attested_bundle_is_not_automatic_production_signoff():
    data, keys, sign = fixture()
    result = verify_bundle(sign(data), expected_sha=COMMIT,
                           owner_public_key=keys[0], operator_public_key=keys[1])
    assert result["technical_evidence_verified"]
    assert result["production_acceptance_signed_off"] is False
    assert result["physical_telegram_deletion_enabled"] is False


@pytest.mark.parametrize("change", [
    lambda d: d["topology"]["hosts"][1].update(machine_id_sha256=d["topology"]["hosts"][0]["machine_id_sha256"]),
    lambda d: d["soak"].update(duration_seconds=3599),
    lambda d: d["soak"].update(telemetry_gate_passed=False),
    lambda d: d["dr"].update(sha256="0"),
    lambda d: d["cutover"].update(not_applicable=False),
    lambda d: d.update(original_telegram_data_attested=False),
    lambda d: d.update(no_legacy_source_attested=False),
])
def test_invalid_production_receipts_rejected_even_if_approved(change):
    data, keys, sign = fixture()
    change(data)
    with pytest.raises(ValueError):
        verify_bundle(sign(data), expected_sha=COMMIT,
                      owner_public_key=keys[0], operator_public_key=keys[1])


def test_modified_bundle_or_reused_owner_key_fails_closed():
    data, keys, sign = fixture()
    signed = sign(data)
    signed["soak"]["duration_seconds"] += 1
    with pytest.raises(ValueError):
        verify_bundle(signed, expected_sha=COMMIT,
                      owner_public_key=keys[0], operator_public_key=keys[1])
    with pytest.raises(ValueError):
        verify_bundle(sign(data), expected_sha=COMMIT,
                      owner_public_key=keys[0], operator_public_key=keys[0])
    with pytest.raises(ValueError):
        verify_bundle(sign(data), expected_sha="b"*40,
                      owner_public_key=keys[0], operator_public_key=keys[1])


def test_approvals_are_optional_but_a_supplied_one_is_still_verified():
    """Owner decision: no two-person requirement.

    The technical evidence still has to verify. An optional signature that IS
    present is still checked, because "optional" must not become "unverified"
    -- a forged signature is a stronger signal than an absent one.
    """
    data, keys, sign = fixture()

    # No approvals block at all: accepted on the technical evidence.
    bare = copy.deepcopy(data)
    bare.pop("approvals", None)
    result = verify_bundle(bare, expected_sha=COMMIT,
                           owner_public_key=keys[0],
                           operator_public_key=keys[1])
    assert result["technical_evidence_verified"] is True
    assert result["verified_attestations"] == []

    # One signature: verified, and reported.
    one = copy.deepcopy(data)
    raw = canonical_payload(one)
    # Sign with a key whose public half we then declare as the owner key.
    solo = Ed25519PrivateKey.generate()
    solo_pub = solo.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    one["approvals"] = {"owner": base64.b64encode(solo.sign(raw)).decode()}
    single = verify_bundle(one, expected_sha=COMMIT,
                           owner_public_key=solo_pub,
                           operator_public_key=keys[1])
    assert single["verified_attestations"] == ["owner"]

    # A bad signature is still a hard failure.
    bad = copy.deepcopy(data)
    bad["approvals"] = {"owner": base64.b64encode(b"x" * 64).decode()}
    with pytest.raises(ValueError, match="Evidence signature|signature"):
        verify_bundle(bad, expected_sha=COMMIT,
                      owner_public_key=keys[0], operator_public_key=keys[1])
