"""Bucket replication API: strict XML, real SQL state, engine enforcement.

The destination of a rule is a configured TeleDrive credential-set label,
not an AWS bucket. These tests assert both the honest HTTP surface and the
engine's actual per-object routing decision (including prefix semantics),
so the configuration can never be cosmetic.
"""
from __future__ import annotations

import asyncio
import time
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy import text

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.replication import (
    MAX_REPLICATION_XML_BYTES, BucketReplicationStore, ReplicationError,
    matching_destination, parse_replication_xml, replication_xml,
)
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.engine import TelegramObjectStorage
from teledrive.storage.manifest import ManifestStore
from tests.storage.test_storage_engine import ReplicaAwareTelegram

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
DESTINATION = "offsite-account"


def add_destination(service, account=DESTINATION):
    db = service[3]()
    try:
        db.connection.execute(text(
            "INSERT INTO telegram_sessions (api_id, api_hash, phone, "
            "session_string, account, channel, strategy, created_at, updated_at) "
            "VALUES (1, 'hash', 'phone', 'session', :a, NULL, "
            "'round_robin', :n, :n)"), {"a": account, "n": int(time.time())})
        db.commit()
    finally:
        db.close()


def create_bucket(service, name="repl-bucket"):
    db = service[3]()
    try:
        BucketCatalog(ManifestStore(db)).create_bucket(name, int(time.time()))
    finally:
        db.close()


def replication_xml_for(*, role=None, rules=None):
    root = ET.Element("ReplicationConfiguration")
    if role is not None:
        ET.SubElement(root, "Role").text = role
    for index, (rule_id, status, prefix, destination) in enumerate(
            rules or [("logs", "Enabled", "logs/", DESTINATION)]):
        rule = ET.SubElement(root, "Rule")
        ET.SubElement(rule, "ID").text = rule_id
        ET.SubElement(rule, "Status").text = status
        destination_node = ET.SubElement(rule, "Destination")
        ET.SubElement(destination_node, "Bucket").text = destination
        if prefix is not None:
            filter_node = ET.SubElement(rule, "Filter")
            ET.SubElement(filter_node, "Prefix").text = prefix
    return ET.tostring(root)


def test_round_trip_get_put_delete_and_honest_404(service):
    add_destination(service)
    create_bucket(service)
    path = "/repl-bucket?replication"
    missing = signed(service, "GET", path)
    assert missing.status_code == 404
    assert ET.fromstring(missing.content).findtext("Code") == \
        "ReplicationConfigurationNotFoundError"

    body = replication_xml_for(
        role="arn:aws:iam::000000000000:role/ignored",
        rules=[
            ("logs", "Enabled", "logs/", DESTINATION),
            ("media", "Disabled", "media/", DESTINATION),
        ],
    )
    created = signed(service, "PUT", path, body)
    assert created.status_code == 200, created.text

    config = signed(service, "GET", path)
    assert config.status_code == 200, config.text
    root = ET.fromstring(config.content)
    assert root.findtext(f"{NS}Role") == "arn:aws:iam::000000000000:role/ignored"
    rules = root.findall(f"{NS}Rule")
    assert [rule.findtext(f"{NS}ID") for rule in rules] == ["logs", "media"]
    assert [rule.findtext(f"{NS}Status") for rule in rules] == [
        "Enabled", "Disabled"]
    assert rules[0].findtext(f"{NS}Filter/{NS}Prefix") == "logs/"
    assert rules[0].findtext(f"{NS}Destination/{NS}Bucket") == DESTINATION

    # The stored row is the source of the response, not a canned document.
    db = service[3]()
    try:
        store = BucketReplicationStore(
            BucketCatalog(ManifestStore(db)), destinations={DESTINATION})
        assert store.get("repl-bucket")["rules"][0]["prefixes"] == ["logs/"]
    finally:
        db.close()

    removed = signed(service, "DELETE", path)
    assert removed.status_code == 204
    assert signed(service, "GET", path).status_code == 404
    # Idempotent like AWS: deleting an absent configuration still answers 204.
    assert signed(service, "DELETE", path).status_code == 204


def test_put_replaces_atomically_and_rejects_unknown_destination(service):
    add_destination(service)
    create_bucket(service)
    path = "/repl-bucket?replication"
    assert signed(service, "PUT", path, replication_xml_for()).status_code == 200

    unknown = signed(service, "PUT", path, replication_xml_for(rules=[
        ("other", "Enabled", "other/", "not-a-configured-account")]))
    assert unknown.status_code == 400, unknown.text
    assert ET.fromstring(unknown.content).findtext("Code") == "InvalidRequest"
    # The rejected PUT did not disturb the previously stored rule set.
    assert b"logs/" in signed(service, "GET", path).content

    assert signed(service, "PUT", path, replication_xml_for(rules=[
        ("media", "Enabled", "media/", DESTINATION)])).status_code == 200
    replaced = signed(service, "GET", path)
    assert b"media/" in replaced.content and b"logs/" not in replaced.content


@pytest.mark.parametrize("body,status,code", [
    (b"<ReplicationConfiguration>", 400, "MalformedXML"),
    (b'<!DOCTYPE x [<!ENTITY bomb "xx">]><ReplicationConfiguration>'
     b'<Role>&bomb;</Role></ReplicationConfiguration>', 400, "MalformedXML"),
    (b"<Bogus/>", 400, "MalformedXML"),
    (b"<ReplicationConfiguration><Role>a</Role><Role>b</Role>"
     b"<Rule><Status>Enabled</Status><Destination><Bucket>x</Bucket>"
     b"</Destination></Rule></ReplicationConfiguration>", 400, "MalformedXML"),
    (b"<ReplicationConfiguration><Unknown/></ReplicationConfiguration>",
     400, "MalformedXML"),
    (b"<ReplicationConfiguration></ReplicationConfiguration>", 400,
     "InvalidRequest"),
    (b"x" * (MAX_REPLICATION_XML_BYTES + 1), 400, "MalformedXML"),
])
def test_strict_xml_rejections(service, body, status, code):
    add_destination(service)
    create_bucket(service)
    response = signed(service, "PUT", "/repl-bucket?replication", body)
    assert response.status_code == status, response.text
    assert ET.fromstring(response.content).findtext("Code") == code
    assert signed(service, "GET", "/repl-bucket?replication").status_code == 404


@pytest.mark.parametrize("xml,status,code", [
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Sideways</Status><Destination><Bucket>x</Bucket></Destination>"
     b"</Rule></ReplicationConfiguration>", 400, "InvalidRequest"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Prefix>a/</Prefix><Filter><Prefix>b/</Prefix>"
     b"</Filter><Destination><Bucket>x</Bucket></Destination></Rule>"
     b"</ReplicationConfiguration>", 400, "InvalidRequest"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Destination><Bucket>x</Bucket>"
     b"<Bucket>y</Bucket></Destination></Rule></ReplicationConfiguration>",
     400, "MalformedXML"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Filter><And><Prefix>x/</Prefix></And></Filter>"
     b"<Destination><Bucket>x</Bucket></Destination></Rule>"
     b"</ReplicationConfiguration>", 501, "NotImplemented"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Destination><Bucket>x</Bucket>"
     b"<StorageClass>STANDARD</StorageClass></Destination></Rule>"
     b"</ReplicationConfiguration>", 501, "NotImplemented"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Destination><Bucket>x</Bucket></Destination>"
     b"<DeleteMarkerReplication><Status>Enabled</Status>"
     b"</DeleteMarkerReplication></Rule></ReplicationConfiguration>",
     501, "NotImplemented"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Destination><Bucket>x</Bucket></Destination>"
     b"<SourceSelectionCriteria/></Rule></ReplicationConfiguration>",
     501, "NotImplemented"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Destination><Bucket>x</Bucket></Destination>"
     b"<ReplicaModifications><Status>Enabled</Status></ReplicaModifications>"
     b"</Rule></ReplicationConfiguration>", 501, "NotImplemented"),
    (b"<ReplicationConfiguration><Role>r</Role><Rule><ID>a</ID>"
     b"<Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::x</Bucket>"
     b"</Destination></Rule></ReplicationConfiguration>", 501, "NotImplemented"),
])
def test_unsupported_or_ambiguous_options_are_rejected(service, xml, status,
                                                       code):
    add_destination(service)
    create_bucket(service)
    response = signed(service, "PUT", "/repl-bucket?replication", xml)
    assert response.status_code == status, response.text
    assert ET.fromstring(response.content).findtext("Code") == code


def test_overlapping_enabled_prefixes_are_rejected(service):
    add_destination(service)
    create_bucket(service)
    body = replication_xml_for(rules=[
        ("one", "Enabled", "logs/", DESTINATION),
        ("two", "Enabled", "logs/2026/", DESTINATION),
    ])
    response = signed(service, "PUT", "/repl-bucket?replication", body)
    assert response.status_code == 400, response.text
    assert ET.fromstring(response.content).findtext("Code") == "InvalidRequest"
    # Disabling one makes the same overlapping prefixes a valid, bounded rule set.
    body = replication_xml_for(rules=[
        ("one", "Enabled", "logs/", DESTINATION),
        ("two", "Disabled", "logs/2026/", DESTINATION),
    ])
    assert signed(service, "PUT", "/repl-bucket?replication", body).status_code == 200


def test_engine_decision_is_prefix_aware_and_does_not_fall_back(service, tmp_path):
    create_bucket(service)
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        store = BucketReplicationStore(catalog, destinations={DESTINATION})
        store.replace("repl-bucket", {
            "role": None,
            "rules": [{
                "id": "logs", "status": "Enabled",
                "prefixes": ["logs/"], "destination": DESTINATION,
            }],
        })
        backend = ReplicaAwareTelegram()
        backend.replica = DESTINATION
        # A global operator target exists, but the stored configuration
        # must win and non-matching keys must NOT fall back to it.
        backend.replica_account = lambda: "global-account"
        engine = TelegramObjectStorage(
            ManifestStore(db), backend, chunk_size=4096)

        assert engine.replication_destination(
            "repl-bucket", "logs/2026/app.log") == DESTINATION
        assert engine.replication_destination(
            "repl-bucket", "media/clip.bin") is None
        assert engine.replication_destination(
            "no-config-bucket", "anything.bin") == "global-account"
        matched, destination = matching_destination(
            db, "repl-bucket", "media/clip.bin")
        assert (matched, destination) == (True, None)

        source = tmp_path / "log"
        source.write_bytes(b"x" * 5000)
        replicated = asyncio.run(
            engine.put_file("repl-bucket", "logs/2026/app.log", source))
        source.write_bytes(b"y" * 5000)
        skipped = asyncio.run(
            engine.put_file("repl-bucket", "media/clip.bin", source))

        rows = lambda item: db.connection.execute(text(
            "SELECT account FROM storage_replica_chunks WHERE object_id = :i"),
            {"i": item.id}).all()
        assert set(_accounts(rows(replicated))) == {DESTINATION}
        assert len(rows(replicated)) == len(ManifestStore(db).parts(replicated.id))
        assert rows(skipped) == []
        assert backend.replica_uploads == len(
            ManifestStore(db).parts(replicated.id))
    finally:
        db.close()


def _accounts(rows):
    return [str(row[0]) for row in rows]


def test_delete_removes_config_and_restores_default_decision(service):
    create_bucket(service)
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        store = BucketReplicationStore(catalog, destinations={DESTINATION})
        store.replace("repl-bucket", {
            "role": None,
            "rules": [{"id": "all", "status": "Enabled", "prefixes": [""],
                       "destination": DESTINATION}],
        })
        assert matching_destination(db, "repl-bucket", "k") == (True, DESTINATION)
        assert store.delete("repl-bucket") is True
        assert store.get("repl-bucket") is None
        assert matching_destination(db, "repl-bucket", "k") == (False, None)
        assert store.delete("repl-bucket") is False
    finally:
        db.close()


def test_permission_separation_for_replication(service):
    add_destination(service)
    create_bucket(service)
    db = service[3]()
    try:
        credentials = S3CredentialStore(db, service[4])
        writer = credentials.create(
            "replication-writer", ["s3:PutBucketReplication"])
        reader = credentials.create(
            "replication-reader", ["s3:GetBucketReplication"])
        remover = credentials.create(
            "replication-remover", ["s3:DeleteBucketReplication"])
        object_only = credentials.create("object-only", ["s3:GetObject"])
    finally:
        db.close()
    path = "/repl-bucket?replication"
    body = replication_xml_for()

    def as_key(method, credential, payload=b""):
        return signed(service, method, path, payload,
                      access=credential.access_key,
                      secret=credential.secret_key)

    assert as_key("PUT", object_only, body).status_code == 403
    assert as_key("PUT", writer, body).status_code == 200
    assert as_key("GET", writer).status_code == 403
    assert as_key("GET", reader).status_code == 200
    assert as_key("GET", object_only).status_code == 403
    assert as_key("DELETE", reader).status_code == 403
    assert as_key("DELETE", remover).status_code == 204
    assert as_key("GET", reader).status_code == 404


def test_route_guard_controls_replication_selectors(service):
    add_destination(service)
    create_bucket(service)
    assert signed(service, "PUT", "/repl-bucket/asset.bin", b"data").status_code == 200

    # Bucket route: GET/PUT/DELETE are real controls; HEAD is not.
    assert signed(service, "HEAD", "/repl-bucket?replication").status_code == 501
    assert signed(service, "GET", "/repl-bucket?replication=1").status_code == 400
    assert signed(service, "GET",
                  "/repl-bucket?replication&replication").status_code == 400
    assert signed(service, "GET",
                  "/repl-bucket?replication&tagging").status_code == 400
    # Object route: replication is not an object operation.
    assert signed(service, "DELETE",
                  "/repl-bucket/asset.bin?replication").status_code == 501
    assert signed(service, "GET",
                  "/repl-bucket/asset.bin?replication").status_code == 501
    # Valid selector still round-trips through the real handler.
    assert signed(service, "PUT", "/repl-bucket?replication",
                  replication_xml_for()).status_code == 200
    assert signed(service, "GET", "/repl-bucket?replication").status_code == 200


def test_parse_helpers_are_bounded_and_round_trip():
    body = replication_xml_for(role="opaque", rules=[
        ("a", "Enabled", "a/", DESTINATION),
        ("b", "Disabled", "", DESTINATION),
    ])
    config = parse_replication_xml(body, {DESTINATION})
    assert config["role"] == "opaque"
    assert parse_replication_xml(replication_xml(config), {DESTINATION}) == config
    with pytest.raises(ReplicationError) as exc:
        parse_replication_xml(
            body.replace(b"<Bucket>" + DESTINATION.encode(),
                         b"<Bucket>ghost"),
            {DESTINATION})
    assert exc.value.code == "InvalidRequest"
