"""Crash-restart column for the single-transaction bucket config writes.

The restart matrix (``tests/s3/test_s3_restart_matrix.py``) deliberately
excludes the config families whose whole effect commits in one SQL
transaction: there is no multi-step state machine to crash between. The
evidence matrix still owes each of them a per-operation restart proof,
and this file provides it: perform the write (or the delete) through the
signed gateway, then open a brand-new ``Database`` and a brand-new store
— exactly what a restarted process would do — and assert the persisted
state reads back exactly, and that a delete stays dead.

Families covered here (33 open crash-restart cells):

* CORS (Put/DeleteBucketCors), versioning (PutBucketVersioning),
  website delete (DeleteBucketWebsite),
* replication (Put/DeleteBucketReplication),
* storage-report deletes (analytics/inventory/metrics),
* intelligent tiering (Put/Delete),
* metadata configuration (create/delete V1+V2, inventory/annotation
  table updates),
* ABAC (PutBucketAbac), ACL (PutBucketAcl),
* ownership controls (Put/Delete), public access block (Put/Delete),
* bucket policy (Put/Delete), bucket encryption (Put/Delete),
* lifecycle (PutBucketLifecycle, PutBucketLifecycleConfiguration,
  DeleteBucketLifecycle),
* request payment / accelerate (the one-state controls),
* bucket tagging delete (DeleteBucketTagging).

The object- and service-level restart cells (CreateBucket,
DeleteBucket, UpdateObjectEncryption, the multipart creates, object
ACL/annotations/lock rows and the object tagging delete) live in
``tests/s3/test_s3_evidence_restart_objects.py``.
"""
from __future__ import annotations

import json
import time
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy import func, select

from teledrive.s3.bucket_encryption import BucketEncryptionStore
from teledrive.s3.cors import BucketCORSStore, cors_config
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.lifecycle import BucketLifecycleStore
from teledrive.s3.policy import BucketAbacStore, BucketPolicyStore
from teledrive.s3.replication import BucketReplicationStore
from teledrive.s3.report_configs import ReportConfigStore
from teledrive.s3.tiering import TieringStore
from teledrive.s3.website import WebsiteConfigStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_metadata_journal import (
    annotation_update, create_body, inventory_update, make_bucket,
    table_body,
)
from tests.s3.test_s3_replication import add_destination
from tests.s3.test_s3_report_configs import analytics, inventory, metrics
from tests.s3.test_s3_tagging import create, tag_xml

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
DESTINATION = "offsite-account"


def _fresh(service):
    """A new Database + catalog, as a restarted process would open them."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _cors_xml(max_age: int = 240) -> bytes:
    root = ET.Element("CORSConfiguration")
    rule = ET.SubElement(root, "CORSRule")
    ET.SubElement(rule, "AllowedOrigin").text = "https://app.example.com"
    ET.SubElement(rule, "AllowedMethod").text = "GET"
    ET.SubElement(rule, "AllowedMethod").text = "PUT"
    ET.SubElement(rule, "MaxAgeSeconds").text = str(max_age)
    return ET.tostring(root)


def _replication_xml(*, rule_id="logs", status="Enabled",
                     prefix="logs/", destination=DESTINATION) -> bytes:
    root = ET.Element("ReplicationConfiguration")
    rule = ET.SubElement(root, "Rule")
    ET.SubElement(rule, "ID").text = rule_id
    ET.SubElement(rule, "Status").text = status
    destination_node = ET.SubElement(rule, "Destination")
    ET.SubElement(destination_node, "Bucket").text = destination
    filter_node = ET.SubElement(rule, "Filter")
    ET.SubElement(filter_node, "Prefix").text = prefix
    return ET.tostring(root)


def _tiering_xml(config_id: str = "tier1") -> bytes:
    return (
        f'<IntelligentTieringConfiguration xmlns="{NS}">'
        f"<Id>{config_id}</Id>"
        f"<Filter><Prefix>cold/</Prefix></Filter>"
        f"<Status>Enabled</Status>"
        f"<Tiering><Days>1</Days>"
        f"<AccessTier>ARCHIVE_ACCESS</AccessTier></Tiering>"
        f"</IntelligentTieringConfiguration>").encode()


def _lifecycle_xml(days: int = 7) -> bytes:
    root = ET.Element("LifecycleConfiguration")
    rule = ET.SubElement(root, "Rule")
    ET.SubElement(rule, "ID").text = "abort-only"
    ET.SubElement(rule, "Status").text = "Enabled"
    filt = ET.SubElement(rule, "Filter")
    ET.SubElement(filt, "Prefix").text = "upload/"
    act = ET.SubElement(rule, "AbortIncompleteMultipartUpload")
    ET.SubElement(act, "DaysAfterInitiation").text = str(days)
    return ET.tostring(root)


def _ownership_xml(model: str) -> bytes:
    return (f'<OwnershipControls xmlns="{NS}"><Rule>'
            f"<ObjectOwnership>{model}</ObjectOwnership>"
            f"</Rule></OwnershipControls>").encode()


def _pab_xml(block: bool, ignore: bool, policy: bool,
             restrict: bool) -> bytes:
    def flag(value: bool) -> str:
        return "true" if value else "false"
    return (f'<PublicAccessBlockConfiguration xmlns="{NS}">'
            f"<BlockPublicAcls>{flag(block)}</BlockPublicAcls>"
            f"<IgnorePublicAcls>{flag(ignore)}</IgnorePublicAcls>"
            f"<BlockPublicPolicy>{flag(policy)}</BlockPublicPolicy>"
            f"<RestrictPublicBuckets>{flag(restrict)}</RestrictPublicBuckets>"
            f"</PublicAccessBlockConfiguration>").encode()


def _acl_xml(owner: str, grants: list[tuple[str, str]]) -> bytes:
    grants_xml = "".join(
        f'<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:type="CanonicalUser"><ID>{grantee}</ID></Grantee>'
        f"<Permission>{permission}</Permission></Grant>"
        for grantee, permission in grants)
    return (f'<AccessControlPolicy xmlns="{NS}">'
            f"<Owner><ID>{owner}</ID></Owner>"
            f"<AccessControlList>{grants_xml}</AccessControlList>"
            f"</AccessControlPolicy>").encode()


def _other_credential(service, name: str):
    db = service[3]()
    try:
        return S3CredentialStore(db, service[4]).create(name, ["s3:GetObject"])
    finally:
        db.close()


def _policy_json(service, bucket: str, effect: str = "Allow") -> bytes:
    other = _other_credential(service, f"policy-{effect.lower()}")
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": effect,
        "Principal": {"CanonicalUser": [other.access_key]},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{bucket}/*",
    }]}).encode()


def _bucket(service, name: str) -> str:
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def test_put_bucket_cors_survives_a_restart(service):
    bucket = _bucket(service, "restart-cors")
    assert signed(service, "PUT", f"/{bucket}?cors",
                  _cors_xml(240)).status_code == 200

    db, _catalog = _fresh(service)
    try:
        rules = BucketCORSStore(BucketCatalog(ManifestStore(db))).get(bucket)
        assert rules, "the CORS rules vanished after a restart"
        assert rules[0]["max_age"] == 240
        assert rules[0]["origins"] == ["https://app.example.com"]
        assert rules[0]["methods"] == ["GET", "PUT"]
        assert db.connection.execute(select(
            func.count()).select_from(cors_config).where(
            cors_config.c.bucket == bucket)).scalar_one() == 1, (
            "a single CORS PUT left more than one row")
    finally:
        db.close()

    config = signed(service, "GET", f"/{bucket}?cors")
    assert config.status_code == 200
    assert b"240" in config.content


def test_delete_bucket_cors_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-cors")
    assert signed(service, "PUT", f"/{bucket}?cors",
                  _cors_xml()).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?cors").status_code == 204

    db, _catalog = _fresh(service)
    try:
        assert BucketCORSStore(BucketCatalog(ManifestStore(db))).get(
            bucket) is None, "a deleted CORS configuration resurrected"
        assert db.connection.execute(select(
            func.count()).select_from(cors_config).where(
            cors_config.c.bucket == bucket)).scalar_one() == 0
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?cors").status_code == 404


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

def test_put_bucket_versioning_survives_a_restart(service):
    """Suspended is a real persisted state, not a process-local flag."""
    bucket = _bucket(service, "restart-versioning")
    suspended = (f'<VersioningConfiguration xmlns="{NS}">'
                 f"<Status>Suspended</Status>"
                 f"</VersioningConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?versioning",
                  suspended).status_code == 200

    db, catalog = _fresh(service)
    try:
        assert catalog.versioning_state(bucket) == "Suspended", (
            "the suspended versioning state vanished after a restart")
    finally:
        db.close()

    read = signed(service, "GET", f"/{bucket}?versioning")
    assert read.status_code == 200
    assert b"Suspended" in read.content


# ---------------------------------------------------------------------------
# Website (delete)
# ---------------------------------------------------------------------------

def test_delete_bucket_website_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-website")
    root = ET.Element("WebsiteConfiguration")
    index = ET.SubElement(root, "IndexDocument")
    ET.SubElement(index, "Suffix").text = "index.html"
    assert signed(service, "PUT", f"/{bucket}?website",
                  ET.tostring(root)).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?website").status_code == 204

    db, _catalog = _fresh(service)
    try:
        assert WebsiteConfigStore(BucketCatalog(ManifestStore(db))).get(
            bucket) is None, "a deleted website configuration resurrected"
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?website").status_code == 404


# ---------------------------------------------------------------------------
# Replication
# ---------------------------------------------------------------------------

def test_put_bucket_replication_survives_a_restart(service):
    add_destination(service)
    bucket = _bucket(service, "restart-replication")
    body = _replication_xml()
    assert signed(service, "PUT", f"/{bucket}?replication",
                  body).status_code == 200

    db, _catalog = _fresh(service)
    try:
        stored = BucketReplicationStore(
            BucketCatalog(ManifestStore(db))).get(bucket)
        assert stored is not None, "the replication configuration vanished"
        assert stored["rules"][0]["id"] == "logs"
        assert stored["rules"][0]["status"] == "Enabled"
        assert stored["rules"][0]["prefixes"] == ["logs/"]
        assert stored["rules"][0]["destination"] == DESTINATION
    finally:
        db.close()

    read = signed(service, "GET", f"/{bucket}?replication")
    assert read.status_code == 200
    assert DESTINATION.encode() in read.content


def test_delete_bucket_replication_stays_dead_after_a_restart(service):
    add_destination(service)
    bucket = _bucket(service, "restart-replication")
    assert signed(service, "PUT", f"/{bucket}?replication",
                  _replication_xml()).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?replication").status_code == 204

    db, _catalog = _fresh(service)
    try:
        assert BucketReplicationStore(
            BucketCatalog(ManifestStore(db))).get(bucket) is None, (
            "a deleted replication configuration resurrected")
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?replication").status_code == 404


# ---------------------------------------------------------------------------
# Storage report deletes
# ---------------------------------------------------------------------------

REPORT_BODIES = {
    "analytics": lambda: analytics("evidence-1"),
    "inventory": lambda: inventory("evidence-1"),
    "metrics": lambda: metrics("evidence-1"),
}


@pytest.mark.parametrize("kind", sorted(REPORT_BODIES))
def test_delete_report_configuration_stays_dead_after_a_restart(
        service, kind):
    _bucket(service, "report-source")
    _bucket(service, "report-dest")
    body = REPORT_BODIES[kind]()
    assert signed(service, "PUT", f"/report-source?{kind}&id=evidence-1",
                  body).status_code == 200
    assert signed(service, "DELETE",
                  f"/report-source?{kind}&id=evidence-1").status_code == 204

    db, _catalog = _fresh(service)
    try:
        store = ReportConfigStore(BucketCatalog(ManifestStore(db)))
        assert store.get("report-source", kind, "evidence-1") is None, (
            "a deleted report configuration resurrected")
        assert store.list("report-source", kind) == []
    finally:
        db.close()
    assert signed(service, "GET",
                  f"/report-source?{kind}&id=evidence-1").status_code == 404


# ---------------------------------------------------------------------------
# Intelligent tiering
# ---------------------------------------------------------------------------

def test_put_bucket_intelligent_tiering_survives_a_restart(service):
    bucket = _bucket(service, "restart-tiering")
    assert signed(service, "PUT", f"/{bucket}?intelligent-tiering&id=tier1",
                  _tiering_xml()).status_code == 200

    db, _catalog = _fresh(service)
    try:
        stored = TieringStore(BucketCatalog(ManifestStore(db))).get(
            bucket, "tier1")
        assert stored is not None, "the tiering configuration vanished"
        assert stored["id"] == "tier1"
        assert stored["status"] == "Enabled"
        assert stored["filter"]["prefix"] == "cold/"
    finally:
        db.close()

    read = signed(service, "GET", f"/{bucket}?intelligent-tiering&id=tier1")
    assert read.status_code == 200
    assert b"tier1" in read.content


def test_delete_bucket_intelligent_tiering_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-tiering")
    assert signed(service, "PUT", f"/{bucket}?intelligent-tiering&id=tier1",
                  _tiering_xml()).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?intelligent-tiering&id=tier1").status_code == 204

    db, _catalog = _fresh(service)
    try:
        store = TieringStore(BucketCatalog(ManifestStore(db)))
        assert store.get(bucket, "tier1") is None, (
            "a deleted tiering configuration resurrected")
        assert store.list(bucket) == []
    finally:
        db.close()
    assert signed(service, "GET",
                  f"/{bucket}?intelligent-tiering&id=tier1").status_code == 404


# ---------------------------------------------------------------------------
# Metadata configuration
# ---------------------------------------------------------------------------

def test_create_bucket_metadata_configuration_survives_a_restart(service):
    make_bucket(service, "restart-metadata")
    assert signed(service, "POST", "/restart-metadata?metadataConfiguration",
                  create_body(days=14)).status_code == 200

    from teledrive.s3.metadata_journal import MetadataConfigurationStore
    db, _catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get("restart-metadata")
        assert stored is not None, "the metadata configuration vanished"
        assert stored["retention_days"] == 14
    finally:
        db.close()
    assert signed(service, "GET",
                  "/restart-metadata?metadataConfiguration").status_code == 200


def test_create_bucket_metadata_table_configuration_survives_a_restart(
        service):
    make_bucket(service, "restart-metadata")
    assert signed(service, "POST", "/restart-metadata?metadataTable",
                  table_body("restart-table")).status_code == 200

    from teledrive.s3.metadata_journal import MetadataConfigurationStore
    db, _catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get("restart-metadata")
        assert stored is not None, "the V1 table configuration vanished"
        assert stored["table_name"] == "restart-table"
    finally:
        db.close()


def test_delete_bucket_metadata_configuration_stays_dead_after_a_restart(
        service):
    make_bucket(service, "restart-metadata")
    assert signed(service, "POST", "/restart-metadata?metadataConfiguration",
                  create_body()).status_code == 200
    assert signed(service, "DELETE",
                  "/restart-metadata?metadataConfiguration").status_code == 204

    from teledrive.s3.metadata_journal import (
        MetadataConfigurationStore, metadata_configs,
    )
    db, _catalog = _fresh(service)
    try:
        assert MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get(
            "restart-metadata") is None, (
            "a deleted metadata configuration resurrected")
        assert db.connection.execute(select(
            func.count()).select_from(metadata_configs).where(
            metadata_configs.c.bucket == "restart-metadata"
        )).scalar_one() == 0
    finally:
        db.close()
    assert signed(service, "GET",
                  "/restart-metadata?metadataConfiguration").status_code == 404


def test_delete_bucket_metadata_table_configuration_stays_dead_after_a_restart(
        service):
    make_bucket(service, "restart-metadata")
    assert signed(service, "POST", "/restart-metadata?metadataTable",
                  table_body("vanishing-table")).status_code == 200
    assert signed(service, "DELETE",
                  "/restart-metadata?metadataTable").status_code == 204

    from teledrive.s3.metadata_journal import (
        MetadataConfigurationStore, metadata_configs,
    )
    db, _catalog = _fresh(service)
    try:
        assert MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get(
            "restart-metadata") is None, (
            "a deleted V1 table configuration resurrected")
        assert db.connection.execute(select(
            func.count()).select_from(metadata_configs).where(
            metadata_configs.c.bucket == "restart-metadata"
        )).scalar_one() == 0
    finally:
        db.close()


def test_update_bucket_metadata_inventory_table_survives_a_restart(service):
    make_bucket(service, "restart-metadata")
    assert signed(service, "POST", "/restart-metadata?metadataConfiguration",
                  create_body(inventory="DISABLED")).status_code == 200
    assert signed(service, "PUT", "/restart-metadata?metadataInventoryTable",
                  inventory_update("ENABLED")).status_code == 200

    from teledrive.s3.metadata_journal import MetadataConfigurationStore
    db, _catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get("restart-metadata")
        assert stored is not None
        assert stored["inventory_enabled"] is True, (
            "the inventory table update vanished after a restart")
    finally:
        db.close()


def test_update_bucket_metadata_annotation_table_survives_a_restart(service):
    make_bucket(service, "restart-metadata")
    assert signed(service, "POST", "/restart-metadata?metadataConfiguration",
                  create_body(annotation="DISABLED")).status_code == 200
    assert signed(service, "PUT", "/restart-metadata?metadataAnnotationTable",
                  annotation_update("ENABLED")).status_code == 200

    from teledrive.s3.metadata_journal import MetadataConfigurationStore
    db, _catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get("restart-metadata")
        assert stored is not None
        assert stored["annotation_enabled"] is True, (
            "the annotation table update vanished after a restart")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ABAC
# ---------------------------------------------------------------------------

def test_put_bucket_abac_survives_a_restart(service):
    bucket = _bucket(service, "restart-abac")
    document = {"Status": "Enabled"}
    assert signed(service, "PUT", f"/{bucket}?abac",
                  json.dumps(document).encode()).status_code == 200

    db, _catalog = _fresh(service)
    try:
        stored = BucketAbacStore(BucketCatalog(ManifestStore(db))).get(bucket)
        assert stored is not None, "the ABAC configuration vanished"
        assert stored["status"] == "Enabled"
        assert stored["document"] == document
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?abac").json()[
        "Status"] == "Enabled"


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------

def test_put_bucket_acl_survives_a_restart(service):
    bucket = _bucket(service, "restart-acl")
    other = _other_credential(service, "acl-grantee")
    owner = service[1].access_key
    grants = [(other.access_key, "READ")]
    assert signed(service, "PUT", f"/{bucket}?acl",
                  _acl_xml(owner, grants)).status_code == 200

    db, catalog = _fresh(service)
    try:
        stored_owner, stored_grants = catalog.bucket_acl(bucket)
        assert stored_owner == owner
        # The owner's implicit FULL_CONTROL row is part of the contract.
        assert sorted(stored_grants) == sorted(
            grants + [(owner, "FULL_CONTROL")])
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?acl")
    assert read.status_code == 200
    assert other.access_key.encode() in read.content


# ---------------------------------------------------------------------------
# Ownership controls
# ---------------------------------------------------------------------------

def test_put_bucket_ownership_controls_survive_a_restart(service):
    bucket = _bucket(service, "restart-ownership")
    assert signed(service, "PUT", f"/{bucket}?ownershipControls",
                  _ownership_xml("ObjectWriter")).status_code == 200

    db, catalog = _fresh(service)
    try:
        assert catalog.object_ownership(bucket) == "ObjectWriter", (
            "the ownership model vanished after a restart")
    finally:
        db.close()
    assert b"ObjectWriter" in signed(
        service, "GET", f"/{bucket}?ownershipControls").content


def test_delete_bucket_ownership_controls_stay_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-ownership")
    assert signed(service, "PUT", f"/{bucket}?ownershipControls",
                  _ownership_xml("ObjectWriter")).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?ownershipControls").status_code == 204

    db, catalog = _fresh(service)
    try:
        assert catalog.object_ownership(bucket) == "BucketOwnerEnforced", (
            "a deleted ownership configuration did not reset to the default")
    finally:
        db.close()
    assert b"BucketOwnerEnforced" in signed(
        service, "GET", f"/{bucket}?ownershipControls").content


# ---------------------------------------------------------------------------
# Public access block
# ---------------------------------------------------------------------------

def test_put_public_access_block_survives_a_restart(service):
    bucket = _bucket(service, "restart-pab")
    flags = {"BlockPublicAcls": False, "IgnorePublicAcls": True,
             "BlockPublicPolicy": False, "RestrictPublicBuckets": True}
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  _pab_xml(False, True, False, True)).status_code == 200

    db, catalog = _fresh(service)
    try:
        assert catalog.public_access_block(bucket) == flags, (
            "the public access block flags vanished or tore after a restart")
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?publicAccessBlock")
    assert b"<IgnorePublicAcls>true</IgnorePublicAcls>" in read.content


def test_delete_public_access_block_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-pab")
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  _pab_xml(False, False, False, False)).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?publicAccessBlock").status_code == 204

    db, catalog = _fresh(service)
    try:
        assert catalog.public_access_block(bucket) == {
            field: True for field in catalog.PAB_FIELDS}, (
            "a deleted public access block did not reset to all-true")
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?publicAccessBlock")
    assert b"<BlockPublicAcls>true</BlockPublicAcls>" in read.content


# ---------------------------------------------------------------------------
# Bucket policy
# ---------------------------------------------------------------------------

def test_put_bucket_policy_survives_a_restart(service):
    bucket = _bucket(service, "restart-policy")
    document = _policy_json(service, bucket)
    assert signed(service, "PUT", f"/{bucket}?policy",
                  document).status_code == 204

    db, _catalog = _fresh(service)
    try:
        stored = BucketPolicyStore(BucketCatalog(ManifestStore(db))).get(
            bucket)
        assert stored is not None, "the bucket policy vanished"
        assert json.loads(stored) == json.loads(document)
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?policy")
    assert read.status_code == 200
    assert read.json() == json.loads(document)


def test_delete_bucket_policy_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-policy")
    assert signed(service, "PUT", f"/{bucket}?policy",
                  _policy_json(service, bucket)).status_code == 204
    assert signed(service, "DELETE", f"/{bucket}?policy").status_code == 204

    db, _catalog = _fresh(service)
    try:
        assert BucketPolicyStore(BucketCatalog(ManifestStore(db))).get(
            bucket) is None, "a deleted bucket policy resurrected"
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?policy").status_code == 404


# ---------------------------------------------------------------------------
# Bucket encryption
# ---------------------------------------------------------------------------

def test_put_bucket_encryption_survives_a_restart(service):
    bucket = _bucket(service, "restart-encryption")
    empty = (f'<ServerSideEncryptionConfiguration xmlns="{NS}"/>').encode()
    assert signed(service, "PUT", f"/{bucket}?encryption",
                  empty).status_code == 200

    db, _catalog = _fresh(service)
    try:
        stored = BucketEncryptionStore(db).get(bucket)
        assert stored == [], (
            "the (empty, SSE-C-only) encryption rule set changed or vanished")
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?encryption").status_code == 200


def test_delete_bucket_encryption_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-encryption")
    empty = (f'<ServerSideEncryptionConfiguration xmlns="{NS}"/>').encode()
    assert signed(service, "PUT", f"/{bucket}?encryption",
                  empty).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?encryption").status_code == 204

    db, _catalog = _fresh(service)
    try:
        assert BucketEncryptionStore(db).get(bucket) is None, (
            "a deleted bucket encryption configuration resurrected")
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?encryption").status_code == 404


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def _lifecycle_restart_read(service, bucket, days):
    db, _catalog = _fresh(service)
    try:
        stored = BucketLifecycleStore(
            BucketCatalog(ManifestStore(db))).get(bucket)
        assert stored is not None, "the lifecycle rules vanished"
        rule = stored[0]
        assert rule["id"] == "abort-only"
        assert rule["status"] == "Enabled"
        assert rule["prefix"] == "upload/"
        assert rule["abort_days"] == days, (
            "the stored abort age changed across the restart")
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?lifecycle")
    assert read.status_code == 200
    assert str(days).encode() in read.content


def test_put_bucket_lifecycle_survives_a_restart(service):
    """The V1 name: the same ``?lifecycle`` selector as the V2 operation."""
    bucket = _bucket(service, "restart-lifecycle")
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  _lifecycle_xml(7)).status_code == 200
    _lifecycle_restart_read(service, bucket, 7)


def test_put_bucket_lifecycle_configuration_survives_a_restart(service):
    """The V2 name: the same ``?lifecycle`` selector as the V1 operation."""
    bucket = _bucket(service, "restart-lifecycle")
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  _lifecycle_xml(14)).status_code == 200
    _lifecycle_restart_read(service, bucket, 14)


def test_delete_bucket_lifecycle_stays_dead_after_a_restart(service):
    bucket = _bucket(service, "restart-lifecycle")
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  _lifecycle_xml(7)).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?lifecycle").status_code == 204

    db, _catalog = _fresh(service)
    try:
        assert BucketLifecycleStore(
            BucketCatalog(ManifestStore(db))).get(bucket) is None, (
            "a deleted lifecycle configuration resurrected")
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?lifecycle").status_code == 404


# ---------------------------------------------------------------------------
# Request payment / accelerate (one-state controls)
# ---------------------------------------------------------------------------

def test_put_bucket_request_payment_survives_a_restart(service):
    """Nothing is stored: the only state is the constant, and a restarted
    process must keep serving it — never a half-configured answer."""
    bucket = _bucket(service, "restart-flags")
    body = (f'<RequestPaymentConfiguration xmlns="{NS}">'
            f"<Payer>BucketOwner</Payer>"
            f"</RequestPaymentConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?requestPayment",
                  body).status_code == 200

    db, catalog = _fresh(service)
    try:
        assert bucket in catalog.list_buckets(), (
            "the bucket row vanished: the control is not durable")
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?requestPayment")
    assert read.status_code == 200
    assert b"BucketOwner" in read.content


def test_put_bucket_accelerate_configuration_survives_a_restart(service):
    bucket = _bucket(service, "restart-flags")
    body = (f'<AccelerateConfiguration xmlns="{NS}">'
            f"<Status>Suspended</Status>"
            f"</AccelerateConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?accelerate",
                  body).status_code == 200

    db, catalog = _fresh(service)
    try:
        assert bucket in catalog.list_buckets(), (
            "the bucket row vanished: the control is not durable")
    finally:
        db.close()
    read = signed(service, "GET", f"/{bucket}?accelerate")
    assert read.status_code == 200
    assert b"Suspended" in read.content


# ---------------------------------------------------------------------------
# Bucket tagging (delete)
# ---------------------------------------------------------------------------

def test_delete_bucket_tagging_stays_dead_after_a_restart(service):
    create(service)
    assert signed(service, "PUT", "/backup-bucket?tagging",
                  tag_xml([("env", "evidence")])).status_code == 200
    assert signed(service, "DELETE", "/backup-bucket?tagging").status_code == 204

    from teledrive.s3.tagging import BucketTagStore
    db, _catalog = _fresh(service)
    try:
        assert BucketTagStore(BucketCatalog(ManifestStore(db))).get(
            "backup-bucket") == [], (
            "a deleted bucket tag set resurrected after a restart")
    finally:
        db.close()
    cleared = signed(service, "GET", "/backup-bucket?tagging")
    assert cleared.status_code == 404
    assert b"NoSuchTagSet" in cleared.content
