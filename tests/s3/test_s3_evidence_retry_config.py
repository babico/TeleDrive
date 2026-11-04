"""Retry column for the config write families the evidence files skipped.

The retry/race matrix covers the write state machines, and the five
``test_s3_evidence_*.py`` files cover reports, tagging, website,
notifications and metadata configuration. This file closes the rest of
the config families (27 open retry cells): the same logical request is
sent twice through the signed gateway — a client retry after a timeout
— and the contract pinned per family is one of:

* **replace-is-idempotent** (CORS, replication, tiering, ABAC, ACL,
  ownership, PAB, policy delete, encryption, lifecycle, lock
  configuration, retention, legal hold, the one-state controls): the
  replay succeeds again and keeps exactly one row / one column value;
  a *conflicting* document is last-write-wins, still one row;
* **delete-stays-dead**: the replayed DELETE answers 204 again and
  never resurrects the row.

The multipart / object-level retry cells (CreateBucket, DeleteBucket,
RenameObject, UpdateObjectEncryption, the multipart creates, restore
and the object annotation delete) live in
``tests/s3/test_s3_evidence_retry_objects.py``.
"""
from __future__ import annotations

import json
import time
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy import func, select

from teledrive.s3.bucket_encryption import (
    BucketEncryptionStore, bucket_encryption,
)
from teledrive.s3.cors import BucketCORSStore, cors_config
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.lifecycle import BucketLifecycleStore
from teledrive.s3.policy import BucketAbacStore, bucket_abac
from teledrive.s3.replication import BucketReplicationStore, replication_configs
from teledrive.s3.report_configs import report_configs
from teledrive.s3.tiering import TieringStore, tiering_configs
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_metadata_journal import (
    annotation_update, create_body, inventory_update, make_bucket, table_body,
)
from tests.s3.test_s3_replication import add_destination

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
DESTINATION = "offsite-account"


def _fresh(service):
    """A new Database + catalog, as a second process would open them."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _rows(service, table, *where):
    db = service[3]()
    try:
        statement = select(func.count()).select_from(table)
        if where:
            statement = statement.where(*where)
        return db.connection.execute(statement).scalar_one()
    finally:
        db.close()


def _bucket(service, name: str) -> str:
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


def _cors_xml(max_age: int = 240) -> bytes:
    root = ET.Element("CORSConfiguration")
    rule = ET.SubElement(root, "CORSRule")
    ET.SubElement(rule, "AllowedOrigin").text = "https://app.example.com"
    ET.SubElement(rule, "AllowedMethod").text = "GET"
    ET.SubElement(rule, "MaxAgeSeconds").text = str(max_age)
    return ET.tostring(root)


def _replication_xml(*, prefix="logs/") -> bytes:
    root = ET.Element("ReplicationConfiguration")
    rule = ET.SubElement(root, "Rule")
    ET.SubElement(rule, "ID").text = "logs"
    ET.SubElement(rule, "Status").text = "Enabled"
    destination = ET.SubElement(rule, "Destination")
    ET.SubElement(destination, "Bucket").text = DESTINATION
    filter_node = ET.SubElement(rule, "Filter")
    ET.SubElement(filter_node, "Prefix").text = prefix
    return ET.tostring(root)


def _tiering_xml() -> bytes:
    return (
        f'<IntelligentTieringConfiguration xmlns="{NS}">'
        f"<Id>tier1</Id>"
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


def _lock_config(days: int) -> bytes:
    return (f'<ObjectLockConfiguration xmlns="{NS}">'
            f"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
            f"<Rule><DefaultRetention><Mode>COMPLIANCE</Mode>"
            f"<Days>{days}</Days></DefaultRetention></Rule>"
            f"</ObjectLockConfiguration>").encode()


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_cors_keeps_one_row_and_last_write_wins(service):
    bucket = _bucket(service, "retry-cors")
    assert signed(service, "PUT", f"/{bucket}?cors",
                  _cors_xml(240)).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?cors",
                  _cors_xml(240)).status_code == 200  # client retry
    assert _rows(service, cors_config,
                 cors_config.c.bucket == bucket) == 1, (
        "a replayed CORS PUT left more than one row")

    # A conflicting document is a replace, not an append.
    assert signed(service, "PUT", f"/{bucket}?cors",
                  _cors_xml(3600)).status_code == 200
    assert _rows(service, cors_config,
                 cors_config.c.bucket == bucket) == 1
    db, _catalog = _fresh(service)
    try:
        assert BucketCORSStore(BucketCatalog(ManifestStore(db))).get(
            bucket)[0]["max_age"] == 3600
    finally:
        db.close()


def test_replayed_delete_bucket_cors_stays_dead(service):
    bucket = _bucket(service, "retry-cors")
    assert signed(service, "PUT", f"/{bucket}?cors",
                  _cors_xml()).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?cors").status_code == 204
    assert signed(service, "DELETE", f"/{bucket}?cors").status_code == 204
    assert _rows(service, cors_config,
                 cors_config.c.bucket == bucket) == 0, (
        "a replayed CORS DELETE resurrected a row")
    assert signed(service, "GET", f"/{bucket}?cors").status_code == 404


# ---------------------------------------------------------------------------
# Replication
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_replication_keeps_one_row(service):
    add_destination(service)
    bucket = _bucket(service, "retry-replication")
    body = _replication_xml()
    assert signed(service, "PUT", f"/{bucket}?replication",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?replication",
                  body).status_code == 200  # client retry
    assert _rows(service, replication_configs,
                 replication_configs.c.bucket == bucket) == 1, (
        "a replayed replication PUT left more than one row")

    # A conflicting rule set is a replace: still one row, new prefix.
    assert signed(service, "PUT", f"/{bucket}?replication",
                  _replication_xml(prefix="archive/")).status_code == 200
    assert _rows(service, replication_configs,
                 replication_configs.c.bucket == bucket) == 1
    db, _catalog = _fresh(service)
    try:
        stored = BucketReplicationStore(
            BucketCatalog(ManifestStore(db))).get(bucket)
        assert stored["rules"][0]["prefixes"] == ["archive/"]
    finally:
        db.close()


def test_replayed_delete_bucket_replication_stays_dead(service):
    add_destination(service)
    bucket = _bucket(service, "retry-replication")
    assert signed(service, "PUT", f"/{bucket}?replication",
                  _replication_xml()).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?replication").status_code == 204
    assert signed(service, "DELETE",
                  f"/{bucket}?replication").status_code == 204
    assert _rows(service, replication_configs,
                 replication_configs.c.bucket == bucket) == 0, (
        "a replayed replication DELETE resurrected a row")
    assert signed(service, "GET", f"/{bucket}?replication").status_code == 404


# ---------------------------------------------------------------------------
# Intelligent tiering
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_intelligent_tiering_keeps_one_row(service):
    bucket = _bucket(service, "retry-tiering")
    body = _tiering_xml()
    assert signed(service, "PUT", f"/{bucket}?intelligent-tiering&id=tier1",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?intelligent-tiering&id=tier1",
                  body).status_code == 200  # client retry
    assert _rows(service, tiering_configs,
                 tiering_configs.c.bucket == bucket,
                 tiering_configs.c.config_id == "tier1") == 1, (
        "a replayed tiering PUT left more than one row")

    # A conflicting document is a replace: still one row.
    replaced = _tiering_xml().replace(b"ARCHIVE_ACCESS",
                                      b"DEEP_ARCHIVE_ACCESS")
    assert signed(service, "PUT", f"/{bucket}?intelligent-tiering&id=tier1",
                  replaced).status_code == 200
    assert _rows(service, tiering_configs,
                 tiering_configs.c.bucket == bucket,
                 tiering_configs.c.config_id == "tier1") == 1


def test_replayed_delete_bucket_intelligent_tiering_stays_dead(service):
    bucket = _bucket(service, "retry-tiering")
    assert signed(service, "PUT", f"/{bucket}?intelligent-tiering&id=tier1",
                  _tiering_xml()).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?intelligent-tiering&id=tier1").status_code == 204
    assert signed(service, "DELETE",
                  f"/{bucket}?intelligent-tiering&id=tier1").status_code == 204
    assert _rows(service, tiering_configs,
                 tiering_configs.c.bucket == bucket) == 0, (
        "a replayed tiering DELETE resurrected a row")
    assert signed(service, "GET",
                  f"/{bucket}?intelligent-tiering&id=tier1").status_code == 404


# ---------------------------------------------------------------------------
# Metadata configuration (V1 table delete + table updates)
# ---------------------------------------------------------------------------

def test_replayed_delete_bucket_metadata_table_stays_dead(service):
    make_bucket(service, "retry-metadata")
    assert signed(service, "POST", "/retry-metadata?metadataTable",
                  table_body("retry-table")).status_code == 200
    path = "/retry-metadata?metadataTable"
    assert signed(service, "DELETE", path).status_code == 204
    assert signed(service, "DELETE", path).status_code == 204  # client retry

    from teledrive.s3.metadata_journal import metadata_configs
    assert _rows(service, metadata_configs,
                 metadata_configs.c.bucket == "retry-metadata") == 0, (
        "a replayed V1 table delete resurrected the configuration")
    assert signed(service, "GET", path).status_code == 404


def test_replayed_inventory_table_update_keeps_one_row(service):
    make_bucket(service, "retry-metadata")
    assert signed(service, "POST", "/retry-metadata?metadataConfiguration",
                  create_body(inventory="DISABLED")).status_code == 200
    for _ in range(2):  # the same logical update twice
        reply = signed(service, "PUT", "/retry-metadata?metadataInventoryTable",
                       inventory_update("ENABLED"))
        assert reply.status_code == 200, reply.text

    from teledrive.s3.metadata_journal import (
        MetadataConfigurationStore, metadata_configs,
    )
    assert _rows(service, metadata_configs,
                 metadata_configs.c.bucket == "retry-metadata") == 1
    db, _catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get("retry-metadata")
        assert stored["inventory_enabled"] is True
    finally:
        db.close()


def test_replayed_annotation_table_update_keeps_one_row(service):
    make_bucket(service, "retry-metadata")
    assert signed(service, "POST", "/retry-metadata?metadataConfiguration",
                  create_body(annotation="DISABLED")).status_code == 200
    for _ in range(2):  # the same logical update twice
        reply = signed(service, "PUT",
                       "/retry-metadata?metadataAnnotationTable",
                       annotation_update("ENABLED"))
        assert reply.status_code == 200, reply.text

    from teledrive.s3.metadata_journal import (
        MetadataConfigurationStore, metadata_configs,
    )
    assert _rows(service, metadata_configs,
                 metadata_configs.c.bucket == "retry-metadata") == 1
    db, _catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(
            BucketCatalog(ManifestStore(db))).get("retry-metadata")
        assert stored["annotation_enabled"] is True
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ABAC
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_abac_keeps_one_row_and_last_write_wins(service):
    bucket = _bucket(service, "retry-abac")
    enabled = json.dumps({"Status": "Enabled"}).encode()
    assert signed(service, "PUT", f"/{bucket}?abac", enabled).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?abac",
                  enabled).status_code == 200  # client retry
    assert _rows(service, bucket_abac,
                 bucket_abac.c.bucket == bucket) == 1, (
        "a replayed ABAC PUT left more than one row")

    # A conflicting document is a replace.
    disabled = json.dumps({"Status": "Disabled"}).encode()
    assert signed(service, "PUT", f"/{bucket}?abac",
                  disabled).status_code == 200
    assert _rows(service, bucket_abac,
                 bucket_abac.c.bucket == bucket) == 1
    db, _catalog = _fresh(service)
    try:
        assert BucketAbacStore(BucketCatalog(ManifestStore(db))).get(
            bucket)["status"] == "Disabled"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_acl_replaces_in_place(service):
    bucket = _bucket(service, "retry-acl")
    other = _other_credential(service, "acl-grantee")
    owner = service[1].access_key
    grants = [(other.access_key, "READ")]
    body = _acl_xml(owner, grants)
    assert signed(service, "PUT", f"/{bucket}?acl",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?acl",
                  body).status_code == 200  # client retry

    db, catalog = _fresh(service)
    try:
        from teledrive.storage.catalog import bucket_acl_grants
        assert db.connection.execute(select(
            func.count()).select_from(bucket_acl_grants).where(
            bucket_acl_grants.c.bucket == bucket)).scalar_one() == 2, (
            "a replayed bucket ACL PUT changed the grant row count")
        stored_owner, stored_grants = catalog.bucket_acl(bucket)
        assert stored_owner == owner
        assert sorted(stored_grants) == sorted(
            grants + [(owner, "FULL_CONTROL")])
    finally:
        db.close()

    # A conflicting grant set is a replace, never an append.
    conflicting = [(other.access_key, "WRITE")]
    assert signed(service, "PUT", f"/{bucket}?acl",
                  _acl_xml(owner, conflicting)).status_code == 200
    db, catalog = _fresh(service)
    try:
        _stored_owner, stored_grants = catalog.bucket_acl(bucket)
        assert sorted(stored_grants) == sorted(
            conflicting + [(owner, "FULL_CONTROL")])
    finally:
        db.close()


def test_replayed_put_object_acl_replaces_in_place(service):
    bucket = _bucket(service, "retry-obj-acl")
    assert signed(service, "PUT", f"/{bucket}/data.bin",
                  b"acl-payload").status_code == 200
    other = _other_credential(service, "object-acl-grantee")
    owner = service[1].access_key
    grants = [(other.access_key, "READ")]
    body = _acl_xml(owner, grants)
    assert signed(service, "PUT", f"/{bucket}/data.bin?acl",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}/data.bin?acl",
                  body).status_code == 200  # client retry

    db, catalog = _fresh(service)
    try:
        stored_owner, stored_grants = catalog.object_acl(bucket, "data.bin")
        assert stored_owner == owner
        assert sorted(stored_grants) == sorted(
            grants + [(owner, "FULL_CONTROL")])
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Ownership controls
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_ownership_controls_are_idempotent(service):
    bucket = _bucket(service, "retry-ownership")
    body = _ownership_xml("ObjectWriter")
    assert signed(service, "PUT", f"/{bucket}?ownershipControls",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?ownershipControls",
                  body).status_code == 200  # client retry

    db, catalog = _fresh(service)
    try:
        # The model is one column on the bucket row: no second state can
        # exist, but the replay must not flip it either.
        assert catalog.object_ownership(bucket) == "ObjectWriter"
    finally:
        db.close()


def test_replayed_delete_bucket_ownership_controls_stay_dead(service):
    bucket = _bucket(service, "retry-ownership")
    assert signed(service, "PUT", f"/{bucket}?ownershipControls",
                  _ownership_xml("ObjectWriter")).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?ownershipControls").status_code == 204
    assert signed(service, "DELETE",
                  f"/{bucket}?ownershipControls").status_code == 204

    db, catalog = _fresh(service)
    try:
        assert catalog.object_ownership(bucket) == "BucketOwnerEnforced", (
            "a replayed ownership DELETE left a non-default model")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Public access block
# ---------------------------------------------------------------------------

def test_replayed_put_public_access_block_keeps_one_value(service):
    bucket = _bucket(service, "retry-pab")
    body = _pab_xml(False, True, False, True)
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  body).status_code == 200  # client retry

    db, catalog = _fresh(service)
    try:
        assert catalog.public_access_block(bucket) == {
            "BlockPublicAcls": False, "IgnorePublicAcls": True,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": True}, (
            "a replayed PAB PUT changed the stored flags")
    finally:
        db.close()

    # A conflicting flag set is a replace (last write wins).
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  _pab_xml(True, True, True, True)).status_code == 200
    db, catalog = _fresh(service)
    try:
        assert catalog.public_access_block(bucket) == {
            field: True for field in catalog.PAB_FIELDS}
    finally:
        db.close()


def test_replayed_delete_public_access_block_stays_dead(service):
    bucket = _bucket(service, "retry-pab")
    assert signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                  _pab_xml(False, False, False, False)).status_code == 200
    assert signed(service, "DELETE",
                  f"/{bucket}?publicAccessBlock").status_code == 204
    assert signed(service, "DELETE",
                  f"/{bucket}?publicAccessBlock").status_code == 204

    db, catalog = _fresh(service)
    try:
        assert catalog.public_access_block(bucket) == {
            field: True for field in catalog.PAB_FIELDS}, (
            "a replayed PAB DELETE left non-default flags")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Bucket policy (delete)
# ---------------------------------------------------------------------------

def test_replayed_delete_bucket_policy_stays_dead(service):
    bucket = _bucket(service, "retry-policy")
    other = _other_credential(service, "policy-principal")
    document = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"CanonicalUser": [other.access_key]},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{bucket}/*",
    }]}).encode()
    assert signed(service, "PUT", f"/{bucket}?policy",
                  document).status_code == 204
    assert signed(service, "DELETE", f"/{bucket}?policy").status_code == 204
    assert signed(service, "DELETE", f"/{bucket}?policy").status_code == 204

    from teledrive.s3.policy import BucketPolicyStore, bucket_policy
    assert _rows(service, bucket_policy,
                 bucket_policy.c.bucket == bucket) == 0, (
        "a replayed policy DELETE resurrected a row")
    db, _catalog = _fresh(service)
    try:
        assert BucketPolicyStore(BucketCatalog(ManifestStore(db))).get(
            bucket) is None
    finally:
        db.close()
    assert signed(service, "GET", f"/{bucket}?policy").status_code == 404


# ---------------------------------------------------------------------------
# Bucket encryption
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_encryption_keeps_one_row(service):
    bucket = _bucket(service, "retry-encryption")
    empty = f'<ServerSideEncryptionConfiguration xmlns="{NS}"/>'.encode()
    assert signed(service, "PUT", f"/{bucket}?encryption",
                  empty).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?encryption",
                  empty).status_code == 200  # client retry
    assert _rows(service, bucket_encryption,
                 bucket_encryption.c.bucket == bucket) == 1, (
        "a replayed encryption PUT left more than one row")

    db, _catalog = _fresh(service)
    try:
        assert BucketEncryptionStore(db).get(bucket) == []
    finally:
        db.close()


def test_replayed_delete_bucket_encryption_stays_dead(service):
    bucket = _bucket(service, "retry-encryption")
    empty = f'<ServerSideEncryptionConfiguration xmlns="{NS}"/>'.encode()
    assert signed(service, "PUT", f"/{bucket}?encryption",
                  empty).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?encryption").status_code == 204
    assert signed(service, "DELETE", f"/{bucket}?encryption").status_code == 204
    assert _rows(service, bucket_encryption,
                 bucket_encryption.c.bucket == bucket) == 0, (
        "a replayed encryption DELETE resurrected a row")
    assert signed(service, "GET", f"/{bucket}?encryption").status_code == 404


# ---------------------------------------------------------------------------
# Object lock family
# ---------------------------------------------------------------------------

def test_replayed_put_object_lock_configuration_is_idempotent(service):
    bucket = _bucket(service, "retry-lock")
    assert signed(service, "PUT", f"/{bucket}?object-lock",
                  _lock_config(30)).status_code == 200
    # The identical request again: still 200, still one configuration.
    assert signed(service, "PUT", f"/{bucket}?object-lock",
                  _lock_config(30)).status_code == 200

    db, catalog = _fresh(service)
    try:
        config = catalog.object_lock_config(bucket)
        assert config and config["default_days"] == 30, (
            "a replayed lock configuration changed the default retention")
    finally:
        db.close()
    # A shortened retention is a clean conflict, not a silent rewrite.
    assert signed(service, "PUT", f"/{bucket}?object-lock",
                  _lock_config(1)).status_code == 400


def test_replayed_put_object_retention_is_idempotent(service):
    bucket = _bucket(service, "retry-lock")
    put = signed(service, "PUT", f"/{bucket}/worm.bin", b"retained")
    assert put.status_code == 200
    version = put.headers["x-amz-version-id"]
    until = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                          time.gmtime(time.time() + 3600))
    body = (f'<Retention xmlns="{NS}"><Mode>COMPLIANCE</Mode>'
            f"<RetainUntilDate>{until}</RetainUntilDate>"
            f"</Retention>").encode()
    assert signed(service, "PUT", f"/{bucket}/worm.bin?retention",
                  body).status_code == 200
    # The identical window again: idempotent success, one state.
    assert signed(service, "PUT", f"/{bucket}/worm.bin?retention",
                  body).status_code == 200

    db, catalog = _fresh(service)
    try:
        state = catalog.object_lock_state(version)
        assert state["mode"] == "COMPLIANCE"
        assert state["retain_until_ns"] > time.time_ns()
    finally:
        db.close()
    # Shortening an active COMPLIANCE window is a clean conflict.
    earlier = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() + 60))
    shortened = (f'<Retention xmlns="{NS}"><Mode>COMPLIANCE</Mode>'
                 f"<RetainUntilDate>{earlier}</RetainUntilDate>"
                 f"</Retention>").encode()
    assert signed(service, "PUT", f"/{bucket}/worm.bin?retention",
                  shortened).status_code in (400, 403)
    # The refused replay did not move the window.
    db, catalog = _fresh(service)
    try:
        assert catalog.object_lock_state(version)["mode"] == "COMPLIANCE"
    finally:
        db.close()


def test_replayed_put_object_legal_hold_is_idempotent(service):
    bucket = _bucket(service, "retry-lock")
    put = signed(service, "PUT", f"/{bucket}/hold.bin", b"held")
    assert put.status_code == 200
    version = put.headers["x-amz-version-id"]
    body = f'<LegalHold xmlns="{NS}"><Status>ON</Status></LegalHold>'.encode()
    assert signed(service, "PUT", f"/{bucket}/hold.bin?legal-hold",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}/hold.bin?legal-hold",
                  body).status_code == 200  # client retry

    db, catalog = _fresh(service)
    try:
        # One boolean column: the replay must not flip or duplicate it.
        assert catalog.object_lock_state(version)["legal_hold"] is True
    finally:
        db.close()
    assert b"<Status>ON</Status>" in signed(
        service, "GET", f"/{bucket}/hold.bin?legal-hold").content


# ---------------------------------------------------------------------------
# Lifecycle (V1 and V2 names share the ?lifecycle selector)
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_lifecycle_keeps_one_row(service):
    bucket = _bucket(service, "retry-lifecycle")
    body = _lifecycle_xml(7)
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  body).status_code == 200  # client retry
    assert _lifecycle_rows(service, bucket) == 1, (
        "a replayed lifecycle PUT left more than one row")

    db, _catalog = _fresh(service)
    try:
        assert BucketLifecycleStore(
            BucketCatalog(ManifestStore(db))).get(bucket)[0][
                "abort_days"] == 7
    finally:
        db.close()


def test_replayed_put_bucket_lifecycle_configuration_keeps_one_row(service):
    """The V2 name: the same ``?lifecycle`` selector as the V1 operation."""
    bucket = _bucket(service, "retry-lifecycle")
    body = _lifecycle_xml(14)
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  body).status_code == 200  # client retry
    assert _lifecycle_rows(service, bucket) == 1

    # A conflicting rule set is a replace (last write wins).
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  _lifecycle_xml(30)).status_code == 200
    assert _lifecycle_rows(service, bucket) == 1
    db, _catalog = _fresh(service)
    try:
        assert BucketLifecycleStore(
            BucketCatalog(ManifestStore(db))).get(bucket)[0][
                "abort_days"] == 30
    finally:
        db.close()


def _lifecycle_rows(service, bucket):
    from teledrive.s3.lifecycle import rules_table
    return _rows(service, rules_table, rules_table.c.bucket == bucket)


def test_replayed_delete_bucket_lifecycle_stays_dead(service):
    bucket = _bucket(service, "retry-lifecycle")
    assert signed(service, "PUT", f"/{bucket}?lifecycle",
                  _lifecycle_xml(7)).status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?lifecycle").status_code == 204
    assert signed(service, "DELETE", f"/{bucket}?lifecycle").status_code == 204
    assert _lifecycle_rows(service, bucket) == 0, (
        "a replayed lifecycle DELETE resurrected a row")
    assert signed(service, "GET", f"/{bucket}?lifecycle").status_code == 404


# ---------------------------------------------------------------------------
# Request payment / accelerate (one-state controls)
# ---------------------------------------------------------------------------

def test_replayed_put_bucket_request_payment_is_idempotent(service):
    bucket = _bucket(service, "retry-flags")
    body = (f'<RequestPaymentConfiguration xmlns="{NS}">'
            f"<Payer>BucketOwner</Payer>"
            f"</RequestPaymentConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?requestPayment",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?requestPayment",
                  body).status_code == 200  # client retry
    read = signed(service, "GET", f"/{bucket}?requestPayment")
    assert read.status_code == 200
    assert b"BucketOwner" in read.content


def test_replayed_put_bucket_accelerate_configuration_is_idempotent(service):
    bucket = _bucket(service, "retry-flags")
    body = (f'<AccelerateConfiguration xmlns="{NS}">'
            f"<Status>Suspended</Status>"
            f"</AccelerateConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?accelerate",
                  body).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?accelerate",
                  body).status_code == 200  # client retry
    read = signed(service, "GET", f"/{bucket}?accelerate")
    assert read.status_code == 200
    assert b"Suspended" in read.content
