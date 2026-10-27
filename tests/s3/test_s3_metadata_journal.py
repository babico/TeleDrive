"""Phase O3: S3 Metadata configuration over a REAL SQL mutation journal.

These tests exercise the signed HTTP gateway, the SQLite journal and the
actual catalog mutations. They deliberately prove the honest backing: the
journal rows are the table, and the GET identifiers are TeleDrive strings,
never fabricated AWS S3 Tables ARNs.
"""
from __future__ import annotations

import time
from xml.etree import ElementTree as ET

import pytest

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.metadata_journal import (
    MetadataJournalStore,
    metadata_journal,
)
from teledrive.s3.route_guard import S3QueryError, validate_s3_query
from starlette.datastructures import QueryParams
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
XMLNS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
BUCKET = "meta-bucket"


def create_body(*, days=None, inventory=None, annotation=None):
    expiration = "<Expiration>DISABLED</Expiration>"
    if days is not None:
        expiration = (f"<Expiration>ENABLED</Expiration><Days>{days}</Days>")
    inventory_xml = ""
    if inventory is not None:
        inventory_xml = (
            "<InventoryTableConfiguration>"
            f"<ConfigurationState>{inventory}</ConfigurationState>"
            "</InventoryTableConfiguration>")
    annotation_xml = ""
    if annotation is not None:
        annotation_xml = (
            "<AnnotationTableConfiguration>"
            f"<ConfigurationState>{annotation}</ConfigurationState>"
            "<Role>arn:aws:iam::123456789012:role/metadata</Role>"
            "</AnnotationTableConfiguration>")
    return (
        f"<MetadataConfiguration {XMLNS}>"
        "<JournalTableConfiguration>"
        f"<RecordExpiration>{expiration}</RecordExpiration>"
        "</JournalTableConfiguration>"
        f"{inventory_xml}{annotation_xml}"
        "</MetadataConfiguration>"
    ).encode()


def journal_update(days=None):
    if days is None:
        return (
            f"<JournalTableConfiguration {XMLNS}><RecordExpiration>"
            "<Expiration>DISABLED</Expiration>"
            "</RecordExpiration></JournalTableConfiguration>").encode()
    return (
        f"<JournalTableConfiguration {XMLNS}><RecordExpiration>"
        f"<Expiration>ENABLED</Expiration><Days>{days}</Days>"
        "</RecordExpiration></JournalTableConfiguration>").encode()


def inventory_update(state):
    return (
        f"<InventoryTableConfiguration {XMLNS}>"
        f"<ConfigurationState>{state}</ConfigurationState>"
        "</InventoryTableConfiguration>").encode()


def annotation_update(state):
    return (
        f"<AnnotationTableConfiguration {XMLNS}>"
        f"<ConfigurationState>{state}</ConfigurationState>"
        "</AnnotationTableConfiguration>").encode()


def table_body(table_name="journal"):
    return (
        f"<MetadataTableConfiguration {XMLNS}><S3TablesDestination>"
        "<TableBucketArn>arn:aws:s3tables:us-east-1:123456789012:"
        "bucket/example</TableBucketArn>"
        f"<TableName>{table_name}</TableName>"
        "</S3TablesDestination></MetadataTableConfiguration>"
    ).encode()


def make_bucket(service, name=BUCKET):
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


def create_config(service, *, bucket=BUCKET, **kwargs):
    return signed(service, "POST", f"/{bucket}?metadataConfiguration",
                  create_body(**kwargs))


def journal_rows(service, bucket=BUCKET):
    db = service[3]()
    try:
        store = MetadataJournalStore(BucketCatalog(ManifestStore(db)))
        return store.rows(bucket)
    finally:
        db.close()


def stats(service, bucket=BUCKET):
    db = service[3]()
    try:
        return MetadataJournalStore(BucketCatalog(ManifestStore(db))).stats(
            bucket)
    finally:
        db.close()


def result_root(response):
    assert response.status_code == 200, response.text
    return ET.fromstring(response.content)


def journal_result(response):
    root = result_root(response)
    node = root.find(NS + "MetadataConfigurationResult")
    assert node is not None
    return node


def record_count(response):
    journal = journal_result(response).find(
        NS + "JournalTableConfigurationResult")
    stats_node = journal.find(NS + "TableStatistics")
    assert stats_node is not None
    return int(stats_node.findtext(NS + "RecordCount"))


@pytest.fixture
def bucket(service):
    return make_bucket(service)


# --------------------------------------------------------------------------
# Configuration CRUD
# --------------------------------------------------------------------------

def test_create_and_get_v2_returns_real_empty_stats(service, bucket):
    created = create_config(service)
    assert created.status_code == 200, created.text
    fetched = signed(service, "GET", f"/{bucket}?metadataConfiguration")
    node = journal_result(fetched)
    assert node.find(NS + "DestinationResult/" + NS + "TableBucketType").text == "teledrive"
    journal = node.find(NS + "JournalTableConfigurationResult")
    assert journal.findtext(NS + "TableStatus") == "ACTIVE"
    assert journal.findtext(NS + "TableStatistics/" + NS + "RecordCount") == "0"
    assert journal.findtext(NS + "RecordExpiration/" + NS + "Expiration") == "DISABLED"


def test_create_is_409_when_configuration_already_exists(service, bucket):
    assert create_config(service).status_code == 200
    duplicate = create_config(service)
    assert duplicate.status_code == 409, duplicate.text
    assert b"BucketMetadataConfigurationAlreadyExists" in duplicate.content


def test_get_and_delete_absent_configuration(service, bucket):
    missing = signed(service, "GET", f"/{bucket}?metadataConfiguration")
    assert missing.status_code == 404
    assert b"NoSuchConfiguration" in missing.content
    # Delete is idempotent and never invents a configuration.
    assert signed(service, "DELETE",
                  f"/{bucket}?metadataConfiguration").status_code == 204


def test_update_operations_require_an_existing_configuration(service, bucket):
    for selector, body in (
        ("metadataJournalTable", journal_update(7)),
        ("metadataInventoryTable", inventory_update("ENABLED")),
        ("metadataAnnotationTable", annotation_update("ENABLED")),
    ):
        response = signed(service, "PUT", f"/{bucket}?{selector}", body)
        assert response.status_code == 404, (selector, response.text)
        assert b"NoSuchConfiguration" in response.content


def test_inventory_and_annotation_updates_round_trip(service, bucket):
    # Create WITH an annotation Role so the round-trip actually covers the
    # optional Role field; an update without Role must preserve it.
    assert create_config(service, annotation="ENABLED").status_code == 200
    assert signed(service, "PUT", f"/{bucket}?metadataInventoryTable",
                  inventory_update("ENABLED")).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?metadataAnnotationTable",
                  annotation_update("ENABLED")).status_code == 200
    node = journal_result(
        signed(service, "GET", f"/{bucket}?metadataConfiguration"))
    inventory = node.find(NS + "InventoryTableConfigurationResult")
    annotation = node.find(NS + "AnnotationTableConfigurationResult")
    assert inventory.findtext(NS + "ConfigurationState") == "ENABLED"
    assert annotation.findtext(NS + "ConfigurationState") == "ENABLED"
    # The stored Role survives an update body that omits it.
    assert annotation.findtext(NS + "Role") == (
        "arn:aws:iam::123456789012:role/metadata")

    assert signed(service, "PUT", f"/{bucket}?metadataInventoryTable",
                  inventory_update("DISABLED")).status_code == 200
    node = journal_result(
        signed(service, "GET", f"/{bucket}?metadataConfiguration"))
    assert node.find(
        NS + "InventoryTableConfigurationResult/"
        + NS + "ConfigurationState").text == "DISABLED"


def test_journal_update_changes_record_expiration(service, bucket):
    assert create_config(service).status_code == 200
    assert signed(service, "PUT", f"/{bucket}?metadataJournalTable",
                  journal_update(365)).status_code == 200
    journal = journal_result(
        signed(service, "GET", f"/{bucket}?metadataConfiguration")).find(
            NS + "JournalTableConfigurationResult")
    assert journal.findtext(NS + "RecordExpiration/" + NS + "Expiration") == "ENABLED"
    assert journal.findtext(NS + "RecordExpiration/" + NS + "Days") == "365"
    assert signed(service, "PUT", f"/{bucket}?metadataJournalTable",
                  journal_update(None)).status_code == 200
    journal = journal_result(
        signed(service, "GET", f"/{bucket}?metadataConfiguration")).find(
            NS + "JournalTableConfigurationResult")
    assert journal.findtext(NS + "RecordExpiration/" + NS + "Expiration") == "DISABLED"


# --------------------------------------------------------------------------
# Journal rows written in the mutation transaction
# --------------------------------------------------------------------------

def test_publish_writes_a_real_journal_row(service, bucket):
    assert create_config(service).status_code == 200
    uploaded = signed(service, "PUT", f"/{bucket}/one.bin", b"payload")
    assert uploaded.status_code == 200
    rows = journal_rows(service)
    assert len(rows) == 1
    assert rows[0]["event"] == "created"
    assert rows[0]["object_key"] == "one.bin"
    assert rows[0]["version_id"] == uploaded.headers["x-amz-version-id"]
    fetched = signed(service, "GET", f"/{bucket}?metadataConfiguration")
    assert record_count(fetched) == 1
    journal = journal_result(fetched).find(NS + "JournalTableConfigurationResult")
    assert journal.findtext(
        NS + "TableStatistics/" + NS + "NewestRecordTimestamp") != ""


def test_copy_and_multipart_complete_are_journaled(service, bucket):
    assert create_config(service).status_code == 200
    assert signed(service, "PUT", f"/{bucket}/source.bin", b"copy-me").status_code == 200
    copied = signed(service, "PUT", f"/{bucket}/copy.bin",
                    extra_headers={"x-amz-copy-source": f"/{bucket}/source.bin"})
    assert copied.status_code == 200, copied.text
    events = [(row["event"], row["object_key"]) for row in journal_rows(service)]
    assert ("created", "source.bin") in events
    assert ("created", "copy.bin") in events

    started = signed(service, "POST", f"/{bucket}/multi.bin?uploads")
    assert started.status_code == 200, started.text
    upload_id = ET.fromstring(started.content).findtext(NS + "UploadId")
    part = signed(service, "PUT",
                  f"/{bucket}/multi.bin?partNumber=1&uploadId={upload_id}",
                  b"multipart-body")
    assert part.status_code == 200, part.text
    completion = ET.Element("CompleteMultipartUpload")
    node = ET.SubElement(completion, "Part")
    ET.SubElement(node, "PartNumber").text = "1"
    ET.SubElement(node, "ETag").text = part.headers["etag"]
    done = signed(service, "POST", f"/{bucket}/multi.bin?uploadId={upload_id}",
                  ET.tostring(completion))
    assert done.status_code == 200, done.text
    assert any(row["event"] == "created" and row["object_key"] == "multi.bin"
               for row in journal_rows(service))


def test_multipart_abort_is_journaled_as_deleted(service, bucket):
    assert create_config(service).status_code == 200
    started = signed(service, "POST", f"/{bucket}/abandoned.bin?uploads")
    upload_id = ET.fromstring(started.content).findtext(NS + "UploadId")
    aborted = signed(service, "DELETE",
                     f"/{bucket}/abandoned.bin?uploadId={upload_id}")
    assert aborted.status_code == 204, aborted.text
    rows = journal_rows(service)
    assert [(row["event"], row["object_key"]) for row in rows] == [
        ("deleted", "abandoned.bin")]


def test_delete_marker_and_version_revocation_are_distinct_events(
        service, bucket):
    assert create_config(service).status_code == 200
    first = signed(service, "PUT", f"/{bucket}/versioned.bin", b"v1")
    second = signed(service, "PUT", f"/{bucket}/versioned.bin", b"v2")
    assert first.status_code == second.status_code == 200
    revoked = signed(
        service, "DELETE",
        f"/{bucket}/versioned.bin?versionId={first.headers['x-amz-version-id']}")
    assert revoked.status_code == 204, revoked.text
    markers = signed(service, "DELETE", f"/{bucket}/versioned.bin")
    assert markers.status_code == 204
    events = [row["event"] for row in journal_rows(service)]
    assert events.count("created") == 2
    assert "version_revoked" in events
    assert "deleted" in events


def test_tag_and_annotation_changes_are_journaled_when_enabled(service, bucket):
    assert create_config(service, annotation="ENABLED").status_code == 200
    assert signed(service, "PUT", f"/{bucket}/tagged.bin", b"data").status_code == 200
    tags = (f"<Tagging {XMLNS}><TagSet><Tag><Key>env</Key>"
            "<Value>ci</Value></Tag></TagSet></Tagging>").encode()
    assert signed(service, "PUT", f"/{bucket}/tagged.bin?tagging",
                  tags).status_code == 200
    assert signed(service, "PUT", f"/{bucket}/tagged.bin?annotation&annotationName=note",
                  b"hello").status_code == 200
    rows = journal_rows(service)
    tagged = [row for row in rows if row["event"] == "tagged"]
    annotations = [row for row in rows if row["event"] == "annotation_changed"]
    assert len(tagged) == 1 and tagged[0]["detail"].startswith("{")
    assert tagged[0]["actor"] == service[1].access_key
    assert len(annotations) == 1
    assert annotations[0]["object_key"] == "tagged.bin"
    # Disabling the annotation table stops annotation journaling but leaves
    # ordinary object journaling intact.
    assert signed(service, "PUT", f"/{bucket}?metadataAnnotationTable",
                  annotation_update("DISABLED")).status_code == 200
    assert signed(service, "PUT",
                  f"/{bucket}/tagged.bin?annotation&annotationName=second",
                  b"world").status_code == 200
    assert len([row for row in journal_rows(service)
                if row["event"] == "annotation_changed"]) == 1


def test_rename_is_journaled(service, bucket):
    assert create_config(service).status_code == 200
    assert signed(service, "PUT", f"/{bucket}/before.bin", b"rename").status_code == 200
    renamed = signed(
        service, "PUT", f"/{bucket}/after.bin?renameObject",
        extra_headers={"x-amz-rename-source": f"{bucket}/before.bin"})
    assert renamed.status_code == 200, renamed.text
    row = journal_rows(service)[-1]
    assert row["event"] == "renamed"
    assert row["object_key"] == "after.bin"
    assert '"source_key":"before.bin"' in row["detail"]


def test_no_journal_rows_without_a_metadata_configuration(service, bucket):
    assert signed(service, "PUT", f"/{bucket}/unconfigured.bin",
                  b"data").status_code == 200
    assert journal_rows(service) == []


def test_journaling_failure_never_fails_the_upload(service, bucket, monkeypatch):
    assert create_config(service).status_code == 200
    import teledrive.s3.metadata_journal as journal_mod

    def explode(*args, **kwargs):
        raise RuntimeError("injected journal failure")

    monkeypatch.setattr(journal_mod, "journal_event_uncommitted", explode)
    uploaded = signed(service, "PUT", f"/{bucket}/resilient.bin", b"payload")
    assert uploaded.status_code == 200, uploaded.text
    assert journal_rows(service) == []
    assert signed(service, "GET", f"/{bucket}/resilient.bin").content == b"payload"


# --------------------------------------------------------------------------
# Retention, V1 compatibility, honesty and strict parsing
# --------------------------------------------------------------------------

def test_retention_trimming_is_real_and_batched(service, bucket):
    assert create_config(service, days=7).status_code == 200
    db = service[3]()
    try:
        catalog = BucketCatalog(ManifestStore(db))
        MetadataJournalStore(catalog)  # ensure tables
        old = time.time_ns() - 30 * 86400 * 1_000_000_000
        db.connection.execute(metadata_journal.insert().values(
            bucket=bucket, object_key="old.bin", version_id=None,
            event="created", actor="", recorded_ns=old, detail="{}"))
        db.connection.execute(metadata_journal.insert().values(
            bucket=bucket, object_key="fresh.bin", version_id=None,
            event="created", actor="", recorded_ns=time.time_ns(),
            detail="{}"))
        db.commit()
        assert MetadataJournalStore(catalog).stats(bucket)["count"] == 2
        # GET applies the configured window lazily, leaving the fresh row.
        fetched = signed(service, "GET", f"/{bucket}?metadataConfiguration")
        assert record_count(fetched) == 1
        assert MetadataJournalStore(catalog).stats(bucket)["count"] == 1
    finally:
        db.close()


def test_v1_create_get_delete_and_v2_cross_version_405(service, bucket):
    assert signed(service, "POST", f"/{bucket}?metadataTable",
                  table_body()).status_code == 200
    v1 = signed(service, "GET", f"/{bucket}?metadataTable")
    assert v1.status_code == 200, v1.text
    root = ET.fromstring(v1.content)
    destination = root.find(
        NS + "MetadataTableConfigurationResult/"
        + NS + "S3TablesDestinationResult")
    assert destination.findtext(NS + "TableArn").startswith("teledrive:metadata:")
    assert root.findtext(NS + "Status") == "ACTIVE"
    # V2 GET works for a V1 configuration.
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").status_code == 200
    assert signed(service, "DELETE", f"/{bucket}?metadataTable").status_code == 204
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").status_code == 404

    # A V2 configuration answers 405 to the V1 GET and DELETE operations.
    assert create_config(service).status_code == 200
    v1_on_v2 = signed(service, "GET", f"/{bucket}?metadataTable")
    assert v1_on_v2.status_code == 405
    assert b"MethodNotAllowed" in v1_on_v2.content
    assert signed(service, "DELETE",
                  f"/{bucket}?metadataTable").status_code == 405


def test_get_never_fabricates_aws_table_arns(service, bucket):
    assert create_config(service).status_code == 200
    fetched = signed(service, "GET", f"/{bucket}?metadataConfiguration")
    text = fetched.text
    assert "teledrive:metadata:" + bucket in text
    assert "arn:aws:s3tables" not in text
    assert "arn:aws:s3:::meta" not in text


def test_delete_configuration_also_removes_its_journal(service, bucket):
    assert create_config(service).status_code == 200
    assert signed(service, "PUT", f"/{bucket}/gone.bin", b"data").status_code == 200
    assert journal_rows(service)
    assert signed(service, "DELETE",
                  f"/{bucket}?metadataConfiguration").status_code == 204
    assert journal_rows(service) == []
    # Re-creating starts a genuinely empty journal.
    assert create_config(service).status_code == 200
    assert record_count(signed(
        service, "GET", f"/{bucket}?metadataConfiguration")) == 0


@pytest.mark.parametrize("body", [
    b"<MetadataConfiguration><JournalTableConfiguration>",
    b"<NotMetadataConfiguration/>",
    (f"<MetadataConfiguration {XMLNS}><JournalTableConfiguration>"
     "<RecordExpiration><Expiration>DISABLED</Expiration></RecordExpiration>"
     "</JournalTableConfiguration><Unknown/></MetadataConfiguration>").encode(),
    (f"<MetadataConfiguration {XMLNS}><JournalTableConfiguration>"
     "<RecordExpiration><Expiration>DISABLED</Expiration></RecordExpiration>"
     "</JournalTableConfiguration><JournalTableConfiguration>"
     "<RecordExpiration><Expiration>DISABLED</Expiration></RecordExpiration>"
     "</JournalTableConfiguration></MetadataConfiguration>").encode(),
    b"x" * (16 * 1024 + 1),
])
def test_create_rejects_malformed_or_unbounded_xml(service, bucket, body):
    response = signed(service, "POST", f"/{bucket}?metadataConfiguration", body)
    assert response.status_code == 400, response.text
    assert b"MalformedXML" in response.content


def test_encryption_claims_are_refused_honestly(service, bucket):
    body = (
        f"<MetadataConfiguration {XMLNS}><JournalTableConfiguration>"
        "<EncryptionConfiguration><KmsKeyArn>arn:aws:kms:us-east-1:1:key/x"
        "</KmsKeyArn><SseAlgorithm>aws:kms</SseAlgorithm>"
        "</EncryptionConfiguration>"
        "<RecordExpiration><Expiration>DISABLED</Expiration></RecordExpiration>"
        "</JournalTableConfiguration></MetadataConfiguration>").encode()
    response = signed(service, "POST", f"/{bucket}?metadataConfiguration", body)
    assert response.status_code == 501, response.text
    assert b"NotImplemented" in response.content


def test_retention_days_must_be_at_least_seven(service, bucket):
    for days in (1, 6, 0, -1):
        response = create_config(service, days=days)
        assert response.status_code == 400, (days, response.text)
        assert b"InvalidArgument" in response.content
    assert create_config(service, days=7).status_code == 200


def test_body_checksum_is_verified(service, bucket):
    response = signed(
        service, "POST", f"/{bucket}?metadataConfiguration",
        create_body(),
        extra_headers={"x-amz-checksum-crc32": "AAAAAA=="})
    assert response.status_code == 400, response.text
    assert b"BadDigest" in response.content


# --------------------------------------------------------------------------
# Permissions and route guard
# --------------------------------------------------------------------------

def test_permissions_are_independently_grantable(service, bucket):
    db = service[3]()
    try:
        reader = S3CredentialStore(db, service[4]).create(
            "metadata-reader", ["s3:GetBucketMetadataTableConfiguration"])
    finally:
        db.close()
    assert create_config(service).status_code == 200
    readable = signed(service, "GET", f"/{bucket}?metadataConfiguration",
                      access=reader.access_key, secret=reader.secret_key)
    assert readable.status_code == 200, readable.text
    denied = signed(service, "POST", f"/{bucket}?metadataConfiguration",
                    create_body(), access=reader.access_key,
                    secret=reader.secret_key)
    assert denied.status_code == 403, denied.text
    denied_update = signed(
        service, "PUT", f"/{bucket}?metadataJournalTable", journal_update(7),
        access=reader.access_key, secret=reader.secret_key)
    assert denied_update.status_code == 403, denied_update.text


@pytest.mark.parametrize("method,selector", [
    ("GET", "metadataConfiguration"),
    ("POST", "metadataConfiguration"),
    ("DELETE", "metadataConfiguration"),
    ("GET", "metadataTable"),
    ("POST", "metadataTable"),
    ("DELETE", "metadataTable"),
    ("PUT", "metadataJournalTable"),
    ("PUT", "metadataInventoryTable"),
    ("PUT", "metadataAnnotationTable"),
])
def test_route_guard_accepts_the_real_aws_selectors(method, selector):
    validate_s3_query(method, "guard-bucket", False, QueryParams({selector: ""}))


@pytest.mark.parametrize("method,selector", [
    ("PUT", "metadataConfiguration"),
    ("POST", "metadataJournalTable"),
    ("DELETE", "metadataInventoryTable"),
    ("GET", "metadataAnnotationTable"),
    ("GET", "metadataTableConfiguration"),
    ("POST", "metadataTableConfiguration"),
])
def test_route_guard_rejects_wrong_methods_and_wrong_selector_names(
        method, selector):
    with pytest.raises(S3QueryError):
        validate_s3_query(method, "guard-bucket", False,
                          QueryParams({selector: ""}))
