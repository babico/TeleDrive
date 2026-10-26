"""Phase N: analytics/inventory/metrics configuration CRUD.

Exercises the real SigV4 gateway against SQLite. Configuration documents are
strict XML: every rejection is asserted by its S3 error code, not just status.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from tests.s3.test_s3_gateway import service, signed

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
XMLNS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'


def analytics(body_id="analytics-1", destination="report-dest", *,
              prefix="data/", fmt="CSV", extra=""):
    return (
        f"<AnalyticsConfiguration {XMLNS}><Id>{body_id}</Id>"
        f"<Filter><Prefix>{prefix}</Prefix></Filter>"
        "<StorageClassAnalysis><DataExport>"
        "<OutputSchemaVersion>V_1</OutputSchemaVersion>"
        f"<Destination><S3BucketDestination>"
        f"<Bucket>arn:aws:s3:::{destination}</Bucket>"
        f"<Format>{fmt}</Format><Prefix>analytics</Prefix>"
        "</S3BucketDestination></Destination>"
        f"</DataExport></StorageClassAnalysis>{extra}"
        "</AnalyticsConfiguration>"
    ).encode()


def inventory(body_id="inventory-1", destination="report-dest", *,
              frequency="Daily", versions="All", fmt="CSV", prefix="",
              optional=None):
    optional_xml = ""
    if optional:
        optional_xml = "<OptionalFields>" + "".join(
            f"<Field>{value}</Field>" for value in optional) + "</OptionalFields>"
    return (
        f"<InventoryConfiguration {XMLNS}><Id>{body_id}</Id>"
        "<IsEnabled>true</IsEnabled>"
        "<Destination><S3BucketDestination>"
        f"<Bucket>arn:aws:s3:::{destination}</Bucket>"
        f"<Format>{fmt}</Format><Prefix>inventory</Prefix>"
        "</S3BucketDestination></Destination>"
        f"<Schedule><Frequency>{frequency}</Frequency></Schedule>"
        f"<Filter><Prefix>{prefix}</Prefix></Filter>"
        f"<IncludedObjectVersions>{versions}</IncludedObjectVersions>"
        f"{optional_xml}</InventoryConfiguration>"
    ).encode()


def metrics(body_id="metrics-1", *, prefix="", extra=""):
    return (
        f"<MetricsConfiguration {XMLNS}><Id>{body_id}</Id>"
        f"<Filter><Prefix>{prefix}</Prefix></Filter>{extra}"
        "</MetricsConfiguration>"
    ).encode()


@pytest.fixture
def bucket(service):
    assert signed(service, "PUT", "/report-source").status_code == 200
    assert signed(service, "PUT", "/report-dest").status_code == 200
    return "report-source"


def put_config(service, kind, config_id, body):
    return signed(service, "PUT", f"/report-source?{kind}&id={config_id}", body)


def test_analytics_crud_round_trip(service, bucket):
    body = analytics()
    assert put_config(service, "analytics", "analytics-1", body).status_code == 200
    fetched = signed(service, "GET",
                     "/report-source?analytics&id=analytics-1")
    assert fetched.status_code == 200
    root = ET.fromstring(fetched.content)
    assert root.tag == NS + "AnalyticsConfiguration"
    assert root.findtext(NS + "Id") == "analytics-1"
    listed = signed(service, "GET", "/report-source?analytics")
    assert listed.status_code == 200
    result = ET.fromstring(listed.content)
    assert result.tag == NS + "ListBucketAnalyticsConfigurationsResult"
    assert [node.findtext(NS + "Id") for node in result
            if node.find(NS + "Id") is not None] == ["analytics-1"]
    deleted = signed(service, "DELETE",
                     "/report-source?analytics&id=analytics-1")
    assert deleted.status_code == 204
    missing = signed(service, "GET",
                     "/report-source?analytics&id=analytics-1")
    assert missing.status_code == 404
    assert b"NoSuchConfiguration" in missing.content


def test_inventory_crud_round_trip_including_versions_and_schedule(service, bucket):
    body = inventory(versions="All", frequency="Weekly")
    assert put_config(service, "inventory", "inventory-1", body).status_code == 200
    fetched = signed(service, "GET",
                     "/report-source?inventory&id=inventory-1")
    assert fetched.status_code == 200
    root = ET.fromstring(fetched.content)
    assert root.tag == NS + "InventoryConfiguration"
    assert root.findtext(NS + "Schedule/" + NS + "Frequency") == "Weekly"
    assert root.findtext(NS + "IncludedObjectVersions") == "All"
    assert root.findtext(
        NS + "Destination/" + NS + "S3BucketDestination/" + NS + "Bucket"
    ) == "arn:aws:s3:::report-dest"


def test_metrics_crud_round_trip_and_implicit_destination(service, bucket):
    assert put_config(service, "metrics", "metrics-1", metrics()).status_code == 200
    fetched = signed(service, "GET", "/report-source?metrics&id=metrics-1")
    assert fetched.status_code == 200
    root = ET.fromstring(fetched.content)
    assert root.tag == NS + "MetricsConfiguration"
    assert root.findtext(NS + "Id") == "metrics-1"
    # Metrics has no AWS Destination element; the store records the analyzed
    # bucket as the honest local sink, never CloudWatch.
    from teledrive.s3.report_configs import ReportConfigStore
    from teledrive.storage.catalog import BucketCatalog
    from teledrive.storage.manifest import ManifestStore
    _, _, _, connection, _ = service
    db = connection()
    try:
        stored = ReportConfigStore(BucketCatalog(ManifestStore(db))).get(
            "report-source", "metrics", "metrics-1")
    finally:
        db.close()
    assert stored["destination"]["bucket"] == "report-source"
    assert stored["destination"]["prefix"] == "reports/metrics/metrics-1"


def test_list_is_sorted_by_id_per_kind(service, bucket):
    for ident in ("zulu", "alpha", "mike"):
        assert put_config(service, "inventory", ident,
                          inventory(body_id=ident)).status_code == 200
    listed = signed(service, "GET", "/report-source?inventory")
    root = ET.fromstring(listed.content)
    assert [node.findtext(NS + "Id") for node in root
            if node.find(NS + "Id") is not None] == [
        "alpha", "mike", "zulu"]


def test_put_replaces_document_by_id(service, bucket):
    assert put_config(service, "analytics", "a", analytics(body_id="a", prefix="x/")).status_code == 200
    assert put_config(service, "analytics", "a", analytics(body_id="a", prefix="y/")).status_code == 200
    listed = signed(service, "GET", "/report-source?analytics")
    root = ET.fromstring(listed.content)
    configs = [node for node in root if node.find(NS + "Id") is not None]
    assert len(configs) == 1
    assert configs[0].findtext(NS + "Filter/" + NS + "Prefix") == "y/"


def test_delete_is_idempotent_and_204(service, bucket):
    first = signed(service, "DELETE", "/report-source?metrics&id=absent")
    second = signed(service, "DELETE", "/report-source?metrics&id=absent")
    assert first.status_code == second.status_code == 204


def test_unknown_destination_bucket_is_rejected_400(service, bucket):
    response = put_config(service, "inventory", "missing-dest",
                          inventory(body_id="missing-dest",
                                    destination="no-such-bucket"))
    assert response.status_code == 400
    assert b"InvalidArgument" in response.content


def test_continuous_inventory_schedule_is_501(service, bucket):
    response = put_config(service, "inventory", "continuous",
                          inventory(body_id="continuous", frequency="Hourly"))
    assert response.status_code == 501
    assert b"NotImplemented" in response.content


def test_orc_and_parquet_inventory_are_501(service, bucket):
    for index, fmt in enumerate(("ORC", "Parquet")):
        response = put_config(service, "inventory", f"fmt{index}",
                              inventory(body_id=f"fmt{index}", fmt=fmt))
        assert response.status_code == 501, fmt
        assert b"NotImplemented" in response.content


def test_analytics_non_csv_format_is_501(service, bucket):
    response = put_config(service, "analytics", "parquet",
                          analytics(body_id="parquet", fmt="Parquet"))
    assert response.status_code == 501


def test_unknown_element_is_rejected(service, bucket):
    response = put_config(service, "metrics", "bad",
                          metrics(body_id="bad", extra="<Bogus>x</Bogus>"))
    assert response.status_code == 400
    assert b"MalformedXML" in response.content


def test_duplicate_id_element_is_rejected(service, bucket):
    body = metrics(body_id="dup", extra="<Id>dup</Id>")
    response = put_config(service, "metrics", "dup", body)
    assert response.status_code == 400
    assert b"Duplicate" in response.content


def test_invalid_id_charset_and_length_are_rejected(service, bucket):
    from urllib.parse import quote
    for ident in ("bad id", "x" * 65, "slash/id", ""):
        response = put_config(service, "metrics", quote(ident, safe=""),
                              metrics(body_id=ident))
        assert response.status_code in (400, 404), ident


def test_query_id_must_match_document_id(service, bucket):
    response = put_config(service, "analytics", "query-id",
                          analytics(body_id="other-id"))
    assert response.status_code == 400
    assert b"does not match" in response.content


def test_oversized_document_is_rejected(service, bucket):
    body = metrics(body_id="large") + b" " * (16 * 1024)
    response = put_config(service, "metrics", "large", body)
    assert response.status_code == 400
    assert b"16 KiB" in response.content


def test_object_size_filter_is_declared_unsupported_501(service, bucket):
    body = (
        f"<MetricsConfiguration {XMLNS}><Id>size</Id>"
        "<Filter><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan></Filter>"
        "</MetricsConfiguration>"
    ).encode()
    response = put_config(service, "metrics", "size", body)
    assert response.status_code == 501


def test_invalid_filter_form_is_rejected(service, bucket):
    body = (
        f"<MetricsConfiguration {XMLNS}><Id>f</Id>"
        "<Filter><Bogus>x</Bogus></Filter></MetricsConfiguration>"
    ).encode()
    response = put_config(service, "metrics", "f", body)
    assert response.status_code == 400


def test_valid_tag_and_filter_round_trip(service, bucket):
    body = (
        f"<AnalyticsConfiguration {XMLNS}><Id>tags</Id>"
        "<Filter><And><Prefix>data/</Prefix>"
        "<Tag><Key>team</Key><Value>blue</Value></Tag></And></Filter>"
        "<StorageClassAnalysis><DataExport>"
        "<OutputSchemaVersion>V_1</OutputSchemaVersion>"
        "<Destination><S3BucketDestination>"
        "<Bucket>arn:aws:s3:::report-dest</Bucket><Format>CSV</Format>"
        "</S3BucketDestination></Destination>"
        "</DataExport></StorageClassAnalysis></AnalyticsConfiguration>"
    ).encode()
    assert put_config(service, "analytics", "tags", body).status_code == 200
    fetched = signed(service, "GET", "/report-source?analytics&id=tags")
    root = ET.fromstring(fetched.content)
    assert root.findtext(
        NS + "Filter/" + NS + "And/" + NS + "Tag/" + NS + "Key") == "team"


def test_missing_tag_value_is_rejected(service, bucket):
    body = (
        f"<MetricsConfiguration {XMLNS}><Id>tag</Id>"
        "<Filter><Tag><Key>a</Key></Tag></Filter></MetricsConfiguration>"
    ).encode()
    response = put_config(service, "metrics", "tag", body)
    assert response.status_code == 400


def test_put_requires_id_query(service, bucket):
    response = signed(service, "PUT", "/report-source?metrics",
                      metrics(body_id="noid"))
    assert response.status_code == 400


def test_delete_requires_id_query(service, bucket):
    response = signed(service, "DELETE", "/report-source?analytics")
    assert response.status_code == 400


def test_delete_with_body_is_rejected(service, bucket):
    response = signed(service, "DELETE",
                      "/report-source?analytics&id=analytics-1", b"x")
    assert response.status_code == 400


def test_duplicate_id_query_is_rejected(service, bucket):
    response = signed(service, "GET",
                      "/report-source?analytics&id=a&id=b")
    assert response.status_code == 400


def test_unrelated_query_parameter_is_rejected(service, bucket):
    response = signed(service, "GET",
                      "/report-source?analytics&prefix=x")
    # The fail-closed route guard rejects the unknown selector before SQL.
    assert response.status_code == 501
    assert b"NotImplemented" in response.content


def test_report_selector_on_object_path_is_501(service, bucket):
    assert signed(service, "PUT", "/report-source/object.bin", b"data").status_code == 200
    response = signed(service, "GET", "/report-source/object.bin?analytics")
    assert response.status_code == 501


def test_head_on_report_selector_is_501(service, bucket):
    response = signed(service, "HEAD", "/report-source?inventory")
    assert response.status_code == 501


def test_missing_configuration_uses_aws_error_name_for_all_kinds(service, bucket):
    for kind in ("analytics", "inventory", "metrics"):
        response = signed(service, "GET", f"/report-source?{kind}&id=absent")
        assert response.status_code == 404
        assert b"NoSuchConfiguration" in response.content


def test_content_md5_mismatch_is_bad_digest(service, bucket):
    import base64
    body = metrics(body_id="md5")
    response = signed(
        service, "PUT", "/report-source?metrics&id=md5", body,
        extra_headers={"content-md5": base64.b64encode(b"\x00" * 16).decode()},
    )
    assert response.status_code == 400
    assert b"BadDigest" in response.content


def test_optional_fields_are_accepted_and_unsupported_ones_are_501(service, bucket):
    accepted = put_config(service, "inventory", "optional",
                          inventory(body_id="optional",
                                    optional=("Size", "ETag")))
    assert accepted.status_code == 200
    unsupported = put_config(service, "inventory", "replication-status",
                             inventory(body_id="replication-status",
                                       optional=("ReplicationStatus",)))
    assert unsupported.status_code == 501


def test_inventory_current_versions_round_trip(service, bucket):
    response = put_config(service, "inventory", "current",
                          inventory(body_id="current", versions="Current"))
    assert response.status_code == 200
    fetched = ET.fromstring(signed(
        service, "GET", "/report-source?inventory&id=current").content)
    assert fetched.findtext(NS + "IncludedObjectVersions") == "Current"
