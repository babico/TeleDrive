"""Phase O5: SelectObjectContent evaluates a bounded SQL subset on real bytes.

The response is the AWS binary event stream, exercised byte-exactly here.
"""
from __future__ import annotations

import struct
import zlib
from xml.etree import ElementTree as ET

import pytest

import web.s3 as gateway
from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.select import encode_event

CSV_OBJECT = b"name,age\nalice,30\nbob,25\ncarol,41\n"
JSON_OBJECT = (
    b'{"name":"alpha","score":1}\n'
    b'{"name":"beta","score":3}\n'
)


def _select_xml(expression, *, input_kind="CSV", output_kind="CSV",
                input_options="", output_options="",
                expression_type="SQL", extra=""):
    return (
        "<SelectObjectContentRequest>"
        f"<Expression>{expression}</Expression>"
        f"<ExpressionType>{expression_type}</ExpressionType>"
        f"<InputSerialization><{input_kind}>{input_options}</{input_kind}>"
        "</InputSerialization>"
        f"<OutputSerialization><{output_kind}>{output_options}</{output_kind}>"
        "</OutputSerialization>"
        f"{extra}"
        "</SelectObjectContentRequest>"
    ).encode()


def _csv_request(expression, *, header="USE", output_kind="CSV",
                 output_options=""):
    return _select_xml(
        expression, input_kind="CSV", output_kind=output_kind,
        input_options=(f"<FileHeaderInfo>{header}</FileHeaderInfo>"
                       if header else ""),
        output_options=output_options,
    )


def _json_request(expression, *, kind="LINES", output_kind="JSON"):
    return _select_xml(
        expression, input_kind="JSON", output_kind=output_kind,
        input_options=f"<Type>{kind}</Type>",
    )


def _select(service, bucket, key, body):
    return signed(service, "POST", f"/{bucket}/{key}?select&select-type=2", body)


def _decode_messages(payload: bytes) -> list[dict]:
    messages = []
    offset = 0
    while offset < len(payload):
        total, header_length = struct.unpack_from(">II", payload, offset)
        prelude = payload[offset:offset + 8]
        (prelude_crc,) = struct.unpack_from(">I", payload, offset + 8)
        assert prelude_crc == zlib.crc32(prelude) & 0xFFFFFFFF
        headers_end = offset + 12 + header_length
        headers = {}
        cursor = offset + 12
        while cursor < headers_end:
            name_length = payload[cursor]
            cursor += 1
            name = payload[cursor:cursor + name_length].decode("ascii")
            cursor += name_length
            assert payload[cursor] == 7  # string header value
            cursor += 1
            (value_length,) = struct.unpack_from(">H", payload, cursor)
            cursor += 2
            headers[name] = payload[cursor:cursor + value_length].decode("ascii")
            cursor += value_length
        message_end = offset + total
        (message_crc,) = struct.unpack_from(">I", payload, message_end - 4)
        assert message_crc == zlib.crc32(payload[offset:message_end - 4]) & 0xFFFFFFFF
        messages.append({
            "headers": headers,
            "payload": payload[headers_end:message_end - 4],
        })
        offset = message_end
    return messages


def _records(messages) -> bytes:
    return b"".join(message["payload"] for message in messages
                    if message["headers"][":event-type"] == "Records")


def _upload(service, key="data.csv", body=CSV_OBJECT, bucket="select-bucket"):
    assert signed(service, "PUT", f"/{bucket}").status_code in (200, 409)
    assert signed(service, "PUT", f"/{bucket}/{key}", body).status_code == 200


def test_csv_select_star_returns_records_stats_and_end(service):
    _upload(service)
    response = _select(service, "select-bucket", "data.csv",
                      _csv_request("SELECT * FROM S3Object WHERE age > 26"))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/vnd.amazon.eventstream")
    messages = _decode_messages(response.content)
    assert [message["headers"][":event-type"] for message in messages] == [
        "Records", "Stats", "End"]
    assert _records(messages) == b"alice,30\ncarol,41\n"
    stats = ET.fromstring(messages[1]["payload"])
    assert stats.findtext("BytesScanned") == str(len(CSV_OBJECT))
    assert stats.findtext("BytesProcessed") == str(len(CSV_OBJECT))
    assert stats.findtext("BytesReturned") == str(len(b"alice,30\ncarol,41\n"))
    assert messages[2]["payload"] == b""


def test_json_lines_select_with_projection(service):
    _upload(service, "data.json", JSON_OBJECT)
    response = _select(service, "select-bucket", "data.json",
                      _json_request(
                          "SELECT name FROM S3Object WHERE score >= 3"))
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b'{"name":"beta"}\n'


def test_json_document_select_star(service):
    _upload(service, "array.json", b'[{"n":1},{"n":2}]')
    response = _select(service, "select-bucket", "array.json",
                      _json_request("SELECT * FROM S3Object WHERE n = 2",
                                    kind="DOCUMENT"))
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b'{"n":2}\n'


def test_where_and_or_not_and_limit(service):
    _upload(service)
    body = _csv_request(
        "SELECT name FROM S3Object WHERE age > 20 AND "
        "(name = 'alice' OR NOT name = 'alice') LIMIT 1")
    response = _select(service, "select-bucket", "data.csv", body)
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b"alice\n"
    body = _csv_request(
        "SELECT name FROM S3Object WHERE name = 'bob' OR name = 'carol' LIMIT 1")
    response = _select(service, "select-bucket", "data.csv", body)
    assert _records(_decode_messages(response.content)) == b"bob\n"


def test_csv_header_options_and_negative_limit(service):
    _upload(service)
    # IGNORE skips the first row and names columns _1/_2.
    body = _select_xml(
        "SELECT _1 FROM S3Object LIMIT 1", input_kind="CSV",
        input_options="<FileHeaderInfo>IGNORE</FileHeaderInfo>")
    response = _select(service, "select-bucket", "data.csv", body)
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b"alice\n"
    bad = _select(service, "select-bucket", "data.csv",
                 _csv_request("SELECT * FROM S3Object LIMIT -1"))
    assert bad.status_code == 400


@pytest.mark.parametrize("expression", [
    "SELECT COUNT(*) FROM S3Object",
    "SELECT * FROM S3Object WHERE name LIKE 'a%'",
    "SELECT * FROM Other",
    "SELECT * FROM S3Object GROUP BY name",
    "SELECT name AS n FROM S3Object",
])
def test_unsupported_sql_is_rejected_never_ignored(service, expression):
    _upload(service)
    response = _select(service, "select-bucket", "data.csv",
                      _csv_request(expression))
    assert response.status_code == 400, response.text
    assert ET.fromstring(response.content).findtext("Code") == "InvalidRequest"


def test_unknown_csv_projection_column_is_rejected(service):
    _upload(service)
    response = _select(service, "select-bucket", "data.csv",
                      _csv_request("SELECT missing FROM S3Object"))
    assert response.status_code == 400, response.text
    assert b"Unknown CSV column" in response.content


def test_parquet_and_compressed_inputs_are_501(service):
    _upload(service)
    parquet = _select_xml("SELECT * FROM S3Object").replace(
        b"<CSV></CSV>", b"<Parquet></Parquet>")
    response = _select(service, "select-bucket", "data.csv", parquet)
    assert response.status_code == 501, response.text
    compressed = _select_xml("SELECT * FROM S3Object").replace(
        b"<CSV></CSV>",
        b"<CompressionType>GZIP</CompressionType><CSV></CSV>")
    response = _select(service, "select-bucket", "data.csv", compressed)
    assert response.status_code == 501, response.text


def test_malformed_xml_and_wrong_select_type_are_400(service):
    _upload(service)
    response = _select(service, "select-bucket", "data.csv", b"<not-xml")
    assert response.status_code == 400
    assert ET.fromstring(response.content).findtext("Code") == "MalformedXML"
    response = signed(
        service, "POST", "/select-bucket/data.csv?select&select-type=1",
        _csv_request("SELECT * FROM S3Object"))
    assert response.status_code == 400
    response = _select(
        service, "select-bucket", "data.csv",
        _select_xml("SELECT * FROM S3Object", expression_type="JSON"))
    assert response.status_code == 501


def test_event_stream_framing_is_byte_exact():
    message = encode_event("End", b"")
    header = (b"\x0d:message-type\x07\x00\x05event"
              b"\x0b:event-type\x07\x00\x03End")
    total = 12 + len(header) + 4
    prelude = struct.pack(">II", total, len(header))
    prelude += struct.pack(">I", zlib.crc32(prelude) & 0xFFFFFFFF)
    expected = prelude + header
    expected += struct.pack(">I", zlib.crc32(expected) & 0xFFFFFFFF)
    assert message == expected
    # Records and Stats carry their documented content-type headers.
    assert b":content-type\x07\x00\x18application/octet-stream" in encode_event(
        "Records", b"x")
    assert b":content-type\x07\x00\x08text/xml" in encode_event("Stats", b"x")


def test_scan_bound_returns_clear_error(service, monkeypatch):
    _upload(service, "large.bin", b"x" * len(CSV_OBJECT))
    monkeypatch.setattr(gateway, "MAX_SELECT_SCAN_BYTES", 8)
    response = _select(service, "select-bucket", "large.bin",
                      _csv_request("SELECT * FROM S3Object"))
    assert response.status_code == 413, response.text
    assert ET.fromstring(response.content).findtext("Code") == "EntityTooLarge"
    assert b"limit" in response.content


def test_select_permission_separation_and_route_guard(service):
    _upload(service)
    db = service[3]()
    try:
        store = S3CredentialStore(db, service[4])
        selector = store.create("select-only", ["s3:SelectObjectContent"])
        reader = store.create("read-only", ["s3:GetObject"])
    finally:
        db.close()
    allowed = _select(service, "select-bucket", "data.csv",
                      _csv_request("SELECT * FROM S3Object LIMIT 1"))
    assert allowed.status_code == 200
    # Credential scopes are independent of the resource ACL baseline.
    allowed = signed(
        service, "POST", "/select-bucket/data.csv?select&select-type=2",
        _csv_request("SELECT * FROM S3Object LIMIT 1"),
        access=selector.access_key, secret=selector.secret_key,
    )
    assert allowed.status_code == 200, allowed.text
    denied = signed(
        service, "POST", "/select-bucket/data.csv?select&select-type=2",
        _csv_request("SELECT * FROM S3Object"),
        access=reader.access_key, secret=reader.secret_key,
    )
    assert denied.status_code == 403
    assert ET.fromstring(denied.content).findtext("Code") == "AccessDenied"
    assert signed(service, "GET", "/select-bucket/data.csv?select").status_code == 501
    assert signed(service, "POST", "/select-bucket/data.csv?select").status_code == 400


def test_select_accepts_the_documented_table_alias_form(service):
    """AWS examples qualify columns with the S3Object alias.

    `SELECT s.name FROM S3Object s WHERE s.age > '35'` is the shape in the
    AWS docs; the alias carries no meaning here (one source object) but it
    must parse and evaluate, not be rejected as unsupported SQL.
    """
    assert signed(service, "PUT", "/select-bucket").status_code == 200
    body = b"name,age\nalice,30\nbob,41\n"
    assert signed(service, "PUT", "/select-bucket/people.csv",
                  body).status_code == 200
    response = _select(
        service, "select-bucket", "people.csv",
        _csv_request("SELECT s.name FROM S3Object s WHERE s.age > '35'"))
    assert response.status_code == 200, response.text
    assert b"bob" in response.content
    assert b"alice" not in response.content
