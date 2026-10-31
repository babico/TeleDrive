"""SelectObjectContent CSV parsing options on real bytes.

Input CSV accepts the AWS delimiters, a custom quote character and quoted
record delimiters (with the explicit opt-in). The same bounded-body checksum
policy as every other object-level control body applies here.
"""
from __future__ import annotations

import base64
import zlib
from xml.etree import ElementTree as ET

from tests.s3.test_s3_gateway import signed
from tests.s3.test_s3_select import (
    _decode_messages, _records, _select, _select_xml, _upload, service,
)


def _body(expression, input_options, *, output_kind="CSV"):
    return _select_xml(expression, input_kind="CSV",
                       output_kind=output_kind, input_options=input_options)


def test_custom_field_delimiter_with_quoted_delimiter(service):
    _upload(service, "pipes.csv", b'name|note\nalice|"x|y"\n')
    response = _select(
        service, "select-bucket", "pipes.csv",
        _body("SELECT note FROM S3Object WHERE name = 'alice'",
              "<FileHeaderInfo>USE</FileHeaderInfo>"
              "<FieldDelimiter>|</FieldDelimiter>"))
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b"x|y\n"


def test_custom_quote_character(service):
    _upload(service, "quoted.csv", b"name,note\nalice,'x,y'\n")
    response = _select(
        service, "select-bucket", "quoted.csv",
        _body("SELECT note FROM S3Object WHERE name = 'alice'",
              "<FileHeaderInfo>USE</FileHeaderInfo>"
              "<QuoteCharacter>'</QuoteCharacter>"))
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b'"x,y"\n'


def test_carriage_return_record_delimiter(service):
    _upload(service, "cr.csv", b"name,age\rbob,25\rcarol,41\r")
    response = _select(
        service, "select-bucket", "cr.csv",
        _body("SELECT name, age FROM S3Object WHERE age = 25",
              "<FileHeaderInfo>USE</FileHeaderInfo>"
              "<RecordDelimiter>&#13;</RecordDelimiter>"))
    assert response.status_code == 200, response.text
    assert _records(_decode_messages(response.content)) == b"bob,25\n"


def test_quoted_record_delimiter_requires_explicit_opt_in(service):
    _upload(service, "multiline.csv",
            b'name,note\nalice,"line1\nline2"\n')
    refused = _select(
        service, "select-bucket", "multiline.csv",
        _body("SELECT note FROM S3Object", "<FileHeaderInfo>USE</FileHeaderInfo>"))
    assert refused.status_code == 400, refused.text
    assert ET.fromstring(refused.content).findtext("Code") == "InvalidRequest"

    allowed = _select(
        service, "select-bucket", "multiline.csv",
        _body("SELECT note FROM S3Object",
              "<FileHeaderInfo>USE</FileHeaderInfo>"
              "<AllowQuotedRecordDelimiter>true</AllowQuotedRecordDelimiter>"))
    assert allowed.status_code == 200, allowed.text
    assert _records(_decode_messages(allowed.content)) == b'"line1\nline2"\n'


def test_select_control_body_checks_crc32(service):
    _upload(service)
    body = _body("SELECT * FROM S3Object", "<FileHeaderInfo>USE</FileHeaderInfo>")
    actual = base64.b64encode(
        (zlib.crc32(body) & 0xffffffff).to_bytes(4, "big")).decode()
    accepted = signed(
        service, "POST", "/select-bucket/data.csv?select&select-type=2", body,
        extra_headers={"x-amz-checksum-crc32": actual})
    assert accepted.status_code == 200, accepted.text

    rejected = signed(
        service, "POST", "/select-bucket/data.csv?select&select-type=2", body,
        extra_headers={
            "x-amz-checksum-crc32": base64.b64encode(b"\0\0\0\0").decode()})
    assert rejected.status_code == 400, rejected.text
    assert ET.fromstring(rejected.content).findtext("Code") == "BadDigest"
