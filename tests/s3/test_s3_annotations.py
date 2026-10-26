"""Phase O2: per-object annotations are a real, separate metadata store."""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import quote
from xml.etree import ElementTree as ET

import pytest
from starlette.datastructures import QueryParams

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.annotations import (
    MAX_ANNOTATIONS_PER_OBJECT,
    MAX_ANNOTATION_NAME_BYTES,
    MAX_ANNOTATION_VALUE_BYTES,
)
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.route_guard import S3QueryError, validate_s3_query


@pytest.fixture
def prepared(service):
    assert signed(service, "PUT", "/annotations").status_code == 200
    assert signed(service, "PUT", "/annotations/doc.txt", b"payload").status_code == 200
    return service


def _single(name: str) -> str:
    return f"annotation&annotationName={quote(name, safe='')}"


def _put(service, name: str, value: bytes, *, access=None, secret=None,
         extra_headers=None):
    return signed(
        service, "PUT", f"/annotations/doc.txt?{_single(name)}", value,
        access=access, secret=secret, extra_headers=extra_headers,
    )


def _get(service, name: str, *, access=None, secret=None, extra_headers=None):
    return signed(service, "GET", f"/annotations/doc.txt?{_single(name)}",
                  access=access, secret=secret, extra_headers=extra_headers)


def _delete(service, name: str, *, access=None, secret=None):
    return signed(service, "DELETE", f"/annotations/doc.txt?{_single(name)}",
                  access=access, secret=secret)


def _list(service, query: str = ""):
    suffix = f"&{query}" if query else ""
    return signed(service, "GET", f"/annotations/doc.txt?annotation{suffix}")


def _entry_names(response) -> list[str]:
    root = ET.fromstring(response.content)
    return [node.text for node in root.iter()
            if node.tag.rsplit("}", 1)[-1] == "AnnotationName"]


def test_annotation_crud_round_trip(prepared):
    service = prepared
    put = _put(service, "summary", "hello annotation".encode())
    assert put.status_code == 200, put.text
    root = ET.fromstring(put.content)
    tags = {node.tag.rsplit("}", 1)[-1]: node.text for node in root}
    assert tags == {"Key": "doc.txt", "AnnotationName": "summary"}
    assert put.headers["x-amz-object-version-id"]

    read = _get(service, "summary")
    assert read.status_code == 200, read.text
    assert read.content == b"hello annotation"
    assert read.headers["etag"] == put.headers["etag"]
    assert read.headers["content-length"] == str(len(b"hello annotation"))

    assert _delete(service, "summary").status_code == 204
    missing = _get(service, "summary")
    assert missing.status_code == 404
    assert b"NoSuchAnnotation" in missing.content
    # DeleteObjectAnnotation is idempotent.
    assert _delete(service, "summary").status_code == 204


def test_replacing_an_annotation_keeps_one_row(prepared):
    service = prepared
    assert _put(service, "status", b"first").status_code == 200
    assert _put(service, "status", b"second").status_code == 200
    assert _get(service, "status").content == b"second"
    listing = _list(service)
    assert listing.status_code == 200
    assert _entry_names(listing) == ["status"]
    root = ET.fromstring(listing.content)
    values = {node.tag.rsplit("}", 1)[-1]: node.text for node in root}
    assert values["AnnotationCount"] == "1"


def test_missing_bucket_object_and_annotation_are_honest_404s(prepared):
    service = prepared
    assert signed(service, "GET", "/absent-bucket/doc.txt?annotation&annotationName=x"
                  ).status_code == 404
    assert signed(service, "GET", "/annotations/absent.txt?annotation&annotationName=x"
                  ).status_code == 404
    assert b"NoSuchKey" in signed(
        service, "GET", "/annotations/absent.txt?annotation&annotationName=x").content
    assert _get(service, "never-written").status_code == 404


def test_annotation_limit_is_fifty_per_object(prepared):
    service = prepared
    for index in range(MAX_ANNOTATIONS_PER_OBJECT):
        assert _put(service, f"n{index:02d}", b"x").status_code == 200
    over = _put(service, "one-too-many", b"x")
    assert over.status_code == 400, over.text
    assert b"AnnotationLimitExceeded" in over.content
    # Replacing an existing annotation at the limit still works.
    assert _put(service, "n00", b"replaced").status_code == 200
    assert _get(service, "n00").content == b"replaced"


def test_list_paginates_with_signed_continuation_token(prepared):
    service = prepared
    names = ["a", "b", "c", "d", "e"]
    for name in names:
        assert _put(service, name, name.encode()).status_code == 200
    seen: list[str] = []
    query = "max-annotation-results=2"
    for _ in range(4):
        page = _list(service, query)
        assert page.status_code == 200, page.text
        seen.extend(_entry_names(page))
        token = next((node.text for node in ET.fromstring(page.content).iter()
                      if node.tag.rsplit("}", 1)[-1] == "NextContinuationToken"), None)
        if token is None:
            break
        query = f"max-annotation-results=2&continuation-token={token}"
    assert seen == names


def test_list_prefix_filter_and_bad_token(prepared):
    service = prepared
    for name in ("logs/1", "logs/2", "metrics/1"):
        assert _put(service, name, b"x").status_code == 200
    page = _list(service, "annotation-prefix=logs%2F")
    assert page.status_code == 200
    assert _entry_names(page) == ["logs/1", "logs/2"]
    bad = _list(service, "continuation-token=forged")
    assert bad.status_code == 400
    assert b"InvalidArgument" in bad.content
    # A token is signed and bound to its bucket/key: tampering is refused.
    page = _list(service, "max-annotation-results=1")
    token = next(node.text for node in ET.fromstring(page.content).iter()
                 if node.tag.rsplit("}", 1)[-1] == "NextContinuationToken")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert _list(service, f"continuation-token={tampered}").status_code == 400


@pytest.mark.parametrize("name,status", [
    ("", 400),
    ("a" * (MAX_ANNOTATION_NAME_BYTES + 1), 400),
    ("has space", 400),
    ("has?query", 400),
    ("unicode-é", 400),
])
def test_annotation_name_validation(prepared, name, status):
    reply = _put(prepared, name, b"x")
    assert reply.status_code == status, (name, reply.text)
    assert b"InvalidAnnotationName" in reply.content or b"AnnotationNameTooLong" in reply.content


def test_annotation_value_validation(prepared):
    service = prepared
    assert _put(service, "max", "é".encode() * (MAX_ANNOTATION_VALUE_BYTES // 2)
                ).status_code == 200
    too_big = _put(service, "big", b"x" * (MAX_ANNOTATION_VALUE_BYTES + 1))
    assert too_big.status_code == 400
    assert b"InvalidRequest" in too_big.content
    binary = _put(service, "binary", b"\xff\xfe\x00")
    assert binary.status_code == 415
    assert b"UnsupportedMediaType" in binary.content


def test_annotations_never_leak_into_tags_or_object_metadata(prepared):
    service = prepared
    assert _put(service, "private-note", b"annotations-are-not-tags").status_code == 200
    tagging = signed(service, "GET", "/annotations/doc.txt?tagging")
    assert tagging.status_code == 200
    assert b"annotations-are-not-tags" not in tagging.content
    assert b"private-note" not in tagging.content
    head = signed(service, "HEAD", "/annotations/doc.txt")
    assert b"annotations-are-not-tags" not in head.content
    assert not any("annotation" in name.lower() for name in head.headers)
    # And a real tag does not appear as an annotation.
    tagged = signed(service, "PUT", "/annotations/doc.txt?tagging",
                    b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value>"
                    b"</Tag></TagSet></Tagging>")
    assert tagged.status_code == 200, tagged.text
    listing = _list(service)
    assert _entry_names(listing) == ["private-note"]


def test_version_revocation_removes_annotations(prepared):
    service = prepared
    _, _, _, connect, _ = service
    uploaded = signed(service, "PUT", "/annotations/versioned.txt", b"v1")
    version = uploaded.headers["x-amz-version-id"]
    assert signed(service, "PUT",
                  f"/annotations/versioned.txt?annotation&annotationName=note",
                  b"about v1").status_code == 200
    assert signed(service, "DELETE",
                  f"/annotations/versioned.txt?versionId={version}").status_code == 204
    db = connect()
    try:
        count = db.connection.exec_driver_sql(
            "SELECT COUNT(*) FROM storage_object_annotations WHERE object_id = ?",
            (version,)).scalar_one()
    finally:
        db.close()
    assert count == 0


def test_bucket_delete_reclaims_orphaned_annotation_rows(prepared):
    service = prepared
    _, _, _, connect, _ = service
    assert signed(service, "PUT", "/orphan-annotations").status_code == 200
    uploaded = signed(service, "PUT", "/orphan-annotations/item", b"body")
    object_id = uploaded.headers["x-amz-version-id"]
    assert signed(service, "PUT",
                  "/orphan-annotations/item?annotation&annotationName=note",
                  b"x").status_code == 200
    db = connect()
    try:
        # Simulate a verified physical GC that reclaimed the manifest row;
        # the annotation row is then an orphan the bucket delete must clear.
        db.connection.exec_driver_sql(
            "DELETE FROM storage_objects WHERE id = ?", (object_id,))
        db.connection.commit()
    finally:
        db.close()
    assert signed(service, "DELETE", "/orphan-annotations").status_code == 204
    db = connect()
    try:
        count = db.connection.exec_driver_sql(
            "SELECT COUNT(*) FROM storage_object_annotations").scalar_one()
    finally:
        db.close()
    assert count == 0


def test_annotation_permission_separation(prepared):
    service = prepared
    _, _, _, connect, master = service
    db = connect()
    try:
        store = S3CredentialStore(db, master)
        reader = store.create("annotation-reader", ["s3:GetObjectAnnotation"])
        lister = store.create("annotation-lister", ["s3:ListObjectAnnotations"])
        writer = store.create("annotation-writer", ["s3:PutObjectAnnotation"])
        deleter = store.create("annotation-deleter", ["s3:DeleteObjectAnnotation"])
    finally:
        db.close()
    assert _put(service, "perm", b"value", access=writer.access_key,
                secret=writer.secret_key).status_code == 200
    assert _get(service, "perm", access=reader.access_key,
                secret=reader.secret_key).status_code == 200
    assert _put(service, "other", b"x", access=reader.access_key,
                secret=reader.secret_key).status_code == 403
    assert _list(service).status_code == 200
    assert signed(service, "GET", "/annotations/doc.txt?annotation",
                  access=lister.access_key,
                  secret=lister.secret_key).status_code == 200
    assert _get(service, "perm", access=lister.access_key,
                secret=lister.secret_key).status_code == 403
    assert _delete(service, "perm", access=deleter.access_key,
                   secret=deleter.secret_key).status_code == 204
    assert _get(service, "perm", access=reader.access_key,
                secret=reader.secret_key).status_code == 404
    assert _put(service, "writer-only", b"x", access=deleter.access_key,
                secret=deleter.secret_key).status_code == 403


@pytest.mark.parametrize("method,params", [
    ("GET", "annotation&annotationName=x"),
    ("PUT", "annotation&annotationName=x"),
    ("DELETE", "annotation&annotationName=x"),
    ("GET", "annotation"),
    ("GET", "annotation&annotation-prefix=a&max-annotation-results=5"),
])
def test_route_guard_accepts_the_real_aws_annotation_shapes(method, params):
    validate_s3_query(method, "b", True, QueryParams(params))


@pytest.mark.parametrize("method,params", [
    ("POST", "annotation&annotationName=x"),
    ("GET", "annotation&annotationName=x&versionId=v"),
    ("GET", "annotation&annotationName=x&annotation-prefix=a"),
    ("PUT", "annotation"),
    ("DELETE", "annotation"),
    ("GET", "annotation&unknown-parameter=x"),
    ("GET", "annotations"),
])
def test_route_guard_rejects_non_aws_or_versioned_annotation_shapes(method, params):
    with pytest.raises(S3QueryError) as denied:
        validate_s3_query(method, "b", True, QueryParams(params))
    assert denied.value.status == 501


def test_listing_uses_aws_parameter_names(prepared):
    """The list form is ?annotation with max-annotation-results, not ?annotations."""
    service = prepared
    assert _put(service, "one", b"x").status_code == 200
    assert _list(service, "max-annotation-results=1").status_code == 200
    assert signed(service, "GET",
                  "/annotations/doc.txt?annotations").status_code == 501
    page = _list(service, "max-annotation-results=1&annotation-prefix=n")
    assert page.status_code == 200
    root = ET.fromstring(page.content)
    values = {node.tag.rsplit("}", 1)[-1]: node.text for node in root}
    assert values["Bucket"] == "annotations"
    assert values["Key"] == "doc.txt"
    assert values["MaxAnnotationResults"] == "1"


def test_annotation_checksum_mode_returns_real_payload_digest(prepared):
    service = prepared
    value = b"checksum-bound-annotation"
    put = _put(service, "digest", value)
    assert put.status_code == 200
    read = _get(service, "digest", extra_headers={"x-amz-checksum-mode": "ENABLED"})
    assert read.status_code == 200
    assert read.headers["x-amz-checksum-sha256"] == base64.b64encode(
        hashlib.sha256(value).digest()).decode("ascii")
    assert read.headers["x-amz-checksum-type"] == "FULL_OBJECT"


def test_annotation_put_verifies_signed_checksum(prepared):
    service = prepared
    bad = _put(service, "signed", b"payload",
               extra_headers={"Content-MD5": "AAAAAAAAAAAAAAAAAAAAAA=="})
    assert bad.status_code == 400
    assert b"BadDigest" in bad.content
    assert _get(service, "signed").status_code == 404
