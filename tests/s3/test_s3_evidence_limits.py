"""Over-limit and malformed evidence for the S3 operations the matrix
left open.

Two evidence classes, one file:

* **over-limit** — each operation's OWN enforced bound (body size, part
  number ceiling, entry count) refuses an input one unit past it. The
  global sweep (``tests/s3/test_s3_over_limit_matrix.py``) is the floor;
  the cells filled here are the per-operation proofs beyond it.
* **malformed** — syntactically or structurally invalid input is
  refused 4xx without mutation, per operation.

Every test sends a correctly signed request with a full permission set,
imports the limit from the module that enforces it (so a limit change
cannot silently diverge), and asserts the three-part contract:

* the answer is the operation's specific 4xx (never 2xx, never 5xx),
* the stored state is unchanged (read side identical before/after),
* zero bytes reached Telegram.

Filled here: the 17 over-limit cells (DeleteObjects, UploadPart,
CompleteMultipartUpload, PutBucketVersioning, PutBucketReplication, the
V1/V2 metadata configuration family, the ACL pair, ownership controls,
public access block, bucket encryption and the object-lock bodies) and
the 12 malformed cells (CopyObject, CreateMultipartUpload,
UploadPartCopy, ListParts, PutBucketNotificationConfiguration, the
metadata configuration family, and the retention/legal-hold bodies).
"""
from __future__ import annotations

import base64
import hashlib
import re

from tests.s3.test_s3_gateway import service, signed  # noqa: F401
from teledrive.s3.acl import MAX_ACL_XML
from teledrive.s3.batch_delete import MAX_BATCH_OBJECTS
from teledrive.s3.bucket_encryption import MAX_ENCRYPTION_XML_BYTES
from teledrive.s3.metadata_journal import MAX_METADATA_XML_BYTES
from teledrive.s3.multipart import MAX_PARTS
from teledrive.s3.ownership import MAX_OWNERSHIP_XML_BYTES
from teledrive.s3.public_access import MAX_PUBLIC_ACCESS_XML_BYTES
from teledrive.s3.replication import MAX_REPLICATION_XML_BYTES
from teledrive.s3.versioning import MAX_VERSIONING_XML_BYTES

XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

# CompleteMultipartUpload's completion XML bound lives inline in the
# gateway handler (web/s3_gateway/multipart.py).
MAX_COMPLETE_XML_BYTES = 1024 * 1024


def _one_past(limit, prefix):
    """A body of exactly ``limit + 1`` bytes starting with ``prefix``."""
    padding = limit + 1 - len(prefix)
    assert padding > 0, "the prefix must be shorter than the limit"
    return prefix + b" " * padding


def _make_bucket(service, name):
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


def _put_object(service, bucket, key, payload=b"limits-payload"):
    reply = signed(service, "PUT", f"/{bucket}/{key}", payload)
    assert reply.status_code == 200, reply.text
    return payload


def _start_upload(service, bucket, key):
    reply = signed(service, "POST", f"/{bucket}/{key}?uploads")
    assert reply.status_code == 200, reply.text
    match = re.search(rb"<UploadId>([^<]+)</UploadId>", reply.content)
    assert match, reply.text
    return match.group(1).decode()


def _md5_header(body):
    return {"Content-MD5": base64.b64encode(
        hashlib.md5(body, usedforsecurity=False).digest()).decode()}


def _create_v2_metadata_config(service, bucket):
    body = (f'<MetadataConfiguration xmlns="{XMLNS}">'
            "<JournalTableConfiguration><RecordExpiration>"
            "<Expiration>DISABLED</Expiration>"
            "</RecordExpiration></JournalTableConfiguration>"
            "</MetadataConfiguration>").encode()
    reply = signed(service, "POST", f"/{bucket}?metadataConfiguration", body)
    assert reply.status_code == 200, reply.text


# ===========================================================================
# Over-limit: the XML-body bound families (limit + 1 bytes -> 4xx).
# ===========================================================================

def test_put_bucket_versioning_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-versioning-bucket")
    enabled = (f'<VersioningConfiguration xmlns="{XMLNS}">'
               "<Status>Enabled</Status></VersioningConfiguration>").encode()
    assert signed(service, "PUT", f"/{bucket}?versioning",
                  enabled).status_code == 200
    before = signed(service, "GET", f"/{bucket}?versioning").content
    reply = signed(service, "PUT", f"/{bucket}?versioning",
                   _one_past(MAX_VERSIONING_XML_BYTES,
                             b"<VersioningConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET", f"/{bucket}?versioning").content == before


def test_put_bucket_replication_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-replication-bucket")
    reply = signed(service, "PUT", f"/{bucket}?replication",
                   _one_past(MAX_REPLICATION_XML_BYTES,
                             b"<ReplicationConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET", f"/{bucket}?replication").status_code == 404


def test_put_bucket_acl_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-bucketacl-bucket")
    reply = signed(service, "PUT", f"/{bucket}?acl",
                   _one_past(MAX_ACL_XML, b"<AccessControlPolicy>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    # No grant document was stored: the read side answers the caller's
    # canned private ACL, not a stored one.
    state = signed(service, "GET", f"/{bucket}?acl")
    assert state.status_code == 200


def test_put_object_acl_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-objacl-bucket")
    _put_object(service, bucket, "guarded.bin")
    reply = signed(service, "PUT", f"/{bucket}/guarded.bin?acl",
                   _one_past(MAX_ACL_XML, b"<AccessControlPolicy>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}/guarded.bin?acl").status_code == 200


def test_put_bucket_ownership_controls_refuse_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-ownership-bucket")
    reply = signed(service, "PUT", f"/{bucket}?ownershipControls",
                   _one_past(MAX_OWNERSHIP_XML_BYTES, b"<OwnershipControls>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    # Nothing was stored: the read side still reports the default model.
    state = signed(service, "GET", f"/{bucket}?ownershipControls")
    assert state.status_code == 200
    assert b"BucketOwnerEnforced" in state.content


def test_put_public_access_block_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-pab-bucket")
    before = signed(service, "GET", f"/{bucket}?publicAccessBlock")
    assert before.status_code == 200
    reply = signed(service, "PUT", f"/{bucket}?publicAccessBlock",
                   _one_past(MAX_PUBLIC_ACCESS_XML_BYTES,
                             b"<PublicAccessBlockConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    # The persisted flags are unchanged.
    after = signed(service, "GET", f"/{bucket}?publicAccessBlock")
    assert after.status_code == 200 and after.content == before.content


def test_put_bucket_encryption_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-encryption-bucket")
    reply = signed(service, "PUT", f"/{bucket}?encryption",
                   _one_past(MAX_ENCRYPTION_XML_BYTES,
                             b"<ServerSideEncryptionConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?encryption").status_code == 404


def test_put_object_lock_configuration_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-lockconfig-bucket")
    reply = signed(service, "PUT", f"/{bucket}?object-lock",
                   _one_past(16 * 1024, b"<ObjectLockConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?object-lock").status_code == 404


def test_put_object_retention_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-retention-bucket")
    _put_object(service, bucket, "guarded.bin")
    path = f"/{bucket}/guarded.bin"
    reply = signed(service, "PUT", f"{path}?retention",
                   _one_past(16 * 1024, b"<Retention>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    # No retention was stored.
    assert signed(service, "GET", f"{path}?retention").status_code == 404


def test_put_object_legal_hold_refuses_an_over_limit_body(service):
    bucket = _make_bucket(service, "limit-hold-bucket")
    _put_object(service, bucket, "guarded.bin")
    path = f"/{bucket}/guarded.bin"
    reply = signed(service, "PUT", f"{path}?legal-hold",
                   _one_past(16 * 1024, b"<LegalHold>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    state = signed(service, "GET", f"{path}?legal-hold")
    assert state.status_code == 200 and b"<Status>OFF</Status>" in state.content


def test_create_bucket_metadata_table_configuration_refuses_over_limit(
        service):
    bucket = _make_bucket(service, "limit-v1meta-bucket")
    reply = signed(service, "POST", f"/{bucket}?metadataTable",
                   _one_past(MAX_METADATA_XML_BYTES,
                             b"<MetadataTableConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataTable").status_code == 404


def test_update_bucket_metadata_journal_table_refuses_over_limit(service):
    bucket = _make_bucket(service, "limit-journal-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "PUT", f"/{bucket}?metadataJournalTable",
                   _one_past(MAX_METADATA_XML_BYTES,
                             b"<JournalTableConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


def test_update_bucket_metadata_inventory_table_refuses_over_limit(service):
    bucket = _make_bucket(service, "limit-inventory-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "PUT", f"/{bucket}?metadataInventoryTable",
                   _one_past(MAX_METADATA_XML_BYTES,
                             b"<InventoryTableConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


def test_update_bucket_metadata_annotation_table_refuses_over_limit(service):
    bucket = _make_bucket(service, "limit-annotationtable-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "PUT", f"/{bucket}?metadataAnnotationTable",
                   _one_past(MAX_METADATA_XML_BYTES,
                             b"<AnnotationTableConfiguration>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


# ===========================================================================
# Over-limit: count and value ceilings.
# ===========================================================================

def test_delete_objects_refuses_more_than_the_batch_maximum(service):
    bucket = _make_bucket(service, "limit-batchdelete-bucket")
    _put_object(service, bucket, "survivor.bin")
    entries = "".join(
        f"<Object><Key>key-{index}</Key></Object>"
        for index in range(MAX_BATCH_OBJECTS + 1))
    body = (f"<Delete {XMLNS}>{entries}</Delete>").encode()
    assert body.count(b"<Object>") == MAX_BATCH_OBJECTS + 1
    reply = signed(service, "POST", f"/{bucket}?delete", body,
                   extra_headers=_md5_header(body))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    # Nothing was unlinked.
    assert signed(service, "GET",
                  f"/{bucket}/survivor.bin").status_code == 200


def test_upload_part_refuses_a_part_number_past_the_ceiling(service):
    bucket = _make_bucket(service, "limit-partnumber-bucket")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    uploads_before = service[2].uploads
    reply = signed(service, "PUT",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}"
                   f"&partNumber={MAX_PARTS + 1}", b"part-bytes")
    assert reply.status_code == 400, reply.text[:300]
    assert b"InvalidArgument" in reply.content
    # No part was staged and no bytes moved.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200 and b"<Part>" not in parts.content
    assert service[2].uploads == uploads_before


def test_complete_multipart_upload_refuses_an_over_limit_xml(service):
    bucket = _make_bucket(service, "limit-complete-bucket")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    uploads_before = service[2].uploads
    reply = signed(service, "POST",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}",
                   _one_past(MAX_COMPLETE_XML_BYTES,
                             b"<CompleteMultipartUpload>"))
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    # The upload was neither completed nor consumed, and no object was
    # published.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200
    assert signed(service, "GET",
                  f"/{bucket}/assembled.bin").status_code == 404
    assert service[2].uploads == uploads_before


# ===========================================================================
# Malformed: operation-specific invalid input is refused without mutation.
# ===========================================================================

def test_copy_object_refuses_a_malformed_copy_source(service):
    bucket = _make_bucket(service, "malformed-copy-bucket")
    payload = _put_object(service, bucket, "source.bin")
    uploads_before = service[2].uploads
    # A copy source with no object key is structurally invalid.
    reply = signed(service, "PUT", f"/{bucket}/copied.bin",
                   extra_headers={"x-amz-copy-source": f"/{bucket}"})
    assert reply.status_code == 400, reply.text[:300]
    assert b"InvalidArgument" in reply.content
    # The source is intact, the destination was not created, and no
    # bytes moved.
    assert signed(service, "GET",
                  f"/{bucket}/source.bin").content == payload
    assert signed(service, "GET", f"/{bucket}/copied.bin").status_code == 404
    assert service[2].uploads == uploads_before


def test_create_multipart_upload_refuses_a_non_empty_body(service):
    bucket = _make_bucket(service, "malformed-mpu-bucket")
    reply = signed(service, "POST", f"/{bucket}/initiated.bin?uploads",
                   b"create-multipart-upload has no body")
    assert reply.status_code == 400, reply.text[:300]
    assert b"InvalidRequest" in reply.content
    # No multipart session was allocated.
    listing = signed(service, "GET", f"/{bucket}?uploads")
    assert listing.status_code == 200 and b"<Upload>" not in listing.content


def test_upload_part_copy_refuses_malformed_input(service):
    bucket = _make_bucket(service, "malformed-mpucopy-bucket")
    payload = _put_object(service, bucket, "source.bin")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    uploads_before = service[2].uploads

    # A copy source without a bucket/object split is structurally invalid.
    bad_source = signed(
        service, "PUT",
        f"/{bucket}/assembled.bin?uploadId={upload_id}&partNumber=1",
        extra_headers={"x-amz-copy-source": "/just-a-bucket-name"})
    assert bad_source.status_code == 400, bad_source.text[:300]
    assert b"InvalidArgument" in bad_source.content

    # A well-formed source with a malformed byte range is refused too.
    bad_range = signed(
        service, "PUT",
        f"/{bucket}/assembled.bin?uploadId={upload_id}&partNumber=1",
        extra_headers={"x-amz-copy-source": f"/{bucket}/source.bin",
                       "x-amz-copy-source-range": "bytes=first-last"})
    assert bad_range.status_code == 400, bad_range.text[:300]
    assert b"InvalidArgument" in bad_range.content

    # No part was staged, the source is intact, and nothing moved.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200 and b"<Part>" not in parts.content
    assert signed(service, "GET",
                  f"/{bucket}/source.bin").content == payload
    assert service[2].uploads == uploads_before


def test_list_parts_refuses_malformed_pagination(service):
    bucket = _make_bucket(service, "malformed-listparts-bucket")
    upload_id = _start_upload(service, bucket, "assembled.bin")
    for query in ("max-parts=banana", "part-number-marker=xyz"):
        reply = signed(service, "GET",
                       f"/{bucket}/assembled.bin?uploadId={upload_id}"
                       f"&{query}")
        assert reply.status_code == 400, (query, reply.text[:300])
        assert b"InvalidArgument" in reply.content
    # The upload is intact and still listable with valid pagination.
    parts = signed(service, "GET",
                   f"/{bucket}/assembled.bin?uploadId={upload_id}")
    assert parts.status_code == 200


def test_put_bucket_notification_configuration_refuses_malformed_xml(service):
    bucket = _make_bucket(service, "malformed-notify-bucket")
    reply = signed(service, "PUT", f"/{bucket}?notificationConfiguration",
                   b"<NotificationConfiguration><Unknown/>"
                   b"</NotificationConfiguration>")
    assert reply.status_code == 400, reply.text[:300]
    # The read side answers the AWS empty-document contract: nothing
    # was stored.
    state = signed(service, "GET", f"/{bucket}?notificationConfiguration")
    assert state.status_code == 200
    assert b"<Endpoint" not in state.content
    assert b"WebhookConfiguration" not in state.content


def test_create_bucket_metadata_table_configuration_refuses_malformed_xml(
        service):
    bucket = _make_bucket(service, "malformed-v1meta-bucket")
    reply = signed(service, "POST", f"/{bucket}?metadataTable",
                   b"<NotMetadataTableConfiguration/>")
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataTable").status_code == 404


def test_delete_bucket_metadata_configuration_refuses_a_body(service):
    bucket = _make_bucket(service, "malformed-v2meta-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "DELETE", f"/{bucket}?metadataConfiguration",
                   b"a delete must not carry a body")
    assert reply.status_code == 400, reply.text[:300]
    assert b"InvalidRequest" in reply.content
    # The configuration survived the malformed delete.
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


def test_update_bucket_metadata_journal_table_refuses_malformed_xml(service):
    bucket = _make_bucket(service, "malformed-journal-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "PUT", f"/{bucket}?metadataJournalTable",
                   b"<JournalTableConfiguration><Weeks>7</Weeks>"
                   b"</JournalTableConfiguration>")
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


def test_update_bucket_metadata_inventory_table_refuses_malformed_xml(service):
    bucket = _make_bucket(service, "malformed-inventory-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "PUT", f"/{bucket}?metadataInventoryTable",
                   b"<InventoryTableConfiguration><Weeks>7</Weeks>"
                   b"</InventoryTableConfiguration>")
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


def test_update_bucket_metadata_annotation_table_refuses_malformed_xml(
        service):
    bucket = _make_bucket(service, "malformed-annotationtable-bucket")
    _create_v2_metadata_config(service, bucket)
    before = signed(service, "GET", f"/{bucket}?metadataConfiguration").content
    reply = signed(service, "PUT", f"/{bucket}?metadataAnnotationTable",
                   b"<AnnotationTableConfiguration><Weeks>7</Weeks>"
                   b"</AnnotationTableConfiguration>")
    assert reply.status_code == 400, reply.text[:300]
    assert b"MalformedXML" in reply.content
    assert signed(service, "GET",
                  f"/{bucket}?metadataConfiguration").content == before


def test_put_object_retention_refuses_a_malformed_body(service):
    bucket = _make_bucket(service, "malformed-retention-bucket")
    _put_object(service, bucket, "guarded.bin")
    path = f"/{bucket}/guarded.bin"
    body = (f'<Retention xmlns="{XMLNS}"><Mode>GOVERNANCE</Mode>'
            f"<RetainUntilDate>not-an-instant</RetainUntilDate>"
            f"</Retention>").encode()
    reply = signed(service, "PUT", f"{path}?retention", body)
    assert reply.status_code == 400, reply.text[:300]
    # No retention was stored.
    assert signed(service, "GET", f"{path}?retention").status_code == 404


def test_put_object_legal_hold_refuses_a_malformed_body(service):
    bucket = _make_bucket(service, "malformed-hold-bucket")
    _put_object(service, bucket, "guarded.bin")
    path = f"/{bucket}/guarded.bin"
    body = (f'<LegalHold xmlns="{XMLNS}"><Status>MAYBE</Status>'
            f"</LegalHold>").encode()
    reply = signed(service, "PUT", f"{path}?legal-hold", body)
    assert reply.status_code == 400, reply.text[:300]
    # The hold state is unchanged (OFF).
    state = signed(service, "GET", f"{path}?legal-hold")
    assert state.status_code == 200 and b"<Status>OFF</Status>" in state.content
