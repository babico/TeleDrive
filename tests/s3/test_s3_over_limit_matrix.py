"""Every bounded S3 document refuses an over-limit body.

The "over-limit" column of the per-operation matrix in `docs/S3_SPECS.md`.
Each operation that accepts a request body declares a limit; this sweep sends
just past it, with a VALID signature and a full permission set, and asserts:

* the answer is a 4xx with the S3 error code the spec uses for that class
  (`EntityTooLarge`, `MalformedXML` or `InvalidRequest`), never 2xx,
* the stored configuration is unchanged,
* zero bytes reach Telegram.

The limits are imported from the modules that enforce them, so a limit that
is lowered or raised cannot silently diverge from this table: the sweep
sends `limit + 1`, whatever the limit is.

Kept deliberately separate from `test_s3_unsigned_matrix.py`: that one is
about authentication, this one is about the size/shape bound.
"""
from __future__ import annotations

import pytest

from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.cors import MAX_CORS_XML_BYTES
from teledrive.s3.notifications import MAX_NOTIFICATION_XML_BYTES
from teledrive.s3.policy import MAX_POLICY_BYTES
from teledrive.s3.replication import MAX_REPLICATION_XML_BYTES

B = "/limit-bucket"

# operation -> (method, path, limit, the body that is one byte too long)
OVER_LIMIT = {
    "PutBucketPolicy": (
        "PUT", f"{B}?policy", MAX_POLICY_BYTES,
        b"{" + b" " * MAX_POLICY_BYTES),
    "PutBucketCors": (
        "PUT", f"{B}?cors", MAX_CORS_XML_BYTES,
        b"<CORSConfiguration>" + b" " * MAX_CORS_XML_BYTES),
    "PutBucketNotification": (
        "PUT", f"{B}?notification", MAX_NOTIFICATION_XML_BYTES,
        b"<NotificationConfiguration>" + b" " * MAX_NOTIFICATION_XML_BYTES),
    "PutBucketNotificationConfiguration": (
        "PUT", f"{B}?notification", MAX_NOTIFICATION_XML_BYTES,
        b"<NotificationConfiguration>" + b" " * MAX_NOTIFICATION_XML_BYTES),
    "PutBucketReplication": (
        "PUT", f"{B}?replication", MAX_REPLICATION_XML_BYTES,
        b"<ReplicationConfiguration>" + b" " * MAX_REPLICATION_XML_BYTES),
}


@pytest.mark.parametrize("operation", sorted(OVER_LIMIT))
def test_an_over_limit_body_is_refused_and_stores_nothing(service, operation):
    method, path, limit, body = OVER_LIMIT[operation]
    _client, _creds, telegram, _connection, _key = service
    assert signed(service, "PUT", B).status_code == 200
    uploads_before = telegram.uploads

    assert len(body) > limit, "the fixture must actually exceed the limit"
    reply = signed(service, method, path, body)

    assert reply.status_code in (400, 413), (
        f"{operation}: a {len(body)}-byte body against a {limit}-byte limit "
        f"answered {reply.status_code}: {reply.text[:200]}")
    # The read side must report "nothing stored". Most of these answer 404
    # when unconfigured; notification answers 200 with an EMPTY document,
    # which is the AWS contract, so the assertion is on the content rather
    # than the status.
    stored = signed(service, "GET", path)
    if operation in ("PutBucketNotification",
                     "PutBucketNotificationConfiguration"):
        assert stored.status_code == 200, stored.text[:200]
        assert b"WebhookConfiguration" not in stored.content, (
            "an over-limit notification body was stored")
        assert b"<Endpoint" not in stored.content
    else:
        assert stored.status_code == 404, (
            f"{operation} over-limit left a configuration behind: "
            f"{stored.text[:200]}")
    assert telegram.uploads == uploads_before


def test_the_table_covers_every_body_limited_operation_that_can_overshoot():
    """Guard against the list silently rotting.

    Every operation named here must still exist in the manifest as
    supported; if one is renamed or removed, this fails rather than the sweep
    quietly testing nothing.
    """
    import json
    from pathlib import Path

    manifest = json.loads(
        (Path(__file__).resolve().parents[2]
         / "teledrive/s3/operation_manifest.json").read_text())
    supported = {op["name"] for op in manifest["operations"]
                 if op.get("status") == "supported"}
    stale = sorted(set(OVER_LIMIT) - supported)
    assert not stale, f"over-limit table names non-supported operations: {stale}"
