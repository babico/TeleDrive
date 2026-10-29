"""S3 Express One Zone surface for a deployment that has no directory buckets.

TeleDrive stores objects in Telegram and metadata in SQL under general-purpose
bucket names. It has never created, and cannot create, an S3 Express One Zone
*directory bucket*. That makes two AWS operations answerable honestly without
pretending the storage class exists:

* ``ListDirectoryBuckets`` (``GET /``): AWS returns an empty
  ``ListDirectoryBucketsResult`` for an account with no directory buckets.
  Because TeleDrive has none anywhere, that empty result is the permanent,
  truthful answer -- not a canned stub. The response deliberately omits both
  ``Buckets`` and ``ContinuationToken``: there is nothing to enumerate and no
  next page can exist. The query surface (``continuation-token`` and
  ``max-directory-buckets``) is validated strictly in
  :mod:`teledrive.s3.route_guard`; an opaque cursor is accepted within the AWS
  bounds because "nothing follows it" is true for every cursor here.
  ``GET /`` is shared with ListBuckets and botocore sends no discriminating
  query field, so the SigV4 credential scope (``s3express`` vs ``s3``) is the
  selector -- see ``route_guard.is_directory_bucket_listing``. The operation
  requires ``s3:ListDirectoryBuckets``; it never returns general-purpose
  buckets.

* ``CreateSession`` (``GET /{bucket}?session``): session credentials only make
  sense for a directory bucket. There are no directory buckets, so no session
  can ever be issued. The rejection distinguishes what the caller actually
  asked for:

  - a malformed bucket name is ``400 InvalidBucketName``;
  - an existing TeleDrive bucket is a general-purpose bucket, and AWS Express
    sessions cannot be created for it: ``400 InvalidRequest``;
  - any other well-formed name (including one shaped like a directory bucket)
    names no bucket here at all: ``404 NoSuchBucket``, matching the only error
    shape the botocore model lists for this operation.

  Returning ``NoSuchBucket`` unconditionally would have mislabelled the
  general-purpose bucket the deployment really owns; a generic 501 would have
  hidden which of those three facts is true.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from teledrive.storage.catalog import BucketCatalog

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_DIRECTORY_BUCKETS = 1000
MAX_DIRECTORY_TOKEN_LENGTH = 1024
SESSION_MODES = frozenset({"ReadOnly", "ReadWrite"})


class DirectoryBucketError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def list_directory_buckets_xml() -> bytes:
    """The complete, always-empty AWS ListDirectoryBuckets result.

    ``Buckets`` and ``ContinuationToken`` are absent, exactly as AWS omits
    them when there is nothing to list and no further page.
    """
    root = ET.Element("ListDirectoryBucketsResult", xmlns=NAMESPACE)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def create_session_error(bucket: str, *, bucket_exists: bool,
                         session_mode: str | None) -> DirectoryBucketError:
    """Return the honest reason no S3 Express session can be issued.

    ``session_mode`` is the signed ``x-amz-create-session-mode`` header. AWS
    validates it even though the call cannot succeed here; TeleDrive does the
    same so a malformed request is a 400 rather than a misleading 404.
    """
    try:
        BucketCatalog.validate_bucket(bucket)
    except ValueError:
        return DirectoryBucketError(
            "InvalidBucketName",
            "The specified bucket name is not valid for S3",
        )
    if session_mode is not None and session_mode not in SESSION_MODES:
        return DirectoryBucketError(
            "InvalidArgument",
            "SessionMode must be ReadOnly or ReadWrite",
        )
    if bucket_exists:
        return DirectoryBucketError(
            "InvalidRequest",
            "CreateSession requires an S3 Express One Zone directory bucket; "
            "this TeleDrive bucket is a general-purpose bucket and no Express "
            "session can be created for it",
        )
    return DirectoryBucketError(
        "NoSuchBucket",
        "The specified bucket does not exist as an S3 Express One Zone "
        "directory bucket; TeleDrive has no directory buckets",
        404,
    )
