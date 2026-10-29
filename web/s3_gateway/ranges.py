"""Byte ranges, continuation cursors, listing pages, vhost selection.

Move-only extraction from ``web/s3.py`` (handoff 01, step 3).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re

from fastapi import Request

from teledrive.s3.sigv4 import SigV4Error
from teledrive.storage.catalog import BucketCatalog


def _range(value: str | None, size: int) -> tuple[int, int, bool]:
    if value is None:
        return 0, size, False
    import re
    # Same digit bound as the REST path: an over-long integer raises before
    # any comparison and would escape as a 500 instead of InvalidRange.
    match = re.fullmatch(r"bytes=(\d{0,20})-(\d{0,20})", value.strip())
    if not match or not (match.group(1) or match.group(2)) or size <= 0:
        raise SigV4Error("InvalidRange", "Unsupported byte range")
    first, last = match.groups()
    if first:
        start = int(first)
        end = min(int(last) + 1, size) if last else size
    else:
        amount = int(last)
        start, end = max(size - amount, 0), size
    if start >= size or start >= end or (not first and int(last) <= 0):
        raise SigV4Error("InvalidRange", "Unsatisfiable byte range")
    return start, end, True


def _cursor_encode(master: bytes, bucket: str, prefix: str, delimiter: str,
                   after: str, skip_prefix: str) -> str:
    payload = json.dumps(
        {"bucket": bucket, "prefix": prefix, "delimiter": delimiter,
         "after": after, "skip_prefix": skip_prefix},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = hmac.new(master, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _cursor_decode(token: str, master: bytes, bucket: str,
                   prefix: str, delimiter: str) -> tuple[str, str]:
    try:
        encoded, signature = token.split(".", 1)
        if len(token) > 4096 or not hmac.compare_digest(
            signature, hmac.new(master, encoded.encode(), hashlib.sha256).hexdigest()
        ):
            raise ValueError("Signature mismatch")
        parsed = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (not isinstance(parsed, dict) or parsed.get("bucket") != bucket
                or parsed.get("prefix") != prefix or parsed.get("delimiter") != delimiter
                or not isinstance(parsed.get("after"), str)
                or not isinstance(parsed.get("skip_prefix"), str)):
            raise ValueError("Cursor does not match request")
        return parsed["after"], parsed["skip_prefix"]
    except (ValueError, UnicodeError, TypeError, KeyError, binascii.Error) as exc:
        raise SigV4Error("InvalidArgument", "Invalid continuation token") from exc


def _page(catalog: BucketCatalog, bucket: str, prefix: str,
          delimiter: str, after: str, limit: int,
          skip_prefix: str) -> tuple[list, list[str], str, str, bool]:
    """Page over raw keys without splitting a common-prefix across pages.

    The last emitted prefix is carried in the signed continuation cursor
    so a folder containing >1000 objects is not shown repeatedly.
    """
    keys = []
    common = []
    seen = {skip_prefix} if skip_prefix else set()
    position = after
    last_consumed = after
    while True:
        batch = catalog.list_objects(bucket, prefix=prefix, after=position, limit=1000)
        if not batch:
            return keys, common, last_consumed, skip_prefix, False
        for item in batch:
            key = item.item.key
            tail = key[len(prefix):]
            common_name = ""
            if delimiter and delimiter in tail:
                common_name = prefix + tail.split(delimiter, 1)[0] + delimiter
            if common_name and common_name in seen:
                position = key
                last_consumed = key
                continue
            if len(keys) + len(common) >= limit:
                return keys, common, last_consumed, skip_prefix, True
            if common_name:
                common.append(common_name)
                seen.add(common_name)
                skip_prefix = common_name
            else:
                keys.append(item)
                skip_prefix = ""
            position = key
            last_consumed = key
        if len(batch) < 1000:
            return keys, common, last_consumed, skip_prefix, False


def _virtual_host_bucket(request: Request) -> str | None:
    """Use Host only when a public DNS suffix was explicitly configured.

    SigV4 must authenticate the exact Host afterwards; never trust proxy
    forwarding headers for bucket selection. The default remains path-style.
    """
    suffix = os.environ.get("TELEDRIVE_S3_VHOST_SUFFIX", "").strip().lower().strip(".")
    if not suffix:
        return None
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(suffix) > 253 or re.fullmatch(label + r"(?:\." + label + r")+", suffix) is None:
        raise SigV4Error("InvalidArgument", "Invalid virtual-host DNS suffix")
    authority = request.headers.get("host", "").lower()
    if authority.count(":") == 1 and authority.rsplit(":", 1)[1].isdigit():
        hostname = authority.rsplit(":", 1)[0]
    else:
        hostname = authority
    ending = "." + suffix
    if not hostname.endswith(ending):
        return None
    bucket = hostname[:-len(ending)]
    try:
        BucketCatalog.validate_bucket(bucket)
    except ValueError as exc:
        raise SigV4Error("InvalidArgument", "Invalid virtual-host bucket") from exc
    return bucket
