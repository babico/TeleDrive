"""S3 XML response builders and AWS read-compatibility responses.

Move-only extraction from ``web/s3.py`` (handoff 01, step 1).  The XML
byte shapes are load-bearing for ``tests/s3``; do not reformat.
"""
from __future__ import annotations

import time
from urllib.parse import quote
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from fastapi.responses import Response

from teledrive.s3.bucket_flags import accelerate_xml, request_payment_xml
from teledrive.s3.tagging import TaggingError, validate_tags

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"


def _xml(tag: str, pairs: list[tuple[str, str]] | None = None) -> bytes:
    root = ET.Element(tag, xmlns=NAMESPACE)
    for name, value in pairs or []:
        ET.SubElement(root, name).text = str(value)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _error(code: str, message: str, status: int) -> Response:
    # S3 error XML is *not* in the successful-response namespace.
    # Boto3/other AWS SDK error parsers otherwise yield Error.Code == "".
    root = ET.Element("Error")
    ET.SubElement(root, "Code").text = code
    ET.SubElement(root, "Message").text = message
    return Response(ET.tostring(root, encoding="utf-8", xml_declaration=True),
                    media_type="application/xml", status_code=status)


def _xml_ok(root) -> Response:
    return Response(ET.tostring(root, encoding="utf-8", xml_declaration=True),
                    media_type="application/xml")


def _list_xml(bucket: str, keys: list, common: list[str], prefix: str,
              limit: int, after: str, delimiter: str,
              more: bool, next_token: str | None, etag_for=None, *,
              version_one: bool = False, next_marker: str | None = None,
              encoding_type: str | None = None,
              include_owner: bool = False, owner: str = "") -> bytes:
    root = ET.Element("ListBucketResult", xmlns=NAMESPACE)
    # S3 EncodingType=url percent-encodes UTF-8 keys *inside XML* so names
    # containing XML control characters remain safely representable.
    encoded = lambda value: quote(value, safe="") if encoding_type == "url" else value
    fields = [("Name", bucket), ("Prefix", encoded(prefix)),
              ("MaxKeys", limit), ("IsTruncated", "true" if more else "false")]
    if not version_one:
        fields.append(("KeyCount", len(keys) + len(common)))
    for field, val in fields:
        ET.SubElement(root, field).text = str(val)
    if delimiter:
        ET.SubElement(root, "Delimiter").text = encoded(delimiter)
    if encoding_type:
        ET.SubElement(root, "EncodingType").text = encoding_type
    if version_one:
        ET.SubElement(root, "Marker").text = encoded(after)
    elif after:
        ET.SubElement(root, "StartAfter").text = encoded(after)
    for item in keys:
        c = ET.SubElement(root, "Contents")
        for field, value in (
            ("Key", encoded(item.item.key)),
            ("LastModified", time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(item.item.created_at))),
            ("ETag", '"' + (etag_for(item.item) if etag_for else item.item.sha256) + '"'),
            ("Size", item.item.size),
            ("StorageClass", "STANDARD"),
        ):
            ET.SubElement(c, field).text = str(value)
        # V1 always carries Owner; V2 only when fetch-owner=true.
        if include_owner:
            owner_node = ET.SubElement(c, "Owner")
            ET.SubElement(owner_node, "ID").text = owner
            ET.SubElement(owner_node, "DisplayName").text = "teledrive"
    for name in common:
        ET.SubElement(ET.SubElement(root, "CommonPrefixes"), "Prefix").text = encoded(name)
    if next_token:
        ET.SubElement(root, "NextContinuationToken").text = next_token
    if version_one and next_marker:
        ET.SubElement(root, "NextMarker").text = encoded(next_marker)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _tag_xml(tags: list[tuple[str, str]]) -> bytes:
    root = ET.Element("Tagging", xmlns=NAMESPACE)
    tagset = ET.SubElement(root, "TagSet")
    for key, value in tags:
        tag = ET.SubElement(tagset, "Tag")
        ET.SubElement(tag, "Key").text = key
        ET.SubElement(tag, "Value").text = value
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _parse_tag_xml(body: bytes, *, bucket: bool = False) -> list[tuple[str, str]]:
    if len(body) > (256 * 1024 if bucket else 16 * 1024):
        raise TaggingError("MalformedXML", "Tagging XML exceeds maximum size")
    try:
        root = SafeET.fromstring(body)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise TaggingError("MalformedXML", "Tagging XML is malformed") from exc
    def tag_name(node):
        # Both bare AWS S3 XML and canonical 2006-03-01 namespace are
        # accepted; arbitrary XML namespaces must not bypass validation.
        name = node.tag.rsplit("}", 1)[-1]
        if node.tag not in {name, f"{{{NAMESPACE}}}{name}"}:
            raise TaggingError("MalformedXML", "Unexpected tagging XML namespace")
        return name
    if (tag_name(root) != "Tagging" or root.attrib
            or len(root) != 1 or tag_name(root[0]) != "TagSet"
            or root[0].attrib):
        raise TaggingError("MalformedXML", "Unexpected tagging XML structure")
    entries = []
    for tag in root[0]:
        if tag_name(tag) != "Tag" or tag.attrib or len(tag) != 2:
            raise TaggingError("MalformedXML", "Invalid Tag element")
        children = {tag_name(child): child for child in tag}
        if (set(children) != {"Key", "Value"} or
                any(child.attrib or len(child) for child in tag)):
            raise TaggingError("MalformedXML", "Invalid Tag key/value fields")
        entries.append((children["Key"].text or "", children["Value"].text or ""))
    return validate_tags(entries, max_tags=50 if bucket else 10)


def _canned_private_acl_xml(owner: str) -> bytes:
    """Private canned ACL: the caller holds FULL_CONTROL, nobody else."""
    root = ET.Element("AccessControlPolicy", xmlns=NAMESPACE)
    owner_node = ET.SubElement(root, "Owner")
    ET.SubElement(owner_node, "ID").text = owner
    ET.SubElement(owner_node, "DisplayName").text = "teledrive"
    acl_node = ET.SubElement(root, "AccessControlList")
    grant = ET.SubElement(acl_node, "Grant")
    grantee = ET.SubElement(grant, "Grantee", {
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:type": "CanonicalUser",
    })
    ET.SubElement(grantee, "ID").text = owner
    ET.SubElement(grantee, "DisplayName").text = "teledrive"
    ET.SubElement(grant, "Permission").text = "FULL_CONTROL"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _compat_bucket_read_response(selector: str, owner: str) -> Response:
    """AWS-shaped read response for an optional, unconfigured bucket feature."""
    if selector == "acl":
        return Response(_canned_private_acl_xml(owner), media_type="application/xml")
    if selector == "ownershipControls":
        root = ET.Element("OwnershipControls", xmlns=NAMESPACE)
        rule = ET.SubElement(root, "Rule")
        ET.SubElement(rule, "ObjectOwnership").text = "BucketOwnerEnforced"
        return _xml_ok(root)
    if selector == "requestPayment":
        # Writable-but-single-state (Phase O6): PUT accepts only
        # Payer=BucketOwner and rejects Requester with 501. This GET
        # therefore reports the one real state, not a fail-closed default.
        return Response(request_payment_xml(), media_type="application/xml")
    if selector == "accelerate":
        # Writable-but-single-state (Phase O6): PUT accepts only
        # Suspended and rejects Enabled with 501 (no edge network).
        return Response(accelerate_xml(), media_type="application/xml")
    if selector in ("notification", "notificationConfiguration"):
        return _xml_ok(ET.Element("NotificationConfiguration", xmlns=NAMESPACE))
    if selector == "logging":
        return _xml_ok(ET.Element("BucketLoggingStatus", xmlns=NAMESPACE))
    if selector == "policy":
        return _error("NoSuchBucketPolicy", "The bucket policy does not exist", 404)
    if selector == "website":
        return _error("NoSuchWebsiteConfiguration",
                      "The specified bucket does not have a website "
                      "configuration", 404)
    if selector == "encryption":
        return _error("ServerSideEncryptionConfigurationNotFoundError",
                      "The server side encryption configuration was not "
                      "found", 404)
    if selector == "object-lock":
        return _error("ObjectLockConfigurationNotFoundError",
                      "Object Lock configuration does not exist for this "
                      "bucket", 404)
    raise AssertionError(f"unknown compat selector: {selector}")


def _compat_object_read_response(selector: str, owner: str) -> Response:
    """AWS-shaped read response for optional object features."""
    if selector == "acl":
        return Response(_canned_private_acl_xml(owner), media_type="application/xml")
    # Object Lock (retention/legal-hold) is never configured in TeleDrive.
    return _error("NoSuchObjectLockConfiguration",
                  "The specified object does not have a ObjectLock "
                  "configuration", 404)
