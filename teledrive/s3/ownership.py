"""Bucket ownership controls (Phase L5).

Three real models change how object ACL grants participate in
authorization:

``BucketOwnerEnforced`` (default)
    Object ACL grants are ignored; the bucket owner and the bucket
    policy decide.  Bucket ACL grants still apply (they are a bucket
    level control, not an object grant).
``ObjectWriter``
    Object ACL grants apply, exactly like the Phase D intersection
    model.
``BucketOwnerPreferred``
    Same as ``ObjectWriter`` plus an automatic owner FULL_CONTROL grant
    when an object is uploaded with ``x-amz-acl:
    bucket-owner-full-control``.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_OWNERSHIP_XML_BYTES = 16 * 1024
MODELS = ("BucketOwnerEnforced", "ObjectWriter", "BucketOwnerPreferred")
DEFAULT_MODEL = "BucketOwnerEnforced"


class OwnershipError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def parse_ownership_xml(payload: bytes) -> str:
    """Strictly parse ``<OwnershipControls><Rule>...``."""
    if len(payload) > MAX_OWNERSHIP_XML_BYTES:
        raise OwnershipError("MalformedXML",
                             "Ownership controls XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise OwnershipError("MalformedXML",
                             "Invalid ownership controls XML") from exc

    def name(node):
        label = node.tag.rsplit("}", 1)[-1]
        if node.tag not in {label, f"{{{NAMESPACE}}}{label}"}:
            raise OwnershipError("MalformedXML",
                                 "Unexpected ownership XML namespace")
        return label

    if (name(root) != "OwnershipControls" or root.attrib
            or len(root) != 1):
        raise OwnershipError("MalformedXML",
                             "Unexpected ownership controls document")
    rule = root[0]
    if (name(rule) != "Rule" or rule.attrib or len(rule) != 1):
        raise OwnershipError("MalformedXML", "Ownership controls require one Rule")
    field = rule[0]
    if (name(field) != "ObjectOwnership" or field.attrib or len(field)):
        raise OwnershipError("MalformedXML",
                             "ObjectOwnership is required")
    value = (field.text or "").strip()
    if value not in MODELS:
        raise OwnershipError(
            "InvalidArgument", "Unknown ObjectOwnership model")
    return value


def ownership_xml(model: str) -> bytes:
    root = ET.Element("OwnershipControls", xmlns=NAMESPACE)
    rule = ET.SubElement(root, "Rule")
    ET.SubElement(rule, "ObjectOwnership").text = model
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
