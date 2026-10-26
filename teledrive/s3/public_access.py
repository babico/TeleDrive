"""Public Access Block S3 controls backed by real bucket state.

TeleDrive denies anonymous/public object access and public ACLs
globally: grantee principals are always TeleDrive access keys, and the
AllUsers/AuthenticatedUsers groups plus email grantees are unwritable
(rejected 501 at ACL write time). Within that invariant, the four PAB
flags are persisted per bucket (default all-true, like AWS) and PUT
accepts any combination — the flags are a forward-looking guard: with
``BlockPublicAcls`` on, only the bucket ACL's owner may author ACL
grants; turning it off is a deliberate owner decision with no public
exposure behind it (there is no public path in this gateway).
"""
from __future__ import annotations

from xml.etree import ElementTree as ET
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

MAX_PUBLIC_ACCESS_XML_BYTES = 16 * 1024
NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
FIELDS = (
    "BlockPublicAcls", "IgnorePublicAcls",
    "BlockPublicPolicy", "RestrictPublicBuckets",
)


class PublicAccessError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def parse_public_access_xml(payload: bytes) -> dict:
    """Parse a PublicAccessBlockConfiguration into {field: bool}.

    Both true and false are accepted for every field — the persisted
    flags carry the owner's deliberate configuration.
    """
    if len(payload) > MAX_PUBLIC_ACCESS_XML_BYTES:
        raise PublicAccessError("MalformedXML", "Public access XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise PublicAccessError("MalformedXML", "Invalid public access XML") from exc
    if (root.tag not in {"PublicAccessBlockConfiguration",
                        f"{{{NAMESPACE}}}PublicAccessBlockConfiguration"}
            or root.attrib or len(root) != 4):
        raise PublicAccessError("MalformedXML", "Unexpected public access document")
    seen: dict[str, bool] = {}
    for element in root:
        field = element.tag.rsplit("}", 1)[-1]
        if (field not in FIELDS or field in seen
                or element.tag not in {field, f"{{{NAMESPACE}}}{field}"}
                or element.attrib or len(element)):
            raise PublicAccessError("MalformedXML", "Unknown or duplicate public access field")
        if element.text == "true":
            seen[field] = True
        elif element.text == "false":
            seen[field] = False
        else:
            raise PublicAccessError("InvalidArgument", "Public access fields must be true or false")
    if set(seen) != set(FIELDS):
        raise PublicAccessError("MalformedXML", "Incomplete public access document")
    return seen


def public_access_xml(flags: dict | None = None) -> bytes:
    """Render the persisted flags as a PublicAccessBlockConfiguration.

    ``flags=None`` renders the all-true default (AWS default).
    """
    root = ET.Element("PublicAccessBlockConfiguration", xmlns=NAMESPACE)
    for field in FIELDS:
        ET.SubElement(root, field).text = (
            "true" if (flags or {}).get(field, True) else "false")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
