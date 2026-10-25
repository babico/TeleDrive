"""S3 ACL grants mapped onto TeleDrive credentials (Phase D).

The grant model: an ACL grantee ``CanonicalUser`` ID is a TeleDrive S3
access key. Email/Group grantees and the AllUsers/AuthenticatedUsers
groups stay unsupported — that is the private-only line.

Enforcement is a fail-closed INTERSECTION: a credential's effective
permission set is ``own scopes ∩ (bucket grants ∪ object grants ∪
owner grants)``. ACLs can only NARROW or delegate within existing
scope; a grant never grants an operation the credential's own scopes
do not already carry (the SigV4 scope check happens first, on every
request). Buckets and keys without a stored ACL keep the unrestricted
baseline — writing an ACL opts the resource into restriction.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_ACL_XML = 16384
BUCKET_ACL_PERMISSIONS = ("READ", "WRITE", "FULL_CONTROL")
OBJECT_ACL_PERMISSIONS = ("READ", "FULL_CONTROL")
_GRANTEE_TYPES = ("CanonicalUser", "AmazonCustomerByEmail", "Group")


class AclError(ValueError):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status


def action_class(action: str) -> str | None:
    """Coarse ACL permission class of an S3 action.

    READ covers the read verbs (s3:Get*/s3:List*); everything else —
    writes, deletes, bucket creation — is WRITE. Unknown actions fall
    into WRITE so an unmapped verb can never slip past a restrictive
    ACL (fail-closed). s3:ListAllMyBuckets addresses no resource and
    is never ACL-gated.
    """
    if action == "s3:ListAllMyBuckets":
        return None
    if action.startswith(("s3:Get", "s3:List")):
        return "READ"
    return "WRITE"


def permits(*, action: str, access_key: str, bucket_rows: list,
            object_rows: list, key: str | None) -> bool:
    """The intersection gate over already-fetched grant rows.

    ``bucket_rows`` is every stored bucket-grant row (any grantee) for
    the bucket; ``object_rows`` every row for the exact object key.
    Restriction applies when either ACL exists; object rows only ever
    affect their own key, never siblings or bucket-level actions.
    """
    scope = action_class(action)
    if scope is None:
        return True
    restricted = bool(bucket_rows) or (key is not None and bool(object_rows))
    if not restricted:
        return True
    mine = {perm for grantee, perm in bucket_rows if grantee == access_key}
    if key is not None:
        mine |= {perm for grantee, perm in object_rows
                 if grantee == access_key}
    return "FULL_CONTROL" in mine or scope in mine


def parse_acl_xml(payload: bytes, *, object_level: bool,
                  now: int | None = None) -> tuple[str | None, list[tuple[str, str]]]:
    """Parse an AccessControlPolicy document.

    Returns (owner access key or None when the document omits Owner,
    grant list of (grantee access key, permission)). Rejects email and
    group grantees (NotImplemented — no backing), malformed documents
    and bucket-only permissions on object ACLs.
    """
    if len(payload) > MAX_ACL_XML:
        raise AclError("MalformedXML", "ACL XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise AclError("MalformedXML", "Invalid ACL XML") from exc
    if root.tag not in {"AccessControlPolicy",
                        f"{{{NAMESPACE}}}AccessControlPolicy"} or root.attrib:
        raise AclError("MalformedXML", "Unexpected ACL document")
    allowed = OBJECT_ACL_PERMISSIONS if object_level else BUCKET_ACL_PERMISSIONS
    owner: str | None = None
    grants: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for element in root:
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "Owner" and owner is None and not element.attrib:
            for sub in element:
                if sub.tag.rsplit("}", 1)[-1] == "ID" and not sub.attrib:
                    owner = (sub.text or "").strip()
                # DisplayName is accepted and ignored (cosmetic).
            if owner is None:
                raise AclError("MalformedXML", "ACL Owner requires an ID")
        elif tag == "AccessControlList" and not element.attrib:
            for grant in element:
                if grant.tag.rsplit("}", 1)[-1] != "Grant" or grant.attrib:
                    raise AclError("MalformedXML", "Unexpected ACL entry")
                grantee_key: str | None = None
                permission: str | None = None
                for sub in grant:
                    subtag = sub.tag.rsplit("}", 1)[-1]
                    if subtag == "Grantee":
                        grantee_type = sub.attrib.get(
                            "{http://www.w3.org/2001/XMLSchema-instance}type",
                            sub.attrib.get("type", ""))
                        if grantee_type not in _GRANTEE_TYPES:
                            raise AclError("MalformedXML",
                                           "Unknown ACL grantee type")
                        if grantee_type != "CanonicalUser":
                            # The private-only line: email and group
                            # grantees have no backing here, ever.
                            raise AclError(
                                "NotImplemented",
                                "Only CanonicalUser grantees (TeleDrive "
                                "access keys) are supported; email and "
                                "group grantees are not", 501)
                        for leaf in sub:
                            if leaf.tag.rsplit("}", 1)[-1] == "ID":
                                grantee_key = (leaf.text or "").strip()
                    elif subtag == "Permission" and permission is None:
                        permission = (sub.text or "").strip()
                    else:
                        raise AclError("MalformedXML", "Unexpected grant field")
                if grantee_key is None or permission is None:
                    raise AclError("MalformedXML", "Grant requires a grantee ID "
                                               "and a permission")
                if permission not in allowed:
                    raise AclError(
                        "InvalidArgument",
                        f"Permission {permission} is not valid for "
                        f"{'object' if object_level else 'bucket'} ACLs")
                if len(grantee_key) > 64:
                    raise AclError("InvalidArgument", "Grantee ID too long")
                pair = (grantee_key, permission)
                if pair not in seen:
                    seen.add(pair)
                    grants.append(pair)
        else:
            raise AclError("MalformedXML", "Unexpected ACL field")
    return owner, grants


def render_acl_xml(owner: str, grants: list[tuple[str, str]]) -> bytes:
    """AWS-shaped AccessControlPolicy for a stored ACL."""
    root = ET.Element("AccessControlPolicy", xmlns=NAMESPACE)
    owner_node = ET.SubElement(root, "Owner")
    ET.SubElement(owner_node, "ID").text = owner
    ET.SubElement(owner_node, "DisplayName").text = "teledrive"
    acl_node = ET.SubElement(root, "AccessControlList")
    for grantee, permission in grants:
        grant = ET.SubElement(acl_node, "Grant")
        grantee_node = ET.SubElement(grant, "Grantee", {
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:type": "CanonicalUser",
        })
        ET.SubElement(grantee_node, "ID").text = grantee
        ET.SubElement(grantee_node, "DisplayName").text = "teledrive"
        ET.SubElement(grant, "Permission").text = permission
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
