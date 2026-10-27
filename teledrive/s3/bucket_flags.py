"""Single-state bucket controls: Requester Pays and Transfer Acceleration.

TeleDrive has no customer billing and no edge network, so exactly one state is
true for each of these configurations:

* ``RequestPaymentConfiguration`` -> ``Payer=BucketOwner``. There is no
  requester-pays billing channel, so ``Requester`` is rejected with 501
  instead of pretending someone will be charged. Nothing is stored: the
  accepted value IS the only state that exists, so a bucket row would only
  duplicate a constant. GET reports that state.
* ``AccelerateConfiguration`` -> ``TransferAcceleratedStatus=Suspended``.
  There is no AWS edge network in front of Telegram storage, so ``Enabled``
  is rejected with 501. GET reports ``Suspended``.

That makes the PUT operations honest "supported" operations: they correctly
manage the only state that exists and refuse the state that would require
absent infrastructure. They do not silently accept-and-ignore.

The GET path is the *same canonical renderer* the PUT accepts: for both
configurations, PUT-then-GET is byte-identical when the client uploads the
document returned by GET. There is no separate fail-closed canned response.

Both documents are strict, namespace-tolerant (bare or 2006-03-01) XML with a
16 KiB bound and unknown fields rejected as MalformedXML.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_BUCKET_FLAG_XML_BYTES = 16 * 1024


class BucketFlagError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def _local(node) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _valid_namespace(node) -> bool:
    name = _local(node)
    return node.tag in {name, f"{{{NS}}}{name}"}


def _single_child(root, expected_root: str, child: str) -> str:
    if (not _valid_namespace(root) or root.attrib
            or _local(root) != expected_root):
        raise BucketFlagError("MalformedXML", "Unexpected bucket control document")
    if len(root) != 1:
        raise BucketFlagError("MalformedXML", f"Exactly one {child} is required")
    node = root[0]
    if (not _valid_namespace(node) or node.attrib or len(node)
            or _local(node) != child):
        raise BucketFlagError("MalformedXML", f"Invalid {child} element")
    return (node.text or "").strip()


def _parse(payload: bytes, expected_root: str, child: str) -> str:
    if len(payload) > MAX_BUCKET_FLAG_XML_BYTES:
        raise BucketFlagError("MalformedXML", "Bucket control XML exceeds 16 KiB")
    try:
        root = SafeET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise BucketFlagError("MalformedXML", "Invalid bucket control XML") from exc
    return _single_child(root, expected_root, child)


def parse_request_payment_xml(payload: bytes) -> str:
    """Accept only ``BucketOwner``; ``Requester`` has no billing backing."""
    payer = _parse(payload, "RequestPaymentConfiguration", "Payer")
    if payer == "BucketOwner":
        return payer
    if payer == "Requester":
        raise BucketFlagError(
            "NotImplemented",
            "Requester Pays is not supported: TeleDrive has no requester "
            "billing channel and the bucket owner always pays",
            501,
        )
    raise BucketFlagError("InvalidArgument",
                          "Payer must be BucketOwner or Requester")


def parse_accelerate_xml(payload: bytes) -> str:
    """Accept only ``Suspended``; ``Enabled`` has no edge network backing."""
    status = _parse(payload, "AccelerateConfiguration", "Status")
    if status == "Suspended":
        return status
    if status == "Enabled":
        raise BucketFlagError(
            "NotImplemented",
            "Transfer Acceleration is not supported: there is no AWS edge "
            "network in front of Telegram-backed storage",
            501,
        )
    raise BucketFlagError("InvalidArgument",
                          "Status must be Enabled or Suspended")


def request_payment_xml() -> bytes:
    root = ET.Element("RequestPaymentConfiguration", xmlns=NS)
    ET.SubElement(root, "Payer").text = "BucketOwner"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def accelerate_xml() -> bytes:
    root = ET.Element("AccelerateConfiguration", xmlns=NS)
    ET.SubElement(root, "TransferAcceleratedStatus").text = "Suspended"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
