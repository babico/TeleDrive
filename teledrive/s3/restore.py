"""S3 RestoreObject request validation (honest without an archive tier).

TeleDrive currently has exactly one immediately-readable storage class. AWS
returns ``403 InvalidObjectState`` when RestoreObject addresses an object that
is not archived, so that is the truthful response for every object here.
The request XML is still validated strictly first: a malformed body is a 400,
not a misleading storage-state error.

Future tiering seam: when a later phase marks an object ``ARCHIVE``, only
``teledrive/s3/restore.py::is_applicable`` and the handler's
``_perform_restore`` branch need to change. No other routing, permission or
XML code assumes the current single-tier behavior.
"""
from __future__ import annotations

from dataclasses import dataclass
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

MAX_RESTORE_XML_BYTES = 16 * 1024
_TIERS = frozenset({"Standard", "Bulk", "Expedited"})


class RestoreError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class RestoreRequest:
    days: int
    tier: str | None
    description: str | None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_restore_request(body: bytes) -> RestoreRequest:
    """Parse a standard (non-Select) AWS RestoreRequest strictly."""
    if not body or len(body) > MAX_RESTORE_XML_BYTES:
        raise RestoreError("MalformedXML", "Invalid RestoreRequest XML length")
    try:
        root = SafeET.fromstring(body)
    except (ParseError, DefusedXmlException) as exc:
        raise RestoreError("MalformedXML", "Unsafe or malformed RestoreRequest XML") from exc
    if _local(root.tag) != "RestoreRequest" or root.attrib:
        raise RestoreError("MalformedXML", "Expected RestoreRequest")
    days: int | None = None
    tier: str | None = None
    description: str | None = None
    seen: set[str] = set()
    for child in root:
        name = _local(child.tag)
        if name in seen:
            raise RestoreError("MalformedXML", f"Repeated RestoreRequest field {name}")
        seen.add(name)
        if name == "Days":
            raw = (child.text or "").strip()
            if not raw.isdigit() or not 1 <= int(raw) <= 36500:
                raise RestoreError(
                    "MalformedXML", "Days must be an integer between 1 and 36500")
            days = int(raw)
        elif name == "Description":
            if list(child) or len((child.text or "").encode("utf-8")) > 1024:
                raise RestoreError("MalformedXML", "Invalid RestoreRequest Description")
            description = (child.text or "").strip()
        elif name == "GlacierJobParameters":
            if list(child) or child.attrib:
                for option in child:
                    if _local(option.tag) != "Tier" or list(option) or option.attrib:
                        raise RestoreError(
                            "MalformedXML", "GlacierJobParameters only supports Tier")
                    tier = (option.text or "").strip()
                if tier not in _TIERS:
                    raise RestoreError(
                        "MalformedXML", "Tier must be Standard, Bulk or Expedited")
            else:
                raise RestoreError("MalformedXML", "GlacierJobParameters requires Tier")
        elif name == "Type":
            # RestoreRequest Type is only SELECT today. SQL restore is not
            # implemented and must not be acknowledged as a job.
            if (child.text or "").strip() != "SELECT":
                raise RestoreError("MalformedXML", "RestoreRequest Type must be SELECT")
            raise RestoreError(
                "NotImplemented", "Select-style RestoreObject is unsupported", 501)
        elif name == "SelectParameters" or name == "OutputLocation":
            raise RestoreError(
                "NotImplemented", "Select-style RestoreObject is unsupported", 501)
        else:
            raise RestoreError("MalformedXML", f"Unknown RestoreRequest field {name}")
    if days is None:
        raise RestoreError("MalformedXML", "RestoreRequest requires Days")
    return RestoreRequest(days=days, tier=tier, description=description)


def is_applicable(item) -> bool:
    """The single tiering seam: is this object in an archived class?

    There is no archive column/phase yet, so this is always False. A future
    phase may consult a real storage-class marker here; the handler already
    routes True to its separate ``_perform_restore`` branch.
    """
    return getattr(item, "storage_class", "STANDARD") == "ARCHIVE"
