"""S3 RestoreObject validation and the archive-tier restore window.

Intelligent-Tiering (``teledrive/s3/tiering.py``) marks an object
``ARCHIVE_ACCESS``/``DEEP_ARCHIVE_ACCESS``. That label is a catalog access
gate: GetObject/HeadObject answer ``403 InvalidObjectState`` until a
restore window is open.

Since handoff 08 there are two honest paths, chosen by whether a
physically verified cold archive exists for the version
(``teledrive.storage.cold_store``):

* **Archived copy verified** (``storage_archive_versions`` row in state
  ``ARCHIVED``): RestoreObject queues a REAL retrieval. A worker copies
  the cold bytes into a bounded staging cache, verifies the whole-object
  SHA-256, and only then opens ``storage_objects.restore_until_ns`` in
  the same transaction. While the work is pending, HEAD/GET answer
  ``403 InvalidObjectState`` with ``x-amz-restore:
  ongoing-request="true"``; after verification, reads are served from
  the staged copy and report ``ongoing-request="false"`` with the
  expiry date. Expiry clears the staged copy, never the archive data.
* **No archive row** (label only, or the worker has not run yet): the
  hot Telegram copy is authoritative, so the restore is today's window
  gate - 202 on acceptance, reads re-open immediately.

* Standard-class object -> RestoreObject is ``403 InvalidObjectState``
  on both paths (AWS semantics: already immediately readable).
* A second restore while work is pending or a window is open is ``409
  RestoreAlreadyInProgress``.
* Expedited/Standard/Bulk tiers are recorded but do NOT change
  scheduling (restores run first-in-first-out). No AWS retrieval-speed
  or pricing SLA is implied.
"""
from __future__ import annotations

from dataclasses import dataclass
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

MAX_RESTORE_XML_BYTES = 16 * 1024
MAX_RESTORE_DAYS = 36500
_ARCHIVED_CLASSES = frozenset({"ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS"})
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
            if not raw.isdigit() or not 1 <= int(raw) <= MAX_RESTORE_DAYS:
                raise RestoreError(
                    "MalformedXML",
                    f"Days must be an integer between 1 and {MAX_RESTORE_DAYS}")
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
    """The single tiering seam: is this object in an archived class?"""
    return getattr(item, "storage_class", "STANDARD") in _ARCHIVED_CLASSES


def is_restored(item, *, now_ns: int) -> bool:
    """True while a restore window is still open for an archived object."""
    if not is_applicable(item):
        return False
    until = getattr(item, "restore_until_ns", None)
    return until is not None and int(until) > int(now_ns)


def restore_header(item, *, now_ns: int) -> str | None:
    """AWS-shaped ``x-amz-restore`` value while restored, else None."""
    if not is_restored(item, now_ns=now_ns):
        return None
    from email.utils import formatdate
    expiry = formatdate(
        int(int(item.restore_until_ns) / 1_000_000_000), usegmt=True)
    return f'ongoing-request="false", expiry-date="{expiry}"'


def ongoing_restore_header() -> str:
    """The ``x-amz-restore`` value while a real retrieval is in flight.

    AWS reports ``ongoing-request="true"`` on the 403 InvalidObjectState
    answers for an archived object whose restore has been accepted but
    has not completed verification yet.
    """
    return 'ongoing-request="true"'
