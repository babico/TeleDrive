"""S3 lifecycle rule engine: aborts, expirations and transitions.

Never deletes Telegram messages, object manifests, or any completed
version's media. Lifecycle expiry is LOGICAL while physical GC is off:
expired current objects become delete markers, expired noncurrent
versions are revoked from version history, and only when the owner's
physical-GC gate is open are their media enqueued for grace-fenced
collection.

Handoff 08, phase D extends the rule grammar beyond the original
AbortIncompleteMultipartUpload/Expiration subset:

* ``Transition`` - move due CURRENT versions to ARCHIVE_ACCESS or
  DEEP_ARCHIVE_ACCESS. The label queues a real, independently verified
  cold copy (``teledrive.storage.cold_store``); Telegram bytes never
  move. GLACIER and every other AWS class are rejected 501 because no
  such medium exists here.
* ``NoncurrentVersionTransitions`` - the same transition for NONCURRENT
  versions after ``NoncurrentDays``, optionally retaining the newest
  ``NewerNoncurrentVersions`` per key.
* ``NoncurrentVersionExpiration`` - revoke due noncurrent versions from
  version history (retaining media; GC-gated collection as above).
* ``ExpiredObjectDeleteMarker`` - remove a delete marker that is the
  only remaining version of its key.
* ``Filter`` - prefix, tag and object-size predicates (the two exclusive
  bounds are byte counts in AWS's 0..5 TiB range), combined with ``And``.

Object Lock rules are preserved: retained or legal-held versions are
never expired, and alias sources (media another version still points at)
are fenced off from noncurrent expiration. Bucket/version races stay
atomic: every action re-verifies the head/generation immediately before
acting, inside the same SQL transaction as the mutation.
"""
from __future__ import annotations
import json
import logging
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from sqlalchemy import Column, ForeignKey, String, Table, Text, exists, not_, or_, select, insert, update, delete
from sqlalchemy.exc import IntegrityError
from teledrive.storage.catalog import BucketCatalog, catalog_metadata, heads as heads_table
from teledrive.storage.manifest import objects

_logger = logging.getLogger(__name__)

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_XML = 32768
rules_table = Table("storage_bucket_lifecycle", catalog_metadata,
    Column("bucket", String(63), ForeignKey("storage_buckets.name"), primary_key=True),
    Column("rules_json", Text, nullable=False))

# The archive classes this deployment can really honour (the same set as
# Intelligent-Tiering). Every other AWS storage class is an honest 501.
_TRANSITION_CLASSES = ("ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS")
_MAX_NEWER_NONCURRENT = 1000
# S3 caps a lifecycle filter at 10 Tags; the same bound keeps a stored
# rule's tag conjunction small and reviewable.
_MAX_FILTER_TAGS = 10
_MAX_TAG_KEY_BYTES = 128
_MAX_TAG_VALUE_BYTES = 256
# ObjectSizeGreaterThan/ObjectSizeLessThan are byte counts in AWS's
# 0..5 TiB range; the filters themselves are exclusive bounds.
_MAX_OBJECT_SIZE = 5 * 1024 ** 4
# A Date-based rule fires when now >= date; bounds keep the stored epoch
# seconds honest (no pre-1970 or far-future garbage).
_MAX_DATE_EPOCH = 4102444800  # 2100-01-01T00:00:00Z

# Rule-level children. Transition and NoncurrentVersionTransitions may
# REPEAT inside one rule (ascending-day ladders), everything else is
# single.
_RULE_CHILDREN = {
    "ID", "Status", "Filter", "AbortIncompleteMultipartUpload",
    "Expiration", "Transition", "NoncurrentVersionExpiration",
    "NoncurrentVersionTransitions",
}


class LifecycleError(ValueError):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status


def fields(node, names):
    result = {}
    for el in node:
        k = el.tag.rsplit("}", 1)[-1]
        if (el.tag not in {k, f"{{{NS}}}{k}"} or el.attrib
                or k not in names or k in result):
            raise LifecycleError("NotImplemented", "Unsupported lifecycle rule", 501)
        result[k] = el
    return result


def children(node, names):
    """Group child elements by local name; repeatable names give lists.

    Unknown elements, foreign namespaces and attributes fail closed with
    501 exactly like :func:`fields`.
    """
    grouped: dict[str, list] = {label: [] for label in names}
    for el in node:
        k = el.tag.rsplit("}", 1)[-1]
        if (el.tag not in {k, f"{{{NS}}}{k}"} or el.attrib
                or k not in names):
            raise LifecycleError("NotImplemented", "Unsupported lifecycle rule", 501)
        grouped[k].append(el)
    return grouped


def scalar(el):
    if el is None or len(el):
        raise LifecycleError("MalformedXML", "Invalid lifecycle element")
    return el.text or ""


def _age(value: str, label: str) -> int:
    """A whole-day age, 1..3650, in the AWS spelling used here."""
    if (not value.isascii() or not value.isdigit() or value.startswith("0")
            or len(value) > 4):
        raise LifecycleError("InvalidArgument", f"Invalid {label} age")
    days = int(value)
    if not 1 <= days <= 3650:
        raise LifecycleError("InvalidArgument", f"{label} age outside 1..3650 days")
    return days


def _newer(value: str) -> int:
    if (not value.isascii() or not value.isdigit()
            or len(value) > len(str(_MAX_NEWER_NONCURRENT))):
        raise LifecycleError("InvalidArgument", "Invalid NewerNoncurrentVersions")
    count = int(value)
    if not 0 <= count <= _MAX_NEWER_NONCURRENT:
        raise LifecycleError("InvalidArgument",
                             "NewerNoncurrentVersions outside 0..1000")
    return count


def _storage_class(value: str) -> str:
    if value not in _TRANSITION_CLASSES:
        raise LifecycleError(
            "NotImplemented",
            f"StorageClass {value!r} cannot be honoured; only ARCHIVE_ACCESS "
            "and DEEP_ARCHIVE_ACCESS are implemented", 501)
    return value


def _date(value: str, label: str) -> int:
    """An ISO-8601 expiration date, as epoch seconds (UTC).

    Accepts a bare calendar date (midnight UTC, the AWS spelling) or a
    full timestamp with ``Z``/offset. The rule fires when
    ``now >= date``; anything unparsable is InvalidArgument, never a
    silent default.
    """
    text = value.strip()
    if not text or len(text) > 35 or not text.isascii():
        raise LifecycleError("InvalidArgument", f"Invalid {label} date")
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LifecycleError("InvalidArgument", f"Invalid {label} date") from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    epoch = int(moment.timestamp())
    if not 0 < epoch < _MAX_DATE_EPOCH:
        raise LifecycleError("InvalidArgument", f"{label} date out of range")
    return epoch


def _parse_tag(node) -> dict:
    """One ``<Tag>`` block: exactly Key (1..128 bytes) and Value
    (0..256 bytes)."""
    tag = fields(node, {"Key", "Value"})
    if set(tag) != {"Key", "Value"}:
        raise LifecycleError("InvalidArgument", "Tag needs Key and Value")
    key, value = scalar(tag["Key"]), scalar(tag["Value"])
    if not 1 <= len(key.encode("utf-8")) <= _MAX_TAG_KEY_BYTES:
        raise LifecycleError("InvalidArgument", "Invalid tag key length")
    if len(value.encode("utf-8")) > _MAX_TAG_VALUE_BYTES:
        raise LifecycleError("InvalidArgument", "Invalid tag value length")
    return {"key": key, "value": value}


def _size(value: str, label: str) -> int:
    """An object-size bound in bytes: 0..5 TiB inclusive."""
    if (not value.isascii() or not value.isdigit()
            or len(value) > len(str(_MAX_OBJECT_SIZE))):
        raise LifecycleError("InvalidArgument", f"Invalid {label}")
    size = int(value)
    if not 0 <= size <= _MAX_OBJECT_SIZE:
        raise LifecycleError("InvalidArgument", f"{label} outside 0..5 TiB")
    return size


def _parse_sizes(group) -> tuple[int | None, int | None]:
    """The optional size bounds of one Filter or And block.

    A repeated element is a duplicate structural node (501), and the
    pair must be an honest interval: ``GreaterThan < LessThan``.
    """
    bounds = {}
    for label in ("ObjectSizeGreaterThan", "ObjectSizeLessThan"):
        nodes = group[label]
        if len(nodes) > 1:
            raise LifecycleError("NotImplemented", f"Duplicate {label}", 501)
        bounds[label] = _size(scalar(nodes[0]), label) if nodes else None
    greater = bounds["ObjectSizeGreaterThan"]
    less = bounds["ObjectSizeLessThan"]
    if greater is not None and less is not None and greater >= less:
        raise LifecycleError(
            "InvalidArgument",
            "ObjectSizeGreaterThan must be less than ObjectSizeLessThan")
    return greater, less


def _check_tag_conjunction(tags) -> None:
    """Parser-side bounds for a filter's tag conjunction: at most 10
    tags and no repeated key (a repeated key is an ambiguous
    conjunction, not a schedule)."""
    if len(tags) > _MAX_FILTER_TAGS:
        raise LifecycleError(
            "InvalidArgument", f"And filter exceeds {_MAX_FILTER_TAGS} tags")
    if len({tag["key"] for tag in tags}) != len(tags):
        raise LifecycleError("InvalidArgument", "Duplicate tag key")


def _parse_filter(node) -> tuple[str, list[dict], int | None, int | None]:
    """A ``<Filter>`` block: one of Prefix, a single Tag, one object-size
    bound, or an And conjunction of an optional Prefix, 1..10 Tags and
    the two object-size bounds.

    AWS accepts one condition directly under Filter; two conditions
    (including both size bounds, or a Tag next to a Prefix) require an
    ``And``. Unknown filter contents (foreign namespaces, unknown
    elements) fail closed with 501 exactly like the rest of the rule
    grammar; known-but-invalid combinations are InvalidArgument.
    """
    names = {"Prefix", "Tag", "And", "ObjectSizeGreaterThan",
             "ObjectSizeLessThan"}
    group = children(node, names)
    kinds = [name for name, nodes in group.items() if nodes]
    if len(kinds) != 1:
        raise LifecycleError(
            "InvalidArgument",
            "Filter accepts one of Prefix, Tag, And, ObjectSizeGreaterThan "
            "or ObjectSizeLessThan")
    if group["Prefix"]:
        if group["Prefix"][0].attrib or len(group["Prefix"]) > 1:
            raise LifecycleError("NotImplemented", "Unsupported lifecycle rule", 501)
        return scalar(group["Prefix"][0]), [], None, None
    if group["Tag"]:
        if len(group["Tag"]) > 1:
            raise LifecycleError(
                "InvalidArgument",
                "Multiple Tags require the And filter")
        return "", [_parse_tag(group["Tag"][0])], None, None
    if group["ObjectSizeGreaterThan"] or group["ObjectSizeLessThan"]:
        # A single size bound may sit directly under Filter; the two
        # bounds together require And (checked above by ``kinds``).
        greater, less = _parse_sizes(group)
        return "", [], greater, less
    inner = children(group["And"][0], names - {"And"})
    prefix = ""
    if len(inner["Prefix"]) > 1:
        raise LifecycleError("NotImplemented", "Duplicate filter prefix", 501)
    if inner["Prefix"]:
        prefix = scalar(inner["Prefix"][0])
    tags = [_parse_tag(tag) for tag in inner["Tag"]]
    greater, less = _parse_sizes(inner)
    if not tags and greater is None and less is None:
        raise LifecycleError(
            "InvalidArgument",
            "And filter needs at least one Tag or object-size condition")
    _check_tag_conjunction(tags)
    return prefix, tags, greater, less


def _validate_tag_set(tags) -> list[dict]:
    """Shared validation for the stored tag conjunction: 0..10 unique
    keys, each a {key, value} dict with bounded byte lengths."""
    if not isinstance(tags, list) or len(tags) > _MAX_FILTER_TAGS:
        raise ValueError()
    seen, result = set(), []
    for tag in tags:
        if (not isinstance(tag, dict)
                or set(tag) != {"key", "value"}
                or not isinstance(tag["key"], str)
                or not isinstance(tag["value"], str)
                or not 1 <= len(tag["key"].encode("utf-8")) <= _MAX_TAG_KEY_BYTES
                or len(tag["value"].encode("utf-8")) > _MAX_TAG_VALUE_BYTES
                or tag["key"] in seen):
            raise ValueError()
        seen.add(tag["key"])
        result.append({"key": tag["key"], "value": tag["value"]})
    return result


def parse_lifecycle_xml(body: bytes):
    if len(body) > MAX_XML:
        raise LifecycleError("MalformedXML", "Lifecycle XML exceeds 32 KiB")
    try:
        root = SafeET.fromstring(body)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise LifecycleError("MalformedXML", "Malformed lifecycle XML") from exc
    if (root.tag not in {"LifecycleConfiguration", f"{{{NS}}}LifecycleConfiguration"}
            or root.attrib or not 1 <= len(root) <= 50):
        raise LifecycleError("MalformedXML", "Requires 1..50 lifecycle rules")
    result, ids = [], set()
    for el in root:
        if el.tag not in {"Rule", f"{{{NS}}}Rule"} or el.attrib:
            raise LifecycleError("NotImplemented", "Unsupported lifecycle node", 501)
        group = children(el, _RULE_CHILDREN)
        if not any(group[name] for name in (
                "AbortIncompleteMultipartUpload", "Expiration", "Transition",
                "NoncurrentVersionExpiration", "NoncurrentVersionTransitions")):
            raise LifecycleError(
                "InvalidArgument",
                "Rule needs at least one action: AbortIncompleteMultipartUpload, "
                "Expiration, Transition, NoncurrentVersionExpiration or "
                "NoncurrentVersionTransitions")
        status = scalar(group["Status"][0]) if group["Status"] else None
        if status is None:
            raise LifecycleError("InvalidArgument", "Missing rule status")
        if status not in {"Enabled", "Disabled"}:
            raise LifecycleError("InvalidArgument", "Invalid rule status")
        ident = (scalar(group["ID"][0]) if group["ID"]
                 else str(len(result) + 1))
        if len(group["ID"]) > 1:
            raise LifecycleError("NotImplemented", "Duplicate rule ID element", 501)
        if not 1 <= len(ident.encode("utf-8")) <= 255 or ident in ids:
            raise LifecycleError("InvalidArgument", "Invalid or duplicate rule ID")
        ids.add(ident)
        prefix, tags = "", []
        greater = less = None
        if group["Filter"]:
            if len(group["Filter"]) > 1:
                raise LifecycleError("NotImplemented", "Duplicate Filter", 501)
            prefix, tags, greater, less = _parse_filter(group["Filter"][0])
        if len(prefix.encode("utf-8")) > 1024:
            raise LifecycleError("InvalidArgument", "Lifecycle prefix too long")
        rule = {
            "id": ident, "status": status, "prefix": prefix, "tags": tags,
            "abort_days": None, "expiration": None, "transitions": [],
            "noncurrent_transitions": [], "noncurrent_expiration": None,
        }
        # Only present bounds are stored, so a rule without a size filter
        # keeps the exact canonical shape written by earlier releases.
        if greater is not None:
            rule["size_greater_than"] = greater
        if less is not None:
            rule["size_less_than"] = less
        if group["AbortIncompleteMultipartUpload"]:
            if len(group["AbortIncompleteMultipartUpload"]) > 1:
                raise LifecycleError("NotImplemented", "Duplicate abort action", 501)
            abort = fields(group["AbortIncompleteMultipartUpload"][0],
                           {"DaysAfterInitiation"})
            if set(abort) != {"DaysAfterInitiation"}:
                raise LifecycleError("InvalidArgument", "Missing abort age")
            rule["abort_days"] = _age(
                scalar(abort["DaysAfterInitiation"]),
                "DaysAfterInitiation")
        if group["Expiration"]:
            if len(group["Expiration"]) > 1:
                raise LifecycleError("NotImplemented", "Duplicate expiration", 501)
            expiration = fields(group["Expiration"][0],
                                {"Days", "Date", "ExpiredObjectDeleteMarker"})
            if ("Days" in expiration) == ("Date" in expiration):
                raise LifecycleError(
                    "InvalidArgument",
                    "Expiration needs exactly one of Days or Date")
            marker = False
            if "ExpiredObjectDeleteMarker" in expiration:
                marker_text = scalar(expiration["ExpiredObjectDeleteMarker"])
                if marker_text not in {"true", "false"}:
                    raise LifecycleError("InvalidArgument",
                                         "ExpiredObjectDeleteMarker must be boolean")
                marker = marker_text == "true"
                if marker and (tags or greater is not None
                               or less is not None):
                    # A delete marker carries neither tags nor a content
                    # size, so a tag or size filter can never match one:
                    # the combination is rejected up front rather than
                    # silently never firing.
                    raise LifecycleError(
                        "InvalidArgument",
                        "ExpiredObjectDeleteMarker cannot be combined with "
                        "a tag or object-size filter")
            rule["expiration"] = {
                "days": (_age(scalar(expiration["Days"]), "expiration")
                         if "Days" in expiration else None),
                "date": (_date(scalar(expiration["Date"]), "expiration")
                         if "Date" in expiration else None),
                "expired_marker": marker,
            }
        for node in group["Transition"]:
            transition = fields(node, {"Days", "StorageClass"})
            if set(transition) != {"Days", "StorageClass"}:
                raise LifecycleError("InvalidArgument",
                                     "Transition needs Days and StorageClass")
            rule["transitions"].append({
                "days": _age(scalar(transition["Days"]), "transition"),
                "storage_class": _storage_class(
                    scalar(transition["StorageClass"])),
            })
        for node in group["NoncurrentVersionTransitions"]:
            transition = fields(
                node, {"NoncurrentDays", "StorageClass",
                       "NewerNoncurrentVersions"})
            if not {"NoncurrentDays", "StorageClass"} <= set(transition):
                raise LifecycleError(
                    "InvalidArgument",
                    "NoncurrentVersionTransitions needs NoncurrentDays and "
                    "StorageClass")
            entry = {
                "days": _age(scalar(transition["NoncurrentDays"]),
                             "NoncurrentDays"),
                "storage_class": _storage_class(
                    scalar(transition["StorageClass"])),
                "newer": None,
            }
            if "NewerNoncurrentVersions" in transition:
                entry["newer"] = _newer(
                    scalar(transition["NewerNoncurrentVersions"]))
            rule["noncurrent_transitions"].append(entry)
        if group["NoncurrentVersionExpiration"]:
            if len(group["NoncurrentVersionExpiration"]) > 1:
                raise LifecycleError("NotImplemented",
                                     "Duplicate NoncurrentVersionExpiration", 501)
            expiration = fields(
                group["NoncurrentVersionExpiration"][0],
                {"NoncurrentDays", "NewerNoncurrentVersions", "Date"})
            if ("NoncurrentDays" in expiration) == ("Date" in expiration):
                raise LifecycleError(
                    "InvalidArgument",
                    "NoncurrentVersionExpiration needs exactly one of "
                    "NoncurrentDays or Date")
            entry = {
                "days": (_age(scalar(expiration["NoncurrentDays"]),
                              "NoncurrentDays")
                         if "NoncurrentDays" in expiration else None),
                "date": (_date(scalar(expiration["Date"]), "NoncurrentDays")
                         if "Date" in expiration else None),
                "newer": None,
            }
            if "NewerNoncurrentVersions" in expiration:
                entry["newer"] = _newer(
                    scalar(expiration["NewerNoncurrentVersions"]))
            rule["noncurrent_expiration"] = entry
        result.append(rule)
    return result


def _normalize_rule(rule):
    """Validate one stored rule and return the canonical shape.

    Accepts both the canonical shape produced by :func:
    `parse_lifecycle_xml` since handoff 08 and the legacy flat shape
    (``action``/``days``/``expired_marker``) stored by earlier releases,
    so an upgrade never invalidates a bucket's existing configuration.
    Raises ``ValueError`` on anything else.
    """
    if not isinstance(rule, dict):
        raise ValueError()
    legacy_keys = {"id", "status", "prefix", "days", "action",
                   "expired_marker"}
    canonical_keys = {"id", "status", "prefix", "tags", "abort_days",
                      "expiration", "transitions", "noncurrent_transitions",
                      "noncurrent_expiration", "size_greater_than",
                      "size_less_than"}
    if not {"id", "status", "prefix"} <= set(rule):
        raise ValueError()
    if not isinstance(rule["id"], str) or not 1 <= len(
            rule["id"].encode("utf-8")) <= 255:
        raise ValueError()
    if rule["status"] not in {"Enabled", "Disabled"}:
        raise ValueError()
    if not isinstance(rule["prefix"], str) or len(
            rule["prefix"].encode("utf-8")) > 1024:
        raise ValueError()
    tags = _validate_tag_set(rule.get("tags") or [])
    if "action" in rule:
        if not set(rule) <= legacy_keys or rule["action"] not in {
                "abort", "expire"}:
            raise ValueError()
        if type(rule["days"]) is not int or not 1 <= rule["days"] <= 3650:
            raise ValueError()
        return {
            "id": rule["id"], "status": rule["status"],
            "prefix": rule["prefix"], "tags": [],
            "abort_days": rule["days"] if rule["action"] == "abort" else None,
            "expiration": (None if rule["action"] != "expire" else {
                "days": rule["days"], "date": None,
                "expired_marker": bool(rule.get("expired_marker", False)),
            }),
            "transitions": [], "noncurrent_transitions": [],
            "noncurrent_expiration": None,
        }
    if not set(rule) <= canonical_keys:
        raise ValueError()
    sizes = {}
    for key in ("size_greater_than", "size_less_than"):
        value = rule.get(key)
        if value is not None and (type(value) is not int
                                  or not 0 <= value <= _MAX_OBJECT_SIZE):
            raise ValueError()
        sizes[key] = value
    if (sizes["size_greater_than"] is not None
            and sizes["size_less_than"] is not None
            and sizes["size_greater_than"] >= sizes["size_less_than"]):
        raise ValueError()
    normalized = {
        "id": rule["id"], "status": rule["status"], "prefix": rule["prefix"],
        "tags": tags,
        "abort_days": rule.get("abort_days"),
        "expiration": rule.get("expiration"),
        "transitions": list(rule.get("transitions") or []),
        "noncurrent_transitions": list(
            rule.get("noncurrent_transitions") or []),
        "noncurrent_expiration": rule.get("noncurrent_expiration"),
        "size_greater_than": sizes["size_greater_than"],
        "size_less_than": sizes["size_less_than"],
    }
    if normalized["abort_days"] is not None:
        if (type(normalized["abort_days"]) is not int
                or not 1 <= normalized["abort_days"] <= 3650):
            raise ValueError()
    expiration = normalized["expiration"]
    if expiration is not None:
        days, date = (expiration.get("days"), expiration.get("date"))
        if (not isinstance(expiration, dict)
                or type(expiration.get("expired_marker")) is not bool
                # Exactly one of Days or Date drives the schedule.
                or (days is None) == (date is None)):
            raise ValueError()
        if days is not None and (type(days) is not int
                                 or not 1 <= days <= 3650):
            raise ValueError()
        if date is not None and (type(date) is not int
                                 or not 0 < date < _MAX_DATE_EPOCH):
            raise ValueError()
        if expiration.get("expired_marker") and (
                tags or sizes["size_greater_than"] is not None
                or sizes["size_less_than"] is not None):
            raise ValueError()
    for transition in normalized["transitions"]:
        if (not isinstance(transition, dict)
                or type(transition.get("days")) is not int
                or not 1 <= transition["days"] <= 3650
                or transition.get("storage_class") not in
                _TRANSITION_CLASSES):
            raise ValueError()
    for transition in normalized["noncurrent_transitions"]:
        newer = transition.get("newer")
        if (not isinstance(transition, dict)
                or type(transition.get("days")) is not int
                or not 1 <= transition["days"] <= 3650
                or transition.get("storage_class") not in
                _TRANSITION_CLASSES
                or (newer is not None
                    and (type(newer) is not int or not 0 <= newer <=
                         _MAX_NEWER_NONCURRENT))):
            raise ValueError()
    expiration = normalized["noncurrent_expiration"]
    if expiration is not None:
        newer = expiration.get("newer")
        days, date = (expiration.get("days"), expiration.get("date"))
        if (not isinstance(expiration, dict)
                or (days is None) == (date is None)
                or (days is not None and (type(days) is not int
                                          or not 1 <= days <= 3650))
                or (date is not None and (type(date) is not int
                                          or not 0 < date < _MAX_DATE_EPOCH))
                or (newer is not None
                    and (type(newer) is not int or not 0 <= newer <=
                         _MAX_NEWER_NONCURRENT))):
            raise ValueError()
    return normalized


def _date_xml(epoch: int) -> str:
    """The ISO-8601 UTC spelling of a stored expiration date."""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def lifecycle_xml(rules):
    root = ET.Element("LifecycleConfiguration", xmlns=NS)
    for raw in rules:
        rule = _normalize_rule(raw)
        el = ET.SubElement(root, "Rule")
        ET.SubElement(el, "ID").text = rule["id"]
        ET.SubElement(el, "Status").text = rule["status"]
        fil = ET.SubElement(el, "Filter")
        prefix, tags = rule["prefix"], rule["tags"]
        greater = rule.get("size_greater_than")
        less = rule.get("size_less_than")
        sized = greater is not None or less is not None
        if not tags and not sized:
            ET.SubElement(fil, "Prefix").text = prefix
        elif not prefix and not sized and len(tags) == 1:
            # A lone Tag sits directly under Filter.
            node = ET.SubElement(fil, "Tag")
            ET.SubElement(node, "Key").text = tags[0]["key"]
            ET.SubElement(node, "Value").text = tags[0]["value"]
        elif not tags and not prefix and sized and (greater is None
                                                    or less is None):
            # A lone size bound also sits directly under Filter.
            label, value = (("ObjectSizeGreaterThan", greater)
                            if greater is not None
                            else ("ObjectSizeLessThan", less))
            ET.SubElement(fil, label).text = str(value)
        else:
            # The remaining combinations are conjunctions: prefix and/or
            # several tags and/or the size interval. AWS element order is
            # Prefix, Tag, ObjectSizeGreaterThan, ObjectSizeLessThan.
            parent = ET.SubElement(fil, "And")
            if prefix:
                ET.SubElement(parent, "Prefix").text = prefix
            for tag in tags:
                node = ET.SubElement(parent, "Tag")
                ET.SubElement(node, "Key").text = tag["key"]
                ET.SubElement(node, "Value").text = tag["value"]
            if greater is not None:
                ET.SubElement(parent, "ObjectSizeGreaterThan").text = \
                    str(greater)
            if less is not None:
                ET.SubElement(parent, "ObjectSizeLessThan").text = str(less)
        if rule["abort_days"] is not None:
            abort = ET.SubElement(el, "AbortIncompleteMultipartUpload")
            ET.SubElement(abort, "DaysAfterInitiation").text = \
                str(rule["abort_days"])
        if rule["expiration"] is not None:
            expiration = ET.SubElement(el, "Expiration")
            if rule["expiration"]["days"] is not None:
                ET.SubElement(expiration, "Days").text = \
                    str(rule["expiration"]["days"])
            else:
                ET.SubElement(expiration, "Date").text = _date_xml(
                    rule["expiration"]["date"])
            ET.SubElement(expiration, "ExpiredObjectDeleteMarker").text = \
                ("true" if rule["expiration"]["expired_marker"] else "false")
        for transition in rule["transitions"]:
            node = ET.SubElement(el, "Transition")
            ET.SubElement(node, "Days").text = str(transition["days"])
            ET.SubElement(node, "StorageClass").text = \
                transition["storage_class"]
        for transition in rule["noncurrent_transitions"]:
            node = ET.SubElement(el, "NoncurrentVersionTransitions")
            ET.SubElement(node, "NoncurrentDays").text = str(transition["days"])
            ET.SubElement(node, "StorageClass").text = \
                transition["storage_class"]
            if transition.get("newer") is not None:
                ET.SubElement(node, "NewerNoncurrentVersions").text = \
                    str(transition["newer"])
        if rule["noncurrent_expiration"] is not None:
            node = ET.SubElement(el, "NoncurrentVersionExpiration")
            if rule["noncurrent_expiration"]["days"] is not None:
                ET.SubElement(node, "NoncurrentDays").text = \
                    str(rule["noncurrent_expiration"]["days"])
            else:
                ET.SubElement(node, "Date").text = _date_xml(
                    rule["noncurrent_expiration"]["date"])
            if rule["noncurrent_expiration"].get("newer") is not None:
                ET.SubElement(node, "NewerNoncurrentVersions").text = \
                    str(rule["noncurrent_expiration"]["newer"])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class BucketLifecycleStore:
    def __init__(self, catalog: BucketCatalog):
        self.catalog, self.db = catalog, catalog.db
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)

    def get(self, bucket):
        if bucket not in self.catalog.list_buckets():
            raise FileNotFoundError("No such bucket")
        raw = self.db.connection.execute(select(rules_table.c.rules_json).where(
            rules_table.c.bucket == bucket)).scalar_one_or_none()
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Corrupted lifecycle policy") from exc

    def replace(self, bucket, rules):
        if bucket not in self.catalog.list_buckets():
            raise FileNotFoundError("No such bucket")
        try:
            if rules is None:
                self.db.connection.execute(delete(rules_table).where(
                    rules_table.c.bucket == bucket))
            else:
                data = json.dumps(rules, separators=(",", ":"), sort_keys=True)
                changed = self.db.connection.execute(update(rules_table).where(
                    rules_table.c.bucket == bucket).values(rules_json=data))
                if changed.rowcount == 0:
                    self.db.connection.execute(insert(rules_table).values(
                        bucket=bucket, rules_json=data))
            self.db.commit()
        except IntegrityError as exc:
            self.db.connection.rollback()
            raise LifecycleError("OperationAborted", "Concurrent policy edit", 409) from exc
        except BaseException:
            self.db.connection.rollback()
            raise

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _matches_tags(db, object_id: str, tags) -> bool:
        """True when the version's tag set satisfies the rule's tag
        conjunction (every rule tag present with an equal value).

        A version with no tags at all fails every non-empty conjunction,
        which is the AWS filter semantics.
        """
        if not tags:
            return True
        from teledrive.s3.tagging import object_tags
        present = dict(db.connection.execute(select(
            object_tags.c.tag_key, object_tags.c.tag_value).where(
            object_tags.c.object_id == object_id)).all())
        return all(present.get(tag["key"]) == tag["value"] for tag in tags)

    @staticmethod
    def _matches_size(size, greater, less) -> bool:
        """True when the object's size satisfies the rule's exclusive
        bounds.

        A missing or non-integer size fails closed: it never matches a
        size-bounded rule (a filter must never be guessed past)."""
        if greater is None and less is None:
            return True
        if size is None or type(size) is not int:
            return False
        if greater is not None and size <= greater:
            return False
        if less is not None and size >= less:
            return False
        return True

    def _archive_queue(self):
        """The physical archive queue, or None when unavailable.

        Transitions must still apply their catalog label when the cold
        store cannot be reached; the version then keeps the window-gate
        restore semantics until a later pass enqueues it."""
        try:
            from teledrive.storage.cold_store import (
                ArchiveStore, ColdBlobStore, default_cold_root,
            )
            return ArchiveStore(
                self.catalog, ColdBlobStore(default_cold_root()))
        except Exception:
            _logger.warning(
                "physical archive queue unavailable; lifecycle applies "
                "the storage-class label only", exc_info=True)
            return None

    def _enqueue_archive(self, object_ids) -> None:
        if not object_ids:
            return
        queue = self._archive_queue()
        if queue is None:
            return
        try:
            queue.enqueue_archive(object_ids)
        except Exception:
            self.db.connection.rollback()
            _logger.warning(
                "lifecycle archive enqueue failed; the label stands and "
                "the next pass retries", exc_info=True)

    def _noncurrent_versions(self, bucket, *, prefix=""):
        """Published, unrevoked, ready NONCURRENT versions of the bucket.

        Returns rows of (object_id, object_key, key_hash, updated_at,
        committed_ns, size) ordered by age; the caller applies per-key
        NewerNoncurrentVersions ranking and age cutoffs.
        """
        from teledrive.storage.catalog import published_versions, removed_versions
        conditions = [
            objects.c.bucket == bucket,
            objects.c.status == "ready",
            objects.c.id == published_versions.c.object_id,
            published_versions.c.bucket == bucket,
            not_(exists(select(1).where(
                heads_table.c.object_id == objects.c.id))),
            not_(exists(select(1).where(
                removed_versions.c.object_id == objects.c.id))),
        ]
        if prefix:
            conditions.append(objects.c.object_key.startswith(
                prefix, autoescape=True))
        return self.db.connection.execute(
            select(objects.c.id, objects.c.object_key,
                   published_versions.c.key_hash, objects.c.updated_at,
                   published_versions.c.committed_ns, objects.c.size)
            .where(*conditions)
            .order_by(objects.c.updated_at, objects.c.id)
        ).all()

    @staticmethod
    def _newer_exempt(rows, newer: int | None):
        """Row ids exempted by NewerNoncurrentVersions, per key.

        ``rows`` is grouped by key_hash; within each key the NEWEST
        ``newer`` noncurrent versions (by publish order, most recent
        first) are exempt from the action.
        """
        if not newer:
            return set()
        by_key: dict[str, list] = {}
        for row in rows:
            by_key.setdefault(row[2], []).append(row)
        exempt = set()
        for group in by_key.values():
            ordered = sorted(
                group, key=lambda r: (int(r[4]), r[0]), reverse=True)
            exempt.update(row[0] for row in ordered[:newer])
        return exempt

    # -- actions ------------------------------------------------------------

    def _transition_due_objects(self, bucket, transition, *, prefix, tags,
                                greater, less, now, limit):
        """Current heads past the transition age move to the archive class
        and are queued for a verified cold copy (an additional copy;
        nothing is moved or deleted)."""
        if limit <= 0:
            return 0
        target = transition["storage_class"]
        conditions = [
            objects.c.bucket == bucket,
            objects.c.status == "ready",
            objects.c.storage_class != target,
            objects.c.updated_at <= now - transition["days"] * 86400,
            objects.c.id.in_(select(heads_table.c.object_id).where(
                heads_table.c.bucket == bucket)),
        ]
        if prefix:
            conditions.append(objects.c.object_key.startswith(
                prefix, autoescape=True))
        rows = self.db.connection.execute(
            select(objects.c.id, objects.c.object_key, objects.c.size)
            .where(*conditions)
            .order_by(objects.c.updated_at).limit(limit)).all()
        changed = []
        for object_id, key, size in rows:
            if not self._matches_size(size, greater, less):
                continue
            if tags and not self._matches_tags(self.db, object_id, tags):
                continue
            # Head race: a newer version may have been published since the
            # selection; only the CURRENT head may transition.
            try:
                current = self.catalog.get(bucket, key)
            except FileNotFoundError:
                continue
            if current.item.id != object_id:
                continue
            moved = self.db.connection.execute(
                update(objects).where(
                    objects.c.id == object_id,
                    objects.c.storage_class != target,
                ).values(storage_class=target))
            if moved.rowcount == 1:
                changed.append(object_id)
        self._enqueue_archive(changed)
        return len(changed)

    def _transition_noncurrent(self, bucket, spec, *, prefix, tags,
                               greater, less, now, limit):
        """Noncurrent versions past NoncurrentDays (minus the newest
        NewerNoncurrentVersions per key) move to the archive class."""
        if limit <= 0:
            return 0
        rows = self._noncurrent_versions(bucket, prefix=prefix)
        exempt = self._newer_exempt(rows, spec.get("newer"))
        target = spec["storage_class"]
        cutoff = now - spec["days"] * 86400
        changed = []
        for object_id, key, _key_hash, updated_at, _committed, size in rows:
            if object_id in exempt or int(updated_at) > cutoff:
                continue
            if not self._matches_size(size, greater, less):
                continue
            if tags and not self._matches_tags(self.db, object_id, tags):
                continue
            row = self.db.connection.execute(select(
                objects.c.storage_class).where(
                objects.c.id == object_id)).scalar_one_or_none()
            if row is None or row == target:
                continue
            # Head race: a noncurrent version can only become current
            # again through revocations of newer versions; re-check.
            try:
                current = self.catalog.get(bucket, key)
            except FileNotFoundError:
                continue
            if current.item.id == object_id:
                continue
            moved = self.db.connection.execute(
                update(objects).where(
                    objects.c.id == object_id,
                    objects.c.storage_class != target,
                ).values(storage_class=target))
            if moved.rowcount == 1:
                changed.append(object_id)
                if len(changed) >= limit:
                    break
        self._enqueue_archive(changed)
        return len(changed)

    def _expire_noncurrent_versions(self, bucket, spec, *, prefix, tags,
                                    greater, less, now, limit):
        """Revoke due noncurrent versions from version history.

        Logical only while GC is off: the media stays retained. Locked or
        legal-held versions and dedup alias sources are fenced off.
        A Date-based schedule fires for every matching noncurrent
        version once ``now >= date``; NoncurrentDays keeps its age
        cutoff."""
        if limit <= 0:
            return []
        days, date = spec.get("days"), spec.get("date")
        if date is not None:
            if now < date:
                return []
            cutoff = None  # every matching noncurrent version is due
        else:
            cutoff = now - days * 86400
        rows = self._noncurrent_versions(bucket, prefix=prefix)
        exempt = self._newer_exempt(rows, spec.get("newer"))
        revoked = []
        for object_id, key, _key_hash, updated_at, _committed, size in rows:
            if object_id in exempt:
                continue
            if cutoff is not None and int(updated_at) > cutoff:
                continue
            if not self._matches_size(size, greater, less):
                continue
            if tags and not self._matches_tags(self.db, object_id, tags):
                continue
            if len(revoked) >= limit:
                break
            fences = self.db.connection.execute(select(
                objects.c.retention_until_ns, objects.c.legal_hold)
                .where(objects.c.id == object_id)).first()
            if fences is not None and (
                    fences[1]
                    or (fences[0] is not None
                        and int(fences[0]) > time.time_ns())):
                continue  # Object Lock: WORM beats lifecycle
            from teledrive.storage.manifest import object_aliases
            if self.db.connection.execute(select(1).where(
                    object_aliases.c.source_object_id == object_id)
            ).first() is not None:
                continue  # media another version still aliases
            try:
                if not self.catalog.delete_version(bucket, key, object_id):
                    continue
            except PermissionError:
                continue  # lock raced in; never expire a locked version
            revoked.append(object_id)
        return revoked

    def _expire_delete_markers(self, bucket, *, prefix, now, limit):
        """ExpiredObjectDeleteMarker: remove a delete marker that is the
        only remaining version of its key."""
        from teledrive.storage.catalog import published_versions, removed_versions
        if limit <= 0:
            return 0
        other_version = select(published_versions.c.object_id).where(
            published_versions.c.bucket == bucket,
            published_versions.c.key_hash == heads_table.c.key_hash,
            published_versions.c.object_id != objects.c.id,
            ~exists(select(1).where(
                removed_versions.c.object_id ==
                published_versions.c.object_id)),
            select(objects.c.status).where(
                objects.c.id == published_versions.c.object_id,
            ).scalar_subquery() != "delete-marker",
        )
        conditions = [
            objects.c.bucket == bucket,
            objects.c.status == "delete-marker",
            objects.c.id == heads_table.c.object_id,
            heads_table.c.bucket == bucket,
            not_(exists(other_version)),
        ]
        if prefix:
            conditions.append(objects.c.object_key.startswith(
                prefix, autoescape=True))
        rows = self.db.connection.execute(
            select(objects.c.id, objects.c.object_key)
            .where(*conditions).order_by(objects.c.updated_at)
            .limit(limit)).all()
        removed = 0
        for marker_id, key in rows:
            # The head CAS inside delete_version makes the removal atomic
            # against a concurrent publish for the same key.
            try:
                if self.catalog.delete_version(bucket, key, marker_id):
                    removed += 1
            except PermissionError:
                continue
        return removed

    def apply_due(self, *, now: int, limit=100):
        """Bounded active-state CAS; no remote or SQL journal deletion.

        Expiration rules create logical delete markers for due current
        objects, NoncurrentVersionExpiration revokes due noncurrent
        versions, ExpiredObjectDeleteMarker removes orphan markers, and
        transitions move due versions to the archive class while queueing
        a verified cold copy. Physical media is only ever enqueued for
        the owner-gated GC collector — lifecycle expiry stays logical
        while GC is off."""
        if type(now) is not int or now < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid lifecycle run bounds")
        from teledrive.s3.multipart import uploads
        from teledrive.storage.schema import ensure_schema
        ensure_schema(self.db.engine)
        entries = self.db.connection.execute(select(
            rules_table.c.bucket, rules_table.c.rules_json)).all()
        gcx = None
        try:
            from teledrive.storage.gc_collect import RetainedMediaGC
            gcx = RetainedMediaGC(self.db)
        except Exception:
            # Optional subsystem: physical GC enqueue must never prevent
            # the logical lifecycle expiry itself. Degrade to logical-only
            # and leave a trace (the media stays until GC is available).
            _logger.warning(
                "physical GC unavailable; lifecycle applies logical "
                "expiry only", exc_info=True)
            gcx = None
        gc_enabled = bool(gcx and gcx.state()["enabled"])
        count = 0
        try:
            for bucket, data in entries:
                try:
                    rules = json.loads(data)
                    if not isinstance(rules, list):
                        raise ValueError()
                except (TypeError, ValueError) as exc:
                    raise RuntimeError("Corrupted lifecycle policy") from exc
                for raw in rules:
                    try:
                        rule = _normalize_rule(raw)
                    except ValueError as exc:
                        raise RuntimeError(
                            "Corrupted lifecycle policy") from exc
                    if rule["status"] != "Enabled":
                        continue
                    remaining = limit - count
                    if remaining <= 0:
                        self.db.commit()
                        return count
                    prefix = rule["prefix"]
                    tags = rule.get("tags") or []
                    greater = rule.get("size_greater_than")
                    less = rule.get("size_less_than")
                    if rule["expiration"] is not None:
                        # Expire due CURRENT objects: a logical delete
                        # marker now, physical media via the GC queue
                        # (grace-fenced) when GC is enabled.
                        expired = self._expire_due_objects(
                            bucket, expiration=rule["expiration"],
                            prefix=prefix, tags=tags, greater=greater,
                            less=less, now=now, limit=remaining)
                        for object_id in expired:
                            if gc_enabled and gcx is not None:
                                gcx.enqueue([object_id],
                                            "lifecycle-expiration")
                        count += len(expired)
                        if rule["expiration"]["expired_marker"]:
                            count += self._expire_delete_markers(
                                bucket, prefix=prefix, now=now,
                                limit=max(0, limit - count))
                    for transition in rule["transitions"]:
                        count += self._transition_due_objects(
                            bucket, transition, prefix=prefix, tags=tags,
                            greater=greater, less=less,
                            now=now, limit=max(0, limit - count))
                    for spec in rule["noncurrent_transitions"]:
                        count += self._transition_noncurrent(
                            bucket, spec, prefix=prefix, tags=tags,
                            greater=greater, less=less, now=now,
                            limit=max(0, limit - count))
                    if rule["noncurrent_expiration"] is not None:
                        revoked = self._expire_noncurrent_versions(
                            bucket, rule["noncurrent_expiration"],
                            prefix=prefix, tags=tags, greater=greater,
                            less=less, now=now,
                            limit=max(0, limit - count))
                        for object_id in revoked:
                            if gc_enabled and gcx is not None:
                                gcx.enqueue([object_id],
                                            "lifecycle-noncurrent-expiration")
                        count += len(revoked)
                    if rule["abort_days"] is not None:
                        remaining = limit - count
                        if remaining <= 0:
                            continue
                        select_ids = select(uploads.c.id).where(
                            uploads.c.bucket == bucket,
                            uploads.c.state == "active",
                            uploads.c.created_at <= now - rule["abort_days"] * 86400,
                        )
                        if prefix:
                            select_ids = select_ids.where(
                                uploads.c.object_key.startswith(
                                    prefix, autoescape=True))
                        ids = self.db.connection.execute(
                            select_ids.order_by(uploads.c.created_at, uploads.c.id)
                            .limit(remaining)).scalars()
                        for ident in list(ids):
                            changed = self.db.connection.execute(update(uploads).where(
                                uploads.c.id == ident, uploads.c.state == "active"
                            ).values(state="aborted"))
                            count += int(changed.rowcount)
            self.db.commit()
            return count
        except BaseException:
            self.db.connection.rollback()
            raise

    def _expire_due_objects(self, bucket, *, expiration, prefix: str,
                            tags, greater, less, now: int, limit: int):
        """Create delete markers for due current objects; returns the
        previously-current object ids whose media is now reclaimable.

        A Days schedule expires heads older than the age; a Date
        schedule fires for every matching head once ``now >= date``."""
        days, date = expiration.get("days"), expiration.get("date")
        if date is not None and now < date:
            return []
        conditions = [
            objects.c.bucket == bucket,
            objects.c.status == "ready",
            # Object lock: retained or legal-held objects never expire.
            or_(objects.c.retention_until_ns.is_(None),
                objects.c.retention_until_ns <= time.time_ns()),
            objects.c.legal_hold.is_(False),
            # Only CURRENT heads: the head join picks live keys.
            objects.c.id.in_(
                select(heads_table.c.object_id).where(
                    heads_table.c.bucket == bucket)),
        ]
        if days is not None:
            conditions.append(objects.c.updated_at <= now - days * 86400)
        rows = self.db.connection.execute(
            select(objects.c.id, objects.c.object_key, objects.c.updated_at,
                   objects.c.size)
            .where(*conditions)
            .order_by(objects.c.updated_at).limit(limit)
        ).all()
        if prefix:
            rows = [row for row in rows
                    if row[1].startswith(prefix)]
        expired = []
        for object_id, key, _updated, size in rows:
            if not self._matches_size(size, greater, less):
                continue
            if tags and not self._matches_tags(self.db, object_id, tags):
                continue
            try:
                current = self.catalog.get(bucket, key)
                if current.item.id != object_id:
                    continue  # head moved since selection; skip
            except FileNotFoundError:
                continue
            self.catalog.delete_marker(bucket, key)
            expired.append(object_id)
        return expired
