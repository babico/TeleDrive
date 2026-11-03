"""The S3 parameter ledger is a machine-checked compatibility contract.

``docs/reference/s3-parameters.md`` claims, per request parameter, whether
the gateway SUPPORTS, REJECTS or has UNVERIFIED behavior. Two failure
modes are worth a test rather than a review comment:

1. a SUPPORTED/REJECTED row that names a test file which does not exist
   (or contains no tests at all), and
2. a parameter the gateway actually parses that has no ledger row —
   including parameters added after the ledger was written.

The parsed-parameter surface is re-derived from the sources on every run:
the route guard's allowlist frozensets plus every literal the gateway and
its protocol helpers read through a query/header accessor. A new parameter
therefore fails this test until it gets an honest ledger row.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/reference/s3-parameters.md"
GATEWAY = ROOT / "web/s3_gateway"
PROTOCOL = ROOT / "teledrive/s3"

STATES = {"SUPPORTED", "REJECTED", "UNVERIFIED"}

# Sources whose literal query/header reads define the required surface.
QUERY_SOURCES = [PROTOCOL / "route_guard.py", PROTOCOL / "sigv4.py"] + \
    sorted(GATEWAY.glob("*.py"))
HEADER_SOURCES = sorted(GATEWAY.glob("*.py")) + [PROTOCOL / name for name in (
    "conditions.py", "write_conditions.py", "aws_chunked.py",
    "object_metadata.py", "sigv4.py",
)] + [ROOT / "teledrive/storage/sse.py"]

# Parameters consumed through helper functions, tuple loops or fail-closed
# rejection sets instead of a direct headers.get("...") literal, plus the
# documented known gaps. Extend this list when adding a new indirect
# parameter — or simply give it a dedicated ledger row.
EXTRA_HEADERS = {
    "x-amz-sdk-checksum-algorithm",
    "x-amz-checksum-sha1", "x-amz-checksum-crc64nvme",
    "x-amz-max-parts", "x-amz-part-number-marker",
    "x-amz-grant-read", "x-amz-grant-write", "x-amz-grant-full-control",
    "x-amz-grant-read-acp", "x-amz-grant-write-acp",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context", "x-amz-bucket-key-enabled",
    "x-amz-website-redirect-location", "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date", "x-amz-object-lock-legal-hold",
    "x-amz-request-payer", "x-amz-expected-bucket-owner",
    "x-amz-storage-class", "x-amz-security-token",
    "x-amz-rename-source-if-*", "x-amz-meta-*",
    "cache-control", "content-disposition", "content-language", "expires",
    "X-Amz-Credential", "X-Amz-Signature", "X-Amz-Expires",
}

QUERY_PATTERNS = [
    re.compile(r'query_params\.get\(\s*"([^"]+)"'),
    re.compile(r'query_params\.getlist\(\s*"([^"]+)"'),
    re.compile(r'query_params\[\s*"([^"]+)"\s*\]'),
    re.compile(r'"([^"]+)"\s+in\s+request\.query_params'),
    re.compile(r'p in request\.query_params for p in \(([^)]*)\)'),
]
HEADER_PATTERNS = [
    re.compile(r'(?:request\.)?headers\.get\(\s*"([^"]+)"'),
    re.compile(r'(?:request\.)?headers\.getlist\(\s*"([^"]+)"'),
    re.compile(r'"([^"]+)"\s+in\s+request\.headers'),
    re.compile(r'name\.startswith\("([^"]+)"\)\s+for name in request\.headers'),
    re.compile(r'checksum_header\(\s*"([^"]+)"'),
]

TEST_PATH = re.compile(r"tests/[A-Za-z0-9_/.-]+\.py")
BACKTICKED = re.compile(r"`([^`]+)`")


def _scrape(patterns: list[re.Pattern], sources: list[Path]) -> set[str]:
    found: set[str] = set()
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            for match in pattern.finditer(text):
                group = match.group(1)
                # A direct accessor captures one name; the tuple-loop
                # patterns capture a quoted list.
                names = re.findall(r'"([^"]+)"', group) or [group]
                found.update(names)
    return found


def _route_guard_allowlist() -> set[str]:
    from teledrive.s3 import route_guard

    names: set[str] = set()
    for value in vars(route_guard).values():
        if isinstance(value, frozenset):
            names.update(item for item in value if isinstance(item, str))
    return names


def _sse_header_names() -> set[str]:
    from teledrive.storage import sse

    names = set(sse.CUSTOMER_HEADERS)
    # UpdateObjectEncryption parses the AWS-spelled copy-source old-key
    # family through the same helper.
    names.update(sse.SOURCE_CUSTOMER_HEADERS)
    return names


def _ledger_rows() -> list[tuple[str, str, str, int]]:
    """(names-cell, state, proof-cell, line-number) for parameter rows."""
    rows = []
    for number, line in enumerate(
            LEDGER.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("|") or set(stripped) <= {"|", "-", " "}:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 4 or cells[1] not in STATES:
            continue
        rows.append((cells[0], cells[1], cells[-1], number))
    return rows


def test_ledger_rows_are_well_formed():
    rows = _ledger_rows()
    assert rows, "no parameter rows found in the ledger"
    problems = []
    for names_cell, state, _proof, number in rows:
        if not BACKTICKED.findall(names_cell):
            problems.append((number, "parameter cell must name it in backticks"))
    assert not problems, problems


def test_supported_and_rejected_rows_name_real_test_files():
    problems = []
    for _names, state, proof, number in _ledger_rows():
        if state == "UNVERIFIED":
            continue
        paths = TEST_PATH.findall(proof)
        if not paths:
            problems.append((number, f"{state} row names no test file"))
            continue
        for path in paths:
            absolute = ROOT / path
            if not absolute.is_file():
                problems.append((number, f"{path} does not exist"))
            elif "def test_" not in absolute.read_text(encoding="utf-8"):
                problems.append((number, f"{path} contains no tests"))
    assert not problems, problems


def test_every_parsed_gateway_parameter_has_a_ledger_row():
    query_required = _scrape(QUERY_PATTERNS, QUERY_SOURCES)
    query_required |= _route_guard_allowlist()
    header_required = _scrape(HEADER_PATTERNS, HEADER_SOURCES)
    header_required |= _sse_header_names()
    header_required |= EXTRA_HEADERS

    documented: set[str] = set()
    for names_cell, _state, _proof, _number in _ledger_rows():
        documented.update(BACKTICKED.findall(names_cell))
    lowered = {name.lower(): name for name in documented}

    # Query names are case-sensitive (S3 subresources); headers are not.
    missing = sorted(query_required - documented)
    missing += sorted(
        name for name in header_required
        if name.lower() not in lowered
        # A prefix scraper (e.g. conditional-rename startswith guard) is
        # satisfied by the wildcard row that names the family.
        and not any(name.rstrip("-") and doc.startswith(name)
                    for doc in documented)
    )
    assert not missing, (
        "parameters the gateway parses but the S3 parameter ledger does "
        f"not document: {missing} — add a row to "
        "docs/reference/s3-parameters.md")
