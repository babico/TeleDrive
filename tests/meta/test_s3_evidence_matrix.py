"""The per-operation S3 evidence matrix is a machine-checked contract.

``docs/reference/s3-evidence.md`` claims, per supported operation in
``teledrive/s3/operation_manifest.json``, which of the seven evidence
classes (normal / auth-failure / malformed / over-limit / retry /
crash-restart / race) have a dedicated proving test. Three failure modes
are worth a test rather than a review comment:

1. a supported operation with no row at all — a new operation could be
   added to the manifest without deciding what its evidence is (the
   acceptance criterion of the roadmap item this enforces),
2. a cell that names a test file which does not exist or contains no
   tests — a stale pointer that proves nothing,
3. a malformed table — a row with the wrong number of columns, or a row
   whose operation cell is not a manifest name, silently breaking the
   parse the first two checks depend on.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs/reference/s3-evidence.md"
MANIFEST = ROOT / "teledrive/s3/operation_manifest.json"

COLUMNS = ["normal", "auth-failure", "malformed", "over-limit", "retry",
           "crash-restart", "race"]
HEADER = ["Operation"] + COLUMNS
TEST_PATH = re.compile(r"tests/[A-Za-z0-9_/.-]+\.py")
NOT_APPLICABLE = "—"


def _supported_operations() -> set[str]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {op["name"] for op in manifest["operations"]
            if op.get("status") == "supported"}


def _rows() -> list[tuple[str, list[str], int]]:
    """(operation, seven cells, line number) for every matrix row.

    Only tables whose header is exactly the evidence-matrix header are
    collected, so the prose tables in the page are ignored.
    """
    lines = DOC.read_text(encoding="utf-8").splitlines()
    rows: list[tuple[str, list[str], int]] = []
    in_matrix = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_matrix = False
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if set(stripped) <= {"|", "-", ":", " "}:
            continue  # the dashed separator row
        if cells[:1] == ["Operation"]:
            in_matrix = cells == HEADER
            if not in_matrix:
                raise AssertionError(
                    f"{DOC}:{number}: a table starts with an Operation "
                    f"column but its header is {cells}, expected {HEADER}")
            continue
        if in_matrix:
            rows.append((cells[0], cells[1:], number))
    return rows


def test_every_supported_operation_has_exactly_one_row():
    """The acceptance criterion: no operation without its evidence row."""
    supported = _supported_operations()
    rows = _rows()
    assert rows, "no evidence matrix rows found in the document"
    problems = []
    seen: set[str] = set()
    for operation, _cells, number in rows:
        if operation in seen:
            problems.append((number, f"{operation} appears more than once"))
        seen.add(operation)
    for operation in sorted(supported - seen):
        problems.append((0, f"{operation} has no evidence row"))
    for operation in sorted(seen - supported):
        problems.append((0, f"{operation} is not a supported operation"))
    assert not problems, problems
    assert seen == supported, (len(seen), len(supported))


def test_every_row_keeps_the_seven_column_shape():
    problems = []
    for operation, cells, number in _rows():
        if len(cells) != len(COLUMNS):
            problems.append(
                (number, f"{operation} has {len(cells)} cells, "
                         f"expected {len(COLUMNS)}"))
            continue
        for name, cell in zip(COLUMNS, cells):
            if cell and cell != NOT_APPLICABLE and not TEST_PATH.fullmatch(
                    cell):
                problems.append(
                    (number, f"{operation}/{name}: cell {cell!r} is neither "
                             f"empty, {NOT_APPLICABLE!r} nor a test path"))
    assert not problems, problems


def test_every_filled_cell_names_a_real_test_file():
    problems = []
    for operation, cells, number in _rows():
        for name, cell in zip(COLUMNS, cells):
            if not cell or cell == NOT_APPLICABLE:
                continue
            path = ROOT / cell
            if not path.is_file():
                problems.append(
                    (number, f"{operation}/{name}: {cell} does not exist"))
            elif "def test_" not in path.read_text(encoding="utf-8"):
                problems.append(
                    (number, f"{operation}/{name}: {cell} contains no tests"))
    assert not problems, problems


def test_the_summary_counts_match_the_tables():
    """The summary table's numbers cannot drift from the rows above."""
    supported = _supported_operations()
    text = DOC.read_text(encoding="utf-8")
    match = re.search(
        r"\*\*(\d+) supported operations, (\d+) cells\.\*\*", text)
    assert match, "the summary must state the operation and cell totals"
    operations, cells = int(match.group(1)), int(match.group(2))
    assert operations == len(supported), (
        f"the summary claims {operations} supported operations, "
        f"the manifest has {len(supported)}")
    assert cells == len(_rows()) * len(COLUMNS), (
        "the stated total cell count does not match the matrix rows")
