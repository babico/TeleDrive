"""DDL is issued by exactly one place.

Invariant #3 of `docs/handoffs/00-baseline.md`: no `create_all` and no
`ALTER TABLE` outside `teledrive/storage/schema.py`. The coordinator exists
because scattered DDL causes three concrete failures this project has already
paid for:

* a schema-init race between workers (only the coordinator takes a real
  cross-process lock),
* a migration that silently never runs on an existing database (steps are
  append-only and versioned),
* a "defensive" ALTER that duplicates a step and hides the fact that the step
  is what actually works.

The last one was live in this tree: `web/app.py` ran
`ALTER TABLE users ADD COLUMN enabled ...` at startup, AFTER `db_connect()`
had already applied the same column through the coordinator's `core` step. It
was dead code, and the comment beside it claimed it was the thing preventing
a "second copy". This test is what would have caught it.

There is one legitimate exception: a module may hold the DDL for structures
the coordinator calls, because a step's body has to live somewhere. Those are
listed below with the step that owns them.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DDL_RE = re.compile(
    r"\b(?:ALTER\s+TABLE|CREATE\s+TABLE|CREATE\s+VIRTUAL\s+TABLE|"
    r"CREATE\s+(?:UNIQUE\s+)?INDEX|DROP\s+TABLE|DROP\s+COLUMN|"
    r"ADD\s+COLUMN|\.create_all\s*\()",
    re.IGNORECASE)

# module (relative path) -> the schema step whose body issues this DDL.
STEP_OWNED_DDL = {
    "teledrive/storage/content_index.py":
        "_step_content_search (FTS5 / tsvector structures)",
}

SCANNED_DIRS = ("teledrive", "web")


def _python_files():
    for directory in SCANNED_DIRS:
        for path in (ROOT / directory).rglob("*.py"):
            relative = path.relative_to(ROOT).as_posix()
            if relative == "teledrive/storage/schema.py":
                continue
            yield relative, path


def test_ddl_appears_only_in_the_schema_coordinator():
    offenders = []
    for relative, path in _python_files():
        if relative in STEP_OWNED_DDL:
            continue
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            # Skip comments and docstrings-by-line: the words may legitimately
            # appear while explaining the rule.
            if stripped.startswith("#"):
                continue
            if DDL_RE.search(line):
                offenders.append(f"{relative}:{number}: {stripped[:100]}")
    assert offenders == [], (
        "DDL outside teledrive/storage/schema.py. Either add a schema step "
        "(append-only, versioned, cross-process locked) or register the "
        "module here with the step that owns its DDL:\n  "
        + "\n  ".join(offenders))


def test_the_step_owned_exceptions_are_still_real():
    """A listed exception must still contain DDL and still be called by a step.

    Otherwise the allowlist is a permanent hole that nobody re-examines.
    """
    schema = (ROOT / "teledrive/storage/schema.py").read_text(encoding="utf-8")
    for relative, step in STEP_OWNED_DDL.items():
        path = ROOT / relative
        assert path.is_file(), f"{relative} no longer exists; drop the exception"
        module = path.stem
        assert DDL_RE.search(path.read_text(encoding="utf-8")), (
            f"{relative} is allowlisted but contains no DDL; drop the exception")
        assert module in schema, (
            f"{relative} is allowlisted as '{step}' but schema.py does not "
            f"import or reference the module {module!r}")
