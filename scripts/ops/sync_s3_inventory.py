#!/usr/bin/env python3
"""Keep the S3 inventory bookkeeping in sync with the manifest.

The manifest (teledrive/s3/operation_manifest.json) is the single source of
truth for operation status. Four other places encode its totals and drift
silently when a phase promotes operations:

* docs/S3_SPECS.md                     — the human-readable inventory totals
* tests/s3/test_s3_route_guard.py      — the Counter assertion
* tests/meta/test_ci_workflows.py      — the docs total assertion string

This script recomputes the counts from the manifest and rewrites those
exactly, so a phase only has to update the manifest and add its spec rows.
It fails loudly if a pattern it needs to rewrite is missing, rather than
leaving the repo half-synced.

Usage:
    python scripts/ops/sync_s3_inventory.py            # apply
    python scripts/ops/sync_s3_inventory.py --check    # verify only (CI-safe)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "teledrive/s3/operation_manifest.json"
SPECS = ROOT / "docs/S3_SPECS.md"
ROUTE_GUARD = ROOT / "tests/s3/test_s3_route_guard.py"
META = ROOT / "tests/meta/test_ci_workflows.py"


class SyncError(RuntimeError):
    pass


def counts() -> dict[str, int]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    ops = data if isinstance(data, list) else data["operations"]
    tally = Counter(op["status"] for op in ops)
    if sum(tally.values()) != 116:
        raise SyncError(f"manifest must list 116 operations, found "
                        f"{sum(tally.values())}")
    unknown = set(tally) - {"supported", "partial", "unsupported"}
    if unknown:
        raise SyncError(f"unknown status values: {sorted(unknown)}")
    return {
        "total": sum(tally.values()),
        "supported": tally["supported"],
        "partial": tally["partial"],
        "by_code": 0,
        "by_design": tally["partial"],
        "unsupported": tally["unsupported"],
    }


def expected_totals_line(tally: dict[str, int]) -> str:
    return (f"**Inventory totals:** {tally['supported']} supported, "
            f"{tally['partial']} partial ({tally['by_code']} by code, "
            f"{tally['by_design']} by design), {tally['unsupported']} "
            f"unsupported; **{tally['total']} AWS S3 operations**.")


TOTALS_RE = re.compile(
    r"\*\*Inventory totals:\*\* \d+ supported, \d+ partial "
    r"\(\d+ by code, \d+ by design\), \d+ unsupported; "
    r"\*\*\d+ AWS S3 operations\*\*\.")

# The counters may be written as a plain dict literal or wrapped in
# Counter(...) — the latter is required once a status can reach zero,
# because a Counter has no key for a zero count.
COUNTER_RE = re.compile(
    r'"supported":\s*\d+,\s*"partial":\s*\d+,\s*"unsupported":\s*\d+,?')
BY_DESIGN_RE = re.compile(
    r'== (?:Counter\()?\{"by design": \d+\}(?:\))?')

META_ASSERT_RE = re.compile(
    r'assert \("\*\*Inventory totals:\*\* \d+ supported, \d+ partial "\n'
    r'\s+"\(0 by code, \d+ by design\), \d+ unsupported;"\) in specs')


def render_counter(tally: dict[str, int]) -> str:
    return (f'"supported":{tally["supported"]}, '
            f'"partial":{tally["partial"]}, '
            f'"unsupported":{tally["unsupported"]},')


def render_by_design(tally: dict[str, int]) -> str:
    # Counter(...) keeps the assertion meaningful when the count is zero.
    return f'== Counter({{"by design": {tally["by_design"]}}})'


def render_meta_assert(tally: dict[str, int]) -> str:
    return ('assert ("**Inventory totals:** '
            f'{tally["supported"]} supported, {tally["partial"]} partial "\n'
            f'            "(0 by code, {tally["by_design"]} by design), '
            f'{tally["unsupported"]} unsupported;") in specs')


def _rewrite(path: Path, pattern: re.Pattern, replacement: str,
             *, check: bool, problems: list[str]) -> None:
    body = path.read_text(encoding="utf-8")
    matches = pattern.findall(body)
    if len(matches) != 1:
        raise SyncError(f"{path.relative_to(ROOT)}: expected exactly one "
                        f"match for {pattern.pattern[:40]}…, found "
                        f"{len(matches)}")
    updated = pattern.sub(lambda _m: replacement, body, count=1)
    if updated == body:
        return
    if check:
        problems.append(str(path.relative_to(ROOT)))
        return
    path.write_text(updated, encoding="utf-8")
    print(f"updated {path.relative_to(ROOT)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="report drift without writing")
    args = parser.parse_args(argv)
    try:
        tally = counts()
    except SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    problems: list[str] = []
    try:
        _rewrite(SPECS, TOTALS_RE, expected_totals_line(tally),
                 check=args.check, problems=problems)
        _rewrite(ROUTE_GUARD, COUNTER_RE, render_counter(tally),
                 check=args.check, problems=problems)
        _rewrite(ROUTE_GUARD, BY_DESIGN_RE, render_by_design(tally),
                 check=args.check, problems=problems)
        _rewrite(META, META_ASSERT_RE, render_meta_assert(tally),
                 check=args.check, problems=problems)
    except SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    summary = (f"{tally['supported']} supported, {tally['partial']} partial "
               f"({tally['by_code']} by code, {tally['by_design']} by design), "
               f"{tally['unsupported']} unsupported")
    if args.check:
        if problems:
            print("DRIFT in: " + ", ".join(problems), file=sys.stderr)
            print(f"manifest says: {summary}", file=sys.stderr)
            print("run: python scripts/ops/sync_s3_inventory.py",
                  file=sys.stderr)
            return 1
        print(f"inventory in sync: {summary}")
        return 0
    print(f"inventory synced: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
