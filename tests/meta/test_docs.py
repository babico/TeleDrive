"""Documentation claims pinned by the test suite.

These checks are deliberately separate from the CI workflow contract tests:
they verify that public Markdown stays complete, truthful and consistent with
the operation manifest, not how GitHub Actions is wired.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_public_markdown_is_english_structured_and_locally_linked():
    """Keep public guides consistent after the documentation consolidation."""
    from urllib.parse import unquote

    guides = (
        "README.md",
        "CONTRIBUTING.md",
        "TODO.md",
        "docs/CI_WORKFLOWS.md",
        "docs/S3_SPECS.md",
        "docs/IMPLEMENTATION_STATUS.md",
        "docs/BACKUP_RESTORE.md",
        "docs/SECURITY.md",
    )
    turkish_glyphs = re.compile(r"[ğĞıİşŞçÇöÖüÜ]")
    for name in guides:
        path = ROOT / name
        content = path.read_text(encoding="utf-8")
        # Markdown fence contents may contain shell comments beginning '#'.
        # Those are source code, not document headings.
        prose_lines = []
        fenced = False
        for line in content.splitlines():
            if line.startswith(("~~~", "```")):
                fenced = not fenced
                continue
            if not fenced:
                prose_lines.append(line)
        prose = "\n".join(prose_lines)
        headings = re.findall(r"(?m)^#{1,6} (.+)$", prose)
        assert content.startswith("# ") and len(
            re.findall(r"(?m)^# ", prose)
        ) == 1, name
        assert sum(heading[0].isdigit() for heading in headings[1:]) >= 3, name
        assert not turkish_glyphs.search(content), name

        for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", content):
            target = target.split("#", 1)[0].strip()
            if not target or target.startswith(
                ("http://", "https://", "mailto:", "data:")
            ):
                continue
            resolved = (path.parent / unquote(target)).resolve()
            assert resolved.is_relative_to(ROOT), (name, target)
            assert resolved.exists(), (name, target)

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docker compose up -d --build" in readme
    assert "one container" in readme.lower()
    assert "a separate Docker Compose profile" not in readme
    assert not (ROOT / "website").exists()


def test_s3_compatibility_matrix_cannot_relabel_safe_lifecycle_as_full_aws():
    specs = (ROOT / "docs/S3_SPECS.md").read_text()
    assert ("**Inventory totals:** 114 supported, 0 partial "
            "(0 by code, 0 by design), 2 unsupported;") in specs
    for action in (
        "GetBucketLifecycleConfiguration", "PutBucketLifecycleConfiguration",
        "DeleteBucketLifecycle",
    ):
        prefix = "| [" + action + "](https://docs.aws.amazon.com"
        matches = [line for line in specs.splitlines() if line.startswith(prefix)]
        assert len(matches) == 1
        # Phase A promoted lifecycle to Supported — but the row must
        # document the GC integration honestly, not claim unconditional
        # physical deletion.
        assert "✅ Supported" in matches[0]
        if action == "PutBucketLifecycleConfiguration":
            assert "GC" in matches[0]
    assert "AbortIncompleteMultipartUpload" in specs
    assert "grace-fenced collection queue" in specs
    # The lifecycle E2E suite and the hourly evaluator are required.
    assert "tests/s3/test_s3_lifecycle.py" in (ROOT /
        ".github/workflows/quality-security.yml").read_text()
    assert "lifecycle_scheduler_loop()" in (ROOT / "web/app.py").read_text()


def test_todo_has_real_markdown_checklist_line_breaks_and_s3_tagging_contract():
    text = (ROOT / "TODO.md").read_text()
    assert r"\n- [x]" not in text
    assert r"\n- [ ]" not in text
    assert "- [x] Complete AWS-compatible PutBucketTagging" in text
    specs = (ROOT / "docs/S3_SPECS.md").read_text()
    assert r"\n\n**Implementation evidence:**" not in specs
    target = "| [PutBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html)"
    assert len([line for line in specs.splitlines() if line.startswith(target)]) == 1
    assert any(line.startswith(target) and "✅ Supported" in line
               for line in specs.splitlines())
    import json
    rows = json.loads((ROOT / "teledrive/s3/operation_manifest.json").read_text())["operations"]
    assert next(x["status"] for x in rows if x["name"] == "PutBucketTagging") == "supported"


def test_s3_specs_markdown_tables_render_as_complete_gfm_tables():
    """All GitHub-flavored Markdown tables need contiguous rows and delimiter."""
    content = (ROOT / "docs/S3_SPECS.md").read_text(encoding="utf-8")
    lines = content.splitlines()
    for artifact in (r"\n\n", r"\n|", r"\n- "):
        assert artifact not in content, ("literal escaped newline", artifact)
    groups = []
    current = []
    for lineno, line in enumerate(lines, 1):
        if line.startswith("|"):
            current.append((lineno, line))
        elif current:
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    assert groups, "S3 compatibility tables are missing"
    for group in groups:
        start = group[0][0]
        assert len(group) >= 2, ("orphan Markdown table row", start)
        columns = group[0][1].count("|")
        separator_cells = group[1][1].strip().strip("|").split("|")
        assert len(separator_cells) == columns - 1 and all(
            re.fullmatch(r":?-{3,}:?", cell.strip())
            for cell in separator_cells
        ), ("missing GitHub-flavored Markdown table delimiter", start)
        assert all(row.count("|") == columns for _, row in group), (
            "mismatched table columns", start
        )
    # Lifecycle operations are Supported since Phase A and must appear
    # as full rows in the section-3.1 table with the GC integration
    # documented.
    all_rows = [row for group in groups for _, row in group[2:]]
    for operation in ("GetBucketLifecycleConfiguration",
                      "PutBucketLifecycleConfiguration",
                      "DeleteBucketLifecycle"):
        row = next(row for row in all_rows if f"[{operation}]" in row)
        assert "| ✅ Supported |" in row, operation
        if operation == "PutBucketLifecycleConfiguration":
            # The write row must document the GC-integrated evaluator.
            assert "GC" in row, operation
    assert sum(
        line.startswith("| [") and
        "](https://docs.aws.amazon.com/AmazonS3/latest/API/" in line
        for line in lines
    ) == 116
