"""The documentation site is a build artifact, so it gets built and checked.

Three failure modes are worth a test rather than a review comment:

1. a page that exists on disk but is missing from `mkdocs.yml`'s navigation
   (it is then reachable only by URL and invisible to readers),
2. a relative link that points at nothing after a file move,
3. a placeholder that survived into main.

The real build (`mkdocs build --strict`) runs in the Docs workflow; these
checks run in the normal suite so a broken doc fails every PR, not only the
docs job.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
CONFIG = ROOT / "mkdocs.yml"

LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


class _Loader(yaml.SafeLoader):
    """SafeLoader that tolerates MkDocs' !!python/name syntax."""


def _ignore_tag(loader, tag_suffix, node):
    return None


_Loader.add_multi_constructor("tag:yaml.org,2002:python/name:", _ignore_tag)
_Loader.add_multi_constructor("!!python/name:", _ignore_tag)


def _config() -> dict:
    return yaml.load(CONFIG.read_text(encoding="utf-8"), Loader=_Loader) or {}


def _nav_targets(items) -> list[str]:
    found = []
    for item in items:
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            for value in item.values():
                if isinstance(value, str):
                    found.append(value)
                elif isinstance(value, list):
                    found.extend(_nav_targets(value))
    return found


def _excluded() -> tuple[str, ...]:
    block = _config().get("exclude_docs") or ""
    return tuple(line.strip().rstrip("*") for line in block.splitlines()
                 if line.strip())


def test_every_docs_page_is_in_the_navigation():
    targets = set(_nav_targets(_config()["nav"]))
    excluded = _excluded()
    pages = {
        str(path.relative_to(DOCS))
        for path in DOCS.rglob("*.md")
        if not any(str(path.relative_to(DOCS)).startswith(prefix)
                   for prefix in excluded)
    }
    assert not (targets - pages), (
        "mkdocs.yml points at pages that do not exist: "
        f"{sorted(targets - pages)}")
    assert not (pages - targets), (
        "docs pages missing from mkdocs.yml navigation: "
        f"{sorted(pages - targets)}")


def test_every_relative_link_resolves_inside_the_site():
    broken = []
    escaping = []
    for path in sorted(DOCS.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for raw in LINK.findall(text):
            target = raw.strip()
            if not target or target.startswith(
                    ("http://", "https://", "mailto:", "data:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / unquote(target)).resolve()
            if not resolved.is_relative_to(DOCS):
                # Published pages must not depend on files outside docs/;
                # link those with their GitHub URL instead.
                escaping.append((str(path.relative_to(ROOT)), raw))
                continue
            if not resolved.exists():
                broken.append((str(path.relative_to(ROOT)), raw))
    assert not escaping, f"links escaping docs/: {escaping}"
    assert not broken, f"broken relative links: {broken}"


def test_no_placeholder_survived_into_the_site():
    leftovers = [
        str(path.relative_to(ROOT))
        for path in DOCS.rglob("*.md")
        if "PLACEHOLDER" in path.read_text(encoding="utf-8")
    ]
    assert not leftovers, f"unwritten pages: {leftovers}"


def test_pages_are_english_titled_and_headed():
    """One H1, a real opening paragraph, and no Turkish-only prose."""
    turkish = re.compile(r"[ğĞıİşŞçÇöÖüÜ]")
    problems = []
    for path in sorted(DOCS.rglob("*.md")):
        rel = str(path.relative_to(DOCS))
        if rel.startswith(_excluded()):
            continue
        text = path.read_text(encoding="utf-8")
        prose = []
        fenced = False
        for line in text.splitlines():
            if line.startswith(("```", "~~~")):
                fenced = not fenced
                continue
            if not fenced:
                prose.append(line)
        body = "\n".join(prose)
        if len(re.findall(r"(?m)^# ", body)) != 1:
            problems.append((rel, "expected exactly one H1"))
        if not body.startswith("# "):
            problems.append((rel, "file must start with its H1"))
        if turkish.search(body):
            problems.append((rel, "non-English glyphs in prose"))
        # A page needs an opening sentence before its first heading break.
        first = body.split("\n", 1)[1].strip() if "\n" in body else ""
        if not first or first.startswith("## "):
            problems.append((rel, "missing opening paragraph"))
    assert not problems, problems


def test_readme_stays_an_introduction():
    """The README is a landing page; the manual lives in docs/."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert len(readme.splitlines()) <= 150, (
        "README grew back into a manual — move detail into docs/")
    assert readme.count("\n# ") == 0, "README must have exactly one H1"
    # It must still tell a stranger how to start the thing.
    assert "docker compose up -d --build" in readme
    assert "docs/index.md" in readme
