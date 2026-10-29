"""Every Alpine expression a page evaluates must resolve to a definition.

``node --check`` only proves a JavaScript file parses. Nothing proved that
the markup's ``@click``/``x-text`` expressions call methods that the assets
loaded by *that* page actually define. Optional component fragments
(``credentials.js``, ``buckets.js``) make that gap real: the fragment is
loaded on one page and spread into ``app()`` only when present, so a page
that calls a fragment method without loading the fragment fails at runtime,
after login, in the browser.

This test is deliberately structural: it parses the HTML attributes and the
JavaScript definition shapes rather than executing Alpine.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "web" / "static"

SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)

# Alpine attributes whose expression can call a component method. Event
# handlers (@click, @change, ...) are all included; x-data is not, because
# its expression is the component factory, not a page method call.
ALPINE_ATTR_RE = re.compile(
    r"""(?:@[A-Za-z0-9_.:\-]+|x-(?:text|show|model|html|init))\s*=\s*
        (?:"([^"]*)"|'([^']*)')""",
    re.X,
)

# A bare call: an identifier followed by "(", not a property access
# (`this.toast(`, `corsRules.splice(`) and not an already-namespaced name.
CALL_RE = re.compile(r"(?<![\w.$])([A-Za-z_$][\w$]*)\s*\(")

# Method/function definition shapes used by app.js and the fragment files:
#   async name(args){ / name(args) { / name: function (args) { / name: async(...)
METHOD_DEF_RE = re.compile(
    r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{", re.M)
PROP_DEF_RE = re.compile(
    r"^\s*([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?function\s*\([^)]*\)\s*\{", re.M)
PROP_ASYNC_RE = re.compile(
    r"^\s*([A-Za-z_$][\w$]*)\s*:\s*async\s*\([^)]*\)\s*\{", re.M)

RESERVED = {
    "if", "for", "while", "switch", "catch", "function", "return", "typeof",
    "new", "delete", "throw", "await", "async", "do", "else", "in", "of",
    "instanceof", "void", "yield", "with", "try", "finally", "class", "const",
    "let", "var",
}

GLOBALS = {
    "Math", "JSON", "Object", "Array", "Number", "String", "Boolean", "Date",
    "Set", "Map", "RegExp", "Error", "Promise", "Intl", "isNaN", "parseInt",
    "parseFloat", "encodeURIComponent", "decodeURIComponent", "encodeURI",
    "decodeURI", "fetch", "confirm", "prompt", "alert", "setTimeout",
    "setInterval", "clearTimeout", "clearInterval", "requestAnimationFrame",
    "WebSocket", "URL", "URLSearchParams", "Blob", "File", "FileReader",
    "FormData", "Uint8Array", "ArrayBuffer", "TextEncoder", "TextDecoder",
    "navigator", "document", "window", "location", "localStorage",
    "sessionStorage", "console", "structuredClone", "btoa", "atob", "BigInt",
    "Symbol", "Reflect", "Proxy", "queueMicrotask", "addEventListener",
}

# Files that export an Alpine fragment spread into app(). They are optional:
# app.js guards the spread, so a page that never loads them simply does not
# get the methods. Such a page must not call them.
GROUP_FILES = {"credentials.js", "buckets.js"}


def script_sources(page: Path) -> list[str]:
    return SCRIPT_SRC_RE.findall(page.read_text(encoding="utf-8"))


def static_path(src: str) -> Path:
    """Map a script src to the file on disk."""
    if src.startswith("/static/"):
        return STATIC / src[len("/static/"):]
    return STATIC / src.lstrip("/")


def defined_names(js: Path) -> set[str]:
    text = js.read_text(encoding="utf-8")
    names = set(METHOD_DEF_RE.findall(text))
    names |= set(PROP_DEF_RE.findall(text))
    names |= set(PROP_ASYNC_RE.findall(text))
    return names - RESERVED


def strip_strings(expr: str) -> str:
    """Drop quoted literals so prose like 'Search results (' is not read as a call."""
    out: list[str] = []
    quote: str | None = None
    escaped = False
    for char in expr:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"', "`"):
            quote = char
            continue
        out.append(char)
    return "".join(out)


def called_names(html: str) -> set[str]:
    names: set[str] = set()
    for match in ALPINE_ATTR_RE.finditer(html):
        expr = match.group(1) if match.group(1) is not None else match.group(2)
        names |= set(CALL_RE.findall(strip_strings(expr)))
    return names - RESERVED - GLOBALS


def is_group_file(path: Path) -> bool:
    if path.name in GROUP_FILES:
        return True
    if path.parent.name == "vendor":
        return False
    text = path.read_text(encoding="utf-8")
    return bool(re.search(r"global\.[A-Za-z_$][\w$]*(?:State|Methods)\s*=", text))


def test_every_page_method_call_is_defined_and_loaded_in_order():
    problems: list[str] = []
    pages = sorted(STATIC.glob("*.html"))
    assert pages, "no HTML pages found"

    for page in pages:
        html = page.read_text(encoding="utf-8")
        scripts = script_sources(page)
        loaded = [static_path(src) for src in scripts]
        loaded = [path for path in loaded if path.exists()]

        # app.js is the component factory and must be there for x-data="app()".
        app_js = STATIC / "app.js"
        assert app_js in loaded, f"{page.name}: does not load /static/app.js"

        definitions: dict[str, set[Path]] = {}
        for js in loaded:
            for name in defined_names(js):
                definitions.setdefault(name, set()).add(js)

        app_index = loaded.index(app_js)
        for method in sorted(called_names(html)):
            owners = definitions.get(method)
            if not owners:
                problems.append(
                    f"{page.name}: calls {method}() but no loaded script defines it")
                continue
            # If an optional fragment defines the method, the fragment must be
            # present before app.js on this page. If app.js also defines the
            # method, the app.js definition is enough (but note the shadow).
            group_owners = [owner for owner in owners if is_group_file(owner)]
            if not group_owners:
                continue
            if any(owner in loaded and loaded.index(owner) < app_index
                   for owner in group_owners):
                continue
            details = []
            for owner in group_owners:
                if owner not in loaded:
                    details.append(f"{owner.name} not loaded")
                else:
                    details.append(f"{owner.name} after app.js")
            problems.append(
                f"{page.name}: calls {method}() from "
                + ", ".join(sorted(owner.name for owner in group_owners))
                + f" ({'; '.join(details)})")

    assert not problems, "page/method composition failures:\n" + "\n".join(problems)


def test_fragment_pages_load_fragment_before_app():
    """Explicit ordering contract for the optional component fragments."""
    for page in sorted(STATIC.glob("*.html")):
        scripts = script_sources(page)
        if "/static/app.js" not in scripts:
            continue
        app_at = scripts.index("/static/app.js")
        for src in scripts:
            path = static_path(src)
            if path.exists() and is_group_file(path):
                assert scripts.index(src) < app_at, (
                    f"{page.name}: {src} must load before /static/app.js")
