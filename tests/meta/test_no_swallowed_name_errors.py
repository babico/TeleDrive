"""A broad `except` must not be the only thing hiding a NameError.

Two real bugs in this codebase had exactly this shape, and both were silently
dead code for a long time:

* `_handle_batch_delete` called `RetainedMediaGC(db)` with no local `db`,
  inside `try: ... except Exception: pass`. The NameError was swallowed, so
  the "queue the media for GC" step never ran.
* Three S3 GC-integration paths called `RetainedMediaGC` without importing it,
  with the same swallowing `except`.

Neither produced a log line, a failed test, or an error response. The only
symptom was work that never happened.

This test resolves names with a real scope chain (locals → enclosing
functions → module → builtins), so a closure over an enclosing variable is
NOT a false positive, and flags only names that genuinely cannot resolve.
"""
from __future__ import annotations

import ast
import builtins
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__",
                                "__spec__", "__package__", "__loader__"}
BROAD = {"Exception", "BaseException"}


def _bindings(node: ast.AST) -> set[str]:
    """Every name this node's own body binds (not descending into nested defs'
    bodies for their internals, but their NAMES are bound here)."""
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(
                child.ctx, (ast.Store, ast.Del)):
            out.add(child.id)
        elif isinstance(child, ast.arg):
            out.add(child.arg)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                ast.ClassDef)):
            out.add(child.name)
            if child is not node:
                # Parameters of a nested function are not visible to us, and
                # neither are its internals: ast.walk already returned them,
                # so remove the ones we cannot legitimately see. Cheaper and
                # safer: re-add nothing and rely on the scope chain below.
                pass
        elif isinstance(child, ast.ExceptHandler) and child.name:
            out.add(child.name)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                out.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(child, ast.Global):
            out.update(child.names)
        elif isinstance(child, ast.Nonlocal):
            out.update(child.names)
    return out


def _module_bindings(tree: ast.Module) -> set[str]:
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                out.add((alias.asname or alias.name).split(".")[0])
        else:
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(
                        child.ctx, (ast.Store, ast.Del)):
                    out.add(child.id)
                elif isinstance(child, ast.ExceptHandler) and child.name:
                    out.add(child.name)
    return out


def _broad_handled_trys(fn: ast.AST) -> list[ast.Try]:
    found = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if handler.type is None:
                found.append(node)
                break
            if (isinstance(handler.type, ast.Name)
                    and handler.type.id in BROAD):
                found.append(node)
                break
    return found


def _walk_scopes(node: ast.AST, inherited: set[str], module: set[str],
                 findings: list):
    """Resolve each function with its real scope chain."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = inherited | _bindings(child) | module
            for try_node in _broad_handled_trys(child):
                loads = {n.id for n in ast.walk(try_node)
                         if isinstance(n, ast.Name)
                         and isinstance(n.ctx, ast.Load)}
                unknown = loads - scope - BUILTINS
                if unknown:
                    findings.append(
                        (child.name, try_node.lineno, sorted(unknown)))
            # Nested functions can close over this function's locals.
            _walk_scopes(child, scope, module, findings)
        elif isinstance(child, ast.ClassDef):
            _walk_scopes(child, inherited, module, findings)
        else:
            _walk_scopes(child, inherited, module, findings)


def _scan():
    findings = []
    for base in ("web", "teledrive", "scripts"):
        for path in (ROOT / base).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            module = _module_bindings(tree)
            local: list = []
            _walk_scopes(tree, set(), module, local)
            for name, line, unknown in local:
                findings.append(
                    f"{path.relative_to(ROOT).as_posix()}:{line} in {name}() "
                    f"-> {unknown}")
    return findings


def test_no_broad_except_hides_an_unresolvable_name():
    findings = _scan()
    assert findings == [], (
        "a `try/except Exception` block references a name that cannot "
        "resolve in its scope, so the error is swallowed and the code is "
        "dead:\n  " + "\n  ".join(findings))


def test_the_scanner_actually_detects_the_known_shape():
    """Guard against the scanner silently passing everything.

    The exact shape of the two real bugs, fed through the same resolver.
    """
    source = (
        "def broken(ctx):\n"
        "    catalog = ctx.catalog\n"
        "    try:\n"
        "        worker = RetainedMediaGC(db)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    tree = ast.parse(source)
    module = _module_bindings(tree)
    findings: list = []
    _walk_scopes(tree, set(), module, findings)
    assert findings, "the scanner failed to flag a genuinely unbound name"
    assert findings[0][2] == ["RetainedMediaGC", "db"]

    closure = (
        "def ok(ctx):\n"
        "    worker = None\n"
        "    def inner():\n"
        "        try:\n"
        "            return worker\n"
        "        except Exception:\n"
        "            pass\n"
        "    return inner\n"
    )
    tree = ast.parse(closure)
    module = _module_bindings(tree)
    findings = []
    _walk_scopes(tree, set(), module, findings)
    assert findings == [], f"closure over an enclosing local is not a bug: {findings}"
