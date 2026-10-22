"""Runs INSIDE the network-less route-truth sandbox (never on the host; ADR 005).

Imports a FastAPI application and prints its runtime route table as JSON:

    {"app": "backend/app/main.py:app", "routes": [{"method": "GET", "path": "/items/{id}",
     "kind": "APIRoute"}, ...], "errors": [...]}

``target`` is "<file>:<variable>" or "auto". With "auto", candidates are found statically
(module-level ``X = FastAPI(...)``, or ``X = factory()`` where a same-module factory builds a
FastAPI) and the one with the most routes wins.

Handles both route-table shapes: classic flat ``app.routes`` and FastAPI >= 0.16x lazy
``_IncludedRouter`` entries (expanded via ``effective_candidates()``; verified against fastapi
0.161.0 source, ``fastapi/routing.py``). Mounted sub-apps are walked with their mount prefix.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import traceback
from pathlib import Path
from typing import Any

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "tests", "test", "migrations", "alembic"}
FRAMEWORK_DOC_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def discover(root: Path) -> list[str]:
    out = []
    for path in sorted(root.rglob("*.py")):
        if SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        factories = {"FastAPI"} | {
            fn.name
            for fn in tree.body
            if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef) and _builds_app(fn)
        }
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and _call_name(node.value.func) in factories
            ):
                out += [
                    f"{path.relative_to(root)}:{t.id}"
                    for t in node.targets
                    if isinstance(t, ast.Name)
                ]
    return out


def _builds_app(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Factory functions (``def get_application() -> FastAPI``) count as app constructors."""
    if fn.returns is not None and _call_name(fn.returns) == "FastAPI":
        return True
    return any(isinstance(n, ast.Call) and _call_name(n.func) == "FastAPI" for n in ast.walk(fn))


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _module_name(root: Path, file: Path) -> tuple[Path, str]:
    """Pick the sys.path root: the highest ancestor dir that keeps the file inside a package."""
    pkg_root = file.parent
    while (pkg_root / "__init__.py").exists() and pkg_root != root:
        pkg_root = pkg_root.parent
    rel = file.relative_to(pkg_root).with_suffix("")
    return pkg_root, ".".join(rel.parts)


def load(root: Path, target: str) -> Any:
    file_s, var = target.rsplit(":", 1)
    file = (root / file_s).resolve()
    sys_root, mod = _module_name(root, file)
    for p in (str(root), str(sys_root)):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location(mod, file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod] = module
    spec.loader.exec_module(module)
    return getattr(module, var)


def walk(routes: list[Any], prefix: str = "") -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for rt in routes:
        if hasattr(rt, "effective_candidates"):  # FastAPI lazy include (_IncludedRouter)
            out += walk(rt.effective_candidates(), prefix)
            continue
        original = getattr(rt, "original_route", rt)  # _EffectiveRouteContext wraps the route
        kind = type(original).__name__
        path = getattr(rt, "path", None) or getattr(original, "path", "")
        sub = getattr(original, "routes", None)
        if kind == "Mount" or (sub is not None and not getattr(original, "methods", None)):
            out += walk(list(sub or []), prefix + path)
            continue
        methods = sorted(getattr(original, "methods", None) or [])
        if "GET" in methods and "HEAD" in methods:
            methods.remove("HEAD")  # Starlette adds HEAD to every GET route
        if not methods:
            out.append(
                {
                    "method": "WS" if "WebSocket" in kind else "ANY",
                    "path": prefix + path,
                    "kind": kind,
                }
            )
        for m in methods:
            out.append({"method": m, "path": prefix + path, "kind": kind})
    return out


def dump(root: Path, target: str) -> dict[str, Any]:
    candidates = discover(root) if target == "auto" else [target]
    best: dict[str, Any] = {"app": None, "routes": [], "errors": []}
    for cand in candidates:
        try:
            app = load(root, cand)
            routes = [r for r in walk(list(app.routes)) if r["path"] not in FRAMEWORK_DOC_PATHS]
        except BaseException:
            best["errors"].append({"app": cand, "error": traceback.format_exc(limit=3)})
            continue
        if len(routes) > len(best["routes"]):
            best.update(app=cand, routes=routes)
    best["routes"].sort(key=lambda r: (r["path"], r["method"]))
    best["candidates"] = candidates
    return best


if __name__ == "__main__":
    json.dump(dump(Path(sys.argv[1]), sys.argv[2]), sys.stdout, indent=2)
    sys.stdout.write("\n")
