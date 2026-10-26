"""dump_routes runs inside the sandbox; here we test its pure parts with stand-in route objects."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_spec = importlib.util.spec_from_file_location(
    "ag_dump_routes", Path(__file__).parents[1] / "sandbox" / "dump_routes.py"
)
assert _spec and _spec.loader
dump_routes = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = dump_routes
_spec.loader.exec_module(dump_routes)


class APIRoute:
    def __init__(self, path: str, methods: set[str]) -> None:
        self.path, self.methods = path, methods


class Route:
    def __init__(self, path: str, methods: set[str]) -> None:
        self.path = path
        self.methods = methods | {"HEAD"} if "GET" in methods else methods


class Mount:
    def __init__(self, path: str, routes: list[Any]) -> None:
        self.path, self.routes = path, routes


class _EffectiveRouteContext:
    def __init__(self, path: str, original_route: Any) -> None:
        self.path, self.original_route = path, original_route


class _IncludedRouter:
    def __init__(self, candidates: list[Any]) -> None:
        self._c = candidates

    def effective_candidates(self) -> list[Any]:
        return self._c


def test_walk_flat_mount_and_lazy_include() -> None:
    routes = [
        APIRoute("/a", {"GET", "HEAD"}),
        Route("/starlette", {"GET"}),
        Route("/head-only", {"HEAD"}),
        Mount("/sub", [APIRoute("/x", {"POST"})]),
        _IncludedRouter(
            [_EffectiveRouteContext("/p/y", APIRoute("/y", {"DELETE"})), _IncludedRouter([])]
        ),
    ]
    got = {(r["method"], r["path"]) for r in dump_routes.walk(routes)}
    assert got == {
        ("GET", "/a"),
        ("HEAD", "/a"),
        ("GET", "/starlette"),
        ("HEAD", "/head-only"),
        ("POST", "/sub/x"),
        ("DELETE", "/p/y"),
    }


def test_discover_finds_module_level_fastapi_assignments(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "main.py").write_text("import fastapi\napp = fastapi.FastAPI()\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    assert dump_routes.discover(tmp_path) == ["pkg/main.py:app"]


def test_discover_follows_same_module_factory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "def get_application() -> FastAPI:\n    return FastAPI()\n"
        "app = get_application()\n"
    )
    assert dump_routes.discover(tmp_path) == ["main.py:app"]


@pytest.mark.parametrize("initial_routes", [[], [APIRoute("/initial", {"GET"})]])
def test_dump_collects_routes_after_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, initial_routes: list[Any]
) -> None:
    app = SimpleNamespace(routes=list(initial_routes))
    monkeypatch.setattr(dump_routes, "load", lambda *_: app)
    monkeypatch.setattr(
        dump_routes, "run_lifespan", lambda app: app.routes.append(APIRoute("/startup", {"POST"}))
    )
    result = dump_routes.dump(tmp_path, "main.py:app")
    paths = {r["path"] for r in result["routes"]}
    assert paths == {r.path for r in initial_routes} | {"/startup"}
    assert result["errors"] == []


def test_dump_falls_back_to_pre_startup_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = SimpleNamespace(routes=[APIRoute("/initial", {"GET"})])
    monkeypatch.setattr(dump_routes, "load", lambda *_: app)

    def startup(app: Any) -> None:
        app.routes.append(APIRoute("/incomplete", {"POST"}))
        raise RuntimeError("sandbox cannot connect to database")

    monkeypatch.setattr(dump_routes, "run_lifespan", startup)
    result = dump_routes.dump(tmp_path, "main.py:app")
    assert [r["path"] for r in result["routes"]] == ["/initial"]
    assert "sandbox cannot connect" in result["errors"][0]["error"]
