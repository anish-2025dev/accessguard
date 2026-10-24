"""Property test (PLAN.md §7 test pyramid): random FastAPI router trees rendered to source files,
enumerated statically, compared with a reference model of FastAPI's prefix/dependency semantics."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from authgraph.engine import analyze
from authgraph.facts.models import Verdict
from authgraph.workspace.tree import DirectoryTree
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from .helpers import DEPS, write_tree

SEG = st.sampled_from(["a", "b", "items", "v1", "{id}", "x-y"])
METHODS = st.sampled_from(["get", "post", "delete"])
# Guards are rare so that each one decides some endpoint's verdict on its own.
GUARD = st.sampled_from([False, False, False, True])


@dataclass
class R:
    prefix: str
    guarded: bool  # APIRouter(dependencies=[Depends(get_current_user)])
    routes: list[tuple[str, str, bool]]  # (method, path, param guard)
    includes: list[tuple[int, str, bool]] = field(default_factory=list)  # (child, prefix, guarded)


@st.composite
def trees(draw: st.DrawFn) -> list[R]:
    n = draw(st.integers(1, 5))
    routers = []
    for _ in range(n):
        prefix = draw(st.sampled_from(["", "/" + draw(SEG)]))
        routes = draw(st.lists(st.tuples(METHODS, SEG.map(lambda s: "/" + s), GUARD), max_size=3))
        routers.append(R(prefix, draw(GUARD), routes))
    for i in range(1, n):  # include every router from an earlier one: a DAG rooted at 0
        parent = draw(st.integers(0, i - 1))
        routers[parent].includes.append(
            (i, draw(st.sampled_from(["", "/" + draw(SEG)])), draw(GUARD))
        )
    return routers


def render(routers: list[R]) -> dict[str, str]:
    files = {"deps.py": DEPS}
    for i, r in enumerate(routers):
        deps = ", dependencies=[Depends(get_current_user)]" if r.guarded else ""
        src = [
            "from fastapi import APIRouter, Depends",
            "from deps import get_current_user",
            *[f"from r{c} import router as r{c}" for c, _, _ in r.includes],
            f'router = APIRouter(prefix="{r.prefix}"{deps})',
        ]
        for j, (m, path, guard) in enumerate(r.routes):
            arg = "u=Depends(get_current_user)" if guard else ""
            src += [f'@router.{m}("{path}")', f"def h{j}({arg}): ..."]
        for c, prefix, guarded in r.includes:
            d = ", dependencies=[Depends(get_current_user)]" if guarded else ""
            src.append(f'router.include_router(r{c}, prefix="{prefix}"{d})')
        files[f"r{i}.py"] = "\n".join(src) + "\n"
    files["main.py"] = (
        "from fastapi import FastAPI\nfrom r0 import router\napp = FastAPI()\n"
        "app.include_router(router)\n"
    )
    return files


def reference(routers: list[R]) -> dict[str, bool]:
    """Expected endpoint id -> authenticated, first registration wins (like the engine)."""
    out: dict[str, bool] = {}

    def walk(i: int, prefix: str, guarded: bool) -> None:
        r = routers[i]
        here = prefix + r.prefix
        g = guarded or r.guarded
        for m, path, pg in r.routes:
            out.setdefault(f"{m.upper()} {here + path}", g or pg)
        for c, p, ig in r.includes:
            walk(c, here + p, g or ig)

    walk(0, "", False)
    return out


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(trees())
def test_static_enumeration_matches_reference(routers: list[R]) -> None:
    with tempfile.TemporaryDirectory() as d:
        root = write_tree(Path(d), render(routers))
        got = {e.id: e.authn for e in analyze(DirectoryTree(root)).facts.endpoints}
    want = reference(routers)
    assert set(got) == set(want)
    for ep, auth in want.items():
        assert got[ep] == (Verdict.AUTH if auth else Verdict.NO_AUTH), ep
