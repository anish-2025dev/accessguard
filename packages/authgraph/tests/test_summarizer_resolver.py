import json
import textwrap
from pathlib import Path

from authgraph.cache.summaries import MemoryCache
from authgraph.engine import summarize_tree
from authgraph.lang.python.resolver import ProjectIndex
from authgraph.lang.python.summarizer import compat_rewrite, summarize
from authgraph.workspace.tree import DirectoryTree, GitTree, blob_sha

from .helpers import write_tree


def _fn(src: str, name: str):  # type: ignore[no-untyped-def]
    return summarize("m.py", textwrap.dedent(src).encode(), "x").functions[name]


def test_raise_conditions_follow_if_else_paths() -> None:
    fn = _fn(
        """
        def g(user):
            if user.role == "admin":
                return user
            else:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        """,
        "g",
    )
    (r,) = fn.raises
    assert r.status == 403
    assert json.loads(r.condition or "") == ["not", ["atom", "'admin' == user.role"]]


def test_exception_variable_and_swallowed_except() -> None:
    fn = _fn(
        """
        def g(token):
            credentials_exception = HTTPException(status_code=401)
            try:
                payload = jwt.decode(token, KEY)
            except JWTError:
                logger.warning("bad token")
            if payload is None:
                raise credentials_exception
        """,
        "g",
    )
    assert fn.token_decode and fn.raises[0].status == 401
    assert fn.excepts[0].body == "log_only"


def test_sinks_and_mass_assignment() -> None:
    fn = _fn(
        """
        def h(item_id, body, user, db):
            item = db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()
            db.execute(delete(Item).where(Item.id == item_id))
            for k, v in body.model_dump(exclude={"role"}).items():
                setattr(item, k, v)
            Other(**body.dict())
        """,
        "h",
    )
    kinds = [(s.kind, s.model, s.predicate_names) for s in fn.sinks]
    assert ("read", "Item", ["item_id", "user"]) in kinds
    assert ("delete", "Item", ["item_id"]) in kinds
    assert [(m.source, m.excluded) for m in fn.mass_assign] == [("body", []), ("body", ["role"])][
        ::-1
    ] or {(m.source, tuple(m.excluded)) for m in fn.mass_assign} == {
        ("body", ("role",)),
        ("body", ()),
    }


def test_pep758_rewrite_keeps_lines() -> None:
    src = b"try:\n    x()\nexcept A, B:\n    raise HTTPException(401)\n"
    assert compat_rewrite(src).count(b"\n") == src.count(b"\n")
    s = summarize(
        "m.py", b"def f():\n" + b"".join(b"    " + ln + b"\n" for ln in src.splitlines()), "x"
    )
    assert s.parse_error is None and s.functions["f"].raises[0].line == 5


def test_resolver_relative_reexport_and_package_submodule(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "backend/app/__init__.py": "",
            "backend/app/api/__init__.py": "from .deps import get_user as current\n",
            "backend/app/api/deps.py": "def get_user(): ...\n",
            "backend/app/api/routes/__init__.py": "",
            "backend/app/api/routes/items.py": "router = 1\n",
            "backend/app/main.py": (
                "from app.api import current\nfrom app.api.routes import items\nimport app.api.deps\n"
            ),
        },
    )
    summaries, _ = summarize_tree(DirectoryTree(tmp_path), MemoryCache())
    ix = ProjectIndex(summaries)
    main = "backend/app/main.py"
    t = ix.resolve(main, "", "current")
    assert (t.kind, t.path, t.name) == ("function", "backend/app/api/deps.py", "get_user")
    t = ix.resolve(main, "", "items.router")
    assert (t.kind, t.path) == ("assign", "backend/app/api/routes/items.py")
    t = ix.resolve(main, "", "app.api.deps.get_user")
    assert t.kind == "function"
    assert ix.resolve(main, "", "fastapi.Depends").kind == "unresolved"


def test_git_tree_matches_directory_blob_shas(tmp_path: Path) -> None:
    import subprocess

    write_tree(tmp_path, {"a.py": "x = 1\n", "pkg/b.py": "y = 2\n"})
    for cmd in (
        ["init", "-q"],
        ["add", "."],
        ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
    ):
        subprocess.run(["git", "-C", str(tmp_path), *cmd], check=True)
    g = GitTree(tmp_path, "HEAD")
    d = DirectoryTree(tmp_path)
    assert g.paths() == d.paths() == ["a.py", "pkg/b.py"]
    assert g.blob_sha("a.py") == d.blob_sha("a.py") == blob_sha(b"x = 1\n")


def test_summary_cache_hits_by_blob(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "x = 1\n", "b/a.py": "x = 1\n"})
    cache = MemoryCache()
    summaries, cov = summarize_tree(DirectoryTree(tmp_path), cache)
    assert cov.cache_hits == 1 and summaries["b/a.py"].module == "b.a"
    _, cov2 = summarize_tree(DirectoryTree(tmp_path), cache)
    assert cov2.cache_hits == 2


def test_namespace_packages_resolve(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "svc/__init__.py": "",
            "svc/routes/views.py": "router = 1\n",
            "svc/main.py": "from svc.routes import views\nimport svc.routes.views\n",
        },
    )
    summaries, _ = summarize_tree(DirectoryTree(tmp_path), MemoryCache())
    ix = ProjectIndex(summaries)
    assert ix.resolve("svc/main.py", "", "views.router").path == "svc/routes/views.py"
    assert ix.resolve("svc/main.py", "", "svc.routes.views.router").path == "svc/routes/views.py"


def test_method_scope_skips_class_body(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "lib.py": "def build(): ...\n",
            "m.py": "from lib import build\nclass C:\n    def build(self):\n        return build()\n",
        },
    )
    summaries, _ = summarize_tree(DirectoryTree(tmp_path), MemoryCache())
    t = ProjectIndex(summaries).resolve("m.py", "C.build", "build")
    assert (t.path, t.name) == ("lib.py", "build")


def test_early_return_conditions_later_raise() -> None:
    fn = _fn(
        """
        def g(user):
            if user:
                return user
            raise HTTPException(status_code=401)
        """,
        "g",
    )
    assert json.loads(fn.raises[0].condition or "") == ["not", ["atom", "user"]]
