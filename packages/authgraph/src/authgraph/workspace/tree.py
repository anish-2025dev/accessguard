"""``SourceTree``: the files of one commit, with git blob SHAs. Nothing here executes code."""

from __future__ import annotations

import fnmatch
import hashlib
import re
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".tox", "site-packages"}
)
MAX_FILE_BYTES = 2_000_000


def blob_sha(data: bytes) -> str:
    """Git's blob object id, so directory and git trees share one summary cache."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


TEST_DIRS = frozenset({"tests", "test", "testing", "__tests__", "cypress", "e2e"})


JS_TEST_NAME = re.compile(r"\.(test|spec|e2e-spec|cy)\.[cm]?[jt]sx?$")
GENERATED_DIRS = frozenset(
    {"node_modules", "dist", "build", ".next", "coverage", "out", "bower_components"}
)


def is_test_path(path: str) -> bool:
    """Test code never ships routes, so it never produces findings (default exclusion)."""
    parts = path.split("/")
    name = parts[-1]
    return (
        bool(TEST_DIRS & set(parts[:-1]))
        or name.startswith("test_")
        or name in {"conftest.py"}
        or name.endswith("_test.py")
        or bool(JS_TEST_NAME.search(name))
    )


def is_generated_path(path: str) -> bool:
    """Vendored dependencies and build output are not the code under review."""
    parts = set(path.split("/")[:-1])
    return bool(GENERATED_DIRS & parts) or path.endswith((".min.js", ".bundle.js", ".d.ts"))


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatch(path, p) or PurePosixPath(path).match(p) or path.startswith(p.rstrip("*"))
        for p in patterns
        if p
    )


class SourceTree(Protocol):
    commit_sha: str

    def paths(self) -> list[str]: ...
    def blob_sha(self, path: str) -> str: ...
    def read(self, path: str) -> bytes: ...
    def exists(self, path: str) -> bool: ...


@dataclass
class DirectoryTree:
    root: Path
    commit_sha: str = "worktree"
    exclude: list[str] = field(default_factory=list)
    _shas: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _paths: list[str] | None = field(default=None, init=False, repr=False)

    def _walk(self) -> Iterator[str]:
        for p in sorted(self.root.rglob("*")):
            rel = p.relative_to(self.root)
            if SKIP_DIRS & set(rel.parts) or not p.is_file() or p.is_symlink():
                continue
            posix = rel.as_posix()
            if not matches_any(posix, self.exclude):
                yield posix

    def paths(self) -> list[str]:
        if self._paths is None:
            self._paths = list(self._walk())
        return self._paths

    def read(self, path: str) -> bytes:
        return (self.root / path).read_bytes()

    def exists(self, path: str) -> bool:
        return path in set(self.paths())

    def blob_sha(self, path: str) -> str:
        if path not in self._shas:
            self._shas[path] = blob_sha(self.read(path))
        return self._shas[path]


@dataclass
class GitTree:
    """Files at ``rev`` read straight from the object database (no checkout)."""

    repo: Path
    rev: str
    exclude: list[str] = field(default_factory=list)
    commit_sha: str = ""
    _entries: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _cache: dict[str, bytes] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.commit_sha = self._git("rev-parse", f"{self.rev}^{{commit}}").strip()
        out = self._git("ls-tree", "-r", "-z", "--full-tree", self.commit_sha)
        for rec in out.split("\0"):
            if not rec:
                continue
            meta, path = rec.split("\t", 1)
            mode, kind, sha = meta.split()
            if kind != "blob" or mode == "120000":  # skip symlinks and submodules
                continue
            if SKIP_DIRS & set(path.split("/")) or matches_any(path, self.exclude):
                continue
            self._entries[path] = sha

    def _git(self, *args: str) -> str:
        return subprocess.run(  # noqa: S603 - fixed git argv, no shell
            ["git", "-C", str(self.repo), *args],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def paths(self) -> list[str]:
        return sorted(self._entries)

    def exists(self, path: str) -> bool:
        return path in self._entries

    def blob_sha(self, path: str) -> str:
        return self._entries[path]

    def read(self, path: str) -> bytes:
        if path not in self._cache:
            self._cache[path] = subprocess.run(  # noqa: S603
                ["git", "-C", str(self.repo), "cat-file", "blob", self._entries[path]],  # noqa: S607
                check=True,
                capture_output=True,
            ).stdout
        return self._cache[path]


def open_tree(spec: str | Path, exclude: list[str] | None = None) -> SourceTree:
    """``spec`` is a directory, or ``<repo>@<rev>`` / a bare rev resolved in the current repo."""
    s = str(spec)
    if "@" in s and not Path(s).exists():
        repo, rev = s.rsplit("@", 1)
        return GitTree(Path(repo or "."), rev, exclude or [])
    p = Path(s)
    if p.is_dir():
        return DirectoryTree(p, exclude=exclude or [])
    return GitTree(Path("."), s, exclude or [])
