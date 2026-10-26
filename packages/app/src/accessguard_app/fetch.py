"""Fetch a commit's source as data only (ADR 005): tarball -> temp dir, deleted after the scan.

Extraction keeps regular files only (no symlinks, hard links or devices), strips GitHub's
``owner-repo-sha/`` top directory, rejects absolute and ``..`` paths, and caps total size.
"""

from __future__ import annotations

import io
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from accessguard_app.github.port import GitHubPort

MAX_MEMBER_BYTES = 2_000_000


class TarballTooLarge(Exception):
    pass


def safe_extract(data: bytes, dest: Path, max_total: int) -> int:
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for m in tar:
            if not m.isreg() or m.size > MAX_MEMBER_BYTES:
                continue
            parts = PurePosixPath(m.name).parts[1:]  # drop owner-repo-sha/
            if not parts or any(p in ("..", "") for p in parts) or m.name.startswith("/"):
                continue
            total += m.size
            if total > max_total:
                raise TarballTooLarge(f"source exceeds {max_total} bytes")
            target = dest.joinpath(*parts)
            if not target.resolve().is_relative_to(dest.resolve()):
                continue
            src = tar.extractfile(m)
            if src is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as out:
                shutil.copyfileobj(src, out)
    return total


@contextmanager
def checkout(data: bytes, max_total: int) -> Iterator[Path]:
    root = Path(tempfile.mkdtemp(prefix="ag-src-"))
    try:
        safe_extract(data, root, max_total)
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)  # no source code kept after the scan


async def fetch_tarball(gh: GitHubPort, installation_id: int, repo: str, sha: str) -> bytes:
    return await gh.download_tarball(installation_id, repo, sha)
