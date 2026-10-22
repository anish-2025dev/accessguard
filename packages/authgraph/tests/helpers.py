from __future__ import annotations

import textwrap
from pathlib import Path

from authgraph.engine import analyze
from authgraph.facts.models import Endpoint
from authgraph.workspace.tree import DirectoryTree


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src).lstrip("\n"), encoding="utf-8")
    return root


def endpoints(root: Path, files: dict[str, str]) -> dict[str, Endpoint]:
    write_tree(root, files)
    return {e.id: e for e in analyze(DirectoryTree(root)).facts.endpoints}


DEPS = """
from fastapi import Depends, Header, HTTPException

def get_current_user(authorization: str = Header(...)):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"id": 1, "role": "user"}

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)
    return user
"""
