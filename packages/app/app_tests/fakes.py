"""In-memory GitHub and queue for app tests. Behaviour mirrors the REST semantics we rely on."""

from __future__ import annotations

import io
import itertools
import tarfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from accessguard_app.github.port import CommentOutsideDiff, Json

_ids = itertools.count(1000)


def tarball_from_dir(root: Path, prefix: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                tar.add(p, arcname=f"{prefix}/{p.relative_to(root).as_posix()}")
    return buf.getvalue()


@dataclass
class FakeRepo:
    id: int
    full_name: str
    default_branch: str = "main"
    commits: dict[str, Path] = field(default_factory=dict)  # sha -> source dir
    pulls: dict[int, Json] = field(default_factory=dict)
    permissions: dict[str, str] = field(default_factory=dict)


@dataclass
class FakeGitHub:
    installations: dict[int, Json] = field(default_factory=dict)
    repos: dict[str, FakeRepo] = field(default_factory=dict)
    inst_repos: dict[int, list[str]] = field(default_factory=dict)
    check_runs: dict[int, Json] = field(default_factory=dict)
    review_comments: dict[int, Json] = field(default_factory=dict)
    issue_comments: dict[int, Json] = field(default_factory=dict)
    issues: list[Json] = field(default_factory=list)
    reactions: dict[int, list[Json]] = field(default_factory=dict)
    failed_deliveries: list[Json] = field(default_factory=list)
    redelivered: list[int] = field(default_factory=list)
    redeliver_hook: Callable[[int], Awaitable[None]] | None = None
    oauth_codes: dict[str, tuple[str, int]] = field(default_factory=dict)  # code -> (verifier, uid)
    user_installations: dict[int, list[int]] = field(default_factory=dict)
    reject_lines: bool = False  # simulate 422 "line not part of the diff"

    # --- setup helpers -------------------------------------------------------------------------
    def add_repo(self, installation_id: int, full_name: str, repo_id: int) -> FakeRepo:
        r = FakeRepo(repo_id, full_name)
        self.repos[full_name] = r
        self.inst_repos.setdefault(installation_id, []).append(full_name)
        self.installations.setdefault(
            installation_id,
            {
                "id": installation_id,
                "account": {"id": 1, "login": "acme", "type": "Organization"},
                "repository_selection": "selected",
                "permissions": {},
            },
        )
        return r

    def repo_json(self, r: FakeRepo) -> Json:
        return {
            "id": r.id,
            "full_name": r.full_name,
            "default_branch": r.default_branch,
            "private": True,
            "archived": False,
            "fork": False,
        }

    def set_pull(
        self,
        repo: str,
        number: int,
        base: str,
        head: str,
        *,
        draft: bool = False,
        state: str = "open",
    ) -> None:
        self.repos[repo].pulls[number] = {
            "number": number,
            "state": state,
            "draft": draft,
            "head": {"sha": head},
            "base": {"sha": base, "ref": "main"},
        }

    # --- app ---------------------------------------------------------------------------------
    async def list_app_installations(self) -> list[Json]:
        return list(self.installations.values())

    async def get_installation(self, installation_id: int) -> Json | None:
        return self.installations.get(installation_id)

    async def list_failed_deliveries(self, since_id: int | None = None) -> list[Json]:
        return list(self.failed_deliveries)

    async def redeliver(self, delivery_id: int) -> None:
        self.redelivered.append(delivery_id)
        if self.redeliver_hook:
            await self.redeliver_hook(delivery_id)

    # --- user OAuth ---------------------------------------------------------------------------
    async def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> str:
        verifier, uid = self.oauth_codes.pop(code)
        if verifier != code_verifier:
            raise PermissionError("PKCE verifier mismatch")
        return f"ghu_{uid}"

    async def get_authenticated_user(self, user_token: str) -> Json:
        uid = int(user_token.removeprefix("ghu_"))
        return {"id": uid, "login": f"user{uid}"}

    async def list_user_installations(self, user_token: str) -> list[Json]:
        uid = int(user_token.removeprefix("ghu_"))
        return [self.installations[i] for i in self.user_installations.get(uid, [])]

    # --- installation -------------------------------------------------------------------------
    async def list_installation_repos(self, installation_id: int) -> list[Json]:
        return [self.repo_json(self.repos[n]) for n in self.inst_repos.get(installation_id, [])]

    async def get_pull(self, installation_id: int, repo: str, number: int) -> Json:
        return dict(self.repos[repo].pulls[number])

    async def compare(self, installation_id: int, repo: str, base: str, head: str) -> Json:
        return {"status": "ahead", "files": []}

    async def download_tarball(self, installation_id: int, repo: str, ref: str) -> bytes:
        r = self.repos[repo]
        src = r.commits[ref]
        return tarball_from_dir(src, f"{repo.replace('/', '-')}-{ref[:7]}")

    async def get_file(self, installation_id: int, repo: str, path: str, ref: str) -> bytes | None:
        f = self.repos[repo].commits[ref] / path
        return f.read_bytes() if f.is_file() else None

    async def list_languages(self, installation_id: int, repo: str) -> dict[str, int]:
        return {"Python": 1000}

    async def get_tree(self, installation_id: int, repo: str, sha: str) -> list[Json]:
        r = self.repos[repo]
        root = r.commits.get(sha) or next(iter(r.commits.values()))
        return [
            {"path": p.relative_to(root).as_posix(), "type": "blob"}
            for p in root.rglob("*")
            if p.is_file()
        ]

    async def list_commit_pulls(self, installation_id: int, repo: str, sha: str) -> list[Json]:
        return [p for p in self.repos[repo].pulls.values() if p["head"]["sha"] == sha]

    async def get_permission(self, installation_id: int, repo: str, username: str) -> str:
        return self.repos[repo].permissions.get(username, "read")

    async def create_check_run(self, installation_id: int, repo: str, body: Json) -> int:
        cid = next(_ids)
        self.check_runs[cid] = {"repo": repo, **body}
        return cid

    async def update_check_run(
        self, installation_id: int, repo: str, check_run_id: int, body: Json
    ) -> None:
        self.check_runs[check_run_id].update(body)

    async def create_review_comment(
        self, installation_id: int, repo: str, number: int, body: Json
    ) -> int:
        if self.reject_lines:
            raise CommentOutsideDiff("422 line must be part of the diff")
        cid = next(_ids)
        self.review_comments[cid] = {"repo": repo, "pr": number, **body}
        return cid

    async def update_review_comment(
        self, installation_id: int, repo: str, comment_id: int, body: str
    ) -> None:
        self.review_comments[comment_id]["body"] = body

    async def list_review_comment_reactions(
        self, installation_id: int, repo: str, comment_id: int, content: str
    ) -> list[Json]:
        return [r for r in self.reactions.get(comment_id, []) if r["content"] == content]

    async def list_issue_comments(self, installation_id: int, repo: str, number: int) -> list[Json]:
        return [c for c in self.issue_comments.values() if c["pr"] == number]

    async def create_issue_comment(
        self, installation_id: int, repo: str, number: int, body: str
    ) -> int:
        cid = next(_ids)
        self.issue_comments[cid] = {"repo": repo, "pr": number, "body": body}
        return cid

    async def update_issue_comment(
        self, installation_id: int, repo: str, comment_id: int, body: str
    ) -> None:
        self.issue_comments[comment_id]["body"] = body

    async def create_issue(self, installation_id: int, repo: str, title: str, body: str) -> int:
        self.issues.append({"repo": repo, "title": title, "body": body})
        return len(self.issues)


@dataclass
class Job:
    function: str
    args: tuple[Any, ...]
    job_id: str
    queue: str
    defer_by: float | None


class InMemoryQueue:
    """ARQ-like: a job id that is already queued is not enqueued again."""

    def __init__(self) -> None:
        self.jobs: list[Job] = []
        self.ids: set[str] = set()
        self.fail = False

    async def enqueue(
        self,
        function: str,
        *args: Any,
        job_id: str,
        queue: str = "high",
        defer_by: float | None = None,
    ) -> bool:
        if self.fail:
            raise ConnectionError("redis down")
        if job_id in self.ids:
            return False
        self.ids.add(job_id)
        self.jobs.append(Job(function, args, job_id, queue, defer_by))
        return True

    def take(self, function: str | None = None) -> list[Job]:
        out = [j for j in self.jobs if function is None or j.function == function]
        self.jobs = [j for j in self.jobs if j not in out]
        for j in out:
            self.ids.discard(j.job_id)
        return out
