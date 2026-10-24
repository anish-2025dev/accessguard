"""Scripted end-to-end PRs against staging (PLAN.md §3 Phase 2 exit gate).

For every eval mutation case: push its base tree to ``e2e/<case>/base`` and its head tree on top
to ``e2e/<case>/head`` in a test repository where the staging App is installed, open a PR, wait
for the AccessGuard check run on the head commit, and compare the reported rule ids with the
case's ``case.yaml``. Prints per-case latency (PR opened -> check completed) and the p95.

    GH_E2E_TOKEN=<PAT with repo scope> python deploy/e2e/staging_e2e.py owner/test-repo

githubkit calls verified against 0.16.1: rest.pulls.async_create(owner, repo, data=),
rest.checks.async_list_for_ref(owner, repo, ref, check_name=), rest.pulls.async_update.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml
from githubkit import GitHub, TokenAuthStrategy

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "eval" / "mutations"
CHECK = "AccessGuard"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def push_case(repo: str, token: str, case: Path, work: Path) -> tuple[str, str]:
    url = f"https://x-access-token:{token}@github.com/{repo}.git"
    d = work / case.name
    d.mkdir()
    git(d, "init", "-q", "-b", "tmp")
    git(d, "config", "user.email", "e2e@accessguard.invalid")
    git(d, "config", "user.name", "accessguard-e2e")
    shutil.copytree(case / "base", d, dirs_exist_ok=True)
    git(d, "add", "-A")
    git(d, "commit", "-qm", f"{case.name} base")
    base = f"e2e/{case.name}/base"
    git(d, "push", "-qf", url, f"HEAD:refs/heads/{base}")
    for p in d.iterdir():
        if p.name != ".git":
            shutil.rmtree(p) if p.is_dir() else p.unlink()
    shutil.copytree(case / "head", d, dirs_exist_ok=True)
    git(d, "add", "-A")
    git(d, "commit", "-qm", f"{case.name} head", "--allow-empty")
    head = f"e2e/{case.name}/head"
    git(d, "push", "-qf", url, f"HEAD:refs/heads/{head}")
    return base, git(d, "rev-parse", "HEAD")


async def run_case(
    gh: GitHub[TokenAuthStrategy], repo: str, token: str, case: Path, work: Path
) -> dict[str, object]:
    owner, name = repo.split("/")
    base, head_sha = push_case(repo, token, case, work)
    t0 = time.perf_counter()
    pr = (
        await gh.rest.pulls.async_create(
            owner,
            name,
            data={
                "title": f"e2e {case.name}",
                "head": f"e2e/{case.name}/head",
                "base": base,
            },
        )
    ).json()
    try:
        deadline = time.time() + 300
        while time.time() < deadline:
            runs = (
                await gh.rest.checks.async_list_for_ref(owner, name, head_sha, check_name=CHECK)
            ).json()
            done = [
                r
                for r in runs["check_runs"]
                if r["status"] == "completed" and r["conclusion"] != "cancelled"
            ]
            if done:
                break
            await asyncio.sleep(3)
        else:
            return {"case": case.name, "ok": False, "error": "timeout"}
        latency = time.perf_counter() - t0
        summary = done[0]["output"]["summary"] or ""
        want = {e["rule_id"] for e in yaml.safe_load((case / "case.yaml").read_text())["expected"]}
        got = {
            r
            for r in ("AG-AUTH-001", "AG-AUTH-002", "AG-AUTH-003", "AG-ROLE-002", "AG-CFG-001")
            if f"`{r}`" in summary
        }
        return {
            "case": case.name,
            "ok": got == want,
            "want": sorted(want),
            "got": sorted(got),
            "latency_s": round(latency, 1),
            "conclusion": done[0]["conclusion"],
        }
    finally:
        await gh.rest.pulls.async_update(owner, name, pr["number"], data={"state": "closed"})


async def main() -> int:
    repo = sys.argv[1]
    token = os.environ["GH_E2E_TOKEN"]
    gh = GitHub(TokenAuthStrategy(token))
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in sorted(p for p in CASES.iterdir() if (p / "case.yaml").exists()):
            r = await run_case(gh, repo, token, case, Path(tmp))
            print(r)
            results.append(r)
    lat = sorted(float(r["latency_s"]) for r in results if "latency_s" in r)  # type: ignore[arg-type]
    p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else None
    ok = sum(bool(r["ok"]) for r in results)
    print(f"\n{ok}/{len(results)} cases matched; p95 latency {p95}s (gate: < 120s)")
    return 0 if ok == len(results) and p95 is not None and p95 < 120 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
