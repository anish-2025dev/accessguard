"""Every eval mutation case through the full delivery path: signed webhook -> outbox -> router ->
scan_pr (tarballs, authgraph) -> reporter. The check-run summary must name exactly the expected
rules, and the per-scan latency is reported (PLAN.md §3 Phase 2: p95 < 2 minutes)."""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

import yaml
from accessguard_app.runtime import Services

from .conftest import drain
from .test_app_flow import MUTATIONS, REPO, gh, install, post_event, pr_payload, setup_repo

RULE = re.compile(r"`(AG-[A-Z]+-\d{3})`")


async def test_all_mutation_cases_end_to_end(services: Services) -> None:
    cases = sorted(p for p in MUTATIONS.iterdir() if (p / "case.yaml").exists())
    g = gh(services)
    latencies = []
    mismatches = []
    for n, case in enumerate(cases, start=1):
        base, head = setup_repo(services, case.name) if n == 1 else _add(services, case.name)
        if n == 1:
            await install(services)
        g.set_pull(REPO, n, base, head)
        t0 = time.perf_counter()
        await post_event(services, "pull_request", pr_payload("opened", number=n))
        await drain(services, include={"route_delivery", "scan_pr"})
        latencies.append(time.perf_counter() - t0)
        check = next(c for c in g.check_runs.values() if c["head_sha"] == head)
        got = set(RULE.findall(check["output"]["summary"]))
        want = {e["rule_id"] for e in yaml.safe_load((case / "case.yaml").read_text())["expected"]}
        if got != want:
            mismatches.append((case.name, sorted(want), sorted(got)))
    latencies.sort()
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
    print(f"\n{len(cases)} cases, p50 {latencies[len(latencies) // 2]:.2f}s, p95 {p95:.2f}s")
    assert mismatches == []
    assert p95 < 120


def _add(services: Services, case: str) -> tuple[str, str]:
    r = gh(services).repos[REPO]
    base, head = f"b{case[:6]}".ljust(40, "0"), f"h{case[:6]}".ljust(40, "0")
    r.commits[base] = MUTATIONS / case / "base"
    r.commits[head] = MUTATIONS / case / "head"
    return base, head


async def test_llm_judge_is_opt_in_can_only_suppress_and_is_reported(
    services: Services, tmp_path: Path
) -> None:
    """With a judge configured and the repository opted in (base-branch ``llm.provider``), an
    advisory IDOR finding it suppresses disappears from the report and the summary counts it.
    Without the opt-in nothing is sent to the judge."""
    from authgraph.facts.models import TriageResult
    from authgraph.llm.fake import FakeJudge

    judge = FakeJudge(lambda f, c: TriageResult(decision="suppress", reason="read-only lookup"))
    services.judge = judge
    try:
        case = "m42_idor_user_not_tied_to_object"
        base, head = setup_repo(services, case)
        await install(services)
        g = gh(services)
        # Without opt-in: the judge is never called and the advisory finding is reported.
        g.set_pull(REPO, 2, base, head)
        await post_event(services, "pull_request", pr_payload("opened", number=2))
        await drain(services, include={"route_delivery", "scan_pr"})
        assert judge.seen == []
        # Opt in on the base branch.
        opted = tmp_path / "base"
        shutil.copytree(MUTATIONS / case / "base", opted)
        (opted / ".accessguard.yml").write_text("version: 1\nllm:\n  provider: api\n")
        base = "c".ljust(40, "0")
        g.repos[REPO].commits[base] = opted
        g.set_pull(REPO, 1, base, head)
        await post_event(services, "pull_request", pr_payload("opened", number=1))
        await drain(services, include={"route_delivery", "scan_pr"})
        runs = [c for c in g.check_runs.values() if c["head_sha"] == head]
        assert "AG-IDOR-002" in runs[0]["output"]["summary"]  # PR 2, not opted in
        summary = runs[-1]["output"]  # PR 1, opted in
        assert "AG-IDOR-002" not in summary["summary"]
        assert "1 heuristic/advisory finding(s) suppressed by LLM triage" in summary["summary"]
        assert {c.rule_id for c in judge.seen} == {"AG-IDOR-002"}
        assert len(judge.seen) == 3  # IDOR judgements are majority-voted
    finally:
        services.judge = None
