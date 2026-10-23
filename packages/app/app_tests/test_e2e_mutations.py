"""Every eval mutation case through the full delivery path: signed webhook -> outbox -> router ->
scan_pr (tarballs, authgraph) -> reporter. The check-run summary must name exactly the expected
rules, and the per-scan latency is reported (PLAN.md §3 Phase 2: p95 < 2 minutes)."""

from __future__ import annotations

import re
import time

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


async def test_llm_judge_can_only_suppress_and_is_reported(services: Services) -> None:
    """With a judge configured, an advisory IDOR finding it suppresses disappears from the
    report and the summary counts it; deterministic findings are never sent to the judge."""
    from authgraph.facts.models import TriageResult
    from authgraph.llm.fake import FakeJudge

    judge = FakeJudge(lambda f, c: TriageResult(decision="suppress", reason="read-only lookup"))
    services.judge = judge
    try:
        base, head = setup_repo(services, "m42_idor_user_not_tied_to_object")
        await install(services)
        g = gh(services)
        g.set_pull(REPO, 1, base, head)
        await post_event(services, "pull_request", pr_payload("opened", number=1))
        await drain(services, include={"route_delivery", "scan_pr"})
        summary = next(c for c in g.check_runs.values() if c["head_sha"] == head)["output"]
        assert "AG-IDOR-002" not in summary["summary"]
        assert "1 heuristic/advisory finding(s) suppressed by LLM triage" in summary["summary"]
        assert {c.rule_id for c in judge.seen} == {"AG-IDOR-002"}
        assert len(judge.seen) == 3  # IDOR judgements are majority-voted
    finally:
        services.judge = None
