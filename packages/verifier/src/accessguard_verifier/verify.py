"""Verification plans and the deterministic comparator (RV-3; PLAN.md §6.14).

A plan is a list of tool calls. The default planner builds it from templates; an optional LLM
planner may propose a different sequence, but its steps are validated against the generated
tool schemas before anything runs, and the outcome is always decided here, by comparing
responses, never by a model:

* missing authentication (AG-AUTH-*): the anonymous identity gets 2xx -> ``verified``;
* missing role check (AG-ROLE-001): ``user_b`` (a non-admin test account) gets 2xx -> verified;
* IDOR (AG-IDOR-*): ``user_a`` creates a marked fixture, ``user_b`` addresses it by id and gets
  2xx (with ``user_a``'s marker in the body for reads) -> ``verified``.

401/403/404 for the attacking identity -> ``refuted``. Anything else (5xx, no credential, policy
refusal, no way to obtain an id) -> ``inconclusive``. Fixtures are deleted afterwards when the
flagged endpoint allows it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from accessguard_verifier.broker import Broker, Observation
from accessguard_verifier.tools import Identity, Target, Toolset

Decision = Literal["verified", "refuted", "inconclusive"]


@dataclass
class Step:
    tool: Literal["call_as", "create_fixture"]
    args: dict[str, Any]
    attack: bool = False  # the step whose response decides
    use_fixture: str | None = None  # path param to fill with the created fixture id


@dataclass
class Plan:
    target: Target
    steps: list[Step]
    needs_marker: bool = False


@dataclass
class Result:
    fingerprint: str
    endpoint_id: str
    rule_id: str
    decision: Decision
    reason: str
    observations: list[Observation] = field(default_factory=list)


class Planner(Protocol):
    def plan(self, target: Target, tools: Toolset) -> Plan | None: ...


class TemplatePlanner:
    def plan(self, target: Target, tools: Toolset) -> Plan | None:
        idor = target.rule_id.startswith("AG-IDOR")
        attacker: Identity = "anonymous"
        if target.rule_id == "AG-ROLE-001" or idor:
            attacker = "user_b"
        if attacker not in tools.identities:
            return None
        if not target.params:
            if target.method not in {"GET", "HEAD"}:
                return None  # a write on a real object would be needed: never done
            return Plan(
                target,
                [
                    Step(
                        "call_as",
                        {"identity": attacker, "endpoint": target.endpoint_id},
                        attack=True,
                    )
                ],
            )
        if target.endpoint_id not in tools.collections or "user_a" not in tools.identities:
            return None  # no way to obtain an id of an object we own
        steps = [
            Step("create_fixture", {"identity": "user_a", "endpoint": target.endpoint_id}),
            Step(
                "call_as",
                {"identity": attacker, "endpoint": target.endpoint_id},
                attack=True,
                use_fixture=target.params[-1],
            ),
        ]
        return Plan(target, steps, needs_marker=idor and target.method in {"GET", "HEAD"})


def validate(plan: Plan, tools: Toolset) -> str | None:
    """A proposed plan may only use generated tools, flagged endpoints and known identities."""
    names = {t["name"] for t in tools.schemas()}
    for s in plan.steps:
        if s.tool not in names:
            return f"unknown tool {s.tool}"
        if s.args.get("identity") not in tools.identities:
            return "unknown identity"
        allowed = tools.collections if s.tool == "create_fixture" else tools.targets
        if s.args.get("endpoint") not in allowed:
            return "endpoint not flagged"
    if sum(s.attack for s in plan.steps) != 1:
        return "a plan has exactly one deciding step"
    return None


def decide(plan: Plan, attack: Observation | None) -> tuple[Decision, str]:
    if attack is None or attack.status is None:
        return "inconclusive", (
            attack.refused if attack else None
        ) or "the deciding call did not run"
    s = attack.status
    who = attack.identity
    if 200 <= s < 300:
        if plan.needs_marker and not attack.marker_seen:
            return "inconclusive", f"{who} got {s} but the response does not contain the fixture"
        if plan.needs_marker:
            return "verified", f"{who} read user_a's object ({s}, fixture marker present)"
        return "verified", f"{who} got {s} from {attack.method} {attack.path}"
    if s in {401, 403, 404}:
        return "refuted", f"{who} got {s}: access is enforced at runtime"
    return "inconclusive", f"{who} got {s}"


async def run_plan(plan: Plan, broker: Broker) -> Result:
    t = plan.target
    obs: list[Observation] = []
    fixture: str | None = None
    attack: Observation | None = None
    for s in plan.steps:
        if s.tool == "create_fixture":
            o = await broker.create_fixture(
                s.args["identity"], s.args["endpoint"], s.args.get("body")
            )
            obs.append(o)
            fixture = o.created_id
            if fixture is None:
                return Result(
                    t.finding,
                    t.endpoint_id,
                    t.rule_id,
                    "inconclusive",
                    o.refused or f"fixture not created ({o.status})",
                    obs,
                )
            continue
        params = dict(s.args.get("path_params") or {})
        if s.use_fixture and fixture is not None:
            params[s.use_fixture] = fixture
        o = await broker.call_as(s.args["identity"], s.args["endpoint"], params)
        obs.append(o)
        if s.attack:
            attack = o
    decision, reason = decide(plan, attack)
    if fixture is not None and fixture in broker.policy.fixtures:
        cleanup = await broker.delete_fixture("user_a", t.endpoint_id, fixture)
        if cleanup.status is not None:  # 404 after a successful attacker DELETE is fine
            obs.append(cleanup)
    return Result(t.finding, t.endpoint_id, t.rule_id, decision, reason, obs)


async def verify(tools: Toolset, broker: Broker, planner: Planner | None = None) -> list[Result]:
    planner = planner or TemplatePlanner()
    out: list[Result] = []
    for target in tools.targets.values():
        plan = planner.plan(target, tools)
        if plan is None:
            out.append(
                Result(
                    target.finding,
                    target.endpoint_id,
                    target.rule_id,
                    "inconclusive",
                    "no safe plan for this endpoint",
                )
            )
            continue
        problem = validate(plan, tools)
        if problem is not None:
            out.append(
                Result(
                    target.finding,
                    target.endpoint_id,
                    target.rule_id,
                    "inconclusive",
                    f"plan rejected: {problem}",
                )
            )
            continue
        out.append(await run_plan(plan, broker))
    return out
