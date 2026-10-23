"""Markdown for review comments, check-run summaries and push issues (no analysis here)."""

from __future__ import annotations

from collections.abc import Sequence

from authgraph.facts.models import Finding

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
MARKER = "<!-- accessguard:{fp} -->"
INTRO = (
    "👋 **AccessGuard** reviews pull requests for access-control regressions: who can access "
    "what, and did this change make it worse? It reports only what this PR changes. Configure it "
    "with `.accessguard.yml` on the default branch; reply `@accessguard ignore <id> <reason>` to "
    "dismiss a finding or `@accessguard scan` to re-run.\n\n"
)


def marker(fp: str) -> str:
    return MARKER.format(fp=fp)


def short(fp: str) -> str:
    return fp[:10]


def comment_body(f: Finding) -> str:
    lines = [
        f"{ICON[f.severity]} **{f.rule_id}** · {f.severity} · {f.title}",
        "",
        "**Evidence**",
    ]
    for step in f.evidence:
        where = f" (`{step.loc.path}:{step.loc.line}`)" if step.loc else ""
        lines.append(f"- {step.message}{where}")
    if f.suggested_fix:
        lines += ["", f"**Fix:** {f.suggested_fix}"]
    lines += [
        "",
        f"<sub>id `{short(f.fingerprint)}` · 👎 if not useful · "
        f"`@accessguard ignore {short(f.fingerprint)} <reason>`</sub>",
        marker(f.fingerprint),
    ]
    return "\n".join(lines)


def resolved_body(old: str, sha: str) -> str:
    if old.startswith("✅ Resolved"):
        return old
    return (
        f"✅ Resolved in {sha[:7]}.\n\n<details><summary>Original finding</summary>\n\n"
        f"{old}\n</details>"
    )


def summary(
    findings: Sequence[Finding],
    *,
    resolved: int,
    unknown: int,
    endpoints: int,
    intro: bool,
    demoted: Sequence[str] = (),
) -> tuple[str, str]:
    """(check-run title, summary markdown)."""
    inline = [f for f in findings if f.tier == "deterministic"]
    advisory = [f for f in findings if f.tier != "deterministic"]
    if not findings:
        title = "No access-control regressions"
    else:
        title = f"{len(findings)} access-control finding(s) introduced by this change"
    out = [INTRO if intro else ""]
    out.append(
        f"Endpoints analysed: **{endpoints}** · unknown verdicts: {unknown} · "
        f"resolved since last scan: {resolved}\n"
    )
    if inline:
        out.append("### Findings")
        out += [
            f"- {ICON[f.severity]} `{f.rule_id}` {f.title} (`{f.loc.path}:{f.loc.line}`, "
            f"id `{short(f.fingerprint)}`)"
            for f in inline
        ]
    if advisory:
        out.append("\n### Advisory (not posted inline)")
        out += [f"- `{f.rule_id}` {f.title} (`{f.loc.path}:{f.loc.line}`)" for f in advisory]
    if demoted:
        out.append(
            "\n<sub>Shown as advisory because their effective false-positive rate exceeds "
            f"10%: {', '.join(demoted)}</sub>"
        )
    return title, "\n".join(o for o in out if o is not None)


def comment_body_from_row(row: object) -> str:
    """Rebuild the original comment text for a stored finding (for the resolved note)."""
    rule = getattr(row, "rule_id", "")
    sev = getattr(row, "severity", "") or "low"
    steps = getattr(row, "evidence", None) or []
    lines = [f"{ICON.get(sev, '')} **{rule}** · {sev} · {getattr(row, 'endpoint_id', '') or ''}"]
    lines += [f"- {s.get('message', '')}" for s in steps if isinstance(s, dict)]
    lines.append(marker(getattr(row, "fingerprint", "")))
    return "\n".join(lines)
