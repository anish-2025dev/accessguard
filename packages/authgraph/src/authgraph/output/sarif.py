"""SARIF 2.1.0 output for code-scanning upload.

Validated in tests against the OASIS schema (tests/data/sarif-schema-2.1.0.json). GitHub-specific
fields follow https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
(``properties.security-severity``, ``partialFingerprints``, repo-relative ``artifactLocation.uri``).
"""

from __future__ import annotations

from typing import Any

from authgraph import __version__
from authgraph.facts.models import Finding
from authgraph.rules import ALL_RULES

SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
PRECISION = {
    "deterministic": "high",
    "heuristic": "medium",
    "advisory": "low",
    "verified": "very-high",
}


def _rule(r: Any) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.__class__.__name__,
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": (r.__doc__ or r.title).strip().split("\n\n")[0]},
        "properties": {
            "tags": ["security", "access-control"],
            "security-severity": SECURITY_SEVERITY[r.default_severity],
            "precision": PRECISION[r.tier],
        },
    }


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    results = []
    for f in findings:
        msg = f.title
        if f.evidence:
            msg += "\n" + "\n".join(f"- {s.message}" for s in f.evidence)
        results.append(
            {
                "ruleId": f.rule_id,
                "level": LEVEL[f.severity],
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.loc.path},
                            "region": {"startLine": max(f.loc.line, 1)},
                        }
                    }
                ],
                "partialFingerprints": {"accessguardFingerprint/v1": f.fingerprint},
                "properties": {
                    "security-severity": SECURITY_SEVERITY[f.severity],
                    "tier": f.tier,
                    "endpoint": f.endpoint_id or f.resource or "",
                },
            }
        )
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AccessGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/anish-2025dev/accessguard",
                        "rules": [_rule(r) for r in ALL_RULES],
                    }
                },
                "results": results,
            }
        ],
    }
