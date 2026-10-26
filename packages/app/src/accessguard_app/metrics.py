"""Prometheus metrics (PLAN.md §7 observability)."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

WEBHOOKS = Counter("accessguard_webhooks_total", "Webhook deliveries by outcome", ["outcome"])
WEBHOOK_LATENCY = Histogram("accessguard_webhook_intake_seconds", "Webhook intake latency")
SCANS = Counter("accessguard_scans_total", "Scans by trigger and outcome", ["trigger", "outcome"])
SCAN_PHASE = Histogram(
    "accessguard_scan_phase_seconds",
    "Scan duration by phase",
    ["phase"],
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)
FINDINGS = Counter("accessguard_findings_total", "Findings posted", ["rule_id", "tier"])
SUPERSEDED = Counter("accessguard_scans_superseded_total", "Scans cancelled by a newer head")
UNKNOWN_RATE = Histogram(
    "accessguard_unknown_rate",
    "UNKNOWN endpoint share per scan",
    buckets=(0.01, 0.05, 0.1, 0.2, 0.5, 1.0),
)
REDELIVERED = Counter("accessguard_redelivered_total", "Failed deliveries redelivered")
RATE_LIMITED = Counter("accessguard_github_rate_limited_total", "GitHub rate-limit backoffs")


def render() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
