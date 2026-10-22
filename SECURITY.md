# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on
this repository. Do not open a public issue. We aim to acknowledge within 3 working days and to
ship a fix or mitigation for confirmed high-severity issues within 30 days.

In scope: the `authgraph` engine and CLI, the GitHub App service, the sandbox and the runtime
verifier. Especially interesting:

- ways to make AccessGuard execute code from a scanned repository outside the sandbox;
- webhook forgery, installation hijack, or reading another installation's data;
- a pull request changing its own scan configuration (config must come from the base branch);
- prompt injection that makes the LLM add findings, reach tools, or see secrets;
- SSRF or credential leakage through the runtime verifier.

## Design controls (summary)

See `docs/PLAN.md` §5 "Security model" and the ADRs. Key points: HMAC-verified webhooks,
least-privilege App permissions (contents read, pull requests / checks / issues write, metadata
read), no source code stored after a scan, PR code never executed outside a disposable
network-less container, LLM is tool-less and may only downgrade findings.

## False negatives

AccessGuard is a review aid, not a guarantee. A missed access-control bug is a product bug, not
a security vulnerability in AccessGuard; please open a normal issue with a minimal reproduction.
