"""Guard seeds and feature scoring for JavaScript middleware (FR-7.6, Express; Phase 3).

Same contract as ``guards/scoring.py``: a middleware is a guard when it can stop a request
(responds 401/403, hands an auth error to ``next(err)``, or is a known security primitive).
Confidence below ``CONFIRMED`` never makes an endpoint AUTH.

Known primitives, by package (APIs checked against each package's README / type definitions):
  express-jwt 8: ``expressjwt({secret, credentialsRequired})``  (credentialsRequired: false =>
    optional)  https://github.com/auth0/express-jwt#readme
  passport 0.7: ``passport.authenticate(strategy, options)``; the "anonymous" strategy never
    rejects  https://www.passportjs.org/concepts/authentication/middleware/
  express-openid-connect 2: ``requiresAuth()``; ``auth({authRequired})`` (default true)
    https://auth0.github.io/express-openid-connect/
  express-oauth2-jwt-bearer 1: ``auth()``, ``requiredScopes()``, ``claimCheck()``,
    ``claimEquals()``, ``claimIncludes()``  https://auth0.github.io/node-oauth2-jwt-bearer/
  connect-ensure-login: ``ensureLoggedIn()``; express-basic-auth: default export;
  @clerk/express: ``requireAuth()`` (rejects), ``clerkMiddleware()`` (attaches, never rejects)
    https://clerk.com/docs/references/express/overview
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from authgraph.facts.models import GuardKind, OnFail
from authgraph.guards.scoring import AUTH_NAME, AUTHZ_NAME, GuardInfo
from authgraph.lang.js.summary import JsFunction

# "<package>.<export>" -> guard. Export "default" is the package's default export.
KNOWN_GUARDS: dict[str, tuple[GuardKind, float]] = {
    "express-jwt.expressjwt": (GuardKind.AUTHN, 0.95),
    "express-jwt.default": (GuardKind.AUTHN, 0.95),  # express-jwt < 7 default export `jwt()`
    "passport.authenticate": (GuardKind.AUTHN, 0.9),
    "passport.default.authenticate": (GuardKind.AUTHN, 0.9),
    "express-openid-connect.requiresAuth": (GuardKind.AUTHN, 0.95),
    "express-openid-connect.auth": (GuardKind.AUTHN, 0.9),
    "express-oauth2-jwt-bearer.auth": (GuardKind.AUTHN, 0.95),
    "express-oauth2-jwt-bearer.requiredScopes": (GuardKind.AUTHZ_ROLE, 0.95),
    "express-oauth2-jwt-bearer.claimCheck": (GuardKind.AUTHZ_ROLE, 0.9),
    "express-oauth2-jwt-bearer.claimEquals": (GuardKind.AUTHZ_ROLE, 0.9),
    "express-oauth2-jwt-bearer.claimIncludes": (GuardKind.AUTHZ_ROLE, 0.9),
    "connect-ensure-login.ensureLoggedIn": (GuardKind.AUTHN, 0.9),
    "express-basic-auth.default": (GuardKind.AUTHN, 0.95),
    "@clerk/express.requireAuth": (GuardKind.AUTHN, 0.95),
    "@clerk/clerk-sdk-node.ClerkExpressRequireAuth": (GuardKind.AUTHN, 0.95),
}
# Middleware that attaches identity but never rejects.
KNOWN_OPTIONAL = frozenset(
    {
        "@clerk/express.clerkMiddleware",
        "@clerk/clerk-sdk-node.ClerkExpressWithAuth",
        "passport.session",
        "passport.default.session",
        "express-session.default",
    }
)
# Calls that reject the request themselves when made inside a local middleware.
REJECTING_CALLS = re.compile(
    r"(^|\.)(authenticate|requiresAuth|expressjwt|ensureLoggedIn|requireAuth|protect)$"
)
# Token checks that only verify; the middleware must reject on failure itself.
VERIFY_CALLS = re.compile(
    r"(^|\.)(verify|verifyIdToken|verifySessionCookie|verifyToken|jwtVerify|decode|getSession|"
    r"getUser|getServerSession|validateToken|introspect)$"
)
OPTIONAL_NAME = re.compile(r"(optional|maybe|soft|attach|populate|identify)", re.I)


def known_external(name: str, options: dict[str, str]) -> GuardInfo | None:
    """``name`` is "<package>.<export>"; ``options`` are literal options of the call."""
    if name in KNOWN_OPTIONAL:
        return GuardInfo(GuardKind.OPTIONAL_AUTHN, 0.9, "none")
    hit = KNOWN_GUARDS.get(name)
    if hit is None:
        return None
    kind, conf = hit
    if options.get("credentialsRequired") == "false" or options.get("authRequired") == "false":
        return GuardInfo(GuardKind.OPTIONAL_AUTHN, conf, "none")
    if options.get("strategy") == "anonymous":
        return GuardInfo(GuardKind.OPTIONAL_AUTHN, conf, "none")
    return GuardInfo(kind, conf, "raise")


def classify_function(fn: JsFunction, helpers: Sequence[JsFunction], name: str) -> GuardInfo | None:
    """Score a local middleware function (and the local helpers it calls)."""
    statuses = set(fn.statuses)
    calls = list(fn.calls)
    role = fn.role_compare
    owner = fn.owner_compare
    next_error = fn.next_error
    for h in helpers:
        statuses |= set(h.statuses)
        calls += h.calls
        role = role or h.role_compare
        owner = owner or h.owner_compare
        next_error = next_error or h.next_error
    named = bool(AUTH_NAME.search(name))
    rejecting = any(REJECTING_CALLS.search(c) for c in calls)
    verifies = any(VERIFY_CALLS.search(c) for c in calls)
    on_fail: OnFail = "return_4xx" if statuses else "raise"
    if OPTIONAL_NAME.search(name) and 403 not in statuses and 401 not in statuses:
        if named or verifies:
            return GuardInfo(GuardKind.OPTIONAL_AUTHN, 0.8, "none")
        return None
    if 403 in statuses or (404 in statuses and owner):
        kind = GuardKind.AUTHZ_OWNER if owner and not role else GuardKind.AUTHZ_ROLE
        strong = role or owner or bool(AUTHZ_NAME.search(name)) or 401 in statuses or rejecting
        return GuardInfo(kind, 0.85 if strong else (0.8 if named else 0.6), on_fail)
    if 401 in statuses or rejecting:
        return GuardInfo(GuardKind.AUTHN, 0.9 if (named or rejecting) else 0.8, on_fail)
    if next_error and (verifies or named) and fn.calls_next:
        return GuardInfo(GuardKind.AUTHN, 0.8 if named else 0.7, "raise")
    if named and verifies and fn.calls_next:
        # Verifies a token but lets every request through: identity only, or a fake guard.
        if fn.logs:
            return GuardInfo(GuardKind.FAKE, 0.8, "log_only")
        return GuardInfo(GuardKind.OPTIONAL_AUTHN, 0.7, "none")
    if named and fn.calls_next and fn.logs and not fn.sends:
        return GuardInfo(GuardKind.FAKE, 0.6, "log_only")
    return None
