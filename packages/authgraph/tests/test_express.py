"""Express support (FR-3.1/3.2 Express, PLAN.md §6.4 guard chain): summarizer, resolver, graph."""

from __future__ import annotations

from pathlib import Path

from authgraph.api import diff_trees
from authgraph.facts.models import GuardKind, Verdict
from authgraph.lang.js.summarizer import summarize
from authgraph.workspace.tree import DirectoryTree

from .helpers import endpoints, write_tree

AUTH = """
const { expressjwt } = require('express-jwt');
const requireAuth = expressjwt({ secret: 's', algorithms: ['HS256'] });
const optionalAuth = expressjwt({ secret: 's', algorithms: ['HS256'], credentialsRequired: false });
function requireAdmin(req, res, next) {
  if (req.auth.role !== 'admin') return res.status(403).json({});
  next();
}
module.exports = { requireAuth, optionalAuth, requireAdmin };
"""


def _verdicts(tmp: Path, files: dict[str, str]) -> dict[str, Verdict]:
    return {k: e.authn for k, e in endpoints(tmp, files).items()}


def test_summary_imports_exports_and_loops() -> None:
    s = summarize(
        "src/a.ts",
        b"""
import express, { Router as R } from 'express';
import * as auth from './auth';
const { x } = require('./x');
export const router = R();
for (const { name } of models) { router.get(`/api/${name}s`, h); }
export default router;
""",
        "sha",
    )
    assert s.imports["express"].name == "default"
    assert s.imports["R"].name == "Router"
    assert s.imports["auth"].name == "*"
    assert s.imports["x"].source == "./x"
    assert {"router", "default"} <= set(s.exports)
    loop = next(f for f in s.functions.values() if "#for@" in f.id)
    assert loop.params == ["{name:name}"]
    route = loop.events[0].value
    assert route.args[0].k == "tmpl"


def test_mount_tree_middleware_order_and_router_level_guards(tmp_path: Path) -> None:
    v = _verdicts(
        tmp_path,
        {
            "auth.js": AUTH,
            "admin.js": """
                const router = require('express').Router();
                const { requireAdmin } = require('./auth');
                router.use(requireAdmin);
                router.delete('/users/:id', (req, res) => res.end());
                module.exports = router;
            """,
            "app.js": """
                const express = require('express');
                const { requireAuth } = require('./auth');
                const app = express();
                app.get('/early', (req, res) => res.end());
                app.use('/api', requireAuth);
                app.get('/api/me', (req, res) => res.json({}));
                app.use('/api/admin', require('./admin'));
                app.get('/apix', (req, res) => res.end());
            """,
        },
    )
    assert v["GET /early"] == Verdict.NO_AUTH  # registered before the middleware
    assert v["GET /api/me"] == Verdict.AUTH
    assert v["DELETE /api/admin/users/:id"] == Verdict.AUTH
    assert v["GET /apix"] == Verdict.NO_AUTH  # "/api" is a path-segment prefix, not a string one


def test_route_chains_router_chains_and_route_tables(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "auth.js": AUTH,
            "users.js": """
                const express = require('express');
                const { requireAuth } = require('./auth');
                const router = express.Router();
                router.route('/:id').get(requireAuth, (req, res) => res.json({}))
                  .delete((req, res) => res.end());
                module.exports = router;
            """,
            "index.js": """
                const express = require('express');
                const router = express.Router();
                const routes = [{ path: '/users', route: require('./users') }];
                routes.forEach((r) => { router.use(r.path, r.route); });
                module.exports = router;
            """,
            "app.ts": """
                import express, { Router } from 'express';
                import v1 from './index';
                const app = express();
                app.use(Router().use('/v1', v1));
            """,
        },
    )
    assert eps["GET /v1/users/:id"].authn == Verdict.AUTH
    assert eps["DELETE /v1/users/:id"].authn == Verdict.NO_AUTH


def test_guard_factories_optional_jwt_and_terminal_handlers(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "auth.js": AUTH,
            "security.ts": """
                import expressJwt from 'express-jwt';
                export const isAuthorized = () => expressJwt({ secret: 'k' });
                export const isAccounting = () => (req, res, next) => {
                  if (req.user.role === 'accounting') { next() } else { res.status(403).end() }
                };
            """,
            "app.ts": """
                import express from 'express';
                import * as security from './security';
                const { optionalAuth } = require('./auth');
                const app = express();
                app.get('/a', security.isAuthorized(), (req, res) => res.end());
                app.get('/b', security.isAccounting(), (req, res) => res.end());
                app.get('/c', optionalAuth, (req, res) => res.end());
                app.post('/login', (req, res, next) => {
                  if (!req.body.ok) return res.status(401).end();
                  res.json({ token: 't' });
                });
                app.use((err, req, res, next) => res.status(401).end());
            """,
        },
    )
    assert eps["GET /a"].authn == Verdict.AUTH
    assert eps["GET /a"].guards[0].symbol == "security.isAuthorized"
    assert eps["GET /b"].guards[0].kind == GuardKind.AUTHZ_ROLE
    assert eps["GET /c"].authn == Verdict.NO_AUTH  # credentialsRequired: false
    # A handler that answers 401 itself is the endpoint, not a guard; the error handler is not
    # a guard either.
    assert eps["POST /login"].authn == Verdict.NO_AUTH
    assert eps["POST /login"].late_guards == []


def test_guard_only_routes_unless_and_finale(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "auth.js": AUTH,
            "app.js": """
                const express = require('express');
                const finale = require('finale-rest');
                const { requireAuth } = require('./auth');
                const app = express();
                app.use('/rest', requireAuth.unless({ path: ['/rest/open'] }));
                app.get('/rest/open', (req, res) => res.end());
                app.get('/rest/closed', (req, res) => res.end());
                app.get('/api/Users', requireAuth);
                finale.initialize({ app });
                for (const { name } of [{ name: 'User' }, { name: 'Card' }]) {
                  finale.resource({ endpoints: [`/api/${name}s`, `/api/${name}s/:id`] });
                }
            """,
        },
    )
    assert eps["GET /rest/open"].authn == Verdict.NO_AUTH
    assert eps["GET /rest/closed"].authn == Verdict.AUTH
    # finale-rest generated CRUD routes; the guard-only registration protects GET /api/Users.
    assert eps["GET /api/Users"].authn == Verdict.AUTH
    assert not eps["GET /api/Users"].guard_only
    assert eps["PUT /api/Cards/:id"].authn == Verdict.NO_AUTH
    assert {"GET /api/Cards", "POST /api/Cards", "DELETE /api/Cards/:id"} <= set(eps)


def test_tsconfig_path_alias(tmp_path: Path) -> None:
    v = _verdicts(
        tmp_path,
        {
            "tsconfig.json": """
                { // comments are allowed
                  "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] }, },
                }
            """,
            "src/auth.js": AUTH,
            "src/app.ts": """
                import express from 'express';
                import { requireAuth } from '@/auth';
                const app = express();
                app.get('/x', requireAuth, (req, res) => res.end());
            """,
        },
    )
    assert v["GET /x"] == Verdict.AUTH


def _diff(tmp: Path, base: dict[str, str], head: dict[str, str]) -> list[tuple[str, str]]:
    b = write_tree(tmp / "base", base)
    h = write_tree(tmp / "head", head)
    r = diff_trees(DirectoryTree(b), DirectoryTree(h), repo_id="r")
    return [(f.rule_id, f.title) for f in r.findings]


APP = """
const express = require('express');
const { requireAuth } = require('./auth');
const app = express();
app.use('/api', requireAuth);
app.get('/api/items', (req, res) => res.json([]));
app.get('/api/Users', requireAuth);
"""


def test_reordered_guard_and_route_before_auth(tmp_path: Path) -> None:
    moved = APP.replace(
        "app.use('/api', requireAuth);\napp.get('/api/items', (req, res) => res.json([]));\n",
        "app.get('/api/items', (req, res) => res.json([]));\napp.use('/api', requireAuth);\n",
    )
    found = _diff(
        tmp_path / "a", {"auth.js": AUTH, "app.js": APP}, {"auth.js": AUTH, "app.js": moved}
    )
    assert found == [("AG-AUTH-002", "GET /api/items: guard reordered")]
    early = APP.replace(
        "app.use('/api', requireAuth);",
        "app.post('/api/export', (req, res) => res.end());\napp.use('/api', requireAuth);",
    )
    found = _diff(
        tmp_path / "b", {"auth.js": AUTH, "app.js": APP}, {"auth.js": AUTH, "app.js": early}
    )
    assert [r for r, _ in found] == ["AG-AUTH-003"]


def test_deleting_a_guard_only_registration_is_a_removal(tmp_path: Path) -> None:
    head = APP.replace("app.get('/api/Users', requireAuth);\n", "")
    found = _diff(tmp_path, {"auth.js": AUTH, "app.js": APP}, {"auth.js": AUTH, "app.js": head})
    assert found == [("AG-AUTH-002", "GET /api/Users: guard removed")]
