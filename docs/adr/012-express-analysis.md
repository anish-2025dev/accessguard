# ADR 012: Express analysis by abstract replay of registration events

- Status: Accepted
- Date: 2026-10-23

## Context
FR-3.1/3.2 for Express (PLAN.md §6.4): routes come from `app`/`Router` method calls spread over
modules, built through `require`/`import`, factories (`module.exports = (app) => …`), route tables
iterated with `forEach` / `for…of`, `router.route(p).get(…).post(…)` and `Router().use(…)` chains,
and generators such as finale-rest. Which middleware guards a route depends on registration
order, path prefixes and methods. Scanned code must never run (ADR 005).

## Decision
1. **Summaries.** tree-sitter (JavaScript, TypeScript, TSX grammars) produces a per-file summary
   cached by blob SHA. It contains imports and exports (CommonJS and ESM), source-ordered events
   (assignments and expression calls) per function, and guard features per function: 4xx
   statuses, `next()` / `next(err)` / forwarding `next`, responses, role and owner comparisons.
2. **Abstract replay.** `frameworks/express.py` replays those events with abstract values: apps
   and routers, functions with their closures, package exports, literals, and unknown. Calls on
   an app or router record `use` / route entries with a global sequence number, which is the
   order Express registers them in. Functions are entered when called (depth ≤ 12, no
   recursion), inline callbacks of unknown calls are followed once, and a step budget bounds the
   work. Nothing is evaluated beyond this value model.
3. **Guard chain (§6.4).** A middleware occurrence guards a route if it is on the route's router
   or an ancestor, registered before the route (or before the mount, in an ancestor), its path
   matches (segment-prefix for `use`, exact for routes), and its method matches. Route-level
   middleware of one route never applies to sibling routes unless that route passes on (calls
   `next()`). Matching middleware registered *after* the route becomes a **late guard**, which
   drives `guard_reordered` (AG-AUTH-002) and `registered_before_auth` (AG-AUTH-003).
   `mw.unless({path})` exemptions are honoured, and an exemption that cannot be evaluated
   withdraws credit for the guard.
4. **Classification.** Known primitives come with their documented options: express-jwt
   (`credentialsRequired`), passport (`anonymous`), express-openid-connect, oauth2-jwt-bearer,
   Clerk and basic-auth. Local middleware is scored like Python guards. A function that never
   calls `next()` is a terminal handler, and a 4-parameter function is an error handler. A
   closure that forwards `next` to a function its factory received (`asyncHandler(mw)`) is
   classified as the wrapped function. Captcha, CSRF and validation checks are not guards.
5. **Guard-only registrations** (`app.get('/api/Users', isAuthorized())` in front of a generated
   handler) act as middleware for later routes on the same path. Deleting one is reported as a
   removal.
6. **Ground truth.** A Node sandbox (`eval/sandbox/node`) installs pinned benchmark repos with
   `npm ci --ignore-scripts`, then loads the app with `--network none`. In that sandbox:
   - `express.application.init` is hooked to collect apps, and `Server#listen` is a no-op;
   - modules that fail to load are replaced by inert stubs, and `process.exit` is ignored;
   - `app._router.stack` is dumped. Express 4 layers keep only a regexp, so `Router#use` records
     its path argument.

## Consequences
Route recall against runtime tables is 143/144 for Juice Shop; the miss is `/robots.txt`, added
inside the `express-robots-txt` package. It is 100% for node-express-boilerplate and
node-express-realworld-example-app. Dynamic paths and unresolvable auth-looking middleware
produce UNKNOWN, never a finding. Express IDOR (sinks) and Express config predicates for Z3 are
not modelled yet. NestJS, Fastify and Next.js route handlers are out of scope for Phase 3.
