// Route ground truth for an Express app (PLAN.md §7 layer 1, Phase 3; ADR 005).
//
// Runs ONLY inside the network-less sandbox container, on pinned benchmark repos. It hooks
// express.application.init to record every app the code creates, records the path argument of
// every Router#use (Express 4 layers keep only a compiled regexp), turns Server#listen into a
// no-op, replaces dependencies that fail to load (native addons installed with --ignore-scripts)
// with inert stubs, then loads the entry module, optionally calls one exported function, and
// prints the route table of every app as JSON on stdout.
//
// Express 4 internals used (express@4.x lib/application.js, lib/router/index.js,
// lib/router/layer.js, lib/router/route.js): app._router.stack, layer.route.{path,methods},
// layer.handle.stack for routers, app.mountpath / app.parent for mounted sub-apps.
//
//   node dump_routes.js <repo-dir> <entry-file> [exported-function] [json-args]
"use strict";

const Module = require("module");
const http = require("http");
const path = require("path");

const [, , repoDir, entry, callName, callArgs] = process.argv;
const errors = [];
const realLog = console.log.bind(console);
for (const k of ["log", "info", "warn", "debug"]) console[k] = () => {};
http.Server.prototype.listen = function listen() {
  return this;
};
process.on("unhandledRejection", (e) => errors.push(`unhandled: ${String(e).slice(0, 200)}`));
// Start-up checks (missing frontend build, ports) may call process.exit: record, don't obey.
const realExit = process.exit.bind(process);
process.exit = (code) => {
  errors.push(`process.exit(${code}) ignored`);
};

function stub(name) {
  const fn = function () {};
  return new Proxy(fn, {
    get(_t, prop) {
      if (prop === "then") return undefined; // not a thenable: `await stub` resolves
      if (prop === Symbol.toPrimitive) return () => `[stub ${name}]`;
      if (prop === "__esModule") return false;
      return stub(`${name}.${String(prop)}`);
    },
    apply() {
      return stub(`${name}()`);
    },
    construct() {
      return stub(`new ${name}`);
    },
  });
}

const origLoad = Module._load;
Module._load = function load(request, parent, isMain) {
  try {
    return origLoad.apply(this, [request, parent, isMain]);
  } catch (e) {
    const local = request.startsWith(".") || request.startsWith("/");
    if (local || request === "express") throw e;
    errors.push(`stubbed ${request}: ${String(e.message || e).split("\n")[0].slice(0, 160)}`);
    return stub(request);
  }
};

const express = require(require.resolve("express", { paths: [repoDir] }));
const apps = [];
const origInit = express.application.init;
express.application.init = function init() {
  apps.push(this);
  return origInit.apply(this, arguments);
};
const routerProto = Object.getPrototypeOf(express.Router());
const origUse = routerProto.use;
routerProto.use = function use(first) {
  const before = this.stack.length;
  const out = origUse.apply(this, arguments);
  let p = "/";
  if (typeof first === "string") p = first;
  else if (Array.isArray(first) && first.every((x) => typeof x === "string")) p = first;
  else if (first instanceof RegExp || (Array.isArray(first) && first.length)) p = null;
  for (let i = before; i < this.stack.length; i++) this.stack[i].__agPath = p;
  return out;
};

function join(prefix, p) {
  return "/" + `${prefix}/${p}`.split("/").filter(Boolean).join("/");
}

function walk(stack, prefix, out) {
  for (const layer of stack || []) {
    if (layer.route) {
      const paths = Array.isArray(layer.route.path) ? layer.route.path : [layer.route.path];
      const methods = Object.keys(layer.route.methods).filter((m) => m !== "_all");
      if (layer.route.methods._all) methods.push("get", "post", "put", "patch", "delete");
      for (const p of paths) {
        const full = typeof p === "string" ? join(prefix, p) : join(prefix, "<dynamic>");
        for (const m of methods) out.push({ method: m.toUpperCase(), path: full, kind: "ExpressRoute" });
      }
    } else if (layer.handle && Array.isArray(layer.handle.stack)) {
      const ps = layer.__agPath === undefined ? ["/"] : [].concat(layer.__agPath);
      for (const p of ps) walk(layer.handle.stack, p === null ? join(prefix, "<dynamic>") : join(prefix, p), out);
    }
  }
}

function mountPrefix(app) {
  let prefix = "";
  for (let a = app; a && a.parent; a = a.parent) {
    const mp = Array.isArray(a.mountpath) ? a.mountpath[0] : a.mountpath;
    prefix = join(typeof mp === "string" ? mp : "<dynamic>", prefix);
  }
  return prefix;
}

async function main() {
  const file = path.resolve(repoDir, entry);
  let mod;
  try {
    mod = require(file);
  } catch (e) {
    errors.push(`load ${entry}: ${String(e.stack || e).split("\n").slice(0, 3).join(" | ")}`);
  }
  if (mod && callName) {
    const fn = mod[callName] || (mod.default && mod.default[callName]);
    try {
      if (typeof fn === "function") await Promise.race([fn(...JSON.parse(callArgs || "[]")), new Promise((r) => setTimeout(r, 30000))]);
      else errors.push(`${callName} is not exported`);
    } catch (e) {
      errors.push(`call ${callName}: ${String(e.stack || e).split("\n").slice(0, 3).join(" | ")}`);
    }
  }
  await new Promise((r) => setTimeout(r, 500)); // let promise-chained registrations settle
  const routes = [];
  for (const app of apps) walk(app._router && app._router.stack, mountPrefix(app), routes);
  const seen = new Set();
  const uniq = routes.filter((r) => {
    const k = `${r.method} ${r.path}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
  realLog(JSON.stringify({ app: apps.length ? entry : null, apps: apps.length, routes: uniq, errors }));
  realExit(0);
}

main();
