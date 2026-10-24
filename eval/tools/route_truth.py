"""Produce runtime route ground truth for corpus repos (PLAN.md §7 layer 1).

For each repo in eval/corpus/repos.yaml ``route_ground_truth``: build the sandbox image with the
repo's checkout, then run eval/sandbox/dump_routes.py with no network and a read-only filesystem.
Output: eval/corpus/truth/<name>.json (committed; route recall in the harness reads these).

    python eval/tools/fetch_corpus.py && python eval/tools/route_truth.py [name ...]

Scanned code is executed ONLY inside this container (ADR 005), and only for pinned benchmark repos.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

EVAL = Path(__file__).resolve().parents[1]
SANDBOX = EVAL / "sandbox"
CHECKOUTS = EVAL / "corpus" / "checkouts"
TRUTH = EVAL / "corpus" / "truth"
BUILD_TIMEOUT = 600
RUN_TIMEOUT = 120

RUN_FLAGS = [
    "--rm",
    "--network",
    "none",
    "--read-only",
    "--tmpfs",
    "/tmp:size=512m",  # noqa: S108 - container-local tmpfs
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "1g",
    "--pids-limit",
    "256",
    "--env",
    "PYTHONDONTWRITEBYTECODE=1",
]


def docker_run_cmd(image: str, target: str, repo: dict[str, Any]) -> list[str]:
    extra: list[str] = []
    for k, v in (repo.get("env") or {}).items():
        extra += ["--env", f"{k}={v}"]
    if repo.get("workdir"):
        extra += ["--workdir", f"/src/{repo['workdir']}"]
    return ["docker", "run", *RUN_FLAGS, *extra, image, target]


def _deps_dir(src: Path, target: str) -> str:
    """Nearest ancestor of the app file that declares dependencies (repo root by default)."""
    if ":" not in target:
        return "."
    d = (src / target.rsplit(":", 1)[0]).parent
    while d != src and d.is_relative_to(src):
        if any((d / f).exists() for f in ("pyproject.toml", "requirements.txt", "setup.py")):
            return str(d.relative_to(src))
        d = d.parent
    return "."


NODE_LOADER = "file:///usr/local/lib/node_modules/tsx/dist/loader.mjs"


def node_truth_for(repo: dict[str, Any], ca_bundle: Path | None = None) -> dict[str, object]:
    """Express: eval/sandbox/node; ``entry`` is loaded, then ``call`` (an export) is awaited."""
    src = CHECKOUTS / repo["name"]
    if not src.is_dir():
        raise SystemExit(f"{src} missing; run eval/tools/fetch_corpus.py first")
    image = f"accessguard-node-routes-{repo['name'].lower()}"
    with tempfile.TemporaryDirectory() as ctx:
        shutil.copytree(
            src, Path(ctx) / "src", symlinks=True, ignore=shutil.ignore_patterns(".git")
        )
        for f in ("Dockerfile", "dump_routes.js"):
            shutil.copy(SANDBOX / "node" / f, Path(ctx) / f)
        (Path(ctx) / "build-ca.crt").write_bytes(ca_bundle.read_bytes() if ca_bundle else b"")
        build = ["docker", "build", "-q", "-t", image]
        build += ["--build-arg", f"APP_DIR={repo.get('workdir', '.')}"]
        if ca_bundle and os.environ.get("HTTPS_PROXY"):
            proxy = os.environ["HTTPS_PROXY"]
            build += ["--network", "host", "--build-arg", f"HTTPS_PROXY={proxy}"]
        subprocess.run([*build, ctx], check=True, timeout=BUILD_TIMEOUT)
    # The app writes into its own tree on start-up (Juice Shop), so the rootfs stays writable;
    # the container is still network-less, unprivileged and discarded after the run.
    flags = [f for f in RUN_FLAGS if f != "--read-only"]
    flags[flags.index("PYTHONDONTWRITEBYTECODE=1")] = "NODE_ENV=test"
    extra: list[str] = []
    for k, v in (repo.get("env") or {}).items():
        extra += ["--env", f"{k}={v}"]
    workdir = f"/src/{repo['workdir']}" if repo.get("workdir") else "/src"
    cmd = ["docker", "run", *flags, *extra, "--workdir", workdir, "--entrypoint", "node", image]
    cmd += ["--import", NODE_LOADER, "/dump_routes.js", workdir, repo["entry"]]
    if repo.get("call"):
        cmd += [repo["call"], json.dumps(repo.get("call_args", []))]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    data: dict[str, object] = json.loads(out.stdout.strip().splitlines()[-1])
    if not data.get("app") or not data.get("routes"):
        raise ValueError(f"no routes recorded; errors: {data.get('errors', [])}")
    data.update(name=repo["name"], ref=repo["ref"])
    return data


def truth_for(repo: dict[str, Any], ca_bundle: Path | None = None) -> dict[str, object]:
    src = CHECKOUTS / repo["name"]
    if not src.is_dir():
        raise SystemExit(f"{src} missing; run eval/tools/fetch_corpus.py first")
    target = repo.get("app", "auto")
    app_dir = repo.get("deps_dir") or _deps_dir(src, target)
    image = f"accessguard-routes-{repo['name'].lower()}"
    with tempfile.TemporaryDirectory() as ctx:
        ignore = shutil.ignore_patterns(".git")
        shutil.copytree(src, Path(ctx) / "src", symlinks=True, ignore=ignore)
        for f in ("Dockerfile", "dump_routes.py", "install_deps.sh"):
            shutil.copy(SANDBOX / f, Path(ctx) / f)
        build = ["docker", "build", "-q", "-t", image, "--build-arg", f"APP_DIR={app_dir}"]
        build += ["--build-arg", f"PYTHON_VERSION={repo.get('python', '3.12')}"]
        build += ["--build-arg", f"MKDIRS={' '.join(repo.get('mkdirs') or [])}"]
        build += ["--build-arg", f"APT_PACKAGES={' '.join(repo.get('apt') or [])}"]
        build += ["--build-arg", f"TOUCH={' '.join(repo.get('touch') or [])}"]
        build += ["--build-arg", f"INSTALL_SELF={1 if repo.get('install_self') else 0}"]
        ca_dest = Path(ctx) / "build-ca.crt"
        ca_dest.write_bytes(ca_bundle.read_bytes() if ca_bundle else b"")
        if ca_bundle and os.environ.get("HTTPS_PROXY"):
            # Behind an egress proxy: the build stage (only) reaches PyPI through it.
            proxy = os.environ["HTTPS_PROXY"]
            build += ["--network", "host", "--build-arg", f"HTTPS_PROXY={proxy}"]
        subprocess.run([*build, ctx], check=True, timeout=BUILD_TIMEOUT)
    cmd = docker_run_cmd(image, target, repo)
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    data: dict[str, object] = json.loads(out.stdout)
    if not isinstance(data, dict):
        raise ValueError("route dumper did not return a JSON object")
    if not data.get("app"):
        raise ValueError(f"no application selected; errors: {data.get('errors', [])}")
    data.update(name=repo["name"], ref=repo["ref"])
    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*")
    ap.add_argument("--ca-bundle", type=Path, help="extra CA for the build stage behind a proxy")
    args = ap.parse_args()
    spec = yaml.safe_load((EVAL / "corpus" / "repos.yaml").read_text(encoding="utf-8"))
    only = set(args.names)
    TRUTH.mkdir(parents=True, exist_ok=True)
    failed = False
    groups = [(r, truth_for) for r in spec["route_ground_truth"]]
    groups += [(r, node_truth_for) for r in spec.get("express_route_ground_truth", [])]
    for repo, fn in groups:
        if only and repo["name"] not in only:
            continue
        try:
            data = fn(repo, args.ca_bundle)
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            print(f"{repo['name']}: FAILED ({e})")
            failed = True
            continue
        routes = data.get("routes") or []
        print(f"{repo['name']}: {len(routes)} routes from {data.get('app')}")  # type: ignore[arg-type]
        (TRUTH / f"{repo['name']}.json").write_text(json.dumps(data, indent=2) + "\n", "utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
