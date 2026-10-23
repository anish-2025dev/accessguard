"""Register the AccessGuard GitHub App from a manifest (one-time, run by a human).

GitHub's manifest flow (https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest):
  1. POST the manifest JSON to https://github.com/settings/apps/new (or the org variant) from a form;
  2. GitHub redirects to ``redirect_url`` with ``?code=...&state=...``;
  3. ``POST /app-manifests/{code}/conversions`` within one hour returns ``id``, ``slug``,
     ``client_id``, ``client_secret``, ``webhook_secret`` and ``pem``
     (https://docs.github.com/en/rest/apps/apps#create-a-github-app-from-a-manifest).

    python deploy/github-app/register.py form dev [--org ORG]   # writes register-dev.html
    # open the HTML file, click "Register", copy the ?code= from the redirect URL, then:
    python deploy/github-app/register.py convert CODE --env-file .env.dev

Secrets go only to the (gitignored) env file and the PEM next to it; nothing is printed.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def form(env: str, org: str | None) -> Path:
    manifest = json.loads((HERE / f"manifest.{env}.json").read_text(encoding="utf-8"))
    base = (
        f"https://github.com/organizations/{org}/settings/apps/new"
        if org
        else ("https://github.com/settings/apps/new")
    )
    state = secrets.token_urlsafe(24)
    page = f"""<!doctype html><meta charset="utf-8"><title>Register {html.escape(manifest["name"])}</title>
<form action="{base}?state={state}" method="post">
<input type="hidden" name="manifest" value="{html.escape(json.dumps(manifest))}">
<p>Registers <b>{html.escape(manifest["name"])}</b>. Expected state on redirect: <code>{state}</code></p>
<button type="submit">Register on GitHub</button></form>
"""
    out = HERE / f"register-{env}.html"
    out.write_text(page, encoding="utf-8")
    return out


def secure_write(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.truncate(0)
        output.write(content)


def convert(code: str, env_file: Path) -> None:
    req = urllib.request.Request(
        f"https://api.github.com/app-manifests/{code}/conversions",
        method="POST",
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        app = json.load(resp)
    pem = env_file.with_name(env_file.name + ".pem")
    secure_write(pem, app["pem"])
    secure_write(
        env_file,
        "\n".join(
            [
                f"GITHUB_APP_ID={app['id']}",
                f"GITHUB_APP_SLUG={app['slug']}",
                f"GITHUB_CLIENT_ID={app['client_id']}",
                f"GITHUB_CLIENT_SECRET={app['client_secret']}",
                f"GITHUB_WEBHOOK_SECRET={app['webhook_secret']}",
                f"GITHUB_PRIVATE_KEY_PATH={pem}",
            ]
        )
        + "\n",
    )
    print(f"Registered {app['slug']} (id {app['id']}); secrets written to {env_file} and {pem}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("form")
    f.add_argument("env", choices=["dev", "prod"])
    f.add_argument("--org")
    c = sub.add_parser("convert")
    c.add_argument("code")
    c.add_argument("--env-file", type=Path, default=Path(".env.dev"))
    args = ap.parse_args()
    if args.cmd == "form":
        print(f"Open {form(args.env, args.org)} in a browser")
    else:
        convert(args.code, args.env_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
