"""``GitHubPort`` over githubkit.

Verified against githubkit 0.16.1 source (``inspect.signature`` on each method):
``AppAuthStrategy(app_id, private_key)``, ``AppInstallationAuthStrategy(app_id, private_key,
installation_id)``, ``rest.apps.async_list_installations``, ``async_get_installation``,
``async_list_webhook_deliveries(per_page, cursor, status)``,
``async_redeliver_webhook_delivery(delivery_id)``,
``async_list_installations_for_authenticated_user``,
``async_list_repos_accessible_to_installation``, ``rest.pulls.async_get``,
``rest.repos.async_compare_commits(owner, repo, basehead)``,
``rest.repos.async_download_tarball_archive(owner, repo, ref)``, ``rest.repos.async_get_content``,
``rest.repos.async_list_languages``, ``rest.git.async_get_tree(..., recursive=)``,
``rest.repos.async_get_collaborator_permission_level``, ``rest.checks.async_create/async_update``,
``rest.pulls.async_create_review_comment/async_update_review_comment``,
``rest.reactions.async_list_for_pull_request_review_comment(content=)``,
``rest.issues.async_list_comments/async_create_comment/async_update_comment/async_create``.

The OAuth code exchange is a direct ``POST https://github.com/login/oauth/access_token`` because
githubkit's web-flow strategy has no ``code_verifier`` (PKCE) parameter; parameters per
https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
"""

from __future__ import annotations

import base64
import re
import time
from typing import Any, cast

import httpx
from githubkit import AppAuthStrategy, AppInstallationAuthStrategy, GitHub, TokenAuthStrategy
from githubkit.exception import RequestFailed

from accessguard_app.github.port import CommentOutsideDiff, InstallationGone, Json, RateLimited
from accessguard_app.settings import Settings

OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105 - URL, not a secret


def _split(repo: str) -> tuple[str, str]:
    owner, name = repo.split("/", 1)
    return owner, name


def _json(resp: Any) -> Any:
    return resp.json()


class GitHubKitAdapter:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self._app = GitHub(AppAuthStrategy(settings.app_id, settings.private_key))
        self._inst: dict[int, GitHub[Any]] = {}

    def _gh(self, installation_id: int) -> GitHub[Any]:
        # githubkit caches and refreshes the installation token inside the auth strategy.
        if installation_id not in self._inst:
            self._inst[installation_id] = self._app.with_auth(
                AppInstallationAuthStrategy(self.s.app_id, self.s.private_key, installation_id)
            )
        return self._inst[installation_id]

    async def _call(self, coro: Any) -> Any:
        try:
            return await coro
        except RequestFailed as e:
            status = e.response.status_code
            headers = e.response.headers
            if status in (403, 429) and (
                "retry-after" in headers or headers.get("x-ratelimit-remaining") == "0"
            ):
                if "retry-after" in headers:
                    retry = float(headers["retry-after"])
                elif "x-ratelimit-reset" in headers:
                    retry = float(headers["x-ratelimit-reset"]) - time.time()
                else:
                    retry = 60
                raise RateLimited(max(1, retry)) from e
            if status in (401, 404) and re.fullmatch(
                r"/app/installations/\d+/access_tokens", e.response.url.path
            ):
                raise InstallationGone(str(e)) from e
            raise

    # --- app ---------------------------------------------------------------------------------
    async def list_app_installations(self) -> list[Json]:
        out: list[Json] = []
        page = 1
        while True:
            r = await self._call(
                self._app.rest.apps.async_list_installations(per_page=100, page=page)
            )
            batch = _json(r)
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    async def get_installation(self, installation_id: int) -> Json | None:
        try:
            r = await self._call(self._app.rest.apps.async_get_installation(installation_id))
        except RequestFailed as e:
            if e.response.status_code == 404:
                return None
            raise
        return dict(_json(r))

    async def list_failed_deliveries(self, since_id: int | None = None) -> list[Json]:
        r = await self._call(
            self._app.rest.apps.async_list_webhook_deliveries(per_page=100, status="failure")
        )
        items = list(_json(r))
        return [d for d in items if since_id is None or int(d["id"]) > since_id]

    async def redeliver(self, delivery_id: int) -> None:
        await self._call(self._app.rest.apps.async_redeliver_webhook_delivery(delivery_id))

    # --- user OAuth -------------------------------------------------------------------------
    async def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> str:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                OAUTH_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.s.client_id,
                    "client_secret": self.s.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                },
            )
        r.raise_for_status()
        data = r.json()
        if "access_token" not in data:
            raise PermissionError(f"code exchange failed: {data.get('error', 'unknown')}")
        return str(data["access_token"])

    async def get_authenticated_user(self, user_token: str) -> Json:
        gh = GitHub(TokenAuthStrategy(user_token))
        return dict(_json(await self._call(gh.rest.users.async_get_authenticated())))

    async def list_user_installations(self, user_token: str) -> list[Json]:
        gh = GitHub(TokenAuthStrategy(user_token))
        r = await self._call(
            gh.rest.apps.async_list_installations_for_authenticated_user(per_page=100)
        )
        return list(_json(r)["installations"])

    # --- installation -----------------------------------------------------------------------
    async def list_installation_repos(self, installation_id: int) -> list[Json]:
        gh = self._gh(installation_id)
        out: list[Json] = []
        page = 1
        while True:
            r = await self._call(
                gh.rest.apps.async_list_repos_accessible_to_installation(per_page=100, page=page)
            )
            batch = _json(r)["repositories"]
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    async def get_pull(self, installation_id: int, repo: str, number: int) -> Json:
        o, n = _split(repo)
        return dict(
            _json(await self._call(self._gh(installation_id).rest.pulls.async_get(o, n, number)))
        )

    async def compare(self, installation_id: int, repo: str, base: str, head: str) -> Json:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.repos.async_compare_commits(o, n, f"{base}...{head}")
        )
        return dict(_json(r))

    async def download_tarball(self, installation_id: int, repo: str, ref: str) -> bytes:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.repos.async_download_tarball_archive(o, n, ref)
        )
        return bytes(r.content)

    async def get_file(self, installation_id: int, repo: str, path: str, ref: str) -> bytes | None:
        o, n = _split(repo)
        try:
            r = await self._call(
                self._gh(installation_id).rest.repos.async_get_content(o, n, path, ref=ref)
            )
        except RequestFailed as e:
            if e.response.status_code == 404:
                return None
            raise
        data = _json(r)
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"])
        return None

    async def list_languages(self, installation_id: int, repo: str) -> dict[str, int]:
        o, n = _split(repo)
        return dict(
            _json(await self._call(self._gh(installation_id).rest.repos.async_list_languages(o, n)))
        )

    async def get_tree(self, installation_id: int, repo: str, sha: str) -> list[Json]:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.git.async_get_tree(o, n, sha, recursive="1")
        )
        return list(_json(r)["tree"])

    async def get_permission(self, installation_id: int, repo: str, username: str) -> str:
        o, n = _split(repo)
        try:
            r = await self._call(
                self._gh(installation_id).rest.repos.async_get_collaborator_permission_level(
                    o, n, username
                )
            )
        except RequestFailed as e:
            if e.response.status_code == 404:
                return "none"
            raise
        return str(_json(r)["permission"])

    async def create_check_run(self, installation_id: int, repo: str, body: Json) -> int:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.checks.async_create(o, n, data=cast(Any, body))
        )
        return int(_json(r)["id"])

    async def update_check_run(
        self, installation_id: int, repo: str, check_run_id: int, body: Json
    ) -> None:
        o, n = _split(repo)
        await self._call(
            self._gh(installation_id).rest.checks.async_update(
                o, n, check_run_id, data=cast(Any, body)
            )
        )

    async def create_review_comment(
        self, installation_id: int, repo: str, number: int, body: Json
    ) -> int:
        o, n = _split(repo)
        try:
            r = await self._call(
                self._gh(installation_id).rest.pulls.async_create_review_comment(
                    o, n, number, data=cast(Any, body)
                )
            )
        except RequestFailed as e:
            if e.response.status_code == 422:
                error = _json(e.response)
                messages = [error.get("message", "")] + [
                    item.get("message", "") if isinstance(item, dict) else str(item)
                    for item in error.get("errors", [])
                ]
                if any(
                    phrase in str(message).lower()
                    for message in messages
                    for phrase in ("must be part of the diff", "not part of the diff")
                ):
                    raise CommentOutsideDiff("Comment line is outside the diff") from e
            raise
        return int(_json(r)["id"])

    async def update_review_comment(
        self, installation_id: int, repo: str, comment_id: int, body: str
    ) -> None:
        o, n = _split(repo)
        await self._call(
            self._gh(installation_id).rest.pulls.async_update_review_comment(
                o, n, comment_id, data={"body": body}
            )
        )

    async def list_review_comment_reactions(
        self, installation_id: int, repo: str, comment_id: int, content: str
    ) -> list[Json]:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.reactions.async_list_for_pull_request_review_comment(
                o,
                n,
                comment_id,
                content=content,  # type: ignore[arg-type]
            )
        )
        return list(_json(r))

    async def list_issue_comments(self, installation_id: int, repo: str, number: int) -> list[Json]:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.issues.async_list_comments(o, n, number, per_page=100)
        )
        return list(_json(r))

    async def create_issue_comment(
        self, installation_id: int, repo: str, number: int, body: str
    ) -> int:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.issues.async_create_comment(
                o, n, number, data={"body": body}
            )
        )
        return int(_json(r)["id"])

    async def update_issue_comment(
        self, installation_id: int, repo: str, comment_id: int, body: str
    ) -> None:
        o, n = _split(repo)
        await self._call(
            self._gh(installation_id).rest.issues.async_update_comment(
                o, n, comment_id, data={"body": body}
            )
        )

    async def create_issue(self, installation_id: int, repo: str, title: str, body: str) -> int:
        o, n = _split(repo)
        r = await self._call(
            self._gh(installation_id).rest.issues.async_create(
                o, n, data={"title": title, "body": body}
            )
        )
        return int(_json(r)["number"])
