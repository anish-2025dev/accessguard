"""Error boundaries and secret transport, using only synthetic HTTP responses."""

from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs

import httpx
import pytest
from accessguard_app.github.githubkit_adapter import GitHubKitAdapter
from accessguard_app.github.port import CommentOutsideDiff, InstallationGone, RateLimited
from accessguard_app.settings import Settings, get_settings
from githubkit.exception import RequestFailed
from githubkit.response import Response


def failure(status: int, path: str, headers=None, body=None) -> RequestFailed:
    response = httpx.Response(
        status,
        request=httpx.Request("POST", f"https://api.github.com{path}"),
        headers=headers,
        json=body or {"message": "rejected"},
    )
    return RequestFailed(Response(response, dict))


@pytest.mark.parametrize(
    ("headers", "delay"),
    [
        ({"retry-after": "7", "x-ratelimit-reset": "1200"}, 7),
        ({"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1100"}, 100),
        ({"x-ratelimit-remaining": "0", "x-ratelimit-reset": "900"}, 1),
        ({"x-ratelimit-remaining": "0"}, 60),
        ({"retry-after": "0"}, 1),
    ],
)
async def test_rate_limit_delay(monkeypatch, headers, delay) -> None:
    monkeypatch.setattr("accessguard_app.github.githubkit_adapter.time.time", lambda: 1000)
    adapter = GitHubKitAdapter(Settings())
    for status in (403, 429):
        with pytest.raises(RateLimited) as raised:
            await adapter._call(AsyncMock(side_effect=failure(status, "/repos/o/r", headers))())
        assert raised.value.retry_after == delay


@pytest.mark.parametrize("status", [401, 404])
@pytest.mark.parametrize(
    ("path", "gone"),
    [
        ("/app/installations/7/access_tokens", True),
        ("/app/installations/7", False),
        ("/installation/repositories", False),
        ("/repos/installation/repo/contents/file", False),
        ("/repos/o/r?endpoint=/app/installations/7/access_tokens", False),
        ("/app/installations/7/access_tokens/other", False),
    ],
)
async def test_only_token_mint_maps_to_installation_gone(status, path, gone) -> None:
    adapter = GitHubKitAdapter(Settings())
    error = failure(status, path)
    with pytest.raises(InstallationGone if gone else RequestFailed) as raised:
        await adapter._call(AsyncMock(side_effect=error)())
    if not gone:
        assert raised.value is error


async def test_oauth_secrets_are_in_form_body(monkeypatch) -> None:
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"access_token": "synthetic-user-token"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)
    adapter = GitHubKitAdapter(Settings(client_id="cid", client_secret="synthetic-secret"))
    assert (
        await adapter.exchange_code("code", "verifier", "https://example.test/callback")
        == "synthetic-user-token"
    )
    (request,) = requests
    assert not request.url.query
    assert request.headers["accept"] == "application/json"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert parse_qs(request.content.decode()) == {
        "client_id": ["cid"],
        "client_secret": ["synthetic-secret"],
        "code": ["code"],
        "code_verifier": ["verifier"],
        "redirect_uri": ["https://example.test/callback"],
    }


@pytest.mark.parametrize(
    ("status", "message", "expected"),
    [
        (422, "line must be part of the diff", CommentOutsideDiff),
        (422, "line is not part of the diff", CommentOutsideDiff),
        (422, "body is too long", RequestFailed),
        (403, "line must be part of the diff", RequestFailed),
        (500, "server error", RequestFailed),
    ],
)
async def test_comment_validation_is_narrow(monkeypatch, status, message, expected) -> None:
    adapter = GitHubKitAdapter(Settings())
    error = failure(
        status,
        "/repos/o/r/pulls/1/comments",
        body={
            "message": "Validation Failed",
            "errors": [{"message": message}],
        },
    )
    create = AsyncMock(side_effect=error)
    monkeypatch.setattr(
        adapter,
        "_gh",
        lambda iid: SimpleNamespace(
            rest=SimpleNamespace(pulls=SimpleNamespace(async_create_review_comment=create))
        ),
    )
    with pytest.raises(expected) as raised:
        await adapter.create_review_comment(7, "o/r", 1, {})
    if expected is RequestFailed:
        assert raised.value is error


CREDENTIALS = {
    "GITHUB_APP_ID": "123",
    "GITHUB_CLIENT_ID": "cid",
    "GITHUB_CLIENT_SECRET": "secret",
    "GITHUB_WEBHOOK_SECRET": "webhook",
    "GITHUB_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nlocal",
}


@pytest.mark.parametrize("missing", list(CREDENTIALS))
def test_runtime_settings_require_credentials_but_fixtures_do_not(monkeypatch, missing) -> None:
    for key, value in CREDENTIALS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("GITHUB_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.setenv(missing, " \t")
    Settings()  # FakeGitHub fixtures may construct settings without real credentials.
    with pytest.raises(ValueError, match="is required"):
        get_settings()


@pytest.mark.parametrize(
    "key",
    ["not-a-pem", "-----BEGIN RSA PRIVATE KEY-----\nlocal", "-----BEGIN PRIVATE KEY-----\nlocal"],
)
def test_runtime_settings_validate_pem_header(monkeypatch, key) -> None:
    for name, value in CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("GITHUB_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.setenv("GITHUB_PRIVATE_KEY", key)
    if key == "not-a-pem":
        with pytest.raises(ValueError, match="PEM"):
            get_settings()
    else:
        assert get_settings().private_key == key
