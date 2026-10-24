"""Runtime settings from the environment (the platform secret store in staging/production)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: _env(
            "DATABASE_URL", "postgresql+asyncpg://accessguard:accessguard@localhost/accessguard"
        )
    )
    redis_url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://localhost:6379/0"))
    app_id: str = field(default_factory=lambda: _env("GITHUB_APP_ID"))
    app_slug: str = field(default_factory=lambda: _env("GITHUB_APP_SLUG", "accessguard"))
    client_id: str = field(default_factory=lambda: _env("GITHUB_CLIENT_ID"))
    client_secret: str = field(default_factory=lambda: _env("GITHUB_CLIENT_SECRET"))
    webhook_secret: str = field(default_factory=lambda: _env("GITHUB_WEBHOOK_SECRET"))
    private_key: str = field(
        default_factory=lambda: (
            Path(p).read_text(encoding="utf-8")
            if (p := _env("GITHUB_PRIVATE_KEY_PATH"))
            else _env("GITHUB_PRIVATE_KEY")
        )
    )
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL", "http://localhost:8000"))
    check_name: str = "AccessGuard"
    bot_login: str = field(default_factory=lambda: _env("GITHUB_BOT_LOGIN", "accessguard[bot]"))
    # PR scans are debounced so a burst of pushes produces one scan (PLAN.md §6.12).
    scan_debounce_seconds: int = field(
        default_factory=lambda: int(_env("SCAN_DEBOUNCE_SECONDS", "15"))
    )
    max_tarball_bytes: int = 200 * 1024 * 1024


def get_settings() -> Settings:
    return Settings()
