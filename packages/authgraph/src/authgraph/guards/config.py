"""``.accessguard.yml`` loader (PLAN.md §6.11). Always read from the base branch (ADR 006)."""

from __future__ import annotations

import fnmatch
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from authgraph.facts.models import GuardKind

CONFIG_FILE = ".accessguard.yml"


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="ignore")


class GuardDecl(_Cfg):
    symbol: str
    kind: GuardKind = GuardKind.AUTHN


class PublicRoute(_Cfg):
    route: str  # "GET /health"; fnmatch wildcards allowed ("GET /public/*")
    reason: str = ""


class Paths(_Cfg):
    exclude: list[str] = Field(default_factory=list)


class RuleToggle(_Cfg):
    enabled: bool = True


class LLMConfig(_Cfg):
    provider: Literal["ollama", "api", "off"] = "off"
    model: str | None = None


class VerifierConfig(_Cfg):
    enabled: bool = False
    preview_hosts: list[str] = Field(default_factory=list)


class Config(_Cfg):
    version: int = 1
    fail_on: Literal["critical", "high", "never"] = "critical"
    scan_drafts: bool = False
    paths: Paths = Field(default_factory=Paths)
    auth_guards: list[GuardDecl] = Field(default_factory=list)
    public_routes: list[PublicRoute] = Field(default_factory=list)
    public_models: list[str] = Field(default_factory=list)
    rules: dict[str, RuleToggle] = Field(default_factory=dict)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    verifier: VerifierConfig = Field(default_factory=VerifierConfig)
    errors: list[str] = Field(default_factory=list)  # validation problems (reported, not fatal)

    def is_public(self, endpoint_id: str) -> PublicRoute | None:
        for r in self.public_routes:
            if r.route == endpoint_id or fnmatch.fnmatchcase(endpoint_id, r.route):
                return r
        return None

    def rule_enabled(self, rule_id: str) -> bool:
        t = self.rules.get(rule_id)
        return True if t is None else t.enabled

    def guard_decl(self, symbol: str) -> GuardDecl | None:
        for g in self.auth_guards:
            # Match the fully-qualified symbol or its trailing qualname (moved-module tolerant).
            if (
                symbol == g.symbol
                or symbol.endswith("." + g.symbol)
                or g.symbol.endswith("." + symbol)
            ):
                return g
        return None


def parse_config(text: str | bytes | None) -> Config:
    if not text:
        return Config()
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        return Config(errors=[f"invalid YAML: {e}"])
    if not isinstance(data, dict):
        return Config(errors=["config root must be a mapping"])
    try:
        return Config.model_validate(data)
    except ValidationError as e:
        return Config(errors=[str(e)])
