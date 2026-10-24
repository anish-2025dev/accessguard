"""SQLAlchemy 2 models for PLAN.md §6.7. No source code is ever stored."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class Installation(Base):
    __tablename__ = "installations"
    installation_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    account_id: Mapped[int] = mapped_column(BigInteger)
    account_login: Mapped[str | None] = mapped_column(Text)
    account_type: Mapped[str | None] = mapped_column(Text)
    repository_selection: Mapped[str | None] = mapped_column(Text)
    permissions: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    login: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()


class InstallationMember(Base):
    __tablename__ = "installation_members"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"), primary_key=True)
    installation_id: Mapped[int] = mapped_column(
        ForeignKey("installations.installation_id"), primary_key=True
    )
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OAuthState(Base):
    __tablename__ = "oauth_states"
    state: Mapped[str] = mapped_column(Text, primary_key=True)
    pkce_verifier: Mapped[str] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(Text)
    user_id: Mapped[int | None] = mapped_column(BigInteger)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Repository(Base):
    __tablename__ = "repositories"
    repo_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    installation_id: Mapped[int | None] = mapped_column(ForeignKey("installations.installation_id"))
    full_name: Mapped[str | None] = mapped_column(Text)
    default_branch: Mapped[str | None] = mapped_column(Text)
    private: Mapped[bool | None] = mapped_column(Boolean)
    archived: Mapped[bool | None] = mapped_column(Boolean)
    fork: Mapped[bool | None] = mapped_column(Boolean)
    status: Mapped[str] = mapped_column(Text, server_default="active")  # active|paused|removed
    detected_stack: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    last_baseline_sha: Mapped[str | None] = mapped_column(Text)
    config_sha: Mapped[str | None] = mapped_column(Text)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    delivery_guid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    event: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(Text)
    installation_id: Mapped[int | None] = mapped_column(BigInteger)
    received_at: Mapped[datetime] = _now()
    status: Mapped[str] = mapped_column(Text, server_default="received")  # received|routed|failed
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class PRState(Base):
    __tablename__ = "pr_state"
    repo_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pr_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_sha: Mapped[str | None] = mapped_column(Text)
    generation: Mapped[int | None] = mapped_column(BigInteger)
    draft: Mapped[bool | None] = mapped_column(Boolean)
    state: Mapped[str | None] = mapped_column(Text)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("repo_id", "head_sha", "trigger", "config_hash"),
        Index(
            "one_active_scan_per_pr",
            "repo_id",
            "pr_number",
            unique=True,
            postgresql_where=text("status in ('queued','running')"),
        ),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.repo_id"))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    trigger: Mapped[str | None] = mapped_column(Text)
    base_sha: Mapped[str | None] = mapped_column(Text)
    head_sha: Mapped[str] = mapped_column(Text)
    config_hash: Mapped[str | None] = mapped_column(Text)
    generation: Mapped[int | None] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(Text)  # queued|running|done|superseded|failed
    check_run_id: Mapped[int | None] = mapped_column(BigInteger)
    coverage: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    timings: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("findings_repo_fingerprint", "repo_id", "fingerprint"),)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.scan_id"))
    repo_id: Mapped[int | None] = mapped_column(BigInteger)
    fingerprint: Mapped[str] = mapped_column(Text)
    rule_id: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(Text)
    tier: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)  # open|resolved|dismissed|suppressed_llm
    endpoint_id: Mapped[str | None] = mapped_column(Text)
    path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[Any] = mapped_column(JSONB, nullable=True)
    llm_triage: Mapped[Any] = mapped_column(JSONB, nullable=True)
    comment_id: Mapped[int | None] = mapped_column(BigInteger)
    pr_number: Mapped[int | None] = mapped_column(Integer)  # scope for PR-thread upserts
    first_seen_sha: Mapped[str | None] = mapped_column(Text)
    last_seen_sha: Mapped[str | None] = mapped_column(Text)


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str | None] = mapped_column(Text)
    repo_id: Mapped[int | None] = mapped_column(BigInteger)
    actor_id: Mapped[int | None] = mapped_column(BigInteger)
    kind: Mapped[str | None] = mapped_column(Text)  # not_useful|fixed|ignored
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()


class RuleStats(Base):
    __tablename__ = "rule_stats"
    rule_id: Mapped[str] = mapped_column(Text, primary_key=True)
    period: Mapped[date] = mapped_column(Date, primary_key=True)
    shown: Mapped[int] = mapped_column(Integer, server_default="0")
    acted: Mapped[int] = mapped_column(Integer, server_default="0")
    not_useful: Mapped[int] = mapped_column(Integer, server_default="0")


class VerifierCredential(Base):  # Phase 4; table created now so the schema matches PLAN.md
    __tablename__ = "verifier_credentials"
    repo_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    label: Mapped[str] = mapped_column(Text, primary_key=True)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = _now()


class VerifierAudit(Base):
    __tablename__ = "verifier_audit"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    tool: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    decision: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
