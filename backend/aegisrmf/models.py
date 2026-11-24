"""Tenant-scoped data model. Every customer-owned row carries tenant_id; services
never query a tenant-owned table without it (see services/scope.py). PostgreSQL
row-level security policies are added in the Alembic migration as a second layer."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


class TenantOwned:
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    data_residency: Mapped[str] = mapped_column(String(40), default="us")
    retention_days: Mapped[int] = mapped_column(Integer, default=2555)  # ~7 years default
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(TenantOwned, Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(30))  # owner|assessor|contributor|viewer|agent
    entra_oid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    __table_args__ = (UniqueConstraint("tenant_id", "email"),)


class ApiKey(TenantOwned, Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    prefix: Mapped[str] = mapped_column(String(16), unique=True)
    secret_hash: Mapped[str] = mapped_column(String(128))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    label: Mapped[str] = mapped_column(String(120), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    user: Mapped[User] = relationship()


class System(TenantOwned, Base):
    __tablename__ = "systems"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    boundary_description: Mapped[str] = mapped_column(Text, default="")
    data_types: Mapped[list] = mapped_column(JSON, default=list)   # ["FCI","CUI"]
    cui_data_flows: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


ASSET_CATEGORIES = {"CUI_ASSET", "SECURITY_PROTECTION_ASSET", "CONTRACTOR_RISK_MANAGED_ASSET",
                    "SPECIALIZED_ASSET", "OUT_OF_SCOPE"}


class Asset(TenantOwned, Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(40))
    asset_type: Mapped[str] = mapped_column(String(60), default="")
    is_external_service_provider: Mapped[bool] = mapped_column(Boolean, default=False)
    shared_responsibility: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class Assessment(TenantOwned, Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id"), index=True)
    framework_id: Mapped[str] = mapped_column(String(40))
    framework_version: Mapped[str] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(30), default="READINESS")  # READINESS|SELF_ASSESSMENT_PREP|C3PAO_PREP
    status: Mapped[str] = mapped_column(String(20), default="DRAFT")    # DRAFT|IN_REVIEW|FINALIZED
    revision: Mapped[int] = mapped_column(Integer, default=1)
    title: Mapped[str] = mapped_column(String(200), default="")
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ObjectiveResult(TenantOwned, Base):
    """Human-determined result for one assessment objective. AI never writes this table."""
    __tablename__ = "objective_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    objective_id: Mapped[str] = mapped_column(String(30))
    requirement_id: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))
    methods: Mapped[list] = mapped_column(JSON, default=list)  # examine|interview|test
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence_link_ids: Mapped[list] = mapped_column(JSON, default=list)
    determined_by: Mapped[str] = mapped_column(String(36))
    determined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (UniqueConstraint("assessment_id", "objective_id"),)


class RequirementCondition(TenantOwned, Base):
    """Scoring qualifiers an assessor records (partial MFA/FIPS, N/A justification)."""
    __tablename__ = "requirement_conditions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    requirement_id: Mapped[str] = mapped_column(String(30))
    partial_condition: Mapped[str | None] = mapped_column(String(60), nullable=True)
    na_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    implementation_statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    __table_args__ = (UniqueConstraint("assessment_id", "requirement_id"),)


class EvidenceArtifact(TenantOwned, Base):
    __tablename__ = "evidence_artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    detected_type: Mapped[str] = mapped_column(String(20))
    evidence_kind: Mapped[str] = mapped_column(String(40))  # policy|procedure|configuration|log|...
    classification: Mapped[str] = mapped_column(String(20))  # PUBLIC|INTERNAL|FCI|CUI
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer, default=1)
    storage_key: Mapped[str] = mapped_column(String(300))
    text_extracted: Mapped[bool] = mapped_column(Boolean, default=False)
    extraction_note: Mapped[str] = mapped_column(Text, default="")
    injection_flags: Mapped[list] = mapped_column(JSON, default=list)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    uploaded_by: Mapped[str] = mapped_column(String(36))
    __table_args__ = (Index("ix_evidence_tenant_sha", "tenant_id", "sha256"),)


class EvidenceChunk(TenantOwned, Base):
    __tablename__ = "evidence_chunks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    artifact_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence_artifacts.id", ondelete="CASCADE"), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    page: Mapped[int | None] = mapped_column(Integer, nullable=True)
    section: Mapped[str] = mapped_column(String(300), default="")
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    injection_suspected: Mapped[bool] = mapped_column(Boolean, default=False)


class EvidenceLink(TenantOwned, Base):
    """Proposed or accepted link between evidence and an assessment objective, with citation."""
    __tablename__ = "evidence_links"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence_artifacts.id"))
    chunk_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence_chunks.id"))
    objective_id: Mapped[str] = mapped_column(String(30), index=True)
    requirement_id: Mapped[str] = mapped_column(String(30))
    origin: Mapped[str] = mapped_column(String(10))  # AI|HUMAN
    status: Mapped[str] = mapped_column(String(20), default="PROPOSED")  # PROPOSED|ACCEPTED|REJECTED
    confidence: Mapped[float] = mapped_column(default=0.0)
    citation: Mapped[dict] = mapped_column(JSON)  # artifact_id, version, sha256, page, lines, quote
    analyzer: Mapped[str] = mapped_column(String(60))
    analyzer_version: Mapped[str] = mapped_column(String(20))
    prompt_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Finding(TenantOwned, Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    requirement_id: Mapped[str] = mapped_column(String(30))
    objective_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    origin: Mapped[str] = mapped_column(String(10))  # AI|HUMAN
    proposed_status: Mapped[str] = mapped_column(String(30))
    statement: Mapped[str] = mapped_column(Text)
    evidence_link_ids: Mapped[list] = mapped_column(JSON, default=list)
    qa_warnings: Mapped[list] = mapped_column(JSON, default=list)
    review_status: Mapped[str] = mapped_column(String(20), default="UNREVIEWED")  # UNREVIEWED|VERIFIED|DISMISSED
    analyzer: Mapped[str] = mapped_column(String(60), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


POAM_STATES = ["DRAFT", "OPEN", "IN_PROGRESS", "BLOCKED", "PENDING_VERIFICATION", "CLOSED", "ACCEPTED_RISK"]


class POAM(TenantOwned, Base):
    __tablename__ = "poams"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    display_id: Mapped[str] = mapped_column(String(40))
    assessment_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessments.id"), index=True)
    requirement_id: Mapped[str] = mapped_column(String(30))
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    weakness: Mapped[str] = mapped_column(Text)
    source_evidence: Mapped[list] = mapped_column(JSON, default=list)
    affected_assets: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(10), default="MODERATE")
    point_value: Mapped[int] = mapped_column(Integer, default=0)
    cmmc_poam_permitted: Mapped[bool] = mapped_column(Boolean, default=False)
    cmmc_poam_basis: Mapped[str] = mapped_column(String(200), default="")
    risk_owner: Mapped[str] = mapped_column(String(200), default="")
    remediation_owner: Mapped[str] = mapped_column(String(200), default="")
    corrective_action: Mapped[str] = mapped_column(Text, default="")
    resources: Mapped[str] = mapped_column(Text, default="")
    dependencies: Mapped[list] = mapped_column(JSON, default=list)
    scheduled_completion: Mapped[str | None] = mapped_column(String(10), nullable=True)  # ISO date
    actual_completion: Mapped[str | None] = mapped_column(String(10), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="DRAFT")
    closure_evidence: Mapped[list] = mapped_column(JSON, default=list)
    verified_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    milestones: Mapped[list["Milestone"]] = relationship(cascade="all, delete-orphan", order_by="Milestone.due_date")
    history: Mapped[list["POAMHistory"]] = relationship(cascade="all, delete-orphan", order_by="POAMHistory.at")


class Milestone(TenantOwned, Base):
    __tablename__ = "milestones"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    poam_id: Mapped[str] = mapped_column(String(36), ForeignKey("poams.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(Text)
    due_date: Mapped[str] = mapped_column(String(10))
    done: Mapped[bool] = mapped_column(Boolean, default=False)


class POAMHistory(TenantOwned, Base):
    __tablename__ = "poam_history"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    poam_id: Mapped[str] = mapped_column(String(36), ForeignKey("poams.id", ondelete="CASCADE"), index=True)
    from_status: Mapped[str] = mapped_column(String(30))
    to_status: Mapped[str] = mapped_column(String(30))
    actor_id: Mapped[str] = mapped_column(String(36))
    comment: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScoreSnapshot(TenantOwned, Base):
    __tablename__ = "score_snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessments.id"), index=True)
    assessment_revision: Mapped[int] = mapped_column(Integer)
    mode: Mapped[str] = mapped_column(String(20))
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    input_hash: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Approval(TenantOwned, Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    entity: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[str] = mapped_column(String(36))
    decision: Mapped[str] = mapped_column(String(20))
    actor_id: Mapped[str] = mapped_column(String(36))
    comment: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditEvent(TenantOwned, Base):
    """Hash-chained, append-only audit log (per tenant)."""
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    seq: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[str] = mapped_column(String(36))
    channel: Mapped[str] = mapped_column(String(10))  # api|mcp|system
    action: Mapped[str] = mapped_column(String(60))
    entity: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[str] = mapped_column(String(36))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[str] = mapped_column(String(40))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    __table_args__ = (UniqueConstraint("tenant_id", "seq"),)
