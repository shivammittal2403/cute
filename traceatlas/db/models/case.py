"""Persistent records for the case plane (cases, investigations, tasks, evidence,
entities, relationships, observations, claims, contradictions, audit, model usage).

JSON columns store canonical domain-object payloads produced by core.to_dict() and
rehydrated with the matching from_dict() classmethod - typed round-trip, no loose dicts.
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from traceatlas.db.base import Base, TimestampMixin


class CaseRecord(Base, TimestampMixin):
    __tablename__ = "cases"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    title: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), index=True)
    payload_json: Mapped[dict] = mapped_column(JSON)  # full Case.to_dict()

    def to_domain(self):
        from traceatlas.core.case import Case
        return Case.from_dict(self.payload_json)


class InvestigationRecord(Base, TimestampMixin):
    __tablename__ = "investigations"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    stop_reason: Mapped[str] = mapped_column(String(64), default="")
    plan_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    payload_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class TaskRecord(Base, TimestampMixin):
    __tablename__ = "tasks"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.investigation_id"), index=True
    )
    wave: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    task_json: Mapped[dict] = mapped_column(JSON)
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class EvidenceRecord(Base, TimestampMixin):
    __tablename__ = "evidence"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    source_slug: Mapped[str] = mapped_column(String(128), index=True)
    uri: Mapped[str] = mapped_column(Text, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    retrieved_at: Mapped[str] = mapped_column(String(64), default="")
    blob_path: Mapped[str] = mapped_column(Text, default="")


class EntityRecord(Base, TimestampMixin):
    __tablename__ = "entities"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    display_name: Mapped[str] = mapped_column(String(512), index=True)
    entity_json: Mapped[dict] = mapped_column(JSON)


class RelationshipRecord(Base, TimestampMixin):
    __tablename__ = "relationships"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    edge_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    src_entity_id: Mapped[str] = mapped_column(String(64), index=True)
    dst_entity_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    relationship_json: Mapped[dict] = mapped_column(JSON)


class ObservationRecord(Base, TimestampMixin):
    __tablename__ = "observations"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    observation_json: Mapped[dict] = mapped_column(JSON)


class ClaimRecord(Base, TimestampMixin):
    __tablename__ = "claims"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    claim_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), index=True, default="unverified")
    claim_json: Mapped[dict] = mapped_column(JSON)


class ContradictionRecord(Base, TimestampMixin):
    __tablename__ = "contradictions"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contradiction_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id"), index=True)
    conflict_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    resolution_status: Mapped[str] = mapped_column(String(32), default="open")
    payload_json: Mapped[dict] = mapped_column(JSON)


class AuditEventRecord(Base, TimestampMixin):
    __tablename__ = "audit_events"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="")
    action: Mapped[str] = mapped_column(String(128), index=True)
    detail_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ModelUsageRecord(Base, TimestampMixin):
    __tablename__ = "model_usage"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    task_kind: Mapped[str] = mapped_column(String(64))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Integer, default=0.0)
