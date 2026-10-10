"""Durable repositories for the truth layer (evidence, graph, observations,
contradictions).

These mirror the case workspace artifacts (content-addressed evidence store,
graph JSONL, observations JSONL, contradiction records) into SQL so production
querying does not depend on process-local filesystem state. Blob bytes stay in
the evidence store (local disk / S3-compatible object storage); the DB keeps
immutable metadata + integrity hashes only.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from traceatlas.core.entity import Entity
from traceatlas.core.enums import ContradictionSeverity
from traceatlas.core.evidence import Evidence
from traceatlas.core.observation import Observation
from traceatlas.core.relationship import Relationship
from traceatlas.db.models.case import (
    ContradictionRecord,
    EntityRecord,
    EvidenceRecord,
    ObservationRecord,
    RelationshipRecord,
)


def _dt(value):
    return value.isoformat() if hasattr(value, "isoformat") else (value or "")


class EvidenceRepository:
    def __init__(self, session: Session):
        self.session = session

    def save(self, ev: Evidence) -> EvidenceRecord:
        rec = self.session.scalar(
            select(EvidenceRecord).where(EvidenceRecord.evidence_id == ev.evidence_id))
        if rec is None:
            rec = EvidenceRecord(evidence_id=ev.evidence_id, case_id=ev.case_id or "",
                                 sha256=ev.sha256, source_slug=ev.source_uri, uri=ev.source_uri,
                                 size_bytes=ev.size_bytes, retrieved_at=_dt(ev.captured_at),
                                 blob_path=ev.storage_key)
            self.session.add(rec)
        else:
            rec.sha256 = ev.sha256
            rec.blob_path = ev.storage_key or rec.blob_path
        self.session.flush()
        return rec

    def get(self, evidence_id: str) -> Evidence | None:
        rec = self.session.scalar(
            select(EvidenceRecord).where(EvidenceRecord.evidence_id == evidence_id))
        if rec is None:
            return None
        return Evidence(evidence_id=rec.evidence_id, case_id=rec.case_id, sha256=rec.sha256,
                        size_bytes=rec.size_bytes, source_uri=rec.uri,
                        captured_at=_parse_dt(rec.retrieved_at), storage_key=rec.blob_path)

    def list_for_case(self, case_id: str) -> list[Evidence]:
        rows = self.session.scalars(
            select(EvidenceRecord).where(EvidenceRecord.case_id == case_id)
            .order_by(EvidenceRecord.pk)).all()
        return [Evidence(evidence_id=r.evidence_id, case_id=r.case_id, sha256=r.sha256,
                         size_bytes=r.size_bytes, source_uri=r.uri,
                         captured_at=_parse_dt(r.retrieved_at), storage_key=r.blob_path)
                for r in rows]

    def ingest_workspace(self, case_id: str, evidence_root: str | Path) -> int:
        """Import an append-only evidence registry JSONL produced by a run."""
        reg = Path(evidence_root) / "evidence_registry.jsonl"
        if not reg.exists():
            return 0
        n = 0
        seen: set[str] = set()
        for line in reg.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = Evidence.from_dict(json.loads(line))
            except Exception:
                continue
            if ev.evidence_id in seen:
                continue
            seen.add(ev.evidence_id)
            self.save(ev)
            n += 1
        return n


def _parse_dt(v: str):
    from datetime import datetime
    try:
        return datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


class GraphRepository:
    def __init__(self, session: Session):
        self.session = session

    def save_entity(self, ent: Entity) -> EntityRecord:
        rec = self.session.scalar(
            select(EntityRecord).where(EntityRecord.entity_id == ent.entity_id))
        if rec is None:
            rec = EntityRecord(entity_id=ent.entity_id, case_id=ent.case_id or "",
                               kind=ent.kind.value, display_name=ent.display_name,
                               entity_json=ent.to_dict())
            self.session.add(rec)
        else:
            rec.kind = ent.kind.value
            rec.display_name = ent.display_name
            rec.entity_json = ent.to_dict()
        self.session.flush()
        return rec

    def save_relationship(self, rel: Relationship) -> RelationshipRecord:
        rec = self.session.scalar(
            select(RelationshipRecord).where(RelationshipRecord.edge_id == rel.relationship_id))
        if rec is None:
            rec = RelationshipRecord(edge_id=rel.relationship_id, case_id=rel.case_id or "",
                                      src_entity_id=rel.source_entity_id,
                                      dst_entity_id=rel.target_entity_id,
                                      kind=rel.kind.value, relationship_json=rel.to_dict())
            self.session.add(rec)
        else:
            rec.kind = rel.kind.value
            rec.relationship_json = rel.to_dict()
        self.session.flush()
        return rec

    def entities(self, case_id: str) -> list[Entity]:
        rows = self.session.scalars(
            select(EntityRecord).where(EntityRecord.case_id == case_id)
            .order_by(EntityRecord.pk)).all()
        return [Entity.from_dict(r.entity_json) for r in rows]

    def relationships(self, case_id: str) -> list[Relationship]:
        rows = self.session.scalars(
            select(RelationshipRecord).where(RelationshipRecord.case_id == case_id)
            .order_by(RelationshipRecord.pk)).all()
        return [Relationship.from_dict(r.relationship_json) for r in rows]

    def snapshot(self, case_id: str) -> dict:
        return {"entities": [e.to_dict() for e in self.entities(case_id)],
                "relationships": [r.to_dict() for r in self.relationships(case_id)]}

    def rebuild_graph(self, case_id: str):
        """Rehydrate an in-memory KnowledgeGraph from durable records."""
        from traceatlas.graph.model import KnowledgeGraph
        g = KnowledgeGraph(persist_path=None)
        for e in self.entities(case_id):
            g.add_entity(e)
        for r in self.relationships(case_id):
            try:
                g.add_relationship(r)
            except ValueError:
                continue  # dangling edge (endpoints pruned) — keep graph consistent
        return g

    def ingest_workspace(self, case_id: str, graph_path: str | Path) -> int:
        """Import a graph JSONL (entity/relationship records) produced by a run."""
        p = Path(graph_path)
        if not p.exists():
            return 0
        n = 0
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            payload = d  # graph JSONL records are flat dicts tagged with _record
            try:
                if "entity_id" in payload:
                    self.save_entity(Entity.from_dict(payload))
                elif "relationship_id" in payload:
                    self.save_relationship(Relationship.from_dict(payload))
                else:
                    continue
                n += 1
            except Exception:
                continue
        return n


class ObservationRepository:
    def __init__(self, session: Session):
        self.session = session

    def save(self, obs: Observation) -> ObservationRecord:
        rec = self.session.scalar(
            select(ObservationRecord).where(
                ObservationRecord.observation_id == obs.observation_id))
        if rec is None:
            rec = ObservationRecord(observation_id=obs.observation_id,
                                    case_id=obs.case_id or "",
                                    evidence_id=obs.evidence_id or "",
                                    observation_json=obs.to_dict())
            self.session.add(rec)
        else:
            rec.observation_json = obs.to_dict()
        self.session.flush()
        return rec

    def list_for_case(self, case_id: str) -> list[Observation]:
        rows = self.session.scalars(
            select(ObservationRecord).where(ObservationRecord.case_id == case_id)
            .order_by(ObservationRecord.pk)).all()
        return [Observation.from_dict(r.observation_json) for r in rows]

    def ingest_workspace(self, case_id: str, observations_path: str | Path) -> int:
        p = Path(observations_path)
        if not p.exists():
            return 0
        n = 0
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                self.save(Observation.from_dict(json.loads(line)))
                n += 1
            except Exception:
                continue
        return n


class ContradictionRepository:
    def __init__(self, session: Session):
        self.session = session

    def save(self, case_id: str, contradiction_id: str, conflict_type: str,
             severity: ContradictionSeverity | str, payload: dict,
             resolution_status: str = "open") -> ContradictionRecord:
        sev = severity.value if isinstance(severity, ContradictionSeverity) else str(severity)
        rec = self.session.scalar(
            select(ContradictionRecord).where(
                ContradictionRecord.contradiction_id == contradiction_id))
        if rec is None:
            rec = ContradictionRecord(contradiction_id=contradiction_id, case_id=case_id,
                                      conflict_type=conflict_type, severity=sev,
                                      resolution_status=resolution_status, payload_json=payload)
            self.session.add(rec)
        else:
            rec.severity = sev
            rec.resolution_status = resolution_status
            rec.payload_json = payload
        self.session.flush()
        return rec

    def list_for_case(self, case_id: str) -> list[dict]:
        rows = self.session.scalars(
            select(ContradictionRecord).where(ContradictionRecord.case_id == case_id)
            .order_by(ContradictionRecord.pk)).all()
        return [r.payload_json for r in rows]
