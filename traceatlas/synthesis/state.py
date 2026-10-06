"""traceatlas.synthesis.state - Unified intelligence state (single source of truth).

Holds fused facts, observations, insights, hypotheses, contradictions, gaps and
NBA candidates produced by the synthesis engine. Everything is typed; every
statement carries its epistemic type so downstream layers cannot confuse a
hypothesis with a fact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.core.provenance import utcnow


class StatementType(str, Enum):
    """Absolute truth boundary categories (spec §2)."""
    FACT = "fact"                     # directly supported by source-backed evidence
    OBSERVATION = "observation"       # extracted from evidence
    INFERENCE = "inference"           # reasoned interpretation from facts
    INSIGHT = "insight"               # analytical interpretation, evidence-backed
    HYPOTHESIS = "hypothesis"         # possible explanation needing more evidence
    SPECULATION = "speculation"       # weak possibility, insufficient support
    UNKNOWN = "unknown"               # information not established
    LIMITATION = "limitation"         # caveat on other statements


@dataclass(slots=True)
class SynthesisStatement:
    statement_id: ID = field(default_factory=lambda: new_id("stmt"))
    stype: StatementType = StatementType.OBSERVATION
    text: str = ""
    evidence_ids: list[ID] = field(default_factory=list)
    entity_ids: list[ID] = field(default_factory=list)
    relationship_ids: list[ID] = field(default_factory=list)
    hypothesis_id: Optional[ID] = None
    confidence: str = "unrated"
    verification_status: str = "unverified"
    created_at: datetime = field(default_factory=utcnow)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"statement_id": self.statement_id, "stype": self.stype.value,
                "text": self.text, "evidence_ids": list(self.evidence_ids),
                "entity_ids": list(self.entity_ids),
                "relationship_ids": list(self.relationship_ids),
                "hypothesis_id": self.hypothesis_id,
                "confidence": self.confidence,
                "verification_status": self.verification_status,
                "created_at": self.created_at.isoformat(),
                "provenance": self.provenance}


@dataclass(slots=True)
class Insight:
    insight_id: ID = field(default_factory=lambda: new_id("insight"))
    title: str = ""
    statement: str = ""
    supporting_evidence_ids: list[ID] = field(default_factory=list)
    supporting_entity_ids: list[ID] = field(default_factory=list)
    source_independence: int = 0
    confidence: str = "moderate"          # qualitative band
    importance: str = "medium"            # critical|high|medium|low — NOT truth
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"insight_id": self.insight_id, "title": self.title,
                "statement": self.statement,
                "supporting_evidence_ids": list(self.supporting_evidence_ids),
                "supporting_entity_ids": list(self.supporting_entity_ids),
                "source_independence": self.source_independence,
                "confidence": self.confidence, "importance": self.importance,
                "limitations": list(self.limitations)}


@dataclass(slots=True)
class Gap:
    gap_id: ID = field(default_factory=lambda: new_id("gap"))
    question: str = ""
    why_it_matters: str = ""
    current_state: str = "unknown"
    missing_evidence: list[str] = field(default_factory=list)
    potential_capabilities: list[str] = field(default_factory=list)
    estimated_information_value: float = 0.5   # 0..1 heuristic, explainable
    priority: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {"gap_id": self.gap_id, "question": self.question,
                "why_it_matters": self.why_it_matters,
                "current_state": self.current_state,
                "missing_evidence": list(self.missing_evidence),
                "potential_capabilities": list(self.potential_capabilities),
                "estimated_information_value": self.estimated_information_value,
                "priority": self.priority}


@dataclass(slots=True)
class ContradictionRecord:
    contradiction_id: ID = field(default_factory=lambda: new_id("contra"))
    ctype: str = "value"            # value|temporal|identity|location|ownership...
    statement_a: str = ""
    statement_b: str = ""
    evidence_ids_a: list[ID] = field(default_factory=list)
    evidence_ids_b: list[ID] = field(default_factory=list)
    severity: float = 0.5
    resolution_status: str = "open"
    probing_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"contradiction_id": self.contradiction_id, "type": self.ctype,
                "statement_a": self.statement_a, "statement_b": self.statement_b,
                "evidence_ids_a": list(self.evidence_ids_a),
                "evidence_ids_b": list(self.evidence_ids_b),
                "severity": self.severity,
                "resolution_status": self.resolution_status,
                "probing_questions": list(self.probing_questions)}


@dataclass(slots=True)
class NextBestAction:
    action_id: ID = field(default_factory=lambda: new_id("nba"))
    kind: str = "collect"           # collect | falsify | discriminate | review
    description: str = ""
    capability: str = ""
    target_entity_id: Optional[ID] = None
    hypothesis_id: Optional[ID] = None
    expected_information_value: float = 0.5
    cost_estimate: float = 0.0
    rationale: str = ""             # WHY persisted (spec §36/§22)

    def to_dict(self) -> dict[str, Any]:
        return {"action_id": self.action_id, "kind": self.kind,
                "description": self.description, "capability": self.capability,
                "target_entity_id": self.target_entity_id,
                "hypothesis_id": self.hypothesis_id,
                "expected_information_value": self.expected_information_value,
                "cost_estimate": self.cost_estimate, "rationale": self.rationale}


@dataclass(slots=True)
class IntelligenceState:
    """Fused picture for one case at one point in time."""
    case_id: Optional[ID] = None
    objective: str = ""
    generated_at: datetime = field(default_factory=utcnow)
    statements: list[SynthesisStatement] = field(default_factory=list)
    insights: list[Insight] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)      # Hypothesis objects
    contradictions: list[ContradictionRecord] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    next_actions: list[NextBestAction] = field(default_factory=list)
    ach_matrices: list[dict[str, Any]] = field(default_factory=list)
    patterns: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    # -- accessors ----------------------------------------------------------
    def facts(self) -> list[SynthesisStatement]:
        return [s for s in self.statements if s.stype is StatementType.FACT]

    def observations(self) -> list[SynthesisStatement]:
        return [s for s in self.statements if s.stype is StatementType.OBSERVATION]

    def unknowns(self) -> list[SynthesisStatement]:
        return [s for s in self.statements if s.stype is StatementType.UNKNOWN]

    def add(self, stype: StatementType, text: str, *, evidence_ids=None,
            entity_ids=None, hypothesis_id=None,
            confidence: str = "unrated") -> SynthesisStatement:
        s = SynthesisStatement(stype=stype, text=text,
                               evidence_ids=list(evidence_ids or []),
                               entity_ids=list(entity_ids or []),
                               hypothesis_id=hypothesis_id, confidence=confidence)
        self.statements.append(s)
        return s

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id, "objective": self.objective,
            "generated_at": self.generated_at.isoformat(),
            "statements": [s.to_dict() for s in self.statements],
            "insights": [i.to_dict() for i in self.insights],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "gaps": [g.to_dict() for g in self.gaps],
            "next_actions": [a.to_dict() for a in self.next_actions],
            "ach_matrices": self.ach_matrices,
            "patterns": self.patterns,
            "metrics": self.metrics,
        }
