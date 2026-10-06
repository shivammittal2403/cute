"""traceatlas.hypotheses.model - Typed hypothesis objects with full lifecycle.

Truth boundary: a hypothesis is NEVER a fact. It can only move to SUPPORTED via
evidence-linked scoring, and even then remains an assessment, not an observation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.core.provenance import utcnow


class HypothesisLifecycle(str, Enum):
    """Canonical lifecycle from the intelligence-synthesis spec."""
    PROPOSED = "proposed"
    ACTIVE = "active"
    TESTING = "testing"
    STRENGTHENED = "strengthened"
    WEAKENED = "weakened"
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    FALSIFIED = "falsified"
    INCONCLUSIVE = "inconclusive"
    ARCHIVED = "archived"


# Allowed transitions. Deliberately excludes any path that would silently
# convert a hypothesis into a fact; SUPPORTED still renders as HYPOTHESIS type.
ALLOWED_TRANSITIONS: dict[HypothesisLifecycle, set[HypothesisLifecycle]] = {
    HypothesisLifecycle.PROPOSED: {HypothesisLifecycle.ACTIVE,
                                   HypothesisLifecycle.ARCHIVED},
    HypothesisLifecycle.ACTIVE: {HypothesisLifecycle.TESTING,
                                 HypothesisLifecycle.ARCHIVED},
    HypothesisLifecycle.TESTING: {HypothesisLifecycle.STRENGTHENED,
                                  HypothesisLifecycle.WEAKENED,
                                  HypothesisLifecycle.SUPPORTED,
                                  HypothesisLifecycle.DISPUTED,
                                  HypothesisLifecycle.FALSIFIED,
                                  HypothesisLifecycle.INCONCLUSIVE},
    HypothesisLifecycle.STRENGTHENED: {HypothesisLifecycle.TESTING,
                                       HypothesisLifecycle.SUPPORTED,
                                       HypothesisLifecycle.DISPUTED,
                                       HypothesisLifecycle.FALSIFIED},
    HypothesisLifecycle.WEAKENED: {HypothesisLifecycle.TESTING,
                                   HypothesisLifecycle.DISPUTED,
                                   HypothesisLifecycle.FALSIFIED,
                                   HypothesisLifecycle.INCONCLUSIVE},
    HypothesisLifecycle.SUPPORTED: {HypothesisLifecycle.TESTING,
                                    HypothesisLifecycle.DISPUTED,
                                    HypothesisLifecycle.FALSIFIED,
                                    HypothesisLifecycle.ARCHIVED},
    HypothesisLifecycle.DISPUTED: {HypothesisLifecycle.TESTING,
                                   HypothesisLifecycle.FALSIFIED,
                                   HypothesisLifecycle.INCONCLUSIVE,
                                   HypothesisLifecycle.ARCHIVED},
    HypothesisLifecycle.FALSIFIED: {HypothesisLifecycle.ARCHIVED},
    HypothesisLifecycle.INCONCLUSIVE: {HypothesisLifecycle.TESTING,
                                       HypothesisLifecycle.ARCHIVED},
    HypothesisLifecycle.ARCHIVED: set(),
}


class QualitativeConfidence(str, Enum):
    """Heuristic bands — NOT calibrated probabilities (spec §9)."""
    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass(frozen=True, slots=True)
class ScoreComponents:
    """Explainable score components stored separately (spec §9)."""
    evidence_strength: float = 0.0        # 0..1 count-weighted support
    source_authority: float = 0.0         # 0..1 mean authority of sources
    source_independence: int = 0          # number of independent clusters
    temporal_consistency: float = 1.0     # 1.0 consistent, 0.0 conflicting
    entity_consistency: float = 1.0
    relationship_consistency: float = 1.0
    evidence_coverage: float = 0.0        # fraction of required evidence held
    contradiction_severity: float = 0.0   # 0..1 max severity of opposing items
    assumption_burden: int = 0            # unverified assumptions relied upon
    alternative_strength: float = 0.0     # strength of best competing hypothesis
    freshness: float = 1.0                # decayed recency of supporting evidence
    missing_evidence_penalty: float = 0.0

    def qualitative(self) -> QualitativeConfidence:
        """Map components to a qualitative band with penalties for burden."""
        raw = (0.30 * self.evidence_strength
               + 0.20 * min(1.0, self.source_independence / 3.0)
               + 0.15 * self.temporal_consistency
               + 0.15 * self.entity_consistency
               + 0.10 * self.freshness
               + 0.05 * self.evidence_coverage)
        raw -= 0.10 * self.contradiction_severity
        raw -= 0.05 * min(self.assumption_burden, 4)
        raw -= 0.15 * self.alternative_strength
        raw = max(0.0, min(1.0, raw))
        if raw < 0.20:
            return QualitativeConfidence.VERY_LOW
        if raw < 0.40:
            return QualitativeConfidence.LOW
        if raw < 0.60:
            return QualitativeConfidence.MODERATE
        if raw < 0.80:
            return QualitativeConfidence.HIGH
        return QualitativeConfidence.VERY_HIGH


@dataclass(slots=True)
class Hypothesis:
    hypothesis_id: ID = field(default_factory=lambda: new_id("hyp"))
    case_id: Optional[ID] = None
    question_id: Optional[str] = None
    statement: str = ""
    description: str = ""
    htype: str = "explanatory"             # explanatory | causal | identity
    status: HypothesisLifecycle = HypothesisLifecycle.PROPOSED
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    created_by: str = "hypothesis_generator"
    supporting_evidence_ids: list[ID] = field(default_factory=list)
    opposing_evidence_ids: list[ID] = field(default_factory=list)
    neutral_evidence_ids: list[ID] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    discriminating_questions: list[str] = field(default_factory=list)
    falsification_conditions: list[str] = field(default_factory=list)
    related_entity_ids: list[ID] = field(default_factory=list)
    competing_with: list[ID] = field(default_factory=list)
    scores: ScoreComponents = field(default_factory=ScoreComponents)
    verification_status: str = "unverified"
    next_actions: list[dict[str, Any]] = field(default_factory=list)

    # -- lifecycle ----------------------------------------------------------
    def transition(self, new_status: HypothesisLifecycle) -> None:
        """Move through the lifecycle; illegal jumps raise ValueError."""
        if new_status == self.status:
            return
        if new_status not in ALLOWED_TRANSITIONS[self.status]:
            raise ValueError(
                f"illegal hypothesis transition {self.status.value} -> {new_status.value}"
            )
        self.status = new_status
        self.updated_at = utcnow()

    @property
    def confidence(self) -> QualitativeConfidence:
        return self.scores.qualitative()

    def add_support(self, evidence_id: ID) -> None:
        if evidence_id not in self.supporting_evidence_ids:
            self.supporting_evidence_ids.append(evidence_id)
            self.updated_at = utcnow()

    def add_opposition(self, evidence_id: ID) -> None:
        if evidence_id not in self.opposing_evidence_ids:
            self.opposing_evidence_ids.append(evidence_id)
            self.updated_at = utcnow()

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id, "case_id": self.case_id,
            "question_id": self.question_id, "statement": self.statement,
            "description": self.description, "type": self.htype,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "opposing_evidence_ids": list(self.opposing_evidence_ids),
            "neutral_evidence_ids": list(self.neutral_evidence_ids),
            "assumptions": list(self.assumptions), "unknowns": list(self.unknowns),
            "contradictions": list(self.contradictions),
            "required_evidence": list(self.required_evidence),
            "discriminating_questions": list(self.discriminating_questions),
            "falsification_conditions": list(self.falsification_conditions),
            "related_entity_ids": list(self.related_entity_ids),
            "competing_with": list(self.competing_with),
            "scores": {k: getattr(self.scores, k) for k in self.scores.__dataclass_fields__},
            "confidence": self.confidence.value,
            "verification_status": self.verification_status,
            "next_actions": list(self.next_actions),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Hypothesis":
        sc = d.get("scores", {})
        fields = ScoreComponents.__dataclass_fields__
        scores = ScoreComponents(**{k: v for k, v in sc.items() if k in fields})
        return cls(
            hypothesis_id=d["hypothesis_id"], case_id=d.get("case_id"),
            question_id=d.get("question_id"), statement=d.get("statement", ""),
            description=d.get("description", ""), htype=d.get("type", "explanatory"),
            status=HypothesisLifecycle(d.get("status", "proposed")),
            created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else utcnow(),
            updated_at=datetime.fromisoformat(d["updated_at"]) if d.get("updated_at") else utcnow(),
            created_by=d.get("created_by", "hypothesis_generator"),
            supporting_evidence_ids=list(d.get("supporting_evidence_ids", [])),
            opposing_evidence_ids=list(d.get("opposing_evidence_ids", [])),
            neutral_evidence_ids=list(d.get("neutral_evidence_ids", [])),
            assumptions=list(d.get("assumptions", [])),
            unknowns=list(d.get("unknowns", [])),
            contradictions=list(d.get("contradictions", [])),
            required_evidence=list(d.get("required_evidence", [])),
            discriminating_questions=list(d.get("discriminating_questions", [])),
            falsification_conditions=list(d.get("falsification_conditions", [])),
            related_entity_ids=list(d.get("related_entity_ids", [])),
            competing_with=list(d.get("competing_with", [])),
            scores=scores,
            verification_status=d.get("verification_status", "unverified"),
            next_actions=list(d.get("next_actions", [])),
        )
