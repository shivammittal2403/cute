"""traceatlas.core.hypothesis - Competing explanations under test."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .confidence import Confidence
from .enums import HypothesisStatus
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Hypothesis:
    hypothesis_id: ID = field(default_factory=lambda: new_id("hypothesis"))
    case_id: Optional[ID] = None
    question: str = ""
    statement: str = ""
    status: HypothesisStatus = HypothesisStatus.OPEN
    alternative_ids: tuple[ID, ...] = ()
    supporting_claim_ids: tuple[ID, ...] = ()
    refuting_claim_ids: tuple[ID, ...] = ()
    predictions: tuple[str, ...] = ()
    confidence: Confidence = field(default_factory=Confidence.unknown)
    created_at: datetime = field(default_factory=utcnow)

    def balance(self) -> float:
        total = len(self.supporting_claim_ids) + len(self.refuting_claim_ids)
        if total == 0:
            return 0.0
        return (len(self.supporting_claim_ids) - len(self.refuting_claim_ids)) / total

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "case_id": self.case_id,
                "question": self.question, "statement": self.statement,
                "status": self.status.value,
                "alternative_ids": list(self.alternative_ids),
                "supporting_claim_ids": list(self.supporting_claim_ids),
                "refuting_claim_ids": list(self.refuting_claim_ids),
                "predictions": list(self.predictions),
                "confidence": self.confidence.to_dict(),
                "created_at": self.created_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Hypothesis":
        return cls(hypothesis_id=d["hypothesis_id"], case_id=d.get("case_id"),
                   question=d.get("question", ""), statement=d["statement"],
                   status=HypothesisStatus(d.get("status", "open")),
                   alternative_ids=tuple(d.get("alternative_ids", ())),
                   supporting_claim_ids=tuple(d.get("supporting_claim_ids", ())),
                   refuting_claim_ids=tuple(d.get("refuting_claim_ids", ())),
                   predictions=tuple(d.get("predictions", ())),
                   confidence=Confidence.from_dict(d["confidence"]),
                   created_at=datetime.fromisoformat(d["created_at"]))
