"""traceatlas.core.fact - Adjudicated facts backed by observations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .confidence import Confidence
from .identifiers import ID, new_id


@dataclass(frozen=True, slots=True)
class Fact:
    fact_id: ID = field(default_factory=lambda: new_id("fact"))
    case_id: Optional[ID] = None
    subject_id: Optional[ID] = None
    predicate: str = ""
    value: Any = None
    observation_ids: tuple[ID, ...] = ()
    contradicting_observation_ids: tuple[ID, ...] = ()
    confidence: Confidence = field(default_factory=Confidence.unknown)
    superseded_by: Optional[ID] = None

    def to_dict(self) -> dict[str, Any]:
        return {"fact_id": self.fact_id, "case_id": self.case_id,
                "subject_id": self.subject_id, "predicate": self.predicate,
                "value": self.value, "observation_ids": list(self.observation_ids),
                "contradicting_observation_ids": list(self.contradicting_observation_ids),
                "confidence": self.confidence.to_dict(),
                "superseded_by": self.superseded_by}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Fact":
        return cls(fact_id=d["fact_id"], case_id=d.get("case_id"),
                   subject_id=d.get("subject_id"), predicate=d["predicate"],
                   value=d.get("value"),
                   observation_ids=tuple(d.get("observation_ids", ())),
                   contradicting_observation_ids=tuple(d.get("contradicting_observation_ids", ())),
                   confidence=Confidence.from_dict(d["confidence"]),
                   superseded_by=d.get("superseded_by"))
