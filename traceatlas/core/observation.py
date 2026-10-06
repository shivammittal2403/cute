"""traceatlas.core.observation - Single-source observations (pre-adjudication)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: ID = field(default_factory=lambda: new_id("observation"))
    case_id: Optional[ID] = None
    subject_id: Optional[ID] = None
    predicate: str = ""
    value: Any = None
    evidence_id: Optional[ID] = None
    source_id: Optional[ID] = None
    observed_at: Optional[datetime] = None
    recorded_at: datetime = field(default_factory=utcnow)
    context: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.subject_id or "", self.predicate)

    def to_dict(self) -> dict[str, Any]:
        return {"observation_id": self.observation_id, "case_id": self.case_id,
                "subject_id": self.subject_id, "predicate": self.predicate,
                "value": self.value, "evidence_id": self.evidence_id,
                "source_id": self.source_id,
                "observed_at": self.observed_at.isoformat() if self.observed_at else None,
                "recorded_at": self.recorded_at.isoformat(), "context": self.context}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Observation":
        return cls(observation_id=d["observation_id"], case_id=d.get("case_id"),
                   subject_id=d.get("subject_id"), predicate=d["predicate"],
                   value=d.get("value"), evidence_id=d.get("evidence_id"),
                   source_id=d.get("source_id"),
                   observed_at=datetime.fromisoformat(d["observed_at"]) if d.get("observed_at") else None,
                   recorded_at=datetime.fromisoformat(d["recorded_at"]),
                   context=d.get("context", {}))
