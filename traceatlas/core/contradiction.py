"""traceatlas.core.contradiction - Recorded conflicts between assertions."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import ContradictionSeverity
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Contradiction:
    contradiction_id: ID = field(default_factory=lambda: new_id("contradiction"))
    case_id: Optional[ID] = None
    left_id: ID = ID("")
    right_id: ID = ID("")
    kind: str = "value"
    severity: ContradictionSeverity = ContradictionSeverity.MEDIUM
    explanation: str = ""
    resolved: bool = False
    resolution: str = ""
    detected_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {"contradiction_id": self.contradiction_id, "case_id": self.case_id,
                "left_id": self.left_id, "right_id": self.right_id,
                "kind": self.kind, "severity": self.severity.value,
                "explanation": self.explanation, "resolved": self.resolved,
                "resolution": self.resolution,
                "detected_at": self.detected_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Contradiction":
        return cls(contradiction_id=d["contradiction_id"], case_id=d.get("case_id"),
                   left_id=d["left_id"], right_id=d["right_id"],
                   kind=d.get("kind", "value"),
                   severity=ContradictionSeverity(d.get("severity", "medium")),
                   explanation=d.get("explanation", ""),
                   resolved=bool(d.get("resolved", False)),
                   resolution=d.get("resolution", ""),
                   detected_at=datetime.fromisoformat(d["detected_at"]))
