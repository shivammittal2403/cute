"""traceatlas.core.information_gap - Known unknowns in the knowledge state."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .identifiers import ID, new_id


@dataclass(slots=True)
class InformationGap:
    gap_id: ID = field(default_factory=lambda: new_id("gap"))
    case_id: Optional[ID] = None
    question: str = ""
    why_it_matters: str = ""
    blocking: bool = False
    candidate_actions: tuple[str, ...] = ()
    filled_by_claim_id: Optional[ID] = None

    @property
    def open(self) -> bool:
        return self.filled_by_claim_id is None

    def to_dict(self) -> dict[str, Any]:
        return {"gap_id": self.gap_id, "case_id": self.case_id,
                "question": self.question, "why_it_matters": self.why_it_matters,
                "blocking": self.blocking,
                "candidate_actions": list(self.candidate_actions),
                "filled_by_claim_id": self.filled_by_claim_id}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "InformationGap":
        return cls(gap_id=d["gap_id"], case_id=d.get("case_id"),
                   question=d.get("question", ""),
                   why_it_matters=d.get("why_it_matters", ""),
                   blocking=bool(d.get("blocking", False)),
                   candidate_actions=tuple(d.get("candidate_actions", ())),
                   filled_by_claim_id=d.get("filled_by_claim_id"))
