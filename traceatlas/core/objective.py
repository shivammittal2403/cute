"""traceatlas.core.objective - Versioned objective attached to a case."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import ObjectiveStatus
from .identifiers import ID, new_id
from .objective_spec import ObjectiveSpec
from .provenance import utcnow


@dataclass(slots=True)
class Objective:
    objective_id: ID = field(default_factory=lambda: new_id("objective"))
    case_id: Optional[ID] = None
    version: int = 1
    status: ObjectiveStatus = ObjectiveStatus.DRAFT
    spec: ObjectiveSpec = field(default_factory=ObjectiveSpec)
    history: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    def revise(self, new_spec: ObjectiveSpec) -> "Objective":
        return Objective(objective_id=new_id("objective"), case_id=self.case_id,
                         version=self.version + 1, status=ObjectiveStatus.DRAFT,
                         spec=new_spec, history=self.history + (self.spec.raw_text,),
                         created_at=utcnow(), updated_at=utcnow())

    def to_dict(self) -> dict[str, Any]:
        return {"objective_id": self.objective_id, "case_id": self.case_id,
                "version": self.version, "status": self.status.value,
                "spec": self.spec.to_dict(), "history": list(self.history),
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Objective":
        return cls(objective_id=d["objective_id"], case_id=d.get("case_id"),
                   version=d.get("version", 1),
                   status=ObjectiveStatus(d.get("status", "draft")),
                   spec=ObjectiveSpec.from_dict(d.get("spec", {})),
                   history=tuple(d.get("history", ())),
                   created_at=datetime.fromisoformat(d["created_at"]),
                   updated_at=datetime.fromisoformat(d["updated_at"]))
