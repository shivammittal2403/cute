"""traceatlas.core.case - Top-level investigative container."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .authorization import Authorization
from .enums import CaseStatus
from .identifiers import ID, new_id
from .objective import Objective
from .provenance import utcnow


@dataclass(slots=True)
class Case:
    case_id: ID = field(default_factory=lambda: new_id("case"))
    tenant_id: str = ""
    title: str = ""
    description: str = ""
    status: CaseStatus = CaseStatus.DRAFT
    objective: Optional[Objective] = None
    authorization: Optional[Authorization] = None
    tags: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    closed_at: Optional[datetime] = None

    def can_collect(self) -> bool:
        return (self.status == CaseStatus.ACTIVE
                and self.authorization is not None
                and self.authorization.is_valid())

    def to_dict(self) -> dict[str, Any]:
        def _dt(v):
            return v.isoformat() if v else None
        return {"case_id": self.case_id, "tenant_id": self.tenant_id,
                "title": self.title, "description": self.description,
                "status": self.status.value,
                "objective": self.objective.to_dict() if self.objective else None,
                "authorization": self.authorization.to_dict() if self.authorization else None,
                "tags": list(self.tags), "created_at": self.created_at.isoformat(),
                "closed_at": _dt(self.closed_at)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Case":
        def _dt(v):
            return datetime.fromisoformat(v) if v else None
        return cls(case_id=d["case_id"], tenant_id=d.get("tenant_id", ""),
                   title=d.get("title", ""), description=d.get("description", ""),
                   status=CaseStatus(d.get("status", "draft")),
                   objective=Objective.from_dict(d["objective"]) if d.get("objective") else None,
                   authorization=Authorization.from_dict(d["authorization"]) if d.get("authorization") else None,
                   tags=tuple(d.get("tags", ())),
                   created_at=datetime.fromisoformat(d["created_at"]),
                   closed_at=_dt(d.get("closed_at")))
