"""traceatlas.core.claim - Claims that must cite evidence to be supported."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .citation import Citation
from .confidence import Confidence
from .enums import ClaimStatus
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: ID = field(default_factory=lambda: new_id("claim"))
    case_id: Optional[ID] = None
    investigation_id: Optional[ID] = None
    statement: str = ""
    status: ClaimStatus = ClaimStatus.PROPOSED
    citations: tuple[Citation, ...] = ()
    confidence: Confidence = field(default_factory=Confidence.unknown)
    counter_claim_ids: tuple[ID, ...] = ()
    raised_by: str = ""
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    def is_supported(self) -> bool:
        return self.status == ClaimStatus.SUPPORTED and len(self.citations) > 0

    def unsupported_reason(self) -> Optional[str]:
        if not self.statement.strip():
            return "empty statement"
        if not self.citations:
            return "no citations"
        if self.status in (ClaimStatus.REFUTED, ClaimStatus.WITHDRAWN):
            return f"status={self.status.value}"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {"claim_id": self.claim_id, "case_id": self.case_id,
                "investigation_id": self.investigation_id,
                "statement": self.statement, "status": self.status.value,
                "citations": [c.to_dict() for c in self.citations],
                "confidence": self.confidence.to_dict(),
                "counter_claim_ids": list(self.counter_claim_ids),
                "raised_by": self.raised_by,
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Claim":
        return cls(claim_id=d["claim_id"], case_id=d.get("case_id"),
                   investigation_id=d.get("investigation_id"),
                   statement=d["statement"], status=ClaimStatus(d.get("status", "proposed")),
                   citations=tuple(Citation.from_dict(c) for c in d.get("citations", [])),
                   confidence=Confidence.from_dict(d["confidence"]),
                   counter_claim_ids=tuple(d.get("counter_claim_ids", ())),
                   raised_by=d.get("raised_by", ""),
                   created_at=datetime.fromisoformat(d["created_at"]),
                   updated_at=datetime.fromisoformat(d["updated_at"]))
