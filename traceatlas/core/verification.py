"""traceatlas.core.verification - Verification outcomes for claims."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .confidence import Confidence
from .enums import VerificationDecision
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Verification:
    verification_id: ID = field(default_factory=lambda: new_id("verification"))
    claim_id: ID = ID("")
    decision: VerificationDecision = VerificationDecision.INCONCLUSIVE
    confidence: Confidence = field(default_factory=Confidence.unknown)
    independent_source_count: int = 0
    reasoning: str = ""
    verifier: str = ""
    verified_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {"verification_id": self.verification_id, "claim_id": self.claim_id,
                "decision": self.decision.value,
                "confidence": self.confidence.to_dict(),
                "independent_source_count": self.independent_source_count,
                "reasoning": self.reasoning, "verifier": self.verifier,
                "verified_at": self.verified_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Verification":
        return cls(verification_id=d["verification_id"], claim_id=d["claim_id"],
                   decision=VerificationDecision(d["decision"]),
                   confidence=Confidence.from_dict(d["confidence"]),
                   independent_source_count=d.get("independent_source_count", 0),
                   reasoning=d.get("reasoning", ""), verifier=d.get("verifier", ""),
                   verified_at=datetime.fromisoformat(d["verified_at"]))
