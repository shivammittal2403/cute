"""traceatlas.core.next_action - Next-best-action recommendation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .enums import RiskLevel, TaskKind
from .identifiers import ID

_RISK_PENALTY = {"none": 0.0, "low": 0.05, "medium": 0.2, "high": 0.5, "critical": 0.9}


@dataclass(frozen=True, slots=True)
class NextAction:
    action: str = ""
    kind: TaskKind = TaskKind.COLLECT
    expected_information_gain: float = 0.0
    estimated_cost_usd: float = 0.0
    risk: RiskLevel = RiskLevel.LOW
    requires_human_approval: bool = False
    addresses_gap_id: Optional[ID] = None
    rationale: str = ""
    priority: float = 0.0

    def compute_priority(self) -> float:
        cost_penalty = min(1.0, self.estimated_cost_usd / 5.0)
        risk_penalty = _RISK_PENALTY[self.risk.value]
        approval_penalty = 0.15 if self.requires_human_approval else 0.0
        return max(0.0, self.expected_information_gain
                   - cost_penalty - risk_penalty - approval_penalty)

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "kind": self.kind.value,
                "expected_information_gain": self.expected_information_gain,
                "estimated_cost_usd": self.estimated_cost_usd,
                "risk": self.risk.value,
                "requires_human_approval": self.requires_human_approval,
                "addresses_gap_id": self.addresses_gap_id,
                "rationale": self.rationale, "priority": round(self.priority, 4)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NextAction":
        return cls(action=d.get("action", ""), kind=TaskKind(d.get("kind", "collect")),
                   expected_information_gain=float(d.get("expected_information_gain", 0.0)),
                   estimated_cost_usd=float(d.get("estimated_cost_usd", 0.0)),
                   risk=RiskLevel(d.get("risk", "low")),
                   requires_human_approval=bool(d.get("requires_human_approval", False)),
                   addresses_gap_id=d.get("addresses_gap_id"),
                   rationale=d.get("rationale", ""),
                   priority=float(d.get("priority", 0.0)))
