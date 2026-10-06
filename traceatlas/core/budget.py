"""traceatlas.core.budget - Investigation budgets."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .cost import Cost


@dataclass(frozen=True, slots=True)
class Budget:
    max_cost_usd: float = 10.0
    max_model_tokens: int = 1_000_000
    max_requests_per_source: int = 200
    max_wall_clock_minutes: int = 60
    max_tasks: int = 500

    def exhausted(self, spent: "Cost") -> bool:
        return (spent.cost_usd >= self.max_cost_usd
                or spent.model_tokens >= self.max_model_tokens
                or spent.tasks >= self.max_tasks)

    def to_dict(self) -> dict[str, Any]:
        return {"max_cost_usd": self.max_cost_usd,
                "max_model_tokens": self.max_model_tokens,
                "max_requests_per_source": self.max_requests_per_source,
                "max_wall_clock_minutes": self.max_wall_clock_minutes,
                "max_tasks": self.max_tasks}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Budget":
        return cls(max_cost_usd=float(d.get("max_cost_usd", 10.0)),
                   max_model_tokens=int(d.get("max_model_tokens", 1_000_000)),
                   max_requests_per_source=int(d.get("max_requests_per_source", 200)),
                   max_wall_clock_minutes=int(d.get("max_wall_clock_minutes", 60)),
                   max_tasks=int(d.get("max_tasks", 500)))
