"""traceatlas.planning.planner_output - Plan container."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from traceatlas.core.identifiers import ID
from traceatlas.core.task import Task


@dataclass(slots=True)
class Plan:
    objective_id: Optional[ID] = None
    tasks: list[Task] = field(default_factory=list)
    estimated_cost_usd: float = 0.0
    estimated_minutes: float = 0.0
    warnings: list[str] = field(default_factory=list)
    stop_conditions: tuple[str, ...] = ()

    def waves(self) -> dict[int, list[Task]]:
        out: dict[int, list[Task]] = {}
        for t in self.tasks:
            out.setdefault(t.wave, []).append(t)
        return dict(sorted(out.items()))

    def to_dict(self) -> dict[str, Any]:
        return {"objective_id": self.objective_id,
                "tasks": [t.to_dict() for t in self.tasks],
                "estimated_cost_usd": self.estimated_cost_usd,
                "estimated_minutes": self.estimated_minutes,
                "warnings": self.warnings}
