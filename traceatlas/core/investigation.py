"""traceatlas.core.investigation - A run of planned tasks against an objective."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .budget import Budget
from .cost import Cost
from .enums import InvestigationStatus, TaskStatus
from .identifiers import ID, new_id
from .task import Task


@dataclass(slots=True)
class Investigation:
    investigation_id: ID = field(default_factory=lambda: new_id("investigation"))
    case_id: ID = ID("")
    objective_id: Optional[ID] = None
    status: InvestigationStatus = InvestigationStatus.PLANNED
    tasks: dict[ID, Task] = field(default_factory=dict)
    budget: Budget = field(default_factory=Budget)
    spent: Cost = field(default_factory=Cost)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    stop_reason: str = ""

    def ready_tasks(self) -> list[Task]:
        out = []
        for t in self.tasks.values():
            if t.status != TaskStatus.PENDING:
                continue
            deps_ok = all(self.tasks[d].status == TaskStatus.SUCCEEDED
                          for d in t.depends_on if d in self.tasks)
            if deps_ok:
                out.append(t)
        return sorted(out, key=lambda t: (t.wave, t.task_id))

    def progress(self) -> float:
        if not self.tasks:
            return 0.0
        done = sum(1 for t in self.tasks.values() if t.terminal)
        return done / len(self.tasks)

    def to_dict(self) -> dict[str, Any]:
        def _dt(v):
            return v.isoformat() if v else None
        return {"investigation_id": self.investigation_id, "case_id": self.case_id,
                "objective_id": self.objective_id, "status": self.status.value,
                "tasks": [t.to_dict() for t in self.tasks.values()],
                "budget": self.budget.to_dict(), "spent": self.spent.to_dict(),
                "started_at": _dt(self.started_at), "finished_at": _dt(self.finished_at),
                "stop_reason": self.stop_reason}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Investigation":
        def _dt(v):
            return datetime.fromisoformat(v) if v else None
        inv = cls(investigation_id=d["investigation_id"], case_id=d["case_id"],
                  objective_id=d.get("objective_id"),
                  status=InvestigationStatus(d.get("status", "planned")),
                  budget=Budget.from_dict(d.get("budget", {})),
                  spent=Cost.from_dict(d.get("spent", {})),
                  started_at=_dt(d.get("started_at")),
                  finished_at=_dt(d.get("finished_at")),
                  stop_reason=d.get("stop_reason", ""))
        inv.tasks = {t["task_id"]: Task.from_dict(t) for t in d.get("tasks", [])}
        return inv
