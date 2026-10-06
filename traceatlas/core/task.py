"""traceatlas.core.task - Unit of executable work in an investigation plan."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .enums import TaskKind, TaskStatus
from .identifiers import ID, new_id


@dataclass(slots=True)
class Task:
    task_id: ID = field(default_factory=lambda: new_id("task"))
    investigation_id: Optional[ID] = None
    kind: TaskKind = TaskKind.COLLECT
    name: str = ""
    instruction: dict[str, Any] = field(default_factory=dict)
    depends_on: tuple[ID, ...] = ()
    wave: int = 0
    status: TaskStatus = TaskStatus.PENDING
    assigned_worker: str = ""
    attempts: int = 0
    max_attempts: int = 3
    timeout_seconds: int = 120
    budget_units: float = 1.0
    result_id: Optional[ID] = None
    error: str = ""

    @property
    def terminal(self) -> bool:
        return self.status in (TaskStatus.SUCCEEDED, TaskStatus.FAILED,
                               TaskStatus.CANCELLED, TaskStatus.SKIPPED)

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "investigation_id": self.investigation_id,
                "kind": self.kind.value, "name": self.name,
                "instruction": self.instruction, "depends_on": list(self.depends_on),
                "wave": self.wave, "status": self.status.value,
                "assigned_worker": self.assigned_worker, "attempts": self.attempts,
                "max_attempts": self.max_attempts,
                "timeout_seconds": self.timeout_seconds,
                "budget_units": self.budget_units, "result_id": self.result_id,
                "error": self.error}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Task":
        return cls(task_id=d["task_id"], investigation_id=d.get("investigation_id"),
                   kind=TaskKind(d.get("kind", "collect")), name=d.get("name", ""),
                   instruction=d.get("instruction", {}),
                   depends_on=tuple(d.get("depends_on", ())),
                   wave=int(d.get("wave", 0)), status=TaskStatus(d.get("status", "pending")),
                   assigned_worker=d.get("assigned_worker", ""),
                   attempts=int(d.get("attempts", 0)),
                   max_attempts=int(d.get("max_attempts", 3)),
                   timeout_seconds=int(d.get("timeout_seconds", 120)),
                   budget_units=float(d.get("budget_units", 1.0)),
                   result_id=d.get("result_id"), error=d.get("error", ""))
