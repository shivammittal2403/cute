"""traceatlas.core.result - Task output envelope."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import TaskStatus
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class TaskResult:
    result_id: ID = field(default_factory=lambda: new_id("result"))
    task_id: ID = ID("")
    status: TaskStatus = TaskStatus.SUCCEEDED
    payload: dict[str, Any] = field(default_factory=dict)
    evidence_ids: tuple[ID, ...] = ()
    metrics: dict[str, float] = field(default_factory=dict)
    error: Optional[str] = None
    finished_at: datetime = field(default_factory=utcnow)

    @property
    def ok(self) -> bool:
        return self.status == TaskStatus.SUCCEEDED and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {"result_id": self.result_id, "task_id": self.task_id,
                "status": self.status.value, "payload": self.payload,
                "evidence_ids": list(self.evidence_ids), "metrics": self.metrics,
                "error": self.error, "finished_at": self.finished_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TaskResult":
        return cls(result_id=d["result_id"], task_id=d["task_id"],
                   status=TaskStatus(d["status"]), payload=d.get("payload", {}),
                   evidence_ids=tuple(d.get("evidence_ids", ())),
                   metrics={k: float(v) for k, v in d.get("metrics", {}).items()},
                   error=d.get("error"),
                   finished_at=datetime.fromisoformat(d["finished_at"]))
