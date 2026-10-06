"""traceatlas.ai_employees.runtime.task_envelope — Typed work unit for employees.

Workers communicate ONLY through TaskEnvelope/ResultEnvelope (never loose
dicts). Every envelope carries tenant/case/investigation/trace identity so
policy, audit and telemetry can enforce authorization on each action.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id


@dataclass(frozen=True, slots=True)
class TaskEnvelope:
    task_id: ID = field(default_factory=lambda: new_id("task"))
    case_id: ID = ""
    investigation_id: ID = ""
    trace_id: ID = ""
    worker: str = ""                 # specialist employee id, e.g. "dns_analyst"
    capability: str = ""             # e.g. "dns.resolution", "rdap.domain"
    target_kind: str = ""            # EntityKind value
    target_value: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    authorization_granted: bool = False   # set only by policy layer, never by LLM
    budget_remaining_usd: Optional[float] = None
    deadline: Optional[datetime] = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    parent_task_id: Optional[ID] = None

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "case_id": self.case_id,
                "investigation_id": self.investigation_id, "trace_id": self.trace_id,
                "worker": self.worker, "capability": self.capability,
                "target_kind": self.target_kind, "target_value": self.target_value,
                "parameters": self.parameters,
                "authorization_granted": self.authorization_granted,
                "budget_remaining_usd": self.budget_remaining_usd,
                "deadline": self.deadline.isoformat() if self.deadline else None,
                "issued_at": self.issued_at.isoformat(),
                "parent_task_id": self.parent_task_id}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TaskEnvelope":
        return cls(task_id=d["task_id"], case_id=d.get("case_id", ""),
                   investigation_id=d.get("investigation_id", ""),
                   trace_id=d.get("trace_id", ""), worker=d.get("worker", ""),
                   capability=d.get("capability", ""),
                   target_kind=d.get("target_kind", ""),
                   target_value=d.get("target_value", ""),
                   parameters=d.get("parameters", {}),
                   authorization_granted=bool(d.get("authorization_granted", False)),
                   budget_remaining_usd=d.get("budget_remaining_usd"),
                   deadline=datetime.fromisoformat(d["deadline"]) if d.get("deadline") else None,
                   issued_at=datetime.fromisoformat(d["issued_at"]) if d.get("issued_at")
                   else datetime.now(timezone.utc),
                   parent_task_id=d.get("parent_task_id"))
