"""traceatlas.ai_employees.runtime.result_envelope — Typed outcome of a TaskEnvelope.

Honest failures are first-class results: status + reason, never fabricated data.
Observations produced by a worker MUST carry evidence_ids (evidence-first rule).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class EnvelopeStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"            # some observations, some sub-steps failed
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    subject_id: str
    predicate: str
    value: Any
    evidence_id: Optional[str] = None
    source_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"subject_id": self.subject_id, "predicate": self.predicate,
                "value": self.value, "evidence_id": self.evidence_id,
                "source_id": self.source_id}


@dataclass(frozen=True, slots=True)
class ResultEnvelope:
    task_id: str
    worker: str
    status: EnvelopeStatus
    observations: tuple[ObservationRecord, ...] = ()
    error: str = ""
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def ok(self) -> bool:
        return self.status in (EnvelopeStatus.SUCCEEDED, EnvelopeStatus.PARTIAL)

    def validate(self) -> None:
        """Evidence-first invariant: an observation without evidence is a defect."""
        if self.status in (EnvelopeStatus.SUCCEEDED, EnvelopeStatus.PARTIAL):
            for o in self.observations:
                if not o.evidence_id:
                    raise ValueError(
                        f"worker {self.worker!r} produced unevidenced observation "
                        f"{o.subject_id}/{o.predicate} — refusing to admit into knowledge plane")

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "worker": self.worker,
                "status": self.status.value,
                "observations": [o.to_dict() for o in self.observations],
                "error": self.error, "cost_usd": self.cost_usd,
                "latency_ms": self.latency_ms,
                "completed_at": self.completed_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ResultEnvelope":
        return cls(task_id=d["task_id"], worker=d.get("worker", ""),
                   status=EnvelopeStatus(d["status"]),
                   observations=tuple(ObservationRecord(**o) for o in d.get("observations", [])),
                   error=d.get("error", ""), cost_usd=d.get("cost_usd", 0.0),
                   latency_ms=d.get("latency_ms", 0.0),
                   completed_at=datetime.fromisoformat(d["completed_at"])
                   if d.get("completed_at") else datetime.now(timezone.utc))
