"""traceatlas.ai_employees.runtime.dispatcher — Policy-gated task dispatch.

Enforces, BEFORE any worker executes:
  1. authorization_granted must be True for network workers (§28 executable policy)
  2. kill switch engaged -> CANCELLED
  3. deadline exceeded -> TIMEOUT
  4. budget exhausted -> BLOCKED_POLICY
and AFTER execution validates the evidence-first invariant.
Every dispatch decision is recorded in an audit list (decision memory hook).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .employee import BaseEmployee
from .result_envelope import EnvelopeStatus, ResultEnvelope
from .task_envelope import TaskEnvelope


@dataclass
class DispatchPolicy:
    kill_switch: Callable[[], bool] = lambda: False
    budget_remaining_usd: Optional[float] = None   # None => unlimited within case scope

    def check(self, task: TaskEnvelope, worker: BaseEmployee) -> Optional[str]:
        if self.kill_switch():
            return "kill switch engaged"
        if getattr(worker.manifest, "network", False) and not task.authorization_granted:
            return ("worker requires network access but task lacks granted authorization; "
                    "refusing to execute (AI cannot expand authorization)")
        if task.deadline and datetime.now(timezone.utc) > task.deadline:
            return "deadline exceeded before dispatch"
        if (self.budget_remaining_usd is not None
                and worker.manifest.cost_per_call_usd > self.budget_remaining_usd):
            return "budget insufficient for this call"
        return None


class Dispatcher:
    def __init__(self, registry: dict[str, BaseEmployee], policy: DispatchPolicy | None = None):
        self.registry = registry
        self.policy = policy or DispatchPolicy()
        self.audit: list[dict] = []

    def dispatch(self, task: TaskEnvelope) -> ResultEnvelope:
        worker = self.registry.get(task.worker)
        if worker is None:
            res = ResultEnvelope(task_id=task.task_id, worker=task.worker,
                                 status=EnvelopeStatus.FAILED,
                                 error=f"no registered worker {task.worker!r}")
            self._log(task, res)
            return res
        block = self.policy.check(task, worker)
        if block:
            status = (EnvelopeStatus.CANCELLED if "kill" in block else
                      EnvelopeStatus.TIMEOUT if "deadline" in block else
                      EnvelopeStatus.BLOCKED_AUTHORIZATION if "authorization" in block else
                      EnvelopeStatus.BLOCKED_POLICY)
            res = ResultEnvelope(task_id=task.task_id, worker=task.worker,
                                 status=status, error=block)
            self._log(task, res)
            return res
        res = worker.execute(task)
        try:
            res.validate()
        except ValueError as exc:      # unevidenced observation => reject result
            res = ResultEnvelope(task_id=task.task_id, worker=task.worker,
                                 status=EnvelopeStatus.FAILED, error=str(exc))
        self._log(task, res)
        return res

    def _log(self, task: TaskEnvelope, res: ResultEnvelope) -> None:
        self.audit.append({"ts": datetime.now(timezone.utc).isoformat(),
                           "task_id": task.task_id, "worker": task.worker,
                           "capability": task.capability,
                           "case_id": task.case_id, "trace_id": task.trace_id,
                           "status": res.status.value, "error": res.error,
                           "observations": len(res.observations),
                           "latency_ms": round(res.latency_ms, 2)})
