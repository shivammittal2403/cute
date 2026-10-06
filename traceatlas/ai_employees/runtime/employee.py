"""traceatlas.ai_employees.runtime.employee — Specialist employee base.

A worker is a bounded, typed function over envelopes — NOT an infinite agent.
The dispatcher enforces: authorization flag, deadline, cancellation token and
kill switch before the worker's execute() ever runs. Workers that touch the
network declare network=True so policy can gate them; pure analysis workers
(deterministic) declare network=False.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .result_envelope import EnvelopeStatus, ResultEnvelope
from .task_envelope import TaskEnvelope


@dataclass(frozen=True, slots=True)
class EmployeeManifest:
    worker_id: str
    display_name: str
    capabilities: tuple[str, ...]
    network: bool = False
    deterministic: bool = True      # no LLM required
    cost_per_call_usd: float = 0.0


class WorkerBlocked(Exception):
    pass


class BaseEmployee:
    manifest: EmployeeManifest

    def __init__(self, fn: Callable[[TaskEnvelope], tuple[EnvelopeStatus, list]] | None = None):
        self._fn = fn

    def execute(self, task: TaskEnvelope) -> ResultEnvelope:
        raise NotImplementedError

    # helpers shared by concrete workers -------------------------------------
    @staticmethod
    def _result(task: TaskEnvelope, status: EnvelopeStatus, obs=(), error="",
                latency_ms=0.0, cost=0.0) -> ResultEnvelope:
        return ResultEnvelope(task_id=task.task_id, worker=task.worker, status=status,
                              observations=tuple(obs), error=error,
                              latency_ms=latency_ms, cost_usd=cost)


class FunctionEmployee(BaseEmployee):
    """Deterministic worker wrapping a plain callable (most analysts are this)."""

    def __init__(self, manifest: EmployeeManifest,
                 fn: Callable[[TaskEnvelope], tuple[EnvelopeStatus, list, str]]):
        self.manifest = manifest
        self._fn = fn

    def execute(self, task: TaskEnvelope) -> ResultEnvelope:
        t0 = time.perf_counter()
        try:
            status, obs, err = self._fn(task)
        except Exception as exc:  # honest failure, never fabricated success
            return self._result(task, EnvelopeStatus.FAILED, error=f"{type(exc).__name__}: {exc}",
                                latency_ms=(time.perf_counter() - t0) * 1000)
        return self._result(task, status, obs, err,
                            latency_ms=(time.perf_counter() - t0) * 1000,
                            cost=self.manifest.cost_per_call_usd)
