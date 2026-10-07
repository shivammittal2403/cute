"""traceatlas.investigation.resume - Crash-safe checkpointing and resume.

Implements the EXECUTION RELIABILITY requirement: persist enough state after
every wave that an interrupted investigation can be restarted without
re-collecting succeeded tasks, without duplicating evidence (the EvidenceStore
is content-addressed) and without losing honest failure records.

Design:
* Checkpoints are written atomically (tmp file + os.replace) so a crash mid
  write cannot corrupt the last good checkpoint.
* A checkpoint records per-task terminal status plus a sha256 fingerprint of
  the plan; resume refuses to apply a checkpoint to a materially different
  plan (fail closed rather than silently skipping the wrong tasks).
* `plan_for_resume()` marks already-succeeded analysis tasks terminal so the
  engine's wave scheduler skips them; COLLECT tasks re-run idempotently —
  dedup at the evidence layer makes repeats cheap and non-duplicative.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from traceatlas.core.enums import TaskStatus
from traceatlas.planning.planner_output import Plan

CHECKPOINT_VERSION = 1


def plan_fingerprint(plan: Plan) -> str:
    """Stable fingerprint over task identity + scheduling-relevant fields."""
    rows = sorted(
        f"{t.task_id}|{t.kind.value}|{t.wave}|{t.name}|"
        f"{json.dumps(t.instruction or {}, sort_keys=True)}"
        for t in plan.tasks)
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def write_checkpoint(path: str | Path, case_id: str, plan: Plan,
                     results: dict[str, Any], extra: dict[str, Any] | None = None
                     ) -> dict[str, Any]:
    """Atomically persist per-task terminal state for later resume."""
    payload = {
        "version": CHECKPOINT_VERSION,
        "case_id": case_id,
        "written_at": datetime.now(timezone.utc).isoformat(),
        "plan_fingerprint": plan_fingerprint(plan),
        "tasks": {tid: {"status": getattr(r, "status", r.get("status") if isinstance(r, dict) else None),
                        "error": getattr(r, "error", r.get("error") if isinstance(r, dict) else None)}
                  for tid, r in results.items()},
        "extra": extra or {},
    }
    # normalize statuses to their enum values where present
    for tid, rec in payload["tasks"].items():
        st = rec.get("status")
        if isinstance(st, TaskStatus):
            rec["status"] = st.value
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, p)
    return payload


def read_checkpoint(path: str | Path) -> Optional[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("version") != CHECKPOINT_VERSION:
        return None
    return data


class ResumeError(RuntimeError):
    """Raised when a checkpoint cannot be safely applied to a plan."""


def plan_for_resume(plan: Plan, checkpoint: dict[str, Any], *,
                    strict: bool = True) -> tuple[Plan, dict[str, Any]]:
    """Return a plan whose previously-succeeded tasks are marked terminal.

    Raises ResumeError (strict) when the checkpoint belongs to a different
    plan fingerprint — applying it would skip the wrong work. Non-strict mode
    ignores mismatched checkpoints (returns plan unchanged + report) so callers
    can choose to start fresh.
    """
    fp = checkpoint.get("plan_fingerprint")
    current = plan_fingerprint(plan)
    if fp != current:
        if strict:
            raise ResumeError(
                f"checkpoint fingerprint {fp!r} does not match plan {current!r}; "
                "refusing to resume with mismatched plan")
        return plan, {"resumed": 0, "skipped_mismatch": True}

    done_ids = [tid for tid, rec in checkpoint.get("tasks", {}).items()
                if rec.get("status") == TaskStatus.SUCCEEDED.value]
    done = set(done_ids)
    new_tasks = []
    for t in plan.tasks:
        if t.task_id in done:
            new_tasks.append(replace(t, status=TaskStatus.SUCCEEDED))
        else:
            new_tasks.append(t)
    resumed_plan = replace(plan, tasks=new_tasks) if hasattr(plan, "__dataclass_fields__") \
        else _rebuild_plan(plan, new_tasks)
    report = {"resumed": len(done),
              "previously_failed": [tid for tid, rec in checkpoint.get("tasks", {}).items()
                                    if rec.get("status") == TaskStatus.FAILED.value]}
    return resumed_plan, report


def _rebuild_plan(plan: Plan, tasks: list) -> Plan:
    """Rebuild a Plan with replaced tasks, preserving other fields."""
    import dataclasses
    if dataclasses.is_dataclass(plan):
        return dataclasses.replace(plan, tasks=tasks)
    # duck-typed fallback
    new = Plan.__new__(type(plan))
    for f in ("objective_id", "case_id"):
        if hasattr(plan, f):
            try:
                setattr(new, f, getattr(plan, f))
            except Exception:
                pass
    new.tasks = tasks
    return new
