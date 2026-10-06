"""traceatlas.planning.wave_planner - Assign wave numbers via topological order."""
from __future__ import annotations

from .planner_output import Plan


def assign_waves(plan: Plan) -> Plan:
    by_id = {t.task_id: t for t in plan.tasks}
    memo: dict[str, int] = {}

    def depth(tid: str, stack: frozenset[str] = frozenset()) -> int:
        if tid in memo:
            return memo[tid]
        if tid in stack:
            return 0  # cycle guard; validator reports separately
        t = by_id.get(tid)
        if t is None or not t.depends_on:
            memo[tid] = 0
            return 0
        d = 1 + max((depth(dep, stack | {tid}) for dep in t.depends_on if dep in by_id),
                    default=-1)
        memo[tid] = max(d, 0)
        return memo[tid]

    for t in plan.tasks:
        t.wave = depth(t.task_id)
    return plan
