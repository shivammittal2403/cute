"""traceatlas.planning.deterministic_validator - Hard checks on any plan.

Semantic (LLM) plans are ALWAYS passed through this validator; tasks that
violate policy/scope/budget are dropped, never silently trusted.
"""
from __future__ import annotations

from traceatlas.core.budget import Budget
from traceatlas.core.scope import Scope

from .planner_output import Plan


def validate_plan(plan: Plan, scope: Scope, budget: Budget) -> list[str]:
    problems: list[str] = []
    ids = {t.task_id for t in plan.tasks}
    for t in plan.tasks:
        for d in t.depends_on:
            if d not in ids:
                problems.append(f"task {t.name}: unknown dependency {d}")
        if t.kind.value == "collect" and not scope.entities_allowed:
            pass  # empty allow-list means "as parsed from objective"; planner enforces deny-list
        for denied in scope.entities_denied:
            if denied in t.instruction.get("target", ""):
                problems.append(f"task {t.name} touches denied target {denied!r}")
    if plan.estimated_cost_usd > budget.max_cost_usd:
        problems.append(f"plan cost ${plan.estimated_cost_usd:.2f} exceeds budget "
                        f"${budget.max_cost_usd:.2f}")
    if len(plan.tasks) > budget.max_tasks:
        problems.append(f"plan has {len(plan.tasks)} tasks > budget.max_tasks")
    _detect_cycles(plan, problems)
    return problems


def _detect_cycles(plan: Plan, problems: list[str]) -> None:
    graph = {t.task_id: set(t.depends_on) for t in plan.tasks}
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {k: WHITE for k in graph}

    def visit(node):
        color[node] = GRAY
        for dep in graph.get(node, ()):
            if color.get(dep) == GRAY:
                problems.append(f"dependency cycle at {node}->{dep}")
            elif color.get(dep) == WHITE:
                visit(dep)
        color[node] = BLACK

    for n in list(graph):
        if color[n] == WHITE:
            visit(n)
