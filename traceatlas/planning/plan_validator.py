"""traceatlas.planning.plan_validator - Public entry combining checks."""
from __future__ import annotations

from traceatlas.core.budget import Budget
from traceatlas.core.scope import Scope

from .cost_planner import estimate
from .deterministic_validator import validate_plan
from .latency_planner import estimate_minutes
from .planner_output import Plan
from .wave_planner import assign_waves


def finalize(plan: Plan, scope: Scope, budget: Budget) -> Plan:
    assign_waves(plan)
    plan.estimated_cost_usd = estimate(plan.tasks)
    plan.estimated_minutes = estimate_minutes(plan.tasks)
    problems = validate_plan(plan, scope, budget)
    plan.warnings.extend(problems)
    return plan
