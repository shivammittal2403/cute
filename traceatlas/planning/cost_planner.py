"""traceatlas.planning.cost_planner - Estimate plan cost."""
from __future__ import annotations

FREE_PER_REQUEST_USD = 0.0
PAID_PER_REQUEST_USD = 0.002
MODEL_CALL_USD = 0.01


def estimate(tasks, paid_sources_used: int = 0, model_calls: int = 0) -> float:
    return round(paid_sources_used * PAID_PER_REQUEST_USD * len(tasks)
                 + model_calls * MODEL_CALL_USD, 4)
