"""traceatlas.planning.stop_condition_builder - Default stop conditions."""
from __future__ import annotations

DEFAULT_STOPS = (
    "objective success criteria met with >=2 independent sources per material claim",
    "all blocking information gaps closed or declared unfillable",
    "budget exhausted",
    "kill switch engaged",
    "human reviewer stops the run",
)


def build(spec) -> tuple[str, ...]:
    return tuple(list(DEFAULT_STOPS) + list(spec.stop_conditions))
