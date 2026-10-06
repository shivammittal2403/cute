"""traceatlas.planning.evidence_planner - Evidence obligations per requirement."""
from __future__ import annotations


def obligations(requirements: tuple[str, ...]) -> list[str]:
    return [f"raw capture + hash required for: {r}" for r in requirements]
