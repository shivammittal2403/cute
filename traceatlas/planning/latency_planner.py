"""traceatlas.planning.latency_planner - Rough wall-clock estimate."""
from __future__ import annotations

SECONDS_PER_TASK = 8.0


def estimate_minutes(tasks: list, concurrency: int = 4) -> float:
    if not tasks:
        return 0.0
    waves: dict[int, int] = {}
    for t in tasks:
        waves[t.wave] = waves.get(t.wave, 0) + 1
    total = sum(max(1, n // max(1, concurrency)) * SECONDS_PER_TASK
                for n in waves.values())
    return round(total / 60.0, 2)
