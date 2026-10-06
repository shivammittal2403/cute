"""traceatlas.planning.subproblem_builder - Group tasks into subproblems."""
from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.task import Task


@dataclass(slots=True)
class Subproblem:
    label: str
    tasks: list[Task] = field(default_factory=list)


def build(tasks: list[Task]) -> list[Subproblem]:
    groups: dict[str, Subproblem] = {}
    for t in tasks:
        key = t.instruction.get("target", t.name.split(":")[0])
        groups.setdefault(key, Subproblem(label=key)).tasks.append(t)
    return list(groups.values())
