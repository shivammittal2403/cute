"""traceatlas.planning.semantic_planner - LLM-assisted decomposition (optional).

The semantic planner proposes free-form tasks; every proposal is converted to
a Task and MUST pass deterministic_validator before entering the plan.
"""
from __future__ import annotations

from typing import Any

from traceatlas.core.enums import TaskKind
from traceatlas.core.task import Task


class SemanticPlanner:
    def __init__(self, gateway=None):
        self.gateway = gateway

    def propose(self, spec, base_plan_tasks: list[Task]) -> list[Task]:
        """Ask the model for gap-closing follow-ups; returns [] without a gateway."""
        if self.gateway is None:
            return []
        prompt = self._prompt(spec, base_plan_tasks)
        try:
            data = self.gateway.complete_json(task="planning", prompt=prompt)
        except Exception:
            return []
        tasks = []
        for item in data.get("tasks", [])[:20]:
            tasks.append(Task(kind=TaskKind(item.get("kind", "collect")),
                              name=item.get("name", "semantic-task"),
                              instruction=item.get("instruction", {}),
                              assigned_worker=item.get("worker", "search_analyst")))
        return tasks

    @staticmethod
    def _prompt(spec, tasks: list[Task]) -> dict[str, Any]:
        return {"question": spec.question,
                "existing": [t.name for t in tasks],
                "instruction": "Propose JSON {'tasks': [...}] closing remaining gaps. "
                               "Only passive OSINT capabilities."}
