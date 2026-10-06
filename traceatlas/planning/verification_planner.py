"""traceatlas.planning.verification_planner - Add verify/review tail tasks."""
from __future__ import annotations

from traceatlas.core.enums import TaskKind
from traceatlas.core.task import Task


def tail_tasks(collect_tasks: list[Task]) -> list[Task]:
    deps = tuple(t.task_id for t in collect_tasks)
    return [Task(kind=TaskKind.VERIFY, name="verify-material-claims",
                 depends_on=deps, assigned_worker="verification_analyst"),
            Task(kind=TaskKind.REVIEW, name="adversarial-review",
                 depends_on=(), assigned_worker="adversarial_supervisor")]
