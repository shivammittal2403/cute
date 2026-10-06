"""traceatlas.planning.planner - Deterministic first-pass planner."""
from __future__ import annotations

from traceatlas.core.enums import TaskKind
from traceatlas.core.identifiers import ID
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.core.task import Task

from .capability_planner import CAPABILITY_BY_DOMAIN, KIND_BY_CAPABILITY_PREFIX
from .intelligence_domain_planner import domains_for
from .plan_validator import finalize
from .planner_output import Plan
from .semantic_planner import SemanticPlanner
from .source_planner import sources_for_capability
from .stop_condition_builder import build as build_stops
from .worker_planner import worker_for


class Planner:
    def __init__(self, source_registry, semantic: SemanticPlanner | None = None):
        self.sources = source_registry
        self.semantic = semantic

    def plan(self, spec: ObjectiveSpec, objective_id: ID | None = None) -> Plan:
        plan = Plan(objective_id=objective_id)
        self._add_collects(spec, plan)
        self._add_analysis_tail(spec, plan)
        if self.semantic is not None:
            plan.tasks.extend(self.semantic.propose(spec, plan.tasks))
        plan.stop_conditions = build_stops(spec)
        return finalize(plan, spec.scope, _default_budget())

    def _add_collects(self, spec: ObjectiveSpec, plan: Plan) -> None:
        from traceatlas.core.enums import IntelligenceDomain
        kinds = {t.kind for t in spec.targets}
        domains = domains_for(kinds)
        for target in spec.targets[:8]:
            for domain in domains:
                for cap in CAPABILITY_BY_DOMAIN.get(domain, []):
                    matches = sources_for_capability(self.sources, cap)
                    if not matches:
                        plan.warnings.append(f"no catalogued source for capability {cap!r}")
                        continue
                    src = matches[0]
                    prefix = cap.split(".", 1)[0]
                    plan.tasks.append(Task(
                        kind=KIND_BY_CAPABILITY_PREFIX.get(prefix, TaskKind.COLLECT),
                        name=f"{cap}:{target.value}",
                        instruction={"capability": cap, "target": target.value,
                                     "source_slug": src.slug},
                        assigned_worker=worker_for(cap)))

    def _add_analysis_tail(self, spec: ObjectiveSpec, plan: Plan) -> None:
        collects = [t for t in plan.tasks if t.kind == TaskKind.COLLECT]
        if not collects:
            return
        deps = tuple(t.task_id for t in collects)
        extract = Task(kind=TaskKind.EXTRACT, name="extract-observations",
                        depends_on=deps, assigned_worker="extraction")
        resolve = Task(kind=TaskKind.RESOLVE, name="resolve-entities",
                       depends_on=(extract.task_id,), assigned_worker="entity_resolution_analyst")
        correlate = Task(kind=TaskKind.CORRELATE, name="correlate-findings",
                         depends_on=(resolve.task_id,), assigned_worker="graph_analyst")
        verify = Task(kind=TaskKind.VERIFY, name="verify-claims",
                      depends_on=(correlate.task_id,), assigned_worker="verification_analyst")
        report = Task(kind=TaskKind.REPORT, name="compose-report",
                      depends_on=(verify.task_id,), assigned_worker="report_analyst")
        plan.tasks.extend([extract, resolve, correlate, verify, report])


def _default_budget():
    from traceatlas.core.budget import Budget
    return Budget()
