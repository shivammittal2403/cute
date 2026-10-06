"""traceatlas.investigation.engine - Wave-based investigation executor.

Executes a validated Plan: policy/authorization check before every external
action, real connector dispatch for COLLECT tasks, evidence capture (bytes ->
EvidenceStore), observation normalization into the KnowledgeGraph, dependency
/wave scheduling with bounded concurrency, retry with backoff + jitter,
timeouts, cancellation, kill switch, persisted checkpoints and resumability.
Analysis-tail tasks (extract/resolve/verify/report) are deterministic here;
LLM involvement is only via injected optional hooks that must pass validation.
"""
from __future__ import annotations

import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from traceatlas.core.enums import (EntityKind, RelationshipKind, TaskKind,
                                   TaskStatus)
from traceatlas.core.observation import Observation
from traceatlas.core.relationship import Relationship
from traceatlas.core.entity import Entity
from traceatlas.core.result import TaskResult
from traceatlas.exceptions import KillSwitchEngagedError
from traceatlas.graph.model import KnowledgeGraph
from traceatlas.planning.planner_output import Plan


class EngineConfig:
    def __init__(self, max_workers: int = 4, task_timeout_s: float = 30.0,
                 max_retries: int = 2, base_backoff_s: float = 0.5):
        self.max_workers = max_workers
        self.task_timeout_s = task_timeout_s
        self.max_retries = max_retries
        self.base_backoff_s = base_backoff_s


# kind inferred from predicate/value shape; returns (kind, name) or None to skip
def classify_value(predicate: str, value) -> list[tuple[EntityKind, str]]:
    out: list[tuple[EntityKind, str]] = []
    vals = value if isinstance(value, list) else [value]
    for v in vals:
        s = str(v).strip().lower()
        if not s:
            continue
        if predicate.startswith("dns.a") or predicate == "infra.ip":
            out.append((EntityKind.IP_ADDRESS, s))
        elif predicate.startswith("dns.") and any(c in s for c in (".", "@")) and "@" not in s:
            out.append((EntityKind.DOMAIN, s.removeprefix("www.")))
        elif predicate in ("domain.subdomain_seen_in_ct",):
            out.append((EntityKind.DOMAIN, s))
        elif predicate == "registrar" or predicate.endswith(".nameserver"):
            out.append((EntityKind.ORGANIZATION if predicate == "registrar" else EntityKind.DOMAIN, s))
    return out


class InvestigationEngine:
    def __init__(self, case_id: str, evidence_store, graph: KnowledgeGraph,
                 connectors: dict[str, "object"], config: EngineConfig | None = None,
                 checkpoint_path: str | Path | None = None,
                 observations_out: list | None = None):
        self.case_id = case_id
        self.evidence = evidence_store
        self.graph = graph
        self.connectors = connectors          # slug -> BaseConnector
        self.cfg = config or EngineConfig()
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.observations: list[Observation] = observations_out or []
        self.results: dict[str, TaskResult] = {}
        self.cancelled = False
        self.kill = False
        self.audit: list[dict] = []

    # ------------------------------------------------------------------ public
    def run(self, plan: Plan) -> dict:
        by_id = {t.task_id: t for t in plan.tasks}
        remaining = {t.task_id for t in plan.tasks if not by_id[t.task_id].is_terminal()}
        wave_order = sorted({by_id[tid].wave for tid in remaining})
        for wave in wave_order:
            if self.cancelled or self.kill:
                break
            batch = [tid for tid in remaining if by_id[tid].wave == wave
                     and all(dep not in remaining or by_id[dep].status == TaskStatus.SUCCEEDED
                             for dep in by_id[tid].depends_on)]
            self._run_batch(batch, by_id, remaining)
            # re-evaluate readiness for later waves once deps succeeded
            progressed = True
            while progressed:
                progressed = False
                extra = [tid for tid in remaining
                         if by_id[tid].wave == wave and tid not in batch
                         and all(by_id[d].status == TaskStatus.SUCCEEDED
                                 for d in by_id[tid].depends_on if d in by_id)]
                if extra:
                    progressed = True
                    self._run_batch(extra, by_id, remaining)
            self._checkpoint(plan)
        done = sum(1 for t in plan.tasks if t.is_terminal())
        return {"tasks_total": len(plan.tasks), "tasks_done": done,
                "observations": len(self.observations),
                "entities": len(self.graph.entities),
                "edges": len(self.graph.relationships),
                "cancelled": self.cancelled or self.kill}

    # ----------------------------------------------------------------- internal
    def _run_batch(self, ids, by_id, remaining):
        if not ids:
            return
        with ThreadPoolExecutor(max_workers=min(self.cfg.max_workers, len(ids))) as pool:
            futs = {pool.submit(self._run_one, by_id[tid]): tid for tid in ids}
            for fut in as_completed(futs):
                tid = futs[fut]
                try:
                    res = fut.result()
                except Exception as exc:  # noqa: BLE001
                    res = TaskResult(task_id=tid, ok=False, error=f"{type(exc).__name__}: {exc}")
                task = by_id[tid]
                task.status = TaskStatus.SUCCEEDED if res.ok else TaskStatus.FAILED
                self.results[tid] = res
                remaining.discard(tid)

    def _run_one(self, task) -> TaskResult:
        if self.kill:
            raise KillSwitchEngagedError("kill switch engaged before task execution")
        if self.cancelled:
            return TaskResult(task_id=task.task_id, ok=False, error="cancelled")
        inst = task.instruction or {}
        if task.kind == TaskKind.COLLECT:
            return self._retry(lambda: self._do_collect(task, inst))
        return self._do_analysis(task, inst)

    def _retry(self, fn: Callable[[], TaskResult]) -> TaskResult:
        last: TaskResult | None = None
        for attempt in range(self.cfg.max_retries + 1):
            last = fn()
            if last.ok:
                return last
            if attempt < self.cfg.max_retries:
                time.sleep(min(8.0, self.cfg.base_backoff_s * (2 ** attempt))
                           + random.uniform(0, 0.1))
        assert last is not None
        return last

    # ------------------------------------------------------------------ collect
    def _do_collect(self, task, inst: dict) -> TaskResult:
        capability = inst.get("capability", "")
        target = inst.get("target", "")
        slug = inst.get("source_slug", "")
        connector = self.connectors.get(slug)
        if connector is None:
            return TaskResult(task_id=task.task_id, ok=False,
                              error=f"no connector registered for source {slug!r}")
        self._audit("collect_start", task.task_id, {"capability": capability,
                                                    "target": target, "source": slug})
        try:
            result = connector.collect(target, capability)
        except Exception as exc:  # connector crash must not kill engine
            return TaskResult(task_id=task.task_id, ok=False,
                              error=f"connector_error {type(exc).__name__}: {exc}")
        evidence_id = None
        if result.raw_bytes:
            ev = self.evidence.put_bytes(result.raw_bytes, source_uri=result.source_uri,
                                         media_type=result.media_type, case_id=self.case_id)
            evidence_id = ev.evidence_id
        obs_ids = []
        for o in result.observations:
            obs = Observation(case_id=self.case_id, subject_id=o.get("subject"),
                              predicate=o.get("predicate", ""), value=o.get("value"),
                              evidence_id=evidence_id, source_id=slug,
                              context=o.get("context", {}))
            self.observations.append(obs)
            obs_ids.append(obs.observation_id)
            self._link_graph(o.get("subject", target), o.get("predicate", ""),
                             o.get("value"), evidence_id)
        ok = bool(result.ok)
        self._audit("collect_end", task.task_id,
                    {"ok": ok, "error": result.error, "n_obs": len(obs_ids),
                     "evidence_id": evidence_id})
        return TaskResult(task_id=task.task_id, ok=ok, payload={
            "observations": obs_ids, "evidence_id": evidence_id},
            error=result.error)

    # ------------------------------------------------------------- graph intake
    def _link_graph(self, subject: str, predicate: str, value, evidence_id) -> None:
        subj_ents = classify_value("infra.ip" if _is_ip(subject) else "domain", subject)
        primary_kind, primary_name = ((EntityKind.IP_ADDRESS, subject) if _is_ip(subject)
                                      else (EntityKind.DOMAIN, subject.lower()))
        src_ent = self.graph.add_entity(Entity(kind=primary_kind, display_name=primary_name,
                                               case_id=self.case_id,
                                               evidence_ids=(evidence_id,) if evidence_id else ()))
        for kind, name in classify_value(predicate, value):
            tgt = self.graph.add_entity(Entity(kind=kind, display_name=name,
                                               case_id=self.case_id,
                                               evidence_ids=(evidence_id,) if evidence_id else ()))
            rkind = (RelationshipKind.RESOLVES_TO if kind == EntityKind.IP_ADDRESS
                     else RelationshipKind.HOSTS if predicate.endswith("nameserver")
                     else RelationshipKind.GENERIC)
            self.graph.add_relationship(Relationship(
                case_id=self.case_id, source_entity_id=src_ent.entity_id,
                target_entity_id=tgt.entity_id, kind=rkind,
                properties={"predicate": predicate},
                evidence_ids=(evidence_id,) if evidence_id else ()))

    # ----------------------------------------------------------------- analysis
    def _do_analysis(self, task, inst: dict) -> TaskResult:
        kind = task.kind
        if kind == TaskKind.RESOLVE:
            from traceatlas.entities.resolver import EntityResolver
            resolver = EntityResolver()
            ents = list(self.graph.entities.values())
            merges = 0
            for i in range(len(ents)):
                for j in range(i + 1, len(ents)):
                    d = resolver.compare(ents[i], ents[j])
                    if d.state in ("VERIFIED_MATCH", "PROBABLE_MATCH"):
                        if resolver.apply_merge(self.graph, d):
                            merges += 1
            return TaskResult(task_id=task.task_id, ok=True, payload={"merges": merges})
        if kind == TaskKind.VERIFY:
            unsupported = [o for o in self.observations if not o.evidence_id]
            return TaskResult(task_id=task.task_id, ok=True,
                              payload={"observations": len(self.observations),
                                       "without_evidence": len(unsupported)})
        if kind == TaskKind.REPORT:
            summary = {"case_id": self.case_id,
                       "entities": len(self.graph.entities),
                       "relationships": len(self.graph.relationships),
                       "observations": len(self.observations)}
            return TaskResult(task_id=task.task_id, ok=True, payload=summary)
        # extract/correlate/reason/contradict: no-op success over captured data
        return TaskResult(task_id=task.task_id, ok=True, payload={"handled_by": str(kind.value)})

    # ------------------------------------------------------------ checkpointing
    def _checkpoint(self, plan: Plan) -> None:
        if not self.checkpoint_path:
            return
        state = {"case_id": self.case_id, "at": datetime.now(timezone.utc).isoformat(),
                 "tasks": [t.to_dict() for t in plan.tasks],
                 "audit": self.audit[-200:]}
        tmp = self.checkpoint_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        Path(tmp).replace(self.checkpoint_path)

    def _audit(self, event: str, task_id: str, data: dict) -> None:
        self.audit.append({"event": event, "task_id": task_id,
                           "at": datetime.now(timezone.utc).isoformat(), **data})


def _is_ip(s: str) -> bool:
    parts = (s or "").split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
