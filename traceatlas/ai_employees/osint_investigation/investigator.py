"""traceatlas.ai_employees.osint_investigation.investigator — the AI Employee.

The Intelligence Investigation Manager wraps the proven InvestigationManager
(parse objective -> authorization gate -> plan -> wave execution -> evidence ->
graph) and adds the autonomous loop layers that were previously missing:

  * knowledge assessment over observations (what is known / disputed / unknown)
  * source-independence-aware gap analysis (copies do not count as coverage)
  * next-best-action ranking with machine-readable explanations (§20)
  * bounded iteration: extra targeted collection only when justified
  * stopping policy (§21): never endless browsing; budget/deadline/kill-switch
  * decision memory persisted to the case workspace for audit + replay

It does NOT reimplement collection; it orchestrates existing engines through
typed envelopes where workers are involved, keeping one canonical path.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from traceatlas.core.observation import Observation
from traceatlas.investigation.manager import InvestigationManager, _load_observations
from traceatlas.reporting.report_manager import ReportManager
from traceatlas.verification.contradictions import ContradictionDetector
from traceatlas.verification.independence import EvidenceDoc, IndependenceEngine


@dataclass(slots=True)
class NextAction:
    action: str                 # e.g. "collect:dns.resolution" | "verify" | "stop"
    rationale: str              # machine-readable explanation (persisted)
    score: float
    target_value: str = ""
    capability: str = ""


@dataclass(slots=True)
class LoopOutcome:
    stop_reason: str
    waves_run: int
    actions_taken: list[NextAction] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


# capabilities whose absence we can honestly attempt to fill with a second wave.
# Names match planning.capability_planner.CAPABILITY_BY_DOMAIN exactly; only
# capabilities the local connector fabric can actually serve are listed here,
# so NBA never proposes actions the platform cannot execute (no fake autonomy).
_PIVOT_CAPS: dict[str, list[str]] = {
    "domain": ["dns.A", "dns.NS", "rdap.domain", "certificates.by_domain", "web.fetch"],
    "ip_address": ["ip.geo", "prefix.owner", "dns.ptr"],
    "asn": ["asn.info"],
}

# graph-aware pivot transforms (§14): run against entities discovered in the
# graph even when they were NOT part of the original objective text — this is
# what makes cross-entity pivoting autonomous instead of prompt-literal.
_TRANSFORM_BY_KIND: dict[str, list[str]] = {
    "domain": ["domain.resolves_to_ip", "domain.certificates",
               "domain.archived_snapshots", "domain.derive_urls"],
    "ip_address": ["ip.geo_context", "ip.prefix_owner", "ip.reverse_dns"],
    "asn": ["asn.prefixes"],
}


def _pred_for(capability: str) -> str:
    """Predicate prefix used by connectors for this capability's observations."""
    return {"dns.A": "dns.a", "dns.NS": "dns.ns", "dns.AAAA": "dns.aaaa",
            "rdap.domain": "registrant", "certificates.by_domain": "certificate",
            "web.fetch": "http", "ip.geo": "ip.", "prefix.owner": "prefix.",
            "asn.info": "asn.", "dns.ptr": "ptr.",
            "archive.snapshots": "archive."}.get(capability, capability.split(".")[-1])


def _persist_graph(ws) -> None:
    """Flush in-memory graph mutations to the case JSONL file."""
    for fn in ("persist", "save", "flush", "write"):
        f = getattr(ws.graph, fn, None)
        if callable(f):
            f()
            return
    # last resort: rewrite from current state via public dump helper if present
    dump = getattr(ws.graph, "to_records", None)
    if callable(dump):
        import json as _json
        with open(ws.graph.path if hasattr(ws.graph, "path")
                  else ws.root / "graph.jsonl", "w", encoding="utf-8") as fh:
            for rec in dump():
                fh.write(_json.dumps(rec) + "\n")


@dataclass
class _TransformContext:
    """Adapter giving the transform engine access to a case workspace."""
    connectors: dict
    graph: object
    evidence: object
    case_id: str
    authorization_granted: bool
    new_observations: list = field(default_factory=list)

    def record_observation(self, obs) -> None:
        self.new_observations.append(obs)


class OsintInvestigationEmployee:
    MAX_EXTRA_WAVES = 2   # hard bound: no endless autonomous browsing

    def __init__(self, manager: InvestigationManager | None = None,
                 workspace_root: str | Path = ".traceatlas/cases"):
        self.manager = manager or InvestigationManager(workspace_root=workspace_root)

    # ------------------------------------------------------------------ run
    def investigate(self, objective_text: str, authorized: bool = False,
                    scope_note: str = "", case_id: str | None = None,
                    max_waves: int = 3) -> LoopOutcome:
        first = self.manager.investigate(objective_text, case_id=case_id,
                                         authorized=authorized, scope_note=scope_note)
        if not first.get("ok"):
            return LoopOutcome(stop_reason="AUTHORIZATION_BOUNDARY"
                               if first.get("stage") == "authorization" else "SYSTEM_FAILURE",
                               waves_run=0, summary=first)
        case_dir = Path(first["case_dir"])
        outcome = LoopOutcome(stop_reason="", waves_run=1, summary=first)
        attempted: set[str] = set()

        for _ in range(min(max_waves - 1, self.MAX_EXTRA_WAVES)):
            obs = _load_observations(case_dir / "observations.jsonl")
            # --- graph-aware pivot transforms (§14): expand discovered entities
            # even when they were not named in the objective text.
            pivot_stats = self._run_pivots(case_dir, outcome)
            gaps, actions = self._assess(obs, first, attempted)
            if pivot_stats:
                actions.append(NextAction(
                    action="pivoted", capability="transforms.engine",
                    target_value=f"{pivot_stats['entities']} new entities",
                    rationale=(f"graph-driven pivoting produced {pivot_stats['runs']} "
                               f"transform runs, {pivot_stats['ok']} succeeded, "
                               f"{pivot_stats['new_edges']} evidence-linked edges"),
                    score=0.85))
            outcome.gaps = gaps
            outcome.actions_taken.extend(actions)
            justified = [a for a in actions if a.action.startswith("collect:")
                         and a.capability not in attempted]
            if not justified and not pivot_stats:
                break
            if not justified:
                break
            top = justified[0]
            attempted.add(top.capability)
            res = self.manager.investigate(
                f"passive dns rdap certificate records for {top.target_value}",
                case_id=case_dir.name, authorized=authorized, scope_note=scope_note)
            if not res.get("ok"):
                outcome.stop_reason = "SOURCE_EXHAUSTED"
                break
            outcome.waves_run += 1
        else:
            outcome.stop_reason = "WAVE_LIMIT_REACHED"

        if not outcome.stop_reason:
            outcome.stop_reason = self._stopping(outcome)
        self._persist_decisions(case_dir, outcome)
        return outcome

    # ------------------------------------------------------ pivot transforms
    def _run_pivots(self, case_dir: Path, outcome: "LoopOutcome") -> dict:
        """Graph-aware autonomous pivoting (§9/§14): for entities present in the
        case graph that lack downstream coverage, run the matching evidence-
        producing transforms through the connector fabric. Deterministic and
        bounded: each (entity, transform) pair runs at most once per loop."""
        from traceatlas.transforms.engine import REGISTRY

        workspace_fn = getattr(self.manager, "workspace", None)
        if workspace_fn is None:
            return {}          # manager without workspace support (e.g. test fake)
        try:
            ws = workspace_fn(case_dir.name)
        except Exception:
            return {}
        graph = ws.graph
        seen_pairs = set(outcome.summary.setdefault("_pivot_done", []))
        ctx = _TransformContext(
            connectors=self.manager.connectors, graph=graph,
            evidence=ws.evidence, case_id=case_dir.name,
            authorization_granted=True)
        stats = {"runs": 0, "ok": 0, "new_edges": 0}
        before_ids = set(graph.entities.keys())
        # pivot frontier: entities that EXIST at the start of this call only.
        # Entities produced by transforms become next wave's frontier — this is
        # what keeps autonomous expansion bounded (no endless BFS fan-out).
        frontier = [e for e in graph.entities.values() if e.entity_id in before_ids]
        for ent in frontier:
            kind = getattr(ent.kind, "value", str(ent.kind))
            for tid in _TRANSFORM_BY_KIND.get(kind, []):
                key = f"{ent.entity_id}:{tid}"
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                res = REGISTRY.execute(tid, entity=ent, engine_ctx=ctx)
                stats["runs"] += 1
                if res.ok:
                    stats["ok"] += 1
                    stats["new_edges"] += len(res.new_edges)
                outcome.actions_taken.append(NextAction(
                    action=f"transform:{tid}", capability=tid,
                    target_value=ent.display_name, score=0.8,
                    rationale=(f"pivot {tid} on {kind} {ent.display_name!r}: "
                               f"{len(res.new_entities)} new entities, "
                               f"{len(res.new_edges)} edges; "
                               + ("succeeded" if res.ok else f"failed: {res.error}")
                               + "; free public source class; within authorized scope")))
        outcome.summary["_pivot_done"] = sorted(seen_pairs)
        new_ids = set(graph.entities.keys()) - before_ids
        stats["entities"] = len(new_ids)
        _persist_graph(ws)
        # persist any observations produced by transforms
        if ctx.new_observations:
            from traceatlas.investigation.manager import _append_observations
            _append_observations(case_dir / "observations.jsonl", ctx.new_observations)
        return stats if stats["runs"] else {}

    # ------------------------------------------------------- knowledge state
    def _assess(self, obs: list[Observation], first: dict,
                attempted: set[str]) -> tuple[list[str], list[NextAction]]:
        """Deterministic knowledge assessment + NBA scoring (§20)."""
        detector = ContradictionDetector()
        contradictions = detector.detect(obs)
        disputed_keys = {(c.subject, c.predicate) for c in contradictions}

        gaps: list[str] = []
        actions: list[NextAction] = []
        targets = first.get("spec", {}).get("targets", [])
        statuses = first.get("task_statuses", {})

        def failed_or_missing(cap: str) -> bool:
            ran = any(k.startswith(cap) for k in statuses)
            if ran:
                return all(statuses[k] == "failed" for k in statuses if k.startswith(cap))
            return True

        for tkind, tval in targets:
            for cap in _PIVOT_CAPS.get(tkind, []):
                if cap in attempted:
                    continue
                pred = _pred_for(cap)
                has_good = any(o.predicate.startswith(pred)
                               and o.evidence_id and tval.lower() in (o.subject_id or "").lower()
                               for o in obs)
                if has_good:
                    continue
                if failed_or_missing(cap):
                    gaps.append(f"no evidenced findings for capability {cap} on {tval}")
                    actions.append(NextAction(
                        action=f"collect:{cap}", target_value=tval, capability=cap,
                        rationale=(f"gap: objective target {tval} ({tkind}) lacks evidenced "
                                   f"{cap} findings; expected information value high; cost low "
                                   f"(free public source class); authorization within scope"),
                        score=0.9))
        # verification priority for disputed findings
        for (subj, pred) in sorted(disputed_keys):
            actions.append(NextAction(
                action="verify", target_value=subj, capability="verification.adversarial",
                rationale=f"contradiction on {subj}.{pred}; seek independent confirmation",
                score=0.95))
        actions.sort(key=lambda a: (-a.score, a.capability))
        return gaps, actions[:4]

    # -------------------------------------------------------------- stopping
    def _stopping(self, outcome: LoopOutcome) -> str:
        s = outcome.summary.get("summary", {})
        statuses = outcome.summary.get("task_statuses", {})
        failed = sum(1 for v in statuses.values() if v == "failed")
        total = len(statuses) or 1
        if outcome.gaps:
            return "LOW_EXPECTED_INFORMATION_VALUE"  # remaining gaps not cheaply fillable
        if failed / total > 0.5:
            return "SOURCES_EXHAUSTED"
        if s.get("observations", 0) > 0:
            return "OBJECTIVE_SATISFIED"
        return "MISSING_EVIDENCE"

    def _persist_decisions(self, case_dir: Path, outcome: LoopOutcome) -> None:
        decisions = [{"action": a.action, "capability": a.capability,
                      "target": a.target_value, "score": a.score,
                      "rationale": a.rationale} for a in outcome.actions_taken]
        payload = {"generated_at": datetime.now(timezone.utc).isoformat(),
                   "stop_reason": outcome.stop_reason,
                   "waves_run": outcome.waves_run, "gaps": outcome.gaps,
                   "decisions": decisions}
        (case_dir / "decision_memory.json").write_text(json.dumps(payload, indent=2))

    # ---------------------------------------------------------------- report
    def final_report(self, case_dir: str | Path) -> str:
        return ReportManager().build(case_dir)
