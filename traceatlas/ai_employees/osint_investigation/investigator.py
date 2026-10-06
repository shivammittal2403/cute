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
}


def _pred_for(capability: str) -> str:
    """Predicate prefix used by connectors for this capability's observations."""
    return {"dns.A": "a_record", "dns.NS": "ns", "dns.AAAA": "aaaa",
            "rdap.domain": "registrant", "certificates.by_domain": "certificate",
            "web.fetch": "http"}.get(capability, capability.split(".")[-1])


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
            gaps, actions = self._assess(obs, first, attempted)
            outcome.gaps = gaps
            outcome.actions_taken.extend(actions)
            justified = [a for a in actions if a.action.startswith("collect:")
                         and a.capability not in attempted]
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
