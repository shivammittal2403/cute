"""traceatlas.gamification.engine - Workflow-clarity gamification (spec §23/§24).

Rewards investigation hygiene, NOT conclusions:
  award: evidence quality, independent corroboration, contradiction resolution,
         falsification attempts, replay completeness.
  never: confirming a preferred hypothesis, more personal data, more nodes,
         sensational claims.
Progress is eight separate bars — never a single 'confidence score'.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from traceatlas.synthesis.state import IntelligenceState


@dataclass(slots=True)
class ProgressBar:
    name: str
    done: int
    total: int

    @property
    def ratio(self) -> float:
        return round(self.done / self.total, 3) if self.total else 0.0


@dataclass(slots=True)
class Achievement:
    key: str
    title: str
    detail: str


FORBIDDEN_AWARD_REASONS = {
    "preferred_hypothesis_confirmed", "personal_data_volume",
    "graph_node_count", "sensational_conclusion",
}


def compute_progress(state: IntelligenceState) -> dict[str, ProgressBar]:
    facts = state.facts()
    cited_facts = [s for s in facts if s.evidence_ids]
    verified = [s for s in facts if s.verification_status == "verified"]
    hyps = state.hypotheses
    tested = [h for h in hyps if h.status.value not in ("proposed",)]
    resolved_contra = [c for c in state.contradictions
                       if c.resolution_status != "open"]
    gaps_total = len(state.gaps)
    # gap "resolved" proxy: hypotheses whose required evidence is now all linked
    gap_closed = sum(1 for h in hyps
                     if h.required_evidence and h.supporting_evidence_ids
                     and h.scores.evidence_coverage >= 1.0)
    replay_ready = 1 if all(s.evidence_ids for s in facts) and hyps else 0
    questions_answered = sum(1 for h in hyps
                             if h.status.value in ("supported", "falsified",
                                                   "disputed", "inconclusive"))
    return {
        "objective_coverage": ProgressBar("Objective Coverage",
                                          min(len(facts), 5), 5),
        "question_coverage": ProgressBar("Question Coverage",
                                         questions_answered, max(len(hyps), 1)),
        "evidence_coverage": ProgressBar("Evidence Coverage",
                                         len(cited_facts), max(len(facts), 1)),
        "verification_coverage": ProgressBar("Verification Coverage",
                                             len(verified), max(len(facts), 1)),
        "entity_resolution_coverage": ProgressBar(
            "Entity Resolution Coverage",
            sum(1 for s in facts if s.entity_ids), max(len(facts), 1)),
        "contradiction_resolution": ProgressBar("Contradiction Resolution",
                                                len(resolved_contra),
                                                max(len(state.contradictions), 1)),
        "gap_resolution": ProgressBar("Gap Resolution", gap_closed,
                                      max(gaps_total, 1)),
        "replay_readiness": ProgressBar("Replay Readiness", replay_ready, 1),
    }


def award_points(state: IntelligenceState, reason: str,
                 amount_hint: int = 0) -> tuple[int, str]:
    """Gatekeeper for any point award. Returns (points, justification)."""
    if reason in FORBIDDEN_AWARD_REASONS:
        return 0, f"no award: '{reason}' rewards conclusion or volume, not rigor"
    table = {
        "independent_corroboration": 10,   # per newly-2-cluster fact
        "contradiction_resolved": 15,
        "false_positive_avoided": 12,
        "falsification_attempted": 8,
        "replay_complete": 20,
        "evidence_quality_reviewed": 5,
    }
    pts = table.get(reason, 0)
    if pts == 0:
        return 0, f"unknown reward channel '{reason}'; no points awarded"
    return pts, f"rewarded {reason}: investigation-hygiene channel"


def achievements_for(state: IntelligenceState) -> list[Achievement]:
    out: list[Achievement] = []
    prog = compute_progress(state)
    if prog["replay_readiness"].ratio >= 1.0:
        out.append(Achievement("replay_ready", "Case Replay Ready",
                               "every fact carries evidence citations"))
    n_falsify = sum(1 for a in state.next_actions if a.kind == "falsify")
    if n_falsify >= 3:
        out.append(Achievement("skeptic_pass", "Skeptic Pass Complete",
                               f"{n_falsify} falsification tests queued"))
    if any(c.resolution_status != "open" for c in state.contradictions):
        out.append(Achievement("conflict_resolver", "Conflict Resolver",
                               "a contradiction was driven to resolution"))
    multi = [h for h in state.hypotheses if len(h.competing_with) >= 2]
    if multi:
        out.append(Achievement("ach_practitioner", "ACH Practitioner",
                               "competing hypotheses maintained under test"))
    return out


def mission_board(state: IntelligenceState) -> dict[str, Any]:
    """Mission/Quest/Task/Clue/Thread/Challenge mapping for the workspace UI."""
    return {
        "mission": {"objective": state.objective},
        "quests": [{"id": g.gap_id, "question": g.question,
                    "priority": g.priority} for g in state.gaps],
        "tasks": [{"id": a.action_id, "kind": a.kind,
                   "description": a.description} for a in state.next_actions],
        "clues": [{"id": s.statement_id, "type": s.stype.value,
                   "text": s.text} for s in state.observations()][:20],
        "threads": [{"id": h.hypothesis_id, "statement": h.statement,
                     "status": h.status.value} for h in state.hypotheses],
        "challenges": [{"id": c.contradiction_id, "type": c.ctype,
                        "detail": f"{c.statement_a} vs {c.statement_b}"}
                       for c in state.contradictions],
        "progress_bars": {k: p.ratio for k, p in compute_progress(state).items()},
    }
