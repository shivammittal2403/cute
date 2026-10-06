"""traceatlas.hypotheses.update - Fold new evidence into hypothesis state.

Deterministic policy (no LLM voting):
  * opposing evidence arrives   -> WEAKENED path, severity recorded
  * independent support grows   -> STRENGTHENED path
  * falsification condition met -> FALSIFIED (terminal except ARCHIVED)
Hypothesis NEVER becomes a fact; SUPPORTED is still an assessment label.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .model import Hypothesis, HypothesisLifecycle, ScoreComponents
from .scorer import EvidenceMeta, rescore


@dataclass(slots=True)
class UpdateResult:
    hypothesis_id: str
    previous_status: HypothesisLifecycle
    new_status: HypothesisLifecycle
    scores: ScoreComponents
    events: list[str]


def apply_evidence(hyp: Hypothesis, meta: list[EvidenceMeta],
                   new_support: list[str], new_opposition: list[str],
                   falsified_condition: Optional[str] = None,
                   contradiction_severity: float = 0.0,
                   best_alternative_strength: float = 0.0) -> UpdateResult:
    """Update one hypothesis with newly ingested evidence ids."""
    prev = hyp.status
    events: list[str] = []

    for eid in new_support:
        if eid not in hyp.supporting_evidence_ids:
            hyp.add_support(eid)
            events.append(f"support+{eid}")
    for eid in new_opposition:
        if eid not in hyp.opposing_evidence_ids:
            hyp.add_opposition(eid)
            events.append(f"opposition+{eid}")

    hyp.scores = rescore(hyp, meta,
                         contradiction_severity=contradiction_severity,
                         best_alternative_strength=best_alternative_strength)

    # Terminal falsification check — explicit condition match only.
    if falsified_condition is not None and falsified_condition in hyp.falsification_conditions:
        from .model import ALLOWED_TRANSITIONS
        reachable = {HypothesisLifecycle.TESTING, HypothesisLifecycle.STRENGTHENED,
                     HypothesisLifecycle.WEAKENED, HypothesisLifecycle.SUPPORTED,
                     HypothesisLifecycle.DISPUTED}
        if hyp.status not in reachable or \
                HypothesisLifecycle.FALSIFIED not in ALLOWED_TRANSITIONS[hyp.status]:
            _move(hyp, HypothesisLifecycle.TESTING, events)
        _move(hyp, HypothesisLifecycle.FALSIFIED, events)
        return UpdateResult(hyp.hypothesis_id, prev, hyp.status, hyp.scores, events)

    # Ensure we are at least ACTIVE/TESTING before judging strength.
    if hyp.status is HypothesisLifecycle.PROPOSED:
        _move(hyp, HypothesisLifecycle.ACTIVE, events)
    if hyp.status is HypothesisLifecycle.ACTIVE:
        _move(hyp, HypothesisLifecycle.TESTING, events)

    q = hyp.confidence
    if q.value in ("high", "very_high") and not hyp.opposing_evidence_ids:
        if hyp.scores.source_independence >= 2:
            _move(hyp, HypothesisLifecycle.SUPPORTED, events)
        else:
            _move(hyp, HypothesisLifecycle.STRENGTHENED, events)
    elif hyp.opposing_evidence_ids and contradiction_severity > 0.5:
        _move(hyp, HypothesisLifecycle.DISPUTED, events)
    elif new_opposition:
        _move(hyp, HypothesisLifecycle.WEAKENED, events)
    elif new_support:
        _move(hyp, HypothesisLifecycle.STRENGTHENED, events)

    return UpdateResult(hyp.hypothesis_id, prev, hyp.status, hyp.scores, events)


def _move(hyp: Hypothesis, target: HypothesisLifecycle, events: list[str]) -> None:
    """Best-effort transition; skips illegal hops rather than faking state."""
    try:
        hyp.transition(target)
        events.append(f"status->{target.value}")
    except ValueError:
        events.append(f"status-skip-{target.value}")
