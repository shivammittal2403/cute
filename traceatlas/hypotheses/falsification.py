"""traceatlas.hypotheses.falsification - Falsification-first task generation.

Spec §8: for every important hypothesis, derive the tests that could prove it
WRONG and emit them as concrete investigation tasks. Confirmation-only
investigation is rejected by construction: falsification tasks are generated
before (and alongside) corroboration tasks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import Hypothesis


@dataclass(slots=True)
class FalsificationTask:
    task_id: str
    hypothesis_id: str
    kind: str                     # falsify | discriminate | check_assumption
    description: str
    capability: str               # requested capability (router chooses source)
    priority: int = 0             # higher first
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "hypothesis_id": self.hypothesis_id,
                "kind": self.kind, "description": self.description,
                "capability": self.capability, "priority": self.priority,
                "rationale": self.rationale}


# Map common required-evidence phrases to platform capabilities so the
# Source Router (not this module) decides which provider answers them.
_CAPABILITY_HINTS: list[tuple[str, str]] = [
    ("historical dns", "dns.history"),
    ("registrant", "registry.ownership"),
    ("registration", "registry.ownership"),
    ("asn", "ip.asn_context"),
    ("hosting", "ip.asn_context"),
    ("certificate", "cert.transparency"),
    ("second independent", "dns.resolve_independent"),
    ("independent resolver", "dns.resolve_independent"),
    ("profile", "social.public_profile"),
    ("verification", "identity.platform_verification"),
    ("origin", "infra.origin_discovery"),
    ("san", "cert.transparency"),
]


def _capability_for(text: str) -> str:
    low = text.lower()
    for needle, cap in _CAPABILITY_HINTS:
        if needle in low:
            return cap
    return "manual_review"


def generate_falsification_tasks(hyp: Hypothesis) -> list[FalsificationTask]:
    """Emit falsify/discriminate/assumption-check tasks for one hypothesis."""
    tasks: list[FalsificationTask] = []
    n = 0

    for cond in hyp.falsification_conditions:
        n += 1
        tasks.append(FalsificationTask(
            task_id=f"{hyp.hypothesis_id}-fal-{n}",
            hypothesis_id=hyp.hypothesis_id, kind="falsify",
            description=f"Test whether '{cond}' holds (would falsify: {hyp.statement[:80]})",
            capability=_capability_for(cond), priority=3,
            rationale="falsification-first: seek disproof before more support"))

    for q in hyp.discriminating_questions:
        n += 1
        tasks.append(FalsificationTask(
            task_id=f"{hyp.hypothesis_id}-dis-{n}",
            hypothesis_id=hyp.hypothesis_id, kind="discriminate",
            description=q, capability=_capability_for(q), priority=2,
            rationale="answers a question that separates competing hypotheses"))

    for a in hyp.assumptions:
        n += 1
        tasks.append(FalsificationTask(
            task_id=f"{hyp.hypothesis_id}-asm-{n}",
            hypothesis_id=hyp.hypothesis_id, kind="check_assumption",
            description=f"Verify assumption: {a}",
            capability=_capability_for(a), priority=1,
            rationale="weakest-link audit: unverified assumptions cap confidence"))

    return tasks


def weakest_link(hypotheses: list[Hypothesis]) -> dict[str, Any] | None:
    """Return the single most fragile point across a hypothesis set (JARVIS:
    'give me the weakest link in this investigation')."""
    best = None
    for h in hypotheses:
        burden = len(h.assumptions) + len(h.opposing_evidence_ids)
        if burden == 0:
            continue
        cand = {"hypothesis_id": h.hypothesis_id, "statement": h.statement,
                "assumptions": list(h.assumptions),
                "opposing_evidence": list(h.opposing_evidence_ids),
                "burden": burden}
        if best is None or burden > best["burden"]:
            best = cand
    return best
