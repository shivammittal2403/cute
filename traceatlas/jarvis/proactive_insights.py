"""traceatlas.jarvis.proactive_insights - Material-change surfacing (spec §20/§22).

Generates proactive alerts ONLY when material, with priority bands. Never
spams: each rule has a threshold and dedupes on a stable key per case.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from traceatlas.synthesis.state import IntelligenceState


@dataclass(slots=True)
class ProactiveInsight:
    key: str                      # dedupe identity
    priority: str                 # critical|high|medium|low
    message: str
    refs: dict[str, Any] = field(default_factory=dict)


def generate(state: IntelligenceState,
             seen_keys: set[str] | None = None) -> list[ProactiveInsight]:
    seen = seen_keys if seen_keys is not None else set()
    out: list[ProactiveInsight] = []

    def emit(ins: ProactiveInsight) -> None:
        if ins.key not in seen:
            seen.add(ins.key)
            out.append(ins)

    # High-impact contradictions
    for c in state.contradictions:
        if c.severity >= 0.6:
            emit(ProactiveInsight(
                key=f"contra:{c.contradiction_id}", priority="critical"
                if c.severity >= 0.8 else "high",
                message=(f"I found a contradiction ({c.ctype}): "
                         f"'{c.statement_a}' vs '{c.statement_b}'"),
                refs={"contradiction_id": c.contradiction_id}))

    # Copied-source warning from insights
    for ins in state.insights:
        if ins.title == "repeated but dependent sources":
            emit(ProactiveInsight(
                key=f"copy:{ins.insight_id}", priority="high",
                message=("Multiple sources repeat the same upstream report; "
                         "corroboration is weaker than counts suggest."),
                refs={"insight_id": ins.insight_id}))

    # Strongest hypothesis resting on unverified assumptions
    live = [h for h in state.hypotheses
            if h.status.value in ("strengthened", "supported", "testing")]
    for h in live:
        if h.assumptions and h.confidence.value in ("moderate", "high", "very_high"):
            emit(ProactiveInsight(
                key=f"assumption:{h.hypothesis_id}", priority="high",
                message=(f"The strongest hypothesis currently depends on "
                         f"{len(h.assumptions)} unverified assumption(s): {h.statement[:70]}"),
                refs={"hypothesis_id": h.hypothesis_id}))

    # Facts without independent corroboration
    for s in state.facts():
        indep = s.provenance.get("independent_source_clusters", 0)
        if indep <= 1:
            emit(ProactiveInsight(
                key=f"single:{s.statement_id}", priority="medium",
                message=("A finding has evidence but no independent corroboration: "
                         + s.text[:80]),
                refs={"statement_id": s.statement_id}))

    # Discriminating-test opportunity
    competing_pairs = [(a, b) for a in live for b in live
                       if a.hypothesis_id < b.hypothesis_id
                       and b.hypothesis_id in a.competing_with]
    for a, b in competing_pairs[:3]:
        q = (a.discriminating_questions or b.discriminating_questions or [""])[0]
        if q:
            emit(ProactiveInsight(
                key=f"discriminate:{a.hypothesis_id}:{b.hypothesis_id}",
                priority="medium",
                message=(f"A targeted test could discriminate hypotheses: {q}"),
                refs={"hypothesis_ids": [a.hypothesis_id, b.hypothesis_id]}))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda i: order.get(i.priority, 4))
