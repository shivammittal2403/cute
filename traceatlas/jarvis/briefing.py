"""traceatlas.jarvis.briefing - Evidence-grounded brief builders.

Every briefing renders ONLY from IntelligenceState/hypothesis data and keeps
statement-type labels visible (spec §36 mandatory style). No invention: if the
state has no facts, the brief says so.
"""
from __future__ import annotations

from typing import Any

from traceatlas.hypotheses.falsification import generate_falsification_tasks, weakest_link
from traceatlas.synthesis.state import IntelligenceState, StatementType


def _label(s) -> str:
    return f"[{s.stype.value.upper()}] {s.text}"


def case_brief(state: IntelligenceState) -> dict[str, Any]:
    facts = state.facts()
    obs = state.observations()
    unknowns = state.unknowns()
    return {
        "objective": state.objective,
        "what_we_know": [_label(s) for s in facts][:10],
        "raw_observations": [_label(s) for s in obs][:10],
        "what_we_do_not_know": [_label(s) for s in unknowns][:10],
        "contradictions": [c.to_dict() for c in state.contradictions][:5],
        "hypotheses": [{"id": h.hypothesis_id, "statement": h.statement,
                        "status": h.status.value,
                        "confidence": h.confidence.value}
                       for h in state.hypotheses][:8],
        "gaps": [g.to_dict() for g in state.gaps][:8],
        "next_actions": [a.to_dict() for a in state.next_actions][:5],
        "fact_count": len(facts),
        "unsupported_fact_count": sum(1 for s in facts if not s.evidence_ids),
    }


def hypothesis_brief(state: IntelligenceState, hypothesis_id: str
                     ) -> dict[str, Any]:
    h = next((x for x in state.hypotheses if x.hypothesis_id == hypothesis_id), None)
    if h is None:
        return {"error": f"unknown hypothesis {hypothesis_id}"}
    tasks = [t.to_dict() for t in generate_falsification_tasks(h)]
    return {
        "id": h.hypothesis_id, "statement": h.statement,
        "status": h.status.value, "confidence": h.confidence.value,
        "score_components": h.scores.__dict__,
        "supporting_evidence": list(h.supporting_evidence_ids),
        "opposing_evidence": list(h.opposing_evidence_ids),
        "assumptions": list(h.assumptions),
        "contradictions": list(h.contradictions),
        "falsification_conditions": list(h.falsification_conditions),
        "discriminating_questions": list(h.discriminating_questions),
        "required_tests": tasks,
        "competing_with": list(h.competing_with),
        # Truth boundary reminder rendered with every hypothesis brief:
        "boundary_note": ("This is an assessment derived from evidence, not a fact. "
                          "It remains labelled HYPOTHESIS until independently "
                          "verified findings supersede it."),
    }


def contradiction_brief(state: IntelligenceState) -> list[dict[str, Any]]:
    return [c.to_dict() for c in state.contradictions]


def gap_brief(state: IntelligenceState) -> list[dict[str, Any]]:
    return [g.to_dict() for g in sorted(
        state.gaps, key=lambda g: g.estimated_information_value, reverse=True)]


def next_action_brief(state: IntelligenceState) -> list[dict[str, Any]]:
    ranked = sorted(state.next_actions,
                    key=lambda a: (a.kind != "falsify",
                                   -a.expected_information_value))
    return [a.to_dict() for a in ranked[:8]]


def weakest_link_brief(state: IntelligenceState) -> dict[str, Any]:
    wl = weakest_link(state.hypotheses)
    if wl is None:
        return {"weakest_link": None,
                "note": "no hypothesis currently carries assumptions or opposition"}
    return {"weakest_link": wl,
            "explanation": (f"Hypothesis '{wl['statement'][:80]}' depends on "
                            f"{len(wl['assumptions'])} unverified assumption(s) and "
                            f"{len(wl['opposing_evidence'])} opposing evidence item(s).")}


def strict_facts_only(state: IntelligenceState) -> list[str]:
    """STRICT FACT MODE: only cited facts; anything else excluded."""
    return [s.text for s in state.statements
            if s.stype is StatementType.FACT and s.evidence_ids]
