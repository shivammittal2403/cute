"""traceatlas.reporting.intelligence_report - Evidence-first report modes (§28).

Modes: EXECUTIVE / ANALYST / STORY / HYPOTHESIS / STRICT_FACT / UNKNOWN.
The report renders from IntelligenceState + Story only; validation runs first
so an unsupported narrative can never reach the document.
"""
from __future__ import annotations

from typing import Any

from traceatlas.gamification.engine import compute_progress, mission_board
from traceatlas.narrative.story_model import Story
from traceatlas.narrative.validation import validate_story
from traceatlas.synthesis.state import IntelligenceState, StatementType

MODES = ("executive", "analyst", "story", "hypothesis", "strict_fact", "unknown")


def _stmt_line(s) -> str:
    cites = f" [evidence: {', '.join(s.evidence_ids[:3])}" \
            + ("...]" if len(s.evidence_ids) > 3 else "]") if s.evidence_ids else ""
    return f"{s.stype.value.upper()}: {s.text}{cites}"


class IntelligenceReportBuilder:
    def build(self, state: IntelligenceState, story: Story,
              mode: str = "analyst") -> dict[str, Any]:
        if mode not in MODES:
            raise ValueError(f"unknown report mode '{mode}'")
        res = validate_story(story)
        if not res.ok:
            raise ValueError("refusing to report a narrative that failed "
                             f"validation: {[i.rule for i in res.issues]}")
        sections: list[dict[str, Any]] = []

        if mode == "executive":
            facts = [s for s in state.facts() if s.evidence_ids]
            sections.append({"title": "Verified findings",
                             "items": [_stmt_line(s) for s in facts]})
            sections.append({"title": "Assessment",
                             "items": [f"HYPOTHESIS (labelled): {h.statement} "
                                       f"[{h.status.value}, confidence {h.confidence.value}]"
                                       for h in state.hypotheses
                                       if h.status.value in ("supported", "disputed")]})
        elif mode == "strict_fact":
            sections.append({"title": "Supported factual statements only",
                             "items": [_stmt_line(s) for s in state.facts()]})
        elif mode == "unknown":
            sections.append({"title": "Unresolved questions and gaps",
                             "items": [g.question + f" ({g.priority})"
                                       for g in state.gaps]
                                      + [s.text for s in state.unknowns()]})
        elif mode == "hypothesis":
            for h in state.hypotheses:
                sections.append({
                    "title": f"HYPOTHESIS {h.hypothesis_id} [{h.status.value}]",
                    "items": [h.statement,
                              f"confidence: {h.confidence.value}",
                              f"supporting: {len(h.supporting_evidence_ids)} items",
                              f"opposing: {len(h.opposing_evidence_ids)} items",
                              f"assumptions: {'; '.join(h.assumptions) or 'none'}",
                              f"falsified by: {'; '.join(h.falsification_conditions)}",
                              f"competing with: {', '.join(h.competing_with) or 'n/a'}"]})
        elif mode == "story":
            for c in story.chapters:
                sections.append({"title": f"Chapter {c.number} — {c.title}",
                                 "items": [_stmt_line(s)
                                           for sc in c.scenes
                                           for s in sc.statements]})
        else:  # analyst: full structure
            sections.append({"title": "Statements",
                             "items": [_stmt_line(s) for s in state.statements]})
            sections.append({"title": "Insights",
                             "items": [f"[importance {i.importance}] {i.statement}"
                                       for i in state.insights]})
            sections.append({"title": "Contradictions",
                             "items": [f"{c.ctype}: {c.statement_a} vs "
                                       f"{c.statement_b} ({c.resolution_status})"
                                       for c in state.contradictions]})
            sections.append({"title": "ACH matrices",
                             "items": [str(m["ranking"])
                                       for m in state.ach_matrices]})
            sections.append({"title": "Patterns",
                             "items": [p["description"] for p in state.patterns]})
            sections.append({"title": "Gaps",
                             "items": [g.question for g in state.gaps]})
            sections.append({"title": "Next actions",
                             "items": [f"[{a.kind}] {a.description} "
                                       f"(value {a.expected_information_value})"
                                       for a in state.next_actions]})

        return {
            "case_id": state.case_id, "mode": mode,
            "objective": state.objective,
            "generated_at": state.generated_at.isoformat(),
            "sections": sections,
            "progress": {k: p.ratio for k, p in compute_progress(state).items()},
            "mission_board": mission_board(state),
            "truth_boundary_note": ("FACT lines are cited evidence claims. "
                                    "HYPOTHESIS lines are assessments and never "
                                    "merge into FACT sections."),
        }
