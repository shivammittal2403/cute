"""traceatlas.narrative.story_builder - IntelligenceState -> validated Story.

Builds the canonical 13-chapter analytical narrative from a fused state.
Statements are copied with their citations; nothing is invented. The result is
validated before return — an invalid story raises instead of being displayed.
"""
from __future__ import annotations

from typing import Optional

from traceatlas.synthesis.state import IntelligenceState, StatementType

from .story_model import (CHAPTER_TITLES, Chapter, NarrativeStatement, Scene,
                          Story)
from .validation import validate_story


def _stmt(s, extra_type: Optional[StatementType] = None) -> NarrativeStatement:
    return NarrativeStatement(
        stype=extra_type or s.stype, text=s.text,
        evidence_ids=list(s.evidence_ids), entity_ids=list(s.entity_ids),
        relationship_ids=list(s.relationship_ids), hypothesis_id=s.hypothesis_id,
        graph_highlight={"entity_ids": list(s.entity_ids),
                         "evidence_ids": list(s.evidence_ids)})


class StoryBuilder:
    def build(self, state: IntelligenceState, mode: str = "investigator",
              title: str = "Case Narrative") -> Story:
        story = Story(case_id=state.case_id, mode=mode, title=title)
        ch_map: dict[int, list[NarrativeStatement]] = {n: [] for n in CHAPTER_TITLES}

        # Ch1 objective
        if state.objective:
            ch_map[1].append(NarrativeStatement(
                stype=StatementType.OBSERVATION,
                text=f"This investigation was opened against the objective: "
                     f"{state.objective}"))

        # Ch2 initial picture: facts first, then observations
        for s in state.statements:
            if s.stype is StatementType.FACT:
                ch_map[2].append(_stmt(s))
            elif s.stype is StatementType.OBSERVATION:
                ch_map[2].append(_stmt(s))

        # Ch8 contradictions
        for c in state.contradictions:
            ch_map[8].append(NarrativeStatement(
                stype=StatementType.UNKNOWN,
                text=(f"Contradiction ({c.ctype}, severity {c.severity}): "
                      f"'{c.statement_a}' conflicts with '{c.statement_b}'. "
                      f"Probing questions: {'; '.join(c.probing_questions) or 'n/a'}"),
                evidence_ids=list(c.evidence_ids_a) + list(c.evidence_ids_b)))

        # Ch9/10 hypotheses: strongest-first labelled HYPOTHESIS statements
        hyps = sorted(state.hypotheses, key=lambda h: h.status.value == "supported",
                      reverse=True)
        for i, h in enumerate(hyps):
            target = 9 if i < 3 else 10
            conf = h.confidence.value.replace("_", " ")
            ch_map[target].append(NarrativeStatement(
                stype=StatementType.HYPOTHESIS,
                text=(f"[HYPOTHESIS | {h.status.value.upper()} | confidence {conf}] "
                      f"{h.statement} "
                      f"(supporting evidence: {len(h.supporting_evidence_ids)}, "
                      f"opposing: {len(h.opposing_evidence_ids)}, "
                      f"assumptions: {len(h.assumptions)})"),
                evidence_ids=list(h.supporting_evidence_ids),
                hypothesis_id=h.hypothesis_id,
                graph_highlight={"hypothesis_id": h.hypothesis_id}))

        # Ch11 unknown information
        for s in state.statements:
            if s.stype in (StatementType.UNKNOWN, StatementType.SPECULATION):
                ch_map[11].append(_stmt(s))
        for g in state.gaps[:8]:
            ch_map[11].append(NarrativeStatement(
                stype=StatementType.UNKNOWN,
                text=f"[GAP] {g.question} — why it matters: {g.why_it_matters}"))

        # Ch12 next moves (persisted WHY)
        for a in state.next_actions[:8]:
            ch_map[12].append(NarrativeStatement(
                stype=StatementType.OBSERVATION,
                text=(f"[NEXT ACTION | {a.kind}] {a.description} "
                      f"(capability: {a.capability}; expected value "
                      f"{a.expected_information_value:.2f}; rationale: {a.rationale})")))

        # Ch13 current assessment — insights only, importance != truth
        for ins in state.insights:
            ch_map[13].append(NarrativeStatement(
                stype=StatementType.INSIGHT,
                text=(f"[INSIGHT | importance {ins.importance.upper()}] "
                      f"{ins.title}: {ins.statement}"
                      + ((" Limitations: " + "; ".join(ins.limitations))
                         if ins.limitations else "")),
                evidence_ids=list(ins.supporting_evidence_ids),
                graph_highlight={"entity_ids": list(ins.supporting_entity_ids)}))

        for num in sorted(CHAPTER_TITLES):
            stmts = ch_map.get(num, [])
            if not stmts and num not in (1,):
                continue
            scene = Scene(title="Findings", statements=stmts) if stmts else Scene(
                title="No material content yet",
                statements=[NarrativeStatement(
                    stype=StatementType.UNKNOWN,
                    text="Nothing established for this section yet.")])
            story.chapters.append(Chapter(number=num, title=CHAPTER_TITLES[num],
                                          scenes=[scene]))

        res = validate_story(story)
        if not res.ok:
            # Builder produced a bad story — that is a bug, fail loudly.
            from .validation import NarrativeValidationError
            raise NarrativeValidationError(
                "generated story failed validation: "
                + "; ".join(f"{i.rule}:{i.detail}" for i in res.issues[:5]))
        return story
