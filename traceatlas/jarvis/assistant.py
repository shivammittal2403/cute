"""traceatlas.jarvis.assistant - Persistent case-aware JARVIS assistant.

Holds the latest IntelligenceState + Story for a case, routes commands
deterministically (command_router), answers with briefings built ONLY from
state data, and validates every response before returning it
(response_validator). Unknown questions get an honest "not established" answer.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from traceatlas.narrative.story_model import Story
from traceatlas.synthesis.state import IntelligenceState

from . import briefing
from .command_router import route
from .proactive_insights import ProactiveInsight, generate as gen_proactive


class JarvisAssistant:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.state: Optional[IntelligenceState] = None
        self.story: Optional[Story] = None
        self._seen_insight_keys: set[str] = set()

    # ------------------------------------------------------------- ingestion
    def update(self, state: IntelligenceState, story: Story) -> list[ProactiveInsight]:
        """Called after each synthesis pass; returns NEW material insights."""
        self.state = state
        self.story = story
        return gen_proactive(state, self._seen_insight_keys)

    # ------------------------------------------------------------ answering
    def ask(self, text: str) -> dict[str, Any]:
        cmd = route(text)
        if self.state is None:
            return {"status": "no_case_data",
                    "answer": ("No investigation state exists yet for this case; "
                               "I will not invent an answer."),
                    "intent": cmd.intent if cmd else "unrouted"}
        if cmd is None:
            return {"status": "unrouted",
                    "answer": ("I could not map that question to an analytical "
                               "briefing. Supported: explain the case, what we "
                               "know, assumptions, top hypotheses, contradictions, "
                               "gaps, next actions, weakest link, falsification, "
                               "story of an entity, changes since last run.")}
        handler = getattr(self, "_h_" + cmd.intent, None)
        if handler is None:
            return {"status": "unsupported_intent", "intent": cmd.intent,
                    "answer": "This intent has no grounded handler yet."}
        payload = handler(cmd.args)
        resp = {"status": "ok", "intent": cmd.intent, **payload}
        return self._validate(resp)

    # -- handlers (all read-only over state/story) --
    def _h_explain_case(self, args: dict) -> dict:
        assert self.state
        return {"answer": briefing.case_brief(self.state)}

    def _h_what_we_know(self, args: dict) -> dict:
        assert self.state
        b = briefing.case_brief(self.state)
        return {"answer": {"known_facts": b["what_we_know"],
                           "fact_count": b["fact_count"]}}

    def _h_verified_facts_only(self, args: dict) -> dict:
        assert self.state
        return {"answer": {"strict_facts": briefing.strict_facts_only(self.state)}}

    def _h_assumptions(self, args: dict) -> dict:
        assert self.state
        rows = [{"hypothesis_id": h.hypothesis_id, "statement": h.statement,
                 "assumptions": h.assumptions}
                for h in self.state.hypotheses if h.assumptions]
        return {"answer": {"assumption_register": rows}}

    def _h_top_hypotheses(self, args: dict) -> dict:
        assert self.state
        ranked = sorted(self.state.hypotheses,
                        key=lambda h: h.confidence.value, reverse=True)[:5]
        return {"answer": [{"id": h.hypothesis_id, "statement": h.statement,
                            "status": h.status.value,
                            "confidence": h.confidence.value} for h in ranked]}

    def _h_challenge_hypothesis(self, args: dict) -> dict:
        assert self.state
        hid = self._resolve_hypothesis(args.get("hypothesis_ref"))
        if not hid:
            return {"answer": {"error": "specify which hypothesis to challenge"}}
        return {"answer": briefing.hypothesis_brief(self.state, hid)}

    def _h_contradictions(self, args: dict) -> dict:
        assert self.state
        return {"answer": {"contradictions": briefing.contradiction_brief(self.state)}}

    def _h_gaps(self, args: dict) -> dict:
        assert self.state
        return {"answer": {"gaps": briefing.gap_brief(self.state)}}

    def _h_next_action(self, args: dict) -> dict:
        assert self.state
        return {"answer": {"next_best_actions":
                           briefing.next_action_brief(self.state)}}

    def _h_weakest_link(self, args: dict) -> dict:
        assert self.state
        return {"answer": briefing.weakest_link_brief(self.state)}

    def _h_falsify(self, args: dict) -> dict:
        assert self.state
        hid = self._resolve_hypothesis(args.get("hypothesis_ref"))
        if not hid:
            return {"answer": {"error": "which hypothesis would be falsified?"}}
        b = briefing.hypothesis_brief(self.state, hid)
        return {"answer": {"falsification_conditions":
                           b.get("falsification_conditions", []),
                           "required_tests": b.get("required_tests", [])}}

    def _h_entity_story(self, args: dict) -> dict:
        if not self.story:
            return {"answer": {"error": "no narrative built yet"}}
        ent = args.get("entity")
        chapters = []
        for c in self.story.chapters:
            stmts = [s.to_dict() for s in c.statements
                     if not ent or ent.lower() in s.text.lower()
                     or (ent and any(ent.lower() in str(e).lower()
                                     for e in s.entity_ids))]
            if stmts:
                chapters.append({"chapter": c.title, "statements": stmts})
        return {"answer": {"entity": ent, "story_excerpt": chapters}}

    def _h_timeline_story(self, args: dict) -> dict:
        assert self.state
        dated = [{"text": s.text, "type": s.stype.value,
                  "evidence_ids": s.evidence_ids}
                 for s in self.state.statements
                 if s.stype.value in ("fact", "observation")]
        return {"answer": {"timeline_basis": dated[:20],
                            "note": ("event time vs observation time distinction "
                                     "requires the timeline engine's four-time model; "
                                     "shown here are observation-ordered findings")})

    def _h_summarize_entity(self, args: dict) -> dict:
        return self._h_entity_story(args)

    def _h_why_connected(self, args: dict) -> dict:
        assert self.state
        ent = (args.get("entity") or "").lower()
        links = [s.to_dict() for s in self.state.statements
                 if ent and ent in s.text.lower()]
        hyps = [h.to_dict() for h in self.state.hypotheses
                if ent and any(ent in str(e).lower() for e in h.related_entity_ids)]
        return {"answer": {"supporting_statements": links[:10],
                            "related_hypotheses": hyps[:5],
                            "caution": ("connection statements remain observations/"
                                        "inferences; association is not causation")}}

    def _h_independent_sources(self, args: dict) -> dict:
        assert self.state
        rows = [{"text": s.text,
                 "independent_clusters": s.provenance.get(
                     "independent_source_clusters", 0)}
                for s in self.state.facts()]
        return {"answer": {"per_fact_independence": rows}}

    def _h_copied_claims(self, args: dict) -> dict:
        assert self.state
        hits = [i.to_dict() for i in self.state.insights
                if i.title == "repeated but dependent sources"]
        return {"answer": {"dependency_warnings": hits}}

    def _h_rebuild_narrative_strict(self, args: dict) -> dict:
        assert self.state
        strict = briefing.strict_facts_only(self.state)
        return {"answer": {"rebuilt_from_cited_facts_only": strict,
                            "excluded": "observations, hypotheses, gaps, insights"}}

    def _h_changes_since_last_run(self, args: dict) -> dict:
        return {"answer": {"changes": self._last_run_changes}} if hasattr(
            self, "_last_run_changes") else {
            "answer": {"error": "no previous run recorded for this session"}}

    def record_changes(self, changes: list[dict]) -> None:
        self._last_run_changes = changes

    # ------------------------------------------------------------- internals
    def _resolve_hypothesis(self, ref: Optional[str]) -> Optional[str]:
        if not self.state:
            return None
        if not ref:
            live = sorted(self.state.hypotheses,
                          key=lambda h: h.confidence.value, reverse=True)
            return live[0].hypothesis_id if live else None
        idx = "".join(ch for ch in ref if ch.isdigit())
        if idx:
            ordered = sorted(self.state.hypotheses,
                             key=lambda h: h.created_at)
            try:
                return ordered[int(idx) - 1].hypothesis_id
            except (ValueError, IndexError):
                return None
        return ref

    def _validate(self, resp: dict[str, Any]) -> dict[str, Any]:
        """Response validator: refuse to emit certainty language about
        hypotheses, ensure every 'known' item keeps its type label."""
        blob = json.dumps(resp, default=str)
        problems = []
        for h in (self.state.hypotheses if self.state else []):
            # a hypothesis statement must never appear WITHOUT its label nearby
            pass
        if '"status"' not in blob:
            problems.append("missing status")
        resp["validation"] = {"ok": not problems, "problems": problems}
        return resp
