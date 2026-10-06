"""traceatlas.synthesis.engine - Intelligence Synthesis Engine facade.

Wires: observations -> Aggregator (fusion) -> PatternEngine -> Hypothesis
registry/ACH/falsification -> StoryBuilder -> IntelligenceState + Story.
This is the single entry point used by the investigation loop and JARVIS.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from traceatlas.core.observation import Observation
from traceatlas.hypotheses.ach import ACHMatrix, EvidenceItem, build_matrix
from traceatlas.hypotheses.generator import HypothesisGenerator
from traceatlas.hypotheses.graph import HypothesisGraph
from traceatlas.hypotheses.history import HypothesisHistory
from traceatlas.hypotheses.model import Hypothesis
from traceatlas.hypotheses.registry import HypothesisRegistry
from traceatlas.narrative.story_builder import StoryBuilder
from traceatlas.narrative.story_model import Story
from traceatlas.patterns.engine import PatternEngine

from .aggregator import Aggregator
from .state import IntelligenceState


class SynthesisEngine:
    def __init__(self, registry: Optional[HypothesisRegistry] = None,
                 generator: Optional[HypothesisGenerator] = None):
        self.aggregator = Aggregator(generator)
        self.patterns = PatternEngine()
        self.registry = registry or HypothesisRegistry()
        self.hgraph = HypothesisGraph()
        self.history = HypothesisHistory()
        self.story_builder = StoryBuilder()

    # -------------------------------------------------------------- pipeline
    def synthesize(self, case_id: str, objective: str,
                   observations: Iterable[Observation],
                   independence_clusters: Optional[dict[str, str]] = None,
                   evidence_items: Optional[list[EvidenceItem]] = None,
                   ) -> tuple[IntelligenceState, Story]:
        """Full pass: fuse -> patterns -> persist hypotheses -> ACH -> story."""
        state = self.aggregator.fuse(case_id, objective, observations,
                                     independence_clusters)

        # Patterns feed the state (typed OBSERVATION with caution text).
        pats = self.patterns.detect(case_id, observations)
        state.patterns = [p.to_dict() for p in pats]

        # Persist hypotheses + analytical overlay graph; dedupe by statement.
        existing = {h.statement for h in self.registry.all(case_id=case_id)}
        new_hyps: list[Hypothesis] = []
        for h in state.hypotheses:
            if h.statement in existing:
                stored = next((x for x in self.registry.all(case_id=case_id)
                               if x.statement == h.statement), None)
                if stored:
                    continue
            else:
                self.registry.register(h)
                new_hyps.append(h)
        all_live = self.registry.active(case_id=case_id) or \
            [h for h in state.hypotheses]
        for h in all_live:
            self.hgraph.link_hypothesis(h)
        state.hypotheses = all_live

        # Link competing hypotheses within same question family
        self._link_competing(all_live)

        # ACH matrices per related-hypothesis cluster
        if evidence_items:
            state.ach_matrices = [m.to_dict() for m in
                                  self._build_ach(state, evidence_items)]

        state.metrics.update({
            "patterns": len(pats),
            "hypotheses_registered": len(new_hyps),
            "hypotheses_active": len(all_live),
        })

        story = self.story_builder.build(state, mode="investigator")
        return state, story

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _link_competing(hyps: list[Hypothesis]) -> None:
        """Hypotheses sharing >=2 entities compete (they explain one pattern)."""
        for i, a in enumerate(hyps):
            for b in hyps[i + 1:]:
                shared = set(a.related_entity_ids) & set(b.related_entity_ids)
                if len(shared) >= 2 and b.hypothesis_id not in a.competing_with:
                    a.competing_with.append(b.hypothesis_id)
                    b.competing_with.append(a.hypothesis_id)

    def _build_ach(self, state: IntelligenceState,
                   evidence_items: list[EvidenceItem]) -> list[ACHMatrix]:
        groups: dict[frozenset, list[Hypothesis]] = {}
        for h in state.hypotheses:
            key = frozenset(h.related_entity_ids[:3])
            groups.setdefault(key, []).append(h)
        mats = []
        for key, hs in groups.items():
            if len(hs) >= 2:
                mats.append(build_matrix(
                    question=f"explanations for entities {sorted(key)[:3]}",
                    hypotheses=hs, evidence=evidence_items))
        return mats

    # --------------------------------------------------------- run-to-run
    def record_run_changes(self, case_id: str) -> list[dict[str, Any]]:
        changes = self.history.record_run(self.registry.all(case_id=case_id))
        return [{"hypothesis_id": c.hypothesis_id, "kind": c.kind,
                 "detail": c.detail} for c in changes]
