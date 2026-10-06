"""traceatlas.synthesis.aggregator - Result fusion across workers (spec §4).

Fuses worker results / observations into an IntelligenceState. Never
concatenates; instead derives typed facts, insights, contradictions and gaps.
No worker result becomes a final conclusion automatically: everything emitted
is FACT/OBSERVATION/INSIGHT/HYPOTHESIS with explicit evidence links.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Optional

from traceatlas.core.observation import Observation
from traceatlas.hypotheses.generator import HypothesisGenerator
from traceatlas.hypotheses.model import Hypothesis

from .state import (ContradictionRecord, Gap, Insight, IntelligenceState,
                    NextBestAction, StatementType)


# predicates that describe point-in-time infrastructure truth -> FACT-eligible
_FACT_PREDICATES = {
    "resolves_to", "hosts", "belongs_to_asn", "issued_for", "registered_at",
    "resolved", "has_record", "prefix_of",
}

_PROBING_BY_TYPE = {
    "value": ["different observation date?", "different jurisdiction?",
              "stale record?", "incorrect source?"],
    "temporal": ["which observation is current?", "was there a change event?"],
    "identity": ["company-name collision?", "namesake?", "subsidiary vs parent?"],
    "ownership": ["leadership change?", "historical vs current ownership?"],
}


class Aggregator:
    def __init__(self, generator: Optional[HypothesisGenerator] = None):
        self.generator = generator or HypothesisGenerator()

    # ------------------------------------------------------------------ fuse
    def fuse(self, case_id: str, objective: str,
             observations: Iterable[Observation],
             independence_clusters: Optional[dict[str, str]] = None
             ) -> IntelligenceState:
        """Main fusion pass. `independence_clusters` maps source_id->cluster_id
        from the source-independence engine (copied sources collapse to one)."""
        state = IntelligenceState(case_id=case_id, objective=objective)
        obs_list = list(observations)
        clusters = independence_clusters or {}

        by_key: dict[tuple, list[Observation]] = defaultdict(list)
        for o in obs_list:
            by_key[o.key()].append(o)

        # 1) FACTS + contradiction scan per (subject,predicate) group
        for (subject, predicate), group in sorted(
                by_key.items(), key=lambda kv: str(kv[0])):
            distinct_values = {str(o.value) for o in group}
            if len(distinct_values) == 1:
                text = f"{subject} {predicate.replace('_',' ')} {distinct_values.pop()} " \
                       f"(as observed at retrieval time)"
                ev_ids = [o.evidence_id for o in group if o.evidence_id]
                indep = len({clusters.get(str(o.source_id), str(o.source_id))
                             for o in group if o.source_id})
                stype = StatementType.FACT if (predicate in _FACT_PREDICATES
                                               and ev_ids) else StatementType.OBSERVATION
                s = state.add(stype, text, evidence_ids=ev_ids,
                              entity_ids=[subject] if subject else [])
                s.confidence = "high" if indep >= 2 else "moderate"
                s.provenance["independent_source_clusters"] = indep
            else:
                # incompatible values for same subject+predicate -> contradiction
                a, b = group[0], group[-1]
                ctype = self._classify_contradiction(a, b)
                rec = ContradictionRecord(
                    ctype=ctype,
                    statement_a=f"{subject} {predicate} = {a.value}",
                    statement_b=f"{subject} {predicate} = {b.value}",
                    evidence_ids_a=[e for e in [a.evidence_id] if e],
                    evidence_ids_b=[e for e in [b.evidence_id] if e],
                    severity=0.7 if predicate in _FACT_PREDICATES else 0.5,
                    probing_questions=list(_PROBING_BY_TYPE.get(ctype, [])))
                state.contradictions.append(rec)
                state.add(StatementType.UNKNOWN,
                          f"conflicting {predicate.replace('_',' ')} observations for "
                          f"{subject}: {sorted({str(o.value) for o in group})}")

        # 2) INSIGHTS — cross-predicate structural readings (never conclusions)
        self._derive_insights(state, obs_list, clusters)

        # 3) HYPOTHESES — multiple competing explanations, never auto-conclusions
        generated = self.generator.generate_for_observations(case_id, obs_list)
        state.hypotheses.extend(generated)
        for h in generated:
            state.add(StatementType.HYPOTHESIS, h.statement,
                      hypothesis_id=h.hypothesis_id,
                      entity_ids=h.related_entity_ids, confidence="unrated")

        # 4) GAPS — required-but-missing evidence on live hypotheses + conflicts
        self._derive_gaps(state)

        # 5) NBA candidates — falsification-first ordering handled by nba module
        self._derive_next_actions(state)

        state.metrics = {
            "observations_in": len(obs_list),
            "statements_out": len(state.statements),
            "facts": len(state.facts()),
            "contradictions": len(state.contradictions),
            "hypotheses": len(state.hypotheses),
            "gaps": len(state.gaps),
        }
        return state

    # ------------------------------------------------------------- internals
    @staticmethod
    def _classify_contradiction(a: Observation, b: Observation) -> str:
        pa = (a.observed_at.isoformat() if a.observed_at else "")[:10]
        pb = (b.observed_at.isoformat() if b.observed_at else "")[:10]
        if pa and pb and pa != pb:
            return "temporal"
        if a.predicate in ("registrant_of", "owns", "manages"):
            return "ownership"
        if a.predicate in ("same_person_as", "located_at"):
            return "identity" if a.predicate == "same_person_as" else "location"
        return "value"

    def _derive_insights(self, state: IntelligenceState,
                         obs: list[Observation],
                         clusters: dict[str, str]) -> None:
        # Shared-infrastructure insight: several domains touching same IP value
        resolves = defaultdict(set)
        for o in obs:
            if o.predicate == "resolves_to" and o.subject_id:
                resolves[str(o.value)].add(str(o.subject_id))
        for ip, subjects in resolves.items():
            if len(subjects) >= 2:
                ev = [o.evidence_id for o in obs
                      if o.predicate == "resolves_to" and str(o.value) == ip
                      and o.evidence_id]
                indep = len({clusters.get(str(o.source_id), str(o.source_id))
                             for o in obs if o.source_id})
                state.insights.append(Insight(
                    title="shared hosting context",
                    statement=(f"Multiple infrastructure observations connect "
                               f"{sorted(subjects)} to {ip}; this is a hosting-context "
                               f"signal, not proof of common control."),
                    supporting_evidence_ids=ev,
                    supporting_entity_ids=[ip] + sorted(subjects),
                    source_independence=indep,
                    importance="medium",
                    limitations=["association != causation",
                                 "shared infrastructure has benign explanations"]))

        # Single-source corroboration warning insight
        by_key: dict[tuple, list[Observation]] = defaultdict(list)
        for o in obs:
            by_key[o.key()].append(o)
        for (subject, predicate), group in by_key.items():
            indep = len({clusters.get(str(o.source_id), str(o.source_id))
                         for o in group if o.source_id})
            if len(group) >= 3 and indep <= 1:
                ev = [o.evidence_id for o in group if o.evidence_id]
                state.insights.append(Insight(
                    title="repeated but dependent sources",
                    statement=(f"{len(group)} mentions of {predicate.replace('_',' ')} "
                               f"for {subject} come from {indep or 1} independent "
                               f"source cluster(s); repetition does not corroborate."),
                    supporting_evidence_ids=ev,
                    importance="high",
                    limitations=["count-based corroboration would be wrong here"]))

    def _derive_gaps(self, state: IntelligenceState) -> None:
        seen: set[str] = set()
        for h in state.hypotheses:
            if h.status.value in ("falsified", "archived"):
                continue
            for req in h.required_evidence:
                if req in seen:
                    continue
                seen.add(req)
                state.gaps.append(Gap(
                    question=req,
                    why_it_matters=f"required to test hypothesis: {h.statement[:100]}",
                    missing_evidence=[req],
                    potential_capabilities=[],
                    estimated_information_value=0.6,
                    priority="high"))
        for c in state.contradictions:
            q = (f"Resolve {c.ctype} conflict: '{c.statement_a}' vs '{c.statement_b}'")
            if q not in seen:
                seen.add(q)
                state.gaps.append(Gap(question=q,
                                      why_it_matters="unresolved contradiction blocks "
                                                     "verification of affected findings",
                                      current_state="disputed",
                                      estimated_information_value=0.8,
                                      priority="high"))

    def _derive_next_actions(self, state: IntelligenceState) -> None:
        from traceatlas.hypotheses.falsification import generate_falsification_tasks
        for h in state.hypotheses:
            if h.status.value in ("falsified", "archived"):
                continue
            for t in generate_falsification_tasks(h)[:3]:
                state.next_actions.append(NextBestAction(
                    kind={"falsify": "falsify", "discriminate": "discriminate",
                          "check_assumption": "collect"}[t.kind],
                    description=t.description, capability=t.capability,
                    hypothesis_id=h.hypothesis_id,
                    expected_information_value=0.4 + 0.2 * t.priority,
                    rationale=t.rationale))
