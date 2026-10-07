"""traceatlas.intelligence.hypothesis_gate — hypotheses stay hypotheses (§7, §27).

Rules enforced here:
* No hypothesis may be produced before a Fact Summary exists (fact-first law).
* A hypothesis is NEVER a fact; promotion attempts are refused.
* Every hypothesis must carry: statement, supporting/opposing FACT references,
  assumptions, unknowns, alternative explanations, at least one falsification
  condition and a next discriminating test.
* The ACH-style matrix scores each hypothesis against every observation
  (CONSISTENT / INCONSISTENT / NEUTRAL / UNKNOWN). One discriminating
  contradiction can outweigh many weak supports — the status transition
  honors that asymmetry.
* Statuses follow constants.HypothesisStatus lifecycle; SUPPORTED is only
  reachable through explicit verification evidence, never by model agreement.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from traceatlas.core.observation import Observation
from traceatlas.intelligence.constants import AchCell, HypothesisStatus
from traceatlas.intelligence.fact_gate import FactSummary, _canon


class HypothesisGateError(ValueError):
    """Raised when a hypothesis violates the gate contract."""


@dataclass(slots=True)
class FalsificationCondition:
    condition: str                 # what observed state would make H false
    test: str                      # concrete next check that could observe it
    status: str = "untested"       # untested | met | not_met | inconclusive

    def to_dict(self) -> dict[str, Any]:
        return {"condition": self.condition, "test": self.test, "status": self.status}


@dataclass(slots=True)
class GatedHypothesis:
    hypothesis_id: str
    question: str
    statement: str
    supporting_fact_ids: tuple[str, ...] = ()
    opposing_fact_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    source_bias_effects: tuple[str, ...] = ()
    independence_notes: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    falsifications: tuple[FalsificationCondition, ...] = ()
    required_evidence: tuple[str, ...] = ()
    next_test: str = ""
    status: str = HypothesisStatus.PROPOSED.value

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "question": self.question,
                "statement": self.statement,
                "supporting_fact_ids": list(self.supporting_fact_ids),
                "opposing_fact_ids": list(self.opposing_fact_ids),
                "assumptions": list(self.assumptions), "unknowns": list(self.unknowns),
                "contradictions": list(self.contradictions),
                "source_bias_effects": list(self.source_bias_effects),
                "independence_notes": list(self.independence_notes),
                "alternative_explanations": list(self.alternative_explanations),
                "falsification_conditions": [f.to_dict() for f in self.falsifications],
                "required_evidence": list(self.required_evidence),
                "next_test": self.next_test, "status": self.status}


@dataclass(slots=True)
class AchRow:
    hypothesis_id: str
    cells: dict[str, str] = field(default_factory=dict)   # obs_key -> AchCell value
    consistent: int = 0
    inconsistent: int = 0
    neutral: int = 0
    unknown: int = 0
    discriminating: tuple[str, ...] = ()                  # obs_keys INCONSISTENT elsewhere

    def score(self) -> float:
        # asymmetric: inconsistency dominates
        return round((self.consistent - 2 * self.inconsistent)
                     / max(1, self.consistent + self.inconsistent + self.neutral), 3)


def _obs_key(o: Observation) -> str:
    return f"{o.subject_id}|{o.predicate}"


class HypothesisGate:
    """Validates and evaluates competing hypotheses over gated facts."""

    # ---------------------------------------------------------------- validate
    def validate(self, h: GatedHypothesis, summary: FactSummary) -> None:
        """Raise HypothesisGateError unless the hypothesis satisfies §27."""
        if summary is None or not isinstance(summary, FactSummary):
            raise HypothesisGateError(
                "Fact Summary required before hypotheses (fact-first law)")
        if not summary.has_promotable_facts() and not (h.opposing_fact_ids or h.unknowns):
            raise HypothesisGateError(
                "no gated facts exist yet; a hypothesis with no facts must declare "
                "opposing evidence or unknowns explicitly")
        if not h.statement.strip():
            raise HypothesisGateError("hypothesis statement empty")
        if not h.falsifications:
            raise HypothesisGateError(
                "hypothesis lacks falsification conditions: unfalsifiable claims "
                "are not admissible")
        for f in h.falsifications:
            if not f.condition.strip() or not f.test.strip():
                raise HypothesisGateError(
                    "every falsification needs both a condition and a concrete test")
        if not h.next_test.strip():
            raise HypothesisGateError("hypothesis lacks a next discriminating test")
        if not h.alternative_explanations:
            raise HypothesisGateError(
                "competing explanation required: a lone hypothesis is narrative, "
                "not analysis")
        supported_ids = {g.observation_ids[0] for g in summary.supported
                         if g.observation_ids}
        all_fact_obs = supported_ids | {g.observation_ids[0] for g in summary.partial
                                        if g.observation_ids}
        for fid in h.supporting_fact_ids:
            if fid not in all_fact_obs and not fid.startswith("fact_"):
                raise HypothesisGateError(
                    f"supporting reference {fid!r} is not a gated fact/observation id")

    def refuse_promotion(self, h: GatedHypothesis) -> None:
        """Story never upgrades a hypothesis into fact (§28). Explicit guard."""
        raise HypothesisGateError(
            f"hypothesis {h.hypothesis_id} cannot become a fact; only the Fact Gate "
            "promotes evidence-linked observations. Keep label HYPOTHESIS.")

    # -------------------------------------------------------------------- ACH
    def build_matrix(self, hypotheses: list[GatedHypothesis],
                     observations: list[Observation]) -> list[AchRow]:
        """Deterministic consistency scoring of each hypothesis against each
        observation. An observation CONTRADICTS a hypothesis when its
        (subject,predicate,value) matches an opposing-fact side; supports when
        it matches a supporting side; otherwise NEUTRAL, and missing/unverifiable
        linkage is UNKNOWN — never silently consistent."""
        by_key: dict[str, list[Observation]] = {}
        for o in observations:
            by_key.setdefault(_obs_key(o), []).append(o)
        rows: list[AchRow] = []
        for h in hypotheses:
            row = AchRow(hypothesis_id=h.hypothesis_id)
            sup_vals = set(h.supporting_fact_ids)
            opp_vals = set(h.opposing_fact_ids)
            for key, group in by_key.items():
                cell = AchCell.NEUTRAL
                for o in group:
                    tag = o.observation_id
                    if tag in opp_vals:
                        cell = AchCell.INCONSISTENT
                        break
                    if tag in sup_vals:
                        cell = AchCell.CONSISTENT
                else:
                    if not sup_vals and not opp_vals:
                        cell = AchCell.UNKNOWN  # no linkage declared at all
                row.cells[key] = cell.value
                if cell == AchCell.CONSISTENT:
                    row.consistent += 1
                elif cell == AchCell.INCONSISTENT:
                    row.inconsistent += 1
                elif cell == AchCell.UNKNOWN:
                    row.unknown += 1
                else:
                    row.neutral += 1
            # discriminating: observations consistent for SOME hypothesis but
            # inconsistent for this one count double below via score(); mark them
            row.discriminating = tuple(k for k, v in row.cells.items()
                                       if v == AchCell.INCONSISTENT.value)
            rows.append(row)
        return rows

    def recommend_status(self, h: GatedHypothesis, row: AchRow,
                         others: list[AchRow]) -> str:
        """Conservative status transition advice; humans/verification still own
        final SUPPORTED/DISPUTED calls."""
        if any(f.status == "met" for f in h.falsifications):
            return HypothesisStatus.FALSIFIED.value
        best_other = max((r.score() for r in others if r.hypothesis_id != h.hypothesis_id),
                         default=None)
        if row.inconsistent and (best_other is None or row.score() < best_other):
            return HypothesisStatus.WEAKENED.value
        if row.consistent and not row.inconsistent:
            return HypothesisStatus.STRENGTHENED.value
        if row.unknown >= max(1, len(row.cells)):
            return HypothesisStatus.INCONCLUSIVE.value
        return HypothesisStatus.ACTIVE.value

    # ------------------------------------------------------- falsification pass
    def falsification_questions(self, h: GatedHypothesis) -> tuple[str, ...]:
        """The dedicated skeptic checklist (§27) rendered as concrete questions."""
        qs = [f"What observed state would make this false? Declared: "
              f"{[f.condition for f in h.falsifications]}"]
        if any("same_person" in s or "owner" in s or "operator" in s
               for s in h.supporting_fact_ids + h.assumptions):
            qs.append("What identity mismatch breaks it (namesake/collision)?")
        qs.append("What temporal conflict breaks it (event vs validity vs observation time)?")
        if h.independence_notes:
            qs.append("Which source dependency weakens it (syndicated/copied support)?")
        qs.append("What alternative explanation fits ALL current facts? "
                  f"Declared alternatives: {list(h.alternative_explanations)}")
        qs.append("What independent source could test the next discriminating check? "
                  f"Next test: {h.next_test}")
        return tuple(qs)
