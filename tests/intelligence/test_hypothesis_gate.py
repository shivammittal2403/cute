"""Hypothesis Gate tests (§27): fact-first ordering, falsifiability, ACH asymmetry."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from traceatlas.core.observation import Observation
from traceatlas.intelligence.constants import HypothesisStatus
from traceatlas.intelligence.fact_gate import FactGate
from traceatlas.intelligence.hypothesis_gate import (
    FalsificationCondition,
    GatedHypothesis,
    HypothesisGate,
    HypothesisGateError,
)

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def _obs(sid, value="1.2.3.4", evidence_id=None, predicate="dns.a_record"):
    if evidence_id is None:
        evidence_id = "ev-" + sid
    return Observation(case_id="c1", subject_id=sid, predicate=predicate,
                       value=value, evidence_id=evidence_id,
                       observed_at=NOW - timedelta(hours=1), recorded_at=NOW)


@pytest.fixture
def summary():
    o = _obs("dom-1")
    return FactGate().run([o], case_id="c1", now=NOW), o


def _h(**kw):
    base = dict(hypothesis_id="hyp_1", question="who runs the site?",
                statement="The scam operator controls the domain.",
                supporting_fact_ids=(), opposing_fact_ids=(),
                assumptions=("registry data is current",),
                unknowns=("hosting tenant",),
                alternative_explanations=("legitimate business with bad marketing",),
                falsifications=(FalsificationCondition(
                    condition="registry shows unrelated active owner",
                    test="RDAP owner check"),),
                next_test="compare registrar contacts across periods")
    base.update(kw)
    return GatedHypothesis(**base)


# ---------------------------------------------------------------- validation
def test_hypothesis_refused_without_fact_summary():
    gate = HypothesisGate()
    with pytest.raises(HypothesisGateError, match="Fact Summary required"):
        gate.validate(_h(), None)


def test_unfalsifiable_hypothesis_inadmissible():
    gate = HypothesisGate()
    s, _ = summary_fixture()
    with pytest.raises(HypothesisGateError, match="unfalsifiable"):
        gate.validate(_h(falsifications=()), s)


def test_falsification_needs_condition_and_concrete_test():
    gate = HypothesisGate()
    s, _ = summary_fixture()
    bad = _h(falsifications=(FalsificationCondition(condition="something bad", test=""),))
    with pytest.raises(HypothesisGateError, match="concrete test"):
        gate.validate(bad, s)


def test_lone_hypothesis_without_alternative_rejected():
    gate = HypothesisGate()
    s, _ = summary_fixture()
    with pytest.raises(HypothesisGateError, match="competing explanation"):
        gate.validate(_h(alternative_explanations=()), s)


def test_missing_next_discriminating_test_rejected():
    gate = HypothesisGate()
    s, _ = summary_fixture()
    with pytest.raises(HypothesisGateError, match="next discriminating test"):
        gate.validate(_h(next_test="  "), s)


def test_supporting_reference_must_be_a_gated_fact_or_observation():
    gate = HypothesisGate()
    s, o = summary_fixture()
    with pytest.raises(HypothesisGateError, match="not a gated fact"):
        gate.validate(_h(supporting_fact_ids=("observation_bogus",)), s)


def test_valid_hypothesis_passes_with_real_observation_reference():
    gate = HypothesisGate()
    s, o = summary_fixture()
    gate.validate(_h(supporting_fact_ids=(o.observation_id,)), s)  # no raise


def test_hypothesis_never_promotes_to_fact():
    gate = HypothesisGate()
    with pytest.raises(HypothesisGateError, match="cannot become a fact"):
        gate.refuse_promotion(_h())


# ------------------------------------------------------------------------- ACH
def summary_fixture():
    o = _obs("dom-1")
    return FactGate().run([o], case_id="c1", now=NOW), o


def test_one_discriminating_contradiction_outweighs_many_weak_supports():
    gate = HypothesisGate()
    obs = [_obs(f"dom-{i}") for i in range(1, 5)]
    h_good = _h(hypothesis_id="hA",
                supporting_fact_ids=tuple(o.observation_id for o in obs[:3]))
    h_bad = _h(hypothesis_id="hB",
               supporting_fact_ids=(obs[0].observation_id,),
               opposing_fact_ids=(obs[3].observation_id,))
    rows = {r.hypothesis_id: r for r in gate.build_matrix([h_good, h_bad], obs)}
    assert gate.recommend_status(h_bad, rows["hB"], [rows["hA"]]) == \
        HypothesisStatus.WEAKENED.value
    assert rows["hB"].score() < rows["hA"].score()


def test_met_falsification_condition_yields_falsified():
    gate = HypothesisGate()
    obs = [_obs("dom-1")]
    h = _h(falsifications=(FalsificationCondition(
        condition="x", test="y", status="met"),))
    row = gate.build_matrix([h], obs)[0]
    assert gate.recommend_status(h, row, []) == HypothesisStatus.FALSIFIED.value


def test_unlinked_hypothesis_cells_are_unknown_not_consistent():
    gate = HypothesisGate()
    obs = [_obs("dom-9")]
    row = gate.build_matrix([_h()], obs)[0]
    assert row.unknown >= 1 and row.consistent == 0


def test_falsification_checklist_covers_identity_time_dependency_alternatives():
    gate = HypothesisGate()
    qs = "\n".join(gate.falsification_questions(
        _h(supporting_fact_ids=("same_person_via_username",))))
    for needle in ("identity mismatch", "temporal conflict",
                   "alternative explanation", "independent source"):
        assert needle in qs
