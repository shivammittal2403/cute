"""Fact Gate domain tests (§7 fact-first law, §8 independence, §35 critical assertions).

Covers: no-evidence rejection, conflict->DISPUTED preservation, single-source
caveat, consequential-predicate corroboration rule, freshness/staleness handling,
syndicated-copy clustering via the real IndependenceEngine-backed clusterer, and
FactSummary completeness for pre-hypothesis reporting.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from traceatlas.core.observation import Observation
from traceatlas.intelligence.constants import FactGateOutcome
from traceatlas.intelligence.fact_gate import (
    FactGate,
    TextCorpusClusterer,
    is_consequential,
)
from traceatlas.verification.independence import IndependenceEngine


NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def _obs(subject="dom-1", predicate="dns.a_record", value="1.2.3.4",
         evidence_id="ev-1", age_h=1):
    return Observation(case_id="case-1", subject_id=subject, predicate=predicate,
                       value=value, evidence_id=evidence_id,
                       observed_at=NOW - timedelta(hours=age_h),
                       recorded_at=NOW)


# ------------------------------------------------------------- fact-first law
def test_candidate_fact_without_evidence_is_rejected_not_promoted():
    gate = FactGate()
    recs = gate.evaluate_group([_obs(evidence_id=None)], now=NOW)
    assert len(recs) == 1
    assert recs[0].outcome == FactGateOutcome.REJECTED_NO_EVIDENCE.value
    assert "fact-first law" in recs[0].reasons[0]


def test_direct_single_source_observation_supported_with_caveat():
    gate = FactGate()
    recs = gate.evaluate_group([_obs()], now=NOW)
    assert recs[0].outcome == FactGateOutcome.SUPPORTED.value
    assert "single-source direct observation" in recs[0].reasons


def test_conflicting_values_are_disputed_and_both_preserved():
    gate = FactGate()
    recs = gate.evaluate_group(
        [_obs(value="1.2.3.4", evidence_id="ev-a"),
         _obs(value="5.6.7.8", evidence_id="ev-b")], now=NOW)
    outcomes = {r.outcome for r in recs}
    assert outcomes == {FactGateOutcome.DISPUTED.value}
    values = {str(r.value).strip().lower() for r in recs}
    assert len(values) == 2  # nothing silently overwritten


# ----------------------------------------------------- consequential predicates
def test_consequential_predicate_needs_two_clusters_else_partial():
    gate = FactGate()
    recs = gate.evaluate_group(
        [_obs(predicate="whois.registrant_owner", value="Acme Ltd",
              evidence_id="ev-1")], now=NOW)
    assert recs[0].outcome == FactGateOutcome.PARTIAL.value
    assert is_consequential("whois.registrant_owner")


def test_consequential_predicate_supported_by_two_independent_evidences():
    gate = FactGate()
    recs = gate.evaluate_group(
        [_obs(predicate="whois.registrant_owner", value="Acme Ltd", evidence_id="ev-1"),
         _obs(predicate="whois.registrant_owner", value="Acme Ltd", evidence_id="ev-2")],
        now=NOW)
    assert recs[0].outcome == FactGateOutcome.SUPPORTED.value
    assert recs[0].independent_cluster_count == 2


# ------------------------------------------------------------------- freshness
def test_stale_dns_observation_is_inconclusive_not_a_current_fact():
    gate = FactGate()
    recs = gate.evaluate_group([_obs(age_h=48)], now=NOW)  # dns window = 24h
    assert recs[0].outcome == FactGateOutcome.INCONCLUSIVE.value
    assert recs[0].stale is True


def test_old_registry_data_remains_valid_within_long_window():
    gate = FactGate()
    recs = gate.evaluate_group(
        [_obs(predicate="registry.status", value="active", age_h=24 * 30)], now=NOW)
    assert recs[0].outcome == FactGateOutcome.SUPPORTED.value


def test_missing_timestamp_treated_as_unverifiable_stale():
    gate = FactGate()
    o = _obs()
    object.__setattr__(o, "observed_at", None)
    object.__setattr__(o, "recorded_at", None)
    recs = gate.evaluate_group([o], now=NOW)
    assert recs[0].outcome == FactGateOutcome.INCONCLUSIVE.value


# ------------------------------------------------------------ source independence
TEXTS = {
    "ev-1": "Global fraud ring targeting retirees exposed by regulators today.",
    "ev-2": "Global fraud ring targeting retirees exposed by regulators today.",  # copy
    "ev-3": "Global fraud ring targeting retirees exposed by regulators today.",  # copy
    "ev-4": "Victims describe weeks of pressure from an unknown call centre.",   # distinct
}


def _clusterer():
    def text_of(eid):
        return TEXTS[eid]

    def meta_of(eid):
        pub = "reuters.com" if eid != "ev-4" else "localpaper.example"
        return {"source_slug": "news-" + eid, "publisher_domain": pub}

    return TextCorpusClusterer(IndependenceEngine(), text_of, meta_of)


def test_five_copied_urls_remain_one_independence_cluster():
    clusters = _clusterer().clusters(["ev-1", "ev-2", "ev-3"])
    assert len(clusters) == 1


def test_syndicated_copies_do_not_corroborate_consequential_claim():
    gate = FactGate(clusterer=_clusterer())
    recs = gate.evaluate_group(
        [_obs(predicate="company.operator_identity", value="Acme Ltd", evidence_id=e)
         for e in ("ev-1", "ev-2", "ev-3")], now=NOW)
    # three copied articles -> one cluster -> PARTIAL, never SUPPORTED
    assert recs[0].outcome == FactGateOutcome.PARTIAL.value
    assert recs[0].independent_cluster_count == 1


def test_genuine_second_source_upgrades_consequential_claim():
    gate = FactGate(clusterer=_clusterer())
    recs = gate.evaluate_group(
        [_obs(predicate="company.operator_identity", value="Acme Ltd", evidence_id="ev-1"),
         _obs(predicate="company.operator_identity", value="Acme Ltd", evidence_id="ev-4")],
        now=NOW)
    assert recs[0].outcome == FactGateOutcome.SUPPORTED.value
    assert recs[0].independent_cluster_count == 2


# ------------------------------------------------------------------ fact summary
def test_fact_summary_buckets_every_outcome_for_pre_hypothesis_review():
    gate = FactGate()
    obs = [
        _obs(),                                        # supported (fresh dns)
        _obs(subject="dom-2", predicate="whois.registrant_owner",
             value="X", evidence_id="ev-9"),           # partial (consequential, 1 cluster)
        _obs(subject="dom-3", predicate="dns.a_record", value="1.1.1.1",
             evidence_id="ev-3"),
        _obs(subject="dom-3", predicate="dns.a_record", value="2.2.2.2",
             evidence_id="ev-4"),                     # disputed pair
        _obs(subject="dom-4", predicate="dns.a_record", value="9.9.9.9",
             evidence_id=None),                       # rejected
    ]
    summary = gate.run(obs, case_id="case-1", now=NOW)
    c = summary.counts()
    assert c["supported"] >= 1 and c["partial"] == 1
    assert c["disputed"] == 2 and c["rejected"] == 1
    assert summary.has_promotable_facts()
    d = summary.to_dict()
    for section in ("reliability_notes", "bias_limitations", "independence_notes",
                    "temporal_limitations", "identity_limitations", "contradictions"):
        assert section in d  # §7 mandatory summary sections exist


def test_empty_input_yields_no_records():
    gate = FactGate()
    assert gate.evaluate_group([], now=NOW) == []
    s = gate.run([], case_id="c", now=NOW)
    assert not s.has_promotable_facts()
