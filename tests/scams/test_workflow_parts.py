"""Tests: incident timeline, attribution ladder, crypto boundaries, workflow gaps."""
from datetime import datetime

import pytest

from traceatlas.scams.attribution import AttributionLedger
from traceatlas.scams.crypto import CryptoTracer, validate_address, validate_tx_hash
from traceatlas.scams.timeline import IncidentTimeline, TimelineEvent


# ------------------------------------------------------------------ timeline
class TestTimeline:
    def test_timezone_and_precision_preserved(self):
        tl = IncidentTimeline("c1")
        ev = tl.add(TimelineEvent(case_id="c1", stage="initial_contact",
                                  description="contact via messaging app",
                                  event_time=datetime(2026, 1, 5, 18, 30),
                                  original_timezone="IST",
                                  event_time_precision="DAY"))
        assert ev.original_timezone == "IST"
        out = tl.to_dict()["events"][0]
        assert out["original_timezone"] == "IST"

    def test_undated_events_sort_last_but_never_dropped(self):
        tl = IncidentTimeline("c1")
        tl.add(TimelineEvent(stage="promise", description="dated",
                             event_time=datetime(2026, 1, 6)))
        tl.add(TimelineEvent(stage="promise", description="undated", event_time=None))
        ordered = tl.ordered()
        assert [e.description for e in ordered] == ["dated", "undated"]

    def test_contradiction_preserved_not_overwritten(self):
        tl = IncidentTimeline("c1")
        a = tl.add(TimelineEvent(stage="payment_instruction", description="chat says day 3",
                                 event_time=datetime(2026, 2, 3)))
        b = tl.add(TimelineEvent(stage="payment_instruction", description="email says day 5",
                                 event_time=datetime(2026, 2, 5), contradicts=(a.event_id,)))
        pairs = tl.contradictions()
        assert len(pairs) == 1 and {p.event_id for p in pairs[0]} == {a.event_id, b.event_id}

    def test_correction_supersedes_and_history_retained(self):
        tl = IncidentTimeline("c1")
        old = tl.add(TimelineEvent(stage="refund", description="OCR'd wrong date",
                                   event_time=datetime(2026, 4, 1)))
        new = tl.correct(old.event_id, event_time=datetime(2026, 9, 1))
        assert tl._events[old.event_id].superseded_by == new.event_id
        assert [e.event_id for e in tl.ordered()] == [new.event_id]
        assert len(tl.full_history()) == 2  # history preserved with reason

    def test_unknown_stage_rejected(self):
        tl = IncidentTimeline("c1")
        with pytest.raises(ValueError):
            tl.add(TimelineEvent(stage="teleportation"))


# --------------------------------------------------------------- attribution
class TestAttributionLadder:
    def _ledger_with_lead(self):
        att = AttributionLedger("c1")
        lead = att.observe("domain", "fakecapital.example", "ev-1")
        return att, lead

    def test_shared_hosting_alone_cannot_promote(self):
        att, lead = self._ledger_with_lead()
        ok, why = att.promote(lead.lead_id, "CLAIMED_IDENTITY",
                              signals=("shared_ip",), evidence_ids=("ev-2",),
                              reviewer="analyst")
        assert not ok and "non_discriminating" in why
        assert lead.level == "OBSERVED_IDENTIFIER"

    def test_similar_name_alone_cannot_promote(self):
        att, lead = self._ledger_with_lead()
        ok, _ = att.promote(lead.lead_id, "CLAIMED_IDENTITY",
                            signals=("similar_name", "template_website"),
                            evidence_ids=("ev-2",), reviewer="analyst")
        assert not ok

    def test_ladder_cannot_be_skipped(self):
        att, lead = self._ledger_with_lead()
        ok, why = att.promote(lead.lead_id, "CORROBORATED_ATTRIBUTION",
                              signals=("registry_match",), evidence_ids=("ev-2",),
                              reviewer="analyst", independent_source_count=3)
        assert not ok and why == "cannot_skip_ladder_rungs"

    def test_no_evidence_abstains(self):
        att, lead = self._ledger_with_lead()
        ok, why = att.promote(lead.lead_id, "CLAIMED_IDENTITY",
                              signals=("statement",), evidence_ids=(), reviewer="a")
        assert not ok and why.startswith("abstain")

    def test_corroboration_requires_two_independent_sources(self):
        att, lead = self._ledger_with_lead()
        att.promote(lead.lead_id, "CLAIMED_IDENTITY", signals=("subject_claim",),
                    evidence_ids=("ev-2",), reviewer="a")
        att.promote(lead.lead_id, "CANDIDATE_ASSOCIATION", signals=("registry_match",),
                    evidence_ids=("ev-3",), reviewer="a")
        ok, why = att.promote(lead.lead_id, "CORROBORATED_ATTRIBUTION",
                              signals=("payment_ref_match",), evidence_ids=("ev-4",),
                              reviewer="a", independent_source_count=1)
        assert not ok and "2_independent" in why
        ok2, _ = att.promote(lead.lead_id, "CORROBORATED_ATTRIBUTION",
                             signals=("payment_ref_match",), evidence_ids=("ev-4",),
                             reviewer="a", independent_source_count=2)
        assert ok2

    def test_mixed_signals_allowed_but_limitation_recorded(self):
        att, lead = self._ledger_with_lead()
        ok, _ = att.promote(lead.lead_id, "CLAIMED_IDENTITY",
                            signals=("subject_claim", "shared_hosting"),
                            evidence_ids=("ev-9",), reviewer="a")
        assert ok
        cur = [l for l in att.leads if l.lead_id == lead.lead_id][0]
        assert any("non-discriminating" in lim for lim in cur.limitations)

    def test_identical_identifier_merges_evidence(self):
        att = AttributionLedger("c1")
        l1 = att.observe("wallet", "0xABCDEF", "ev-a")
        l2 = att.observe("wallet", "0xabcdef ", "ev-b")
        assert l1.lead_id == l2.lead_id and set(l2.evidence_ids) == {"ev-a", "ev-b"}


# -------------------------------------------------------------------- crypto
BTC1 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
ETH1 = "0x" + "a" * 40
TXH = "0x" + "b" * 64


class TestCrypto:
    def test_validation_shapes(self):
        assert validate_address("bitcoin", BTC1)[0]
        assert not validate_address("bitcoin", "not-an-address")[0]
        assert validate_address("ethereum", ETH1)[0]
        assert validate_tx_hash(TXH)[0]
        assert not validate_tx_hash("zzz")[0]
        assert not validate_address("monero", "anything")[0]  # unsupported chain disclosed

    def test_custodial_boundary_stops_trace_without_fabrication(self):
        calls = {"n": 0}
        def fetcher(chain, key):
            calls["n"] += 1
            if key == ETH1:
                return {"neighbors": ["0x" + "c" * 40]}
            if key == "0x" + "c" * 40:
                return {"neighbors": ["0x" + "d" * 40]}
            return {"neighbors": []}
        tracer = CryptoTracer("c1", fetcher=fetcher, max_depth=5)
        exchange = "0x" + "d" * 40
        res = tracer.trace_from("ethereum", ETH1, custodial_labels={exchange: "ProviderX"})
        assert exchange in res["stopped_at"]
        assert exchange not in res["visited"]
        assert len(tracer.boundaries) == 1
        assert tracer.boundaries[0].status == "CLAIM_REQUIRING_REVIEW"
        # nothing beyond boundary visited
        assert all(v != exchange for v in res["visited"])

    def test_call_budget_enforced(self):
        def fetcher(chain, key):
            return {"neighbors": ["0x" + str(i) * 0 + format(hash(key) & 0xFFFFFFFFFF, '040x')]}
        tracer = CryptoTracer("c1", fetcher=lambda c, k: {"neighbors": []}, max_calls=2)
        a = "0x" + "1" * 40
        r = tracer.trace_from("ethereum", a)
        assert tracer.calls_used <= 2

    def test_invalid_address_no_trace_attempted(self):
        tracer = CryptoTracer("c1", fetcher=lambda c, k: {"neighbors": []})
        res = tracer.trace_from("ethereum", "garbage")
        assert res["abstained"] == ["invalid_address_no_trace_attempted"]
        assert res["visited"] == []

    def test_missing_record_list_mentions_no_recovery_guarantee(self):
        tracer = CryptoTracer("c1")
        items = tracer.missing_record_list()
        assert any("does not guarantee" in i for i in items)
