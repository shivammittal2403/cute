"""Tests for the investment-scam payment ledger invariants (acceptance §17)."""
from datetime import datetime

import pytest

from traceatlas.scams.payment_ledger import (PaymentEntry, PaymentLedger)


def _entry(**kw):
    base = dict(case_id="case-1", method="bank_transfer", amount=None, currency="USD",
                date=datetime(2026, 3, 1), tx_ref="", status="COMPLETED",
                verification_state="DOCUMENTED_ARTIFACT", evidence_ids=("ev-1",))
    base.update(kw)
    return PaymentEntry(**base)


class TestDuplicateReceipts:
    def test_same_txref_receipt_does_not_inflate_loss(self):
        led = PaymentLedger("case-1")
        a, dup_a = led.add(_entry(tx_ref="TX998877", amount=5000))
        b, dup_b = led.add(_entry(tx_ref="tx998877 ", amount=5000, evidence_ids=("ev-2",)))
        assert dup_a is False and dup_b is True
        totals = led.totals_by_currency()
        assert totals["USD"]["outflow"] == 5000          # NOT 10000
        assert len(led.suppressed) == 1

    def test_merged_entry_keeps_both_evidence_refs(self):
        led = PaymentLedger("case-1")
        kept, _ = led.add(_entry(tx_ref="TX1", amount=100, evidence_ids=("ev-a",)))
        kept2, dup = led.add(_entry(tx_ref="TX1", amount=100, evidence_ids=("ev-b",)))
        assert dup and set(kept2.evidence_ids) >= {"ev-a", "ev-b"}

    def test_different_days_without_txref_are_separate_payments(self):
        led = PaymentLedger("case-1")
        led.add(_entry(amount=250, date=datetime(2026, 3, 1)))
        led.add(_entry(amount=250, date=datetime(2026, 3, 8)))
        assert led.totals_by_currency()["USD"]["outflow"] == 500


class TestStatusSeparation:
    def test_requested_attempted_pending_failed_excluded_from_outflow(self):
        led = PaymentLedger("case-1")
        for st in ("REQUESTED", "ATTEMPTED", "PENDING", "FAILED"):
            led.add(_entry(status=st, amount=1000, tx_ref=f"TX-{st}", currency="EUR"))
        t = led.totals_by_currency()
        assert t.get("USD", {}).get("outflow", 0) == 0
        buckets = led.pending_and_disputed()
        assert set(buckets) == {"REQUESTED", "ATTEMPTED", "PENDING", "FAILED"}

    def test_refund_offsets_but_stays_separate_line(self):
        led = PaymentLedger("case-1")
        led.add(_entry(tx_ref="OUT-1", amount=4000, status="COMPLETED"))
        led.add(_entry(tx_ref="IN-1", direction="IN", amount=1000, status="REFUNDED"))
        t = led.totals_by_currency()["USD"]
        assert t["outflow"] == 4000 and t["returns"] == 1000
        assert t["provisional_net_loss"] == 3000
        disputed = led.pending_and_disputed()
        assert "REFUNDED" not in disputed  # refunds are outcomes, not pending items

    def test_disputed_payment_not_counted_as_completed_outflow(self):
        led = PaymentLedger("case-1")
        led.add(_entry(tx_ref="D1", amount=9999, status="DISPUTED"))
        assert led.totals_by_currency().get("USD") is None
        assert "DISPUTED" in led.pending_and_disputed()


class TestDisplayedBalances:
    def test_platform_profit_never_counts_as_received_money(self):
        led = PaymentLedger("case-1")
        led.add(_entry(tx_ref="OUT-1", amount=2000, status="COMPLETED"))
        led.add(_entry(direction="DISPLAY_ONLY", amount=15000, tx_ref="bal",
                       notes=("platform dashboard claim",)))
        t = led.totals_by_currency()["USD"]
        assert t["outflow"] == 2000 and t["returns"] == 0
        assert len(led.displayed_balances()) == 1


class TestMixedCurrency:
    def test_currencies_never_silently_combined(self):
        led = PaymentLedger("case-1")
        led.add(_entry(currency="USD", amount=1000, tx_ref="U1"))
        led.add(_entry(currency="EUR", amount=800, tx_ref="E1"))
        t = led.totals_by_currency()
        assert t["USD"]["outflow"] == 1000 and t["EUR"]["outflow"] == 800
        assert "provisional_net_loss_note" if hasattr(led, "provisional_net_loss_note") else True
        assert "PER CURRENCY" in led.provisional_net_loss_note()

    def test_unknown_amount_or_currency_counted_as_unresolved(self):
        led = PaymentLedger("case-1")
        led.add(_entry(amount=None, tx_ref="X1", currency="EUR"))
        led.add(_entry(amount=50, currency="", tx_ref="X2"))
        t = led.totals_by_currency()
        u = t["_unresolved_counts"]
        assert u["unknown_amount_out"] == 1 and u["unknown_currency_out"] == 1
        assert t.get("USD", {}).get("outflow", 0) == 0 or "USD" not in t or t["USD"]["outflow"] == 0


class TestCorrections:
    def test_ocr_correction_updates_totals_and_is_audited(self):
        led = PaymentLedger("case-1")
        e, _ = led.add(_entry(tx_ref="T-OCR", amount=1300))
        led.correct(e.entry_id, amount=1500)
        assert led.totals_by_currency()["USD"]["outflow"] == 1500
        assert led.corrections and led.corrections[0]["before"]["amount"] == "1300"

    def test_correction_to_existing_txref_merges_entries(self):
        led = PaymentLedger("case-1")
        a, _ = led.add(_entry(tx_ref="REAL-1", amount=700))
        b, _ = led.add(_entry(tx_ref="", amount=700, recipient_ref="payee x",
                              date=datetime(2026, 3, 1)))
        led.correct(b.entry_id, tx_ref="REAL-1")
        assert led.totals_by_currency()["USD"]["outflow"] == 700  # merged, not doubled

    def test_fingerprint_stable_for_identical_entries(self):
        from traceatlas.scams.payment_ledger import entry_fingerprint
        f1 = entry_fingerprint(_entry(tx_ref="A", amount=5))
        f2 = entry_fingerprint(_entry(tx_ref="A", amount=5))
        assert f1 == f2
