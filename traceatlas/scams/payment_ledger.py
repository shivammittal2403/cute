"""traceatlas.scams.payment_ledger — deterministic money tracking (requirement §6/§9).

Invariants enforced in code (each covered by tests/scams/test_payment_ledger.py):
  * duplicate receipts for one transaction reference collapse to ONE entry
    (loss is never inflated by re-submitting the same receipt);
  * REQUESTED / ATTEMPTED / PENDING / FAILED payments are NOT outflow;
  * REFUNDED and RETURNED amounts offset outflow but stay separate line items;
  * platform-displayed balances are tracked separately and NEVER counted as
    money received or recoverable;
  * per-currency totals only — mixed currencies are never silently combined;
  * every amount carries a verification state derived from its evidence, not a
    model's confidence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id

PAYMENT_STATUSES = ("REQUESTED", "ATTEMPTED", "PENDING", "COMPLETED",
                    "FAILED", "REFUNDED", "DISPUTED")

# Statuses that document actual money leaving the victim.
PROVISIONAL_OUTFLOW_STATUSES = ("COMPLETED",)
# Statuses that document money coming back.
RETURN_STATUSES = ("REFUNDED",)


@dataclass(slots=True)
class PaymentEntry:
    entry_id: ID = field(default_factory=lambda: new_id("pay"))
    case_id: ID = ""
    direction: str = "OUT"                # OUT | IN | DISPLAY_ONLY
    method: str = ""                      # bank_transfer|card|payment_app|crypto|cash|unknown
    amount: Optional[Decimal] = None      # None => unknown amount (never guessed)
    currency: str = ""                    # ISO code or ticker; "" => unknown
    date: Optional[datetime] = None
    date_precision: str = "DAY"           # DAY | MONTH_APPROX | UNKNOWN
    original_timezone: str = ""           # preserved exactly as submitted
    sender_ref: str = ""                  # redactable label, not identity claim
    recipient_ref: str = ""
    tx_ref: str = ""                      # bank/chain reference if present
    status: str = "PENDING"               # PAYMENT_STATUSES
    verification_state: str = "UNSUPPORTED_STATEMENT"  # see VERIFICATION_STATES
    evidence_ids: tuple[ID, ...] = ()     # exact artifacts supporting THIS entry
    notes: tuple[str, ...] = ()

    def dedup_key(self) -> tuple:
        """Canonical identity of the underlying transaction.

        Two receipts citing the same tx reference (case-insensitive, stripped)
        are the SAME transaction. Without a tx ref we fall back to
        (direction, amount, currency, date-day, recipient_ref) — conservative:
        different days are different payments.
        """
        if self.tx_ref:
            return ("txref", self.tx_ref.strip().lower())
        day = self.date.strftime("%Y-%m-%d") if self.date else ""
        amt = str(self.amount) if self.amount is not None else ""
        return ("fields", self.direction, amt, self.currency.upper(), day,
                self.recipient_ref.strip().lower(), self.method.lower())


VERIFICATION_STATES = (
    "UNSUPPORTED_STATEMENT",   # only claimed (e.g., chat message) — not documented
    "DOCUMENTED_ARTIFACT",     # a receipt/statement excerpt supports it
    "CORROBORATED",            # >=2 independent authorized records agree
    "DISPUTED",                # records conflict
)

# Strength ordering used for dedup precedence (documented beats statement).
_STATE_RANK = {"UNSUPPORTED_STATEMENT": 0, "DISPUTED": 1,
               "DOCUMENTED_ARTIFACT": 2, "CORROBORATED": 3}

# Status strength for merges: COMPLETED outcome outranks REQUESTED/PENDING etc.
_STATUS_RANK = {"FAILED": 0, "REQUESTED": 1, "ATTEMPTED": 2, "PENDING": 3,
                "DISPUTED": 4, "REFUNDED": 5, "COMPLETED": 6}


def _stronger_status(a: str, b: str) -> str:
    return a if _STATUS_RANK.get(a, -1) >= _STATUS_RANK.get(b, -1) else b


class PaymentLedger:
    """Case-scoped, deterministic ledger with dedup and per-currency math."""

    def __init__(self, case_id: ID):
        self.case_id = case_id
        self._entries: dict[ID, PaymentEntry] = {}
        self._by_dedup: dict[tuple, ID] = {}
        self.suppressed: list[tuple[ID, ID]] = []  # (new_entry_id, kept_entry_id)
        self.corrections: list[dict] = []          # audit trail of edits

    # ------------------------------------------------------------- ingestion
    def add(self, entry: PaymentEntry) -> tuple[PaymentEntry, bool]:
        """Add an entry. Returns (kept_entry, was_duplicate).

        Duplicate receipts do NOT create a second amount; evidence ids merge
        onto the kept entry so provenance is preserved, and the suppressed
        entry id is recorded for transparency.

        Dedup precedence rule: when two records collide on a transaction key,
        the canonical line keeps the STRONGER verification state (a documented
        artifact outranks a bare statement) and the higher confidence field —
        amounts are never silently replaced by weaker claims.
        """
        key = entry.dedup_key()
        if key in self._by_dedup:
            kept_id = self._by_dedup[key]
            kept = self._entries[kept_id]
            loser = next((e for e in (kept, entry) if e.entry_id != kept_id), entry)
            merged_evidence = tuple(sorted(set(kept.evidence_ids) | set(entry.evidence_ids)))
            stronger_rank = max(_STATE_RANK.get(kept.verification_state, 0),
                                _STATE_RANK.get(entry.verification_state, 0))
            # keep non-None amount from the stronger-state source where possible
            strong_amt_src = (entry if _STATE_RANK.get(entry.verification_state, 0) >=
                              _STATE_RANK.get(kept.verification_state, 0) else kept)
            amount = strong_amt_src.amount if strong_amt_src.amount is not None else (
                kept.amount if entry is strong_amt_src else entry.amount)
            notes_extra = f"duplicate receipt {loser.entry_id} merged"
            updated = field_update(kept,
                                   evidence_ids=merged_evidence,
                                   verification_state=max(
                                       (kept.verification_state, entry.verification_state),
                                       key=lambda s: _STATE_RANK.get(s, 0)),
                                   amount=amount,
                                   status=_stronger_status(kept.status, entry.status),
                                   tx_ref=kept.tx_ref or entry.tx_ref,
                                   date=kept.date or entry.date,
                                   recipient_ref=kept.recipient_ref or entry.recipient_ref,
                                   notes=kept.notes + (notes_extra,))
            self._entries[kept_id] = updated
            self.suppressed.append((loser.entry_id, kept_id))
            return updated, True
        self._entries[entry.entry_id] = entry
        self._by_dedup[key] = entry.entry_id
        return entry, False

    def correct(self, entry_id: ID, **changes: Any) -> PaymentEntry:
        """Human/parser correction of OCR'd amounts, dates, references.

        Corrections rebuild the dedup index and are audited. If a corrected tx
        ref collides with an existing entry, the entries merge (dedup applies
        after correction too).
        """
        old = self._entries.get(entry_id)
        if old is None:
            raise KeyError(entry_id)
        new = field_update(old, **changes)
        del self._entries[entry_id]
        # remove stale dedup mapping for the old key
        old_key = old.dedup_key()
        if self._by_dedup.get(old_key) == entry_id:
            del self._by_dedup[old_key]
        self.corrections.append({"entry_id": entry_id, "changed": sorted(changes),
                                 "before": _safe_snapshot(old)})
        key = new.dedup_key()
        if key in self._by_dedup:
            kept, dup = self.add(new)
            self.corrections[-1]["merged_into"] = kept.entry_id
            return kept
        self._entries[entry_id] = new
        self._by_dedup[key] = entry_id
        return new

    # ---------------------------------------------------------------- views
    @property
    def entries(self) -> list[PaymentEntry]:
        return list(self._entries.values())

    def displayed_balances(self) -> list[PaymentEntry]:
        """Platform-claimed profit/balance entries — explicitly quarantined
        from all loss math (requirement: displayed != received)."""
        return [e for e in self.entries if e.direction == "DISPLAY_ONLY"]

    # ------------------------------------------------------------ accounting
    def totals_by_currency(self) -> dict[str, dict[str, Decimal]]:
        """Per-currency outflow/returns/provisional net loss. Unknown amounts
        or currencies are COUNTED SEPARATELY as unresolved lines, never folded
        into a numeric total."""
        totals: dict[str, dict[str, Any]] = {}
        unresolved = {"unknown_amount_out": 0, "unknown_currency_out": 0,
                      "unknown_amount_in": 0, "unknown_currency_in": 0}
        for e in self.entries:
            cur = (e.currency or "").upper()
            if e.direction == "OUT":
                if e.status in PROVISIONAL_OUTFLOW_STATUSES:
                    if e.amount is None:
                        unresolved["unknown_amount_out"] += 1
                        continue
                    if not cur:
                        unresolved["unknown_currency_out"] += 1
                        continue
                    t = totals.setdefault(cur, {"outflow": Decimal(0), "returns": Decimal(0)})
                    t["outflow"] += e.amount
            elif e.direction == "IN":
                if e.status in RETURN_STATUSES:
                    if e.amount is None:
                        unresolved["unknown_amount_in"] += 1
                        continue
                    if not cur:
                        unresolved["unknown_currency_in"] += 1
                        continue
                    t = totals.setdefault(cur, {"outflow": Decimal(0), "returns": Decimal(0)})
                    t["returns"] += e.amount
            # DISPLAY_ONLY intentionally ignored entirely
        result: dict[str, dict[str, Decimal]] = {}
        for cur, t in totals.items():
            result[cur] = {"outflow": t["outflow"], "returns": t["returns"],
                           "provisional_net_loss": t["outflow"] - t["returns"]}
        result["_unresolved_counts"] = {k: Decimal(v) for k, v in unresolved.items()}
        return result

    def provisional_net_loss_note(self) -> str:
        """Mandatory disclosure accompanying any cross-currency summary."""
        return ("Provisional net loss is computed PER CURRENCY. No exchange-rate "
                "conversion is applied. If conversion is requested, the rate source, "
                "rate date and assumptions must be disclosed alongside the figure.")

    def pending_and_disputed(self) -> dict[str, list[PaymentEntry]]:
        buckets: dict[str, list[PaymentEntry]] = {}
        for e in self.entries:
            if e.status in ("PENDING", "DISPUTED", "ATTEMPTED", "REQUESTED", "FAILED"):
                buckets.setdefault(e.status, []).append(e)
        return buckets

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id,
                "entries": [_entry_dict(e) for e in self.entries],
                "suppressed_duplicates": [[a, b] for a, b in self.suppressed],
                "corrections": self.corrections}


def field_update(obj, **changes):
    """dataclasses.replace that tolerates Decimal/datetime values."""
    from dataclasses import replace
    return replace(obj, **changes)


def _safe_snapshot(e: PaymentEntry) -> dict:
    d = _entry_dict(e)
    for k in ("amount", "date"):
        v = d.get(k)
        d[k] = str(v) if v is not None else None
    return d


def _entry_dict(e: PaymentEntry) -> dict[str, Any]:
    return {"entry_id": e.entry_id, "case_id": e.case_id, "direction": e.direction,
            "method": e.method, "amount": e.amount, "currency": e.currency,
            "date": e.date.isoformat() if e.date else None,
            "date_precision": e.date_precision, "original_timezone": e.original_timezone,
            "sender_ref": e.sender_ref, "recipient_ref": e.recipient_ref,
            "tx_ref": e.tx_ref, "status": e.status,
            "verification_state": e.verification_state,
            "evidence_ids": list(e.evidence_ids), "notes": list(e.notes)}


def entry_fingerprint(e: PaymentEntry) -> str:
    """Stable content hash for cache/idempotency keys.

    Excludes per-instance ids/notes so two receipts describing the SAME
    transaction produce the same fingerprint (idempotent re-ingest)."""
    payload = {k: v for k, v in _entry_dict(e).items()
               if k not in ("entry_id", "evidence_ids", "notes")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
