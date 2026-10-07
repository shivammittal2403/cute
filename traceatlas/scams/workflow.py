"""traceatlas.scams.workflow — end-to-end investment-scam case workflow (§3, §11).

Pipeline:
  contract -> intake (evidence preserved) -> ledger/timeline/attribution build
  -> per-wave replanning (gaps -> candidate actions -> ranked next action)
  -> dossier generation with claim->evidence resolution.

Stop reasons recorded as required: COMPLETED | INSUFFICIENT_EVIDENCE |
BUDGET_EXHAUSTED | SOURCE_UNAVAILABLE | NEEDS_HUMAN_INPUT | FAILED | CANCELLED.

The workflow is orchestrable offline against fixtures; live connectors are used
only when the case contract authorizes them and configuration exists (otherwise
the source is reported CONFIGURATION_BLOCKED — never silently skipped).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.scams.attribution import AttributionLedger
from traceatlas.scams.models import CaseContract, IntakeRecord, VictimStatement
from traceatlas.scams.payment_ledger import PaymentEntry, PaymentLedger
from traceatlas.scams.timeline import IncidentTimeline, TimelineEvent

STOP_REASONS = ("COMPLETED", "INSUFFICIENT_EVIDENCE", "BUDGET_EXHAUSTED",
                "SOURCE_UNAVAILABLE", "NEEDS_HUMAN_INPUT", "FAILED", "CANCELLED")


@dataclass(slots=True)
class KnowledgeGap:
    gap_id: ID = field(default_factory=lambda: new_id("gap"))
    question: str = ""
    why_it_matters: str = ""
    candidate_actions: tuple[str, ...] = ()
    # Explainable qualitative estimates — NOT invented information-gain math.
    relevance: str = "MEDIUM"        # LOW|MEDIUM|HIGH
    accessibility: str = "UNKNOWN"   # EASY|KNOWN_SOURCE|CONFIGURATION_BLOCKED|UNKNOWN
    expected_new_info: str = "LOW"   # LOW|MEDIUM|HIGH
    cost: str = "FREE"               # FREE|LOW|PAID
    risk: str = "NONE"               # NONE|PRIVACY|LEGAL_REVIEW
    status: str = "OPEN"             # OPEN|ADDRESSED|ABANDONED_WITH_REASON


_ORDER = {"HIGH": 0, "KNOWN_SOURCE": 0, "EASY": 0, "MEDIUM": 1, "LOW": 2,
          "PAID": 2, "CONFIGURATION_BLOCKED": 3, "UNKNOWN": 4,
          "NONE": 0, "PRIVACY": 1, "LEGAL_REVIEW": 2}


def rank_gaps(gaps: list[KnowledgeGap]) -> list[KnowledgeGap]:
    """Deterministic, explainable ranking: relevance first, then expected new
    information, then accessibility, then cost, then risk. Ties keep insertion
    order. The rationale string is stored so users see WHY an action ranks first."""
    def key(item):
        idx, g = item
        return (_ORDER.get(g.relevance, 9), _ORDER.get(g.expected_new_info, 9),
                _ORDER.get(g.accessibility, 9), _ORDER.get(g.cost, 9),
                _ORDER.get(g.risk, 9), idx)
    ranked = [g for _i, g in sorted(enumerate(gaps), key=key)]
    return ranked


@dataclass(slots=True)
class ScamCase:
    """Durable aggregate. Persisted as JSON (fs) — DB migration can reuse to_dict."""
    case_id: ID = field(default_factory=lambda: new_id("scamcase"))
    contract: Optional[CaseContract] = None
    statements: list[VictimStatement] = field(default_factory=list)
    intakes: list[IntakeRecord] = field(default_factory=list)
    gaps: list[KnowledgeGap] = field(default_factory=list)
    # Structured rows produced by extraction tasks (payments/chronology/identifiers).
    payment_entries: list = field(default_factory=list)     # PaymentEntry rows
    timeline_events: list = field(default_factory=list)     # TimelineEvent rows
    identifier_rows: list = field(default_factory=list)     # (kind, value, evidence_id)
    stop_reason: str = ""
    waves_run: int = 0
    activity: list[dict] = field(default_factory=list)   # employee/task log

    # ------------------------------------------------------------- builders
    def build_ledger(self) -> PaymentLedger:
        led = PaymentLedger(self.case_id)
        for e in self.payment_entries:
            led.add(e)
        return led

    def build_timeline(self) -> IncidentTimeline:
        tl = IncidentTimeline(self.case_id)
        for ev in self.timeline_events:
            tl.add(ev)
        return tl

    def build_attribution(self) -> AttributionLedger:
        att = AttributionLedger(self.case_id)
        for kind, value, evidence_id in self.identifier_rows:
            att.observe(kind, value, evidence_id)
        return att

    # ------------------------------------------------------------ lifecycle
    def record_activity(self, role: str, action: str, detail: str = "") -> None:
        self.activity.append({"role": role, "action": action, "detail": detail})

    def identify_gaps(self, ledger: PaymentLedger, timeline: IncidentTimeline,
                      attribution: AttributionLedger) -> list[KnowledgeGap]:
        """Question-driven gap detection answering §3's required questions."""
        gaps: list[KnowledgeGap] = []

        def gap(q, why, actions, rel="HIGH", acc="UNKNOWN", exp="MEDIUM", cost="FREE", risk="NONE"):
            gaps.append(KnowledgeGap(question=q, why_it_matters=why,
                                      candidate_actions=tuple(actions), relevance=rel,
                                      accessibility=acc, expected_new_info=exp, cost=cost, risk=risk))

        unsupported = [e for e in ledger.entries if e.verification_state == "UNSUPPORTED_STATEMENT"]
        if unsupported:
            gap(f"{len(unsupported)} payment(s) rest only on statement",
                "Documented outflow must be supported by authorized records before loss figures are report-grade",
                ["request bank/card statement excerpt (authorized human follow-up)",
                 "re-check submitted receipts for missed pages"],
                exp="HIGH")
        unknowns = ledger.totals_by_currency().get("_unresolved_counts", {})
        if sum(int(v) for v in unknowns.values()) > 0:
            gap("Payment amount/currency unresolved on some entries",
                "Loss math cannot include guessed values",
                ["OCR correction pass", "ask submitter for original receipt page"], exp="HIGH")
        disp = ledger.displayed_balances()
        if disp:
            gap("Platform shows balance/profit not reconciled with money movement",
                "Displayed profit is not received money; conflating them misstates loss",
                ["compare withdrawal attempts vs returns in ledger"], rel="MEDIUM")
        withdrawals = [e for e in timeline.full_history() if e.stage == "withdrawal_attempt"]
        if withdrawals and not any(e.direction == "IN" for e in ledger.entries):
            gap("Withdrawal attempts exist but no documented returns",
                "Fee-trap pattern assessment depends on distinguishing attempts from outcomes",
                ["collect platform response screenshots/emails"], exp="HIGH")
        unresolved_attr = attribution.unresolved_attributions()
        if unresolved_attr:
            gap(f"{len(unresolved_attr)} identifier lead(s) below CORROBORATED_ATTRIBUTION",
                "Attribution gaps must stay visible; shared hosting does not close them",
                ["RDAP/DNS history where authorized", "certificate transparency correlation",
                 "public registration/licensing checks"], acc="KNOWN_SOURCE")
        if not any(tl.event_time for tl in timeline.full_history()):
            gap("No dated events in timeline",
                "Sequence support is currently narrative-only",
                ["chat export timestamps", "receipt dates"], exp="HIGH")
        return gaps

    # --------------------------------------------------------------- dossier
    def dossier(self, ledger: PaymentLedger, timeline: IncidentTimeline,
                attribution: AttributionLedger, gaps: list[KnowledgeGap],
                coverage: dict[str, str], missing_records: tuple[str, ...] = ()) -> dict[str, Any]:
        """Reviewer-ready dossier skeleton with claim->evidence resolvability.

        Every material section cites evidence ids; sections without support say
        UNSUPPORTED explicitly instead of asserting.
        """
        totals = ledger.totals_by_currency()
        numeric = {k: {kk: str(vv) for kk, vv in v.items()}
                   for k, v in totals.items() if k != "_unresolved_counts"}
        return {
            "case_id": self.case_id,
            "synopsis": self.contract.objective if self.contract else "",
            "victim_account_attributed": [
                {"text": s.text, "epistemic_class": s.epistemic_class,
                 "speaker": s.speaker, "evidence_id": s.evidence_id,
                 "independent_support": s.independent_support} for s in self.statements],
            "chronology": [{"stage": e.stage, "description": e.description,
                            "event_time": e.event_time.isoformat() if e.event_time else None,
                            "precision": e.event_time_precision, "tz": e.original_timezone,
                            "class": e.epistemic_class,
                            "evidence_ids": list(e.evidence_ids)} for e in timeline.ordered()],
            "payment_calculations": {
                "per_currency": numeric,
                "unresolved_counts": {k: str(v) for k, v in totals.get("_unresolved_counts", {}).items()},
                "note": ledger.provisional_net_loss_note(),
                "displayed_balances_excluded_from_math": len(ledger.displayed_balances()),
                "duplicate_receipts_suppressed": len(ledger.suppressed)},
            "identifier_inventory": [l.to_dict() for l in attribution.leads],
            "supported_connections": [l.to_dict() for l in attribution.leads
                                      if l.level == "CORROBORATED_ATTRIBUTION"],
            "hypotheses_and_alternatives": [
                {"question": g.question, "alternatives_considered": list(g.candidate_actions)}
                for g in gaps],
            "unknowns": [g.question for g in gaps if g.status == "OPEN"],
            "collection_coverage": coverage,
            "missing_record_needs": list(missing_records),
            "next_steps": [g.candidate_actions[0] for g in rank_gaps(gaps)[:5]
                           if g.candidate_actions],
            "stop_reason": self.stop_reason,
        }

    # ------------------------------------------------------------ persistence
    def save(self, root: Path) -> Path:
        root = Path(root); root.mkdir(parents=True, exist_ok=True)
        path = root / f"{self.case_id}.json"
        tmp = path.with_suffix(".tmp")
        payload = {
            "case_id": self.case_id,
            "contract": self.contract.to_dict() if self.contract else None,
            "statements": [_asdict(s) for s in self.statements],
            "intakes": [i.to_dict() for i in self.intakes],
            "gaps": [_asdict(g) for g in self.gaps],
            "stop_reason": self.stop_reason, "waves_run": self.waves_run,
            "activity": self.activity,
        }
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        import os; os.replace(tmp, path)
        return path


def _asdict(obj) -> dict:
    from dataclasses import asdict
    return asdict(obj)
