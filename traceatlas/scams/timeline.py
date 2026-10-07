"""traceatlas.scams.timeline — incident chronology (requirement §6).

Scam-stage vocabulary: initial_contact, promise, onboarding, payment_instruction,
transfer_supported, claimed_profit, withdrawal_attempt, additional_fee, refund,
subsequent_contact.

Temporal model per requirement §12: every event keeps
  event_time (when it happened), observed_at (artifact date), retrieved_at,
  recorded_at — plus timezone preservation and precision flags. Contradictory
  dates are PRESERVED as separate observations with a contradiction marker;
  the timeline never silently overwrites one account with another.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.core.provenance import utcnow

SCAM_STAGES = (
    "initial_contact", "promise", "onboarding", "payment_instruction",
    "transfer_supported", "claimed_profit", "withdrawal_attempt",
    "additional_fee", "refund", "subsequent_contact", "other",
)


@dataclass(slots=True)
class TimelineEvent:
    event_id: ID = field(default_factory=lambda: new_id("tev"))
    case_id: ID = ""
    stage: str = "other"                  # SCAM_STAGES
    description: str = ""                 # neutral phrasing of what the record shows
    epistemic_class: str = "CLAIM"        # CLAIM (victim statement) | OBSERVATION (artifact/record)
    event_time: Optional[datetime] = None
    event_time_precision: str = "DAY"     # DAY | MONTH_APPROX | YEAR_APPROX | UNKNOWN
    original_timezone: str = ""           # preserved verbatim ("IST", "+05:30", unknown)
    normalized_utc: Optional[datetime] = None
    observed_at: Optional[datetime] = None    # artifact's own timestamp context
    retrieved_at: datetime = field(default_factory=utcnow)
    recorded_at: datetime = field(default_factory=utcnow)
    evidence_ids: tuple[ID, ...] = ()
    source_label: str = ""                # submitter/chat export/provider — provenance, not truth
    contradicts: tuple[ID, ...] = ()      # event ids whose time/place conflicts with this one
    superseded_by: Optional[ID] = None    # set when a corrected event replaces this one
    notes: tuple[str, ...] = ()

    def sort_key(self) -> tuple:
        """Undated events sort AFTER dated ones (never dropped)."""
        return (self.event_time is None,
                self.normalized_utc or self.event_time or datetime.max.replace(tzinfo=None),
                self.recorded_at)


class IncidentTimeline:
    def __init__(self, case_id: ID):
        self.case_id = case_id
        self._events: dict[ID, TimelineEvent] = {}

    def add(self, ev: TimelineEvent) -> TimelineEvent:
        if ev.stage not in SCAM_STAGES:
            raise ValueError(f"unknown stage {ev.stage!r}; allowed: {SCAM_STAGES}")
        self._events[ev.event_id] = ev
        return ev

    def correct(self, event_id: ID, **changes) -> TimelineEvent:
        """Corrections SUPERSEDE rather than mutate history: old event stays
        (marked superseded) so the correction itself is auditable."""
        old = self._events.get(event_id)
        if old is None:
            raise KeyError(event_id)
        new = TimelineEvent(**{**{k: getattr(old, k) for k in old.__dataclass_fields__},
                               **changes})
        new.event_id = new_id("tev")
        new.recorded_at = utcnow()
        self._events[event_id] = _mark_superseded(old, new.event_id)
        self._events[new.event_id] = new
        return new

    def ordered(self) -> list[TimelineEvent]:
        return sorted((e for e in self._events.values() if e.superseded_by is None),
                      key=lambda e: e.sort_key())

    def full_history(self) -> list[TimelineEvent]:
        """Including superseded events — required for 'preserve why it changed'."""
        return sorted(self._events.values(), key=lambda e: e.sort_key())

    def contradictions(self) -> list[tuple[TimelineEvent, TimelineEvent]]:
        out = []
        for e in self._events.values():
            for other_id in e.contradicts:
                other = self._events.get(other_id)
                if other is not None and e.superseded_by is None and other.superseded_by is None:
                    pair = tuple(sorted((e.event_id, other.event_id)))
                    out.append((self._events[pair[0]], self._events[pair[1]]))
        # de-duplicate symmetric pairs
        seen, uniq = set(), []
        for a, b in out:
            k = (a.event_id, b.event_id)
            if k not in seen:
                seen.add(k)
                uniq.append((a, b))
        return uniq

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id,
                "events": [_ev_dict(e) for e in self.full_history()]}


def _mark_superseded(ev: TimelineEvent, by_id: ID) -> TimelineEvent:
    from dataclasses import replace
    return replace(ev, superseded_by=by_id,
                   notes=ev.notes + (f"superseded by {by_id}",))


def _ev_dict(e: TimelineEvent) -> dict[str, Any]:
    d = {}
    for k in e.__dataclass_fields__:
        v = getattr(e, k)
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        else:
            d[k] = list(v) if isinstance(v, tuple) else v
    return d
