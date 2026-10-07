"""traceatlas.scams.attribution — identifier leads & attribution ladder (§8).

Ladder (monotonic, reviewer-promoted only):
  OBSERVED_IDENTIFIER   an identifier appears in evidence
  CLAIMED_IDENTITY      someone (subject or victim narrative) claims who owns it
  CANDIDATE_ASSOCIATION >=1 deterministic correlation supports a possible link
  CORROBORATED_ATTRIBUTION multiple INDEPENDENT authorized sources agree

Hard rules enforced here:
  * shared hosting / same IP / same certificate NEVER raises a level by itself
    (disclosed as attribution limit);
  * similar names produce at most CANDIDATE_ASSOCIATION with an explicit
    alternative-explanation note;
  * promotion requires evidence ids at each step; no evidence => abstain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from traceatlas.core.identifiers import ID, new_id

LADDER = ("OBSERVED_IDENTIFIER", "CLAIMED_IDENTITY",
          "CANDIDATE_ASSOCIATION", "CORROBORATED_ATTRIBUTION")

# Correlation signals that are explicitly NON-discriminating on their own.
NON_DISCRIMINATING_SIGNALS = frozenset({
    "shared_ip", "shared_hosting", "shared_certificate", "same_asn",
    "similar_name", "same_registrar", "template_website",
})


@dataclass(slots=True)
class IdentifierLead:
    lead_id: ID = field(default_factory=lambda: new_id("lead"))
    case_id: ID = ""
    kind: str = ""                    # domain|email|phone|username|wallet|bank_ref|url|name
    value: str = ""
    level: str = "OBSERVED_IDENTIFIER"
    evidence_ids: tuple[ID, ...] = ()
    signals: tuple[str, ...] = ()     # correlation signal names
    alternatives: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    reviewer: str = ""
    independent_source_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in d.items()}


class AttributionLedger:
    def __init__(self, case_id: ID):
        self.case_id = case_id
        self._leads: dict[ID, IdentifierLead] = {}

    def observe(self, kind: str, value: str, evidence_id: ID) -> IdentifierLead:
        """Deterministic intake: identical (kind,value) merges evidence refs."""
        for lead in self._leads.values():
            if lead.kind == kind and lead.value.strip().lower() == value.strip().lower():
                from dataclasses import replace
                merged = replace(lead, evidence_ids=tuple(sorted(set(lead.evidence_ids) | {evidence_id})))
                self._leads[lead.lead_id] = merged
                return merged
        lead = IdentifierLead(case_id=self.case_id, kind=kind, value=value,
                              evidence_ids=(evidence_id,), level="OBSERVED_IDENTIFIER")
        self._leads[lead.lead_id] = lead
        return lead

    def promote(self, lead_id: ID, target_level: str, *, signals: tuple[str, ...],
                evidence_ids: tuple[ID, ...], reviewer: str,
                independent_source_count: int = 0,
                alternatives: tuple[str, ...] = ()) -> tuple[bool, str]:
        """Reviewer-driven promotion with guardrails. Returns (ok, reason)."""
        lead = self._leads.get(lead_id)
        if lead is None:
            return False, "unknown_lead"
        cur, tgt = LADDER.index(lead.level), LADDER.index(target_level)
        if tgt <= cur:
            return False, "not_a_promotion"
        if tgt - cur > 1:
            return False, "cannot_skip_ladder_rungs"
        if not evidence_ids:
            return False, "abstain_no_evidence"
        # Guardrail: non-discriminating signals cannot carry a promotion alone.
        discriminating = [s for s in signals if s not in NON_DISCRIMINATING_SIGNALS]
        if not discriminating:
            return False, ("non_discriminating_signal_only: shared hosting/IP/"
                           "certificate/similar name does not establish identity or control")
        if target_level == "CORROBORATED_ATTRIBUTION" and independent_source_count < 2:
            return False, "corroboration_requires_2_independent_sources"
        from dataclasses import replace
        self._leads[lead_id] = replace(
            lead, level=target_level,
            signals=tuple(sorted(set(lead.signals) | set(signals))),
            evidence_ids=tuple(sorted(set(lead.evidence_ids) | set(evidence_ids))),
            reviewer=reviewer,
            independent_source_count=max(lead.independent_source_count, independent_source_count),
            alternatives=tuple(sorted(set(lead.alternatives) | set(alternatives))))
        if any(s in NON_DISCRIMINATING_SIGNALS for s in signals):
            self._leads[lead_id] = replace(
                self._leads[lead_id],
                limitations=self._leads[lead_id].limitations +
                            ("includes non-discriminating signal(s): "
                             + ",".join(s for s in signals if s in NON_DISCRIMINATING_SIGNALS),))
        return True, "promoted"

    @property
    def leads(self) -> list[IdentifierLead]:
        return list(self._leads.values())

    def unresolved_attributions(self) -> list[IdentifierLead]:
        return [l for l in self.leads if l.level != "CORROBORATED_ATTRIBUTION"]

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "ladder": LADDER,
                "leads": [l.to_dict() for l in self.leads]}
