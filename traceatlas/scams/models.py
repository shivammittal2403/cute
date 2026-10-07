"""traceatlas.scams.models — domain models for scam case contracts and intake.

Epistemic separation is structural: `VictimStatement` items are CLAIMS supplied
by the submitter; they only become findings through verification elsewhere.
Intake validation refuses routine secrets (passwords, OTPs, seed phrases) per
case-contract policy — presence of such fields is flagged, never stored verbatim.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.core.provenance import utcnow

# --------------------------------------------------------------------------
# Case contract (requirement §4)
# --------------------------------------------------------------------------

@dataclass(slots=True)
class CaseContract:
    """What the user authorized. Stored with the case; checked before collection."""
    contract_id: ID = field(default_factory=lambda: new_id("contract"))
    case_id: ID = ""
    owner: str = ""                       # accountable human
    submitter: str = ""                   # who provided evidence
    submitter_authority: str = ""         # basis: victim / investigator / custodian
    objective: str = ""
    questions: tuple[str, ...] = ()
    target_identifiers: tuple[str, ...] = ()
    jurisdiction: str = ""
    authorized_collection: tuple[str, ...] = ()   # e.g. ("dns","rdap","crtsh","wayback")
    restrictions: tuple[str, ...] = ()            # e.g. ("no_subject_contact",)
    deliverables: tuple[str, ...] = ("dossier",)
    completion_criteria: str = ""
    time_budget_hours: float = 0.0
    cost_budget_usd: float = 0.0
    sensitivity: str = "CONFIDENTIAL"     # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
    access_policy: tuple[str, ...] = ()   # allowed principals
    status: str = "ACTIVE"
    stop_reason: str = ""

    def allows(self, source_kind: str) -> bool:
        return source_kind in self.authorized_collection

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


# --------------------------------------------------------------------------
# Evidence intake record (requirement §5)
# --------------------------------------------------------------------------

@dataclass(slots=True)
class IntakeRecord:
    """Metadata wrapper preserved alongside every submitted artifact.

    The original bytes live in the content-addressed EvidenceStore; this record
    links to them and captures submission context + extraction uncertainty.
    """
    intake_id: ID = field(default_factory=lambda: new_id("intake"))
    case_id: ID = ""
    evidence_id: ID = ""                  # reference into EvidenceStore
    sha256: str = ""                      # integrity of the ORIGINAL artifact
    source: str = ""                      # where it came from (not a claim about truth)
    submitter: str = ""
    collected_at: datetime = field(default_factory=utcnow)
    media_type: str = ""
    format_kind: str = ""                 # chat_export|email|image|pdf|csv|receipt|json|audio|video|api_response
    locator_hint: str = ""                # page/message/time-range guidance for exact location
    parser_version: str = "intake-1.0"
    extraction_uncertainty: str = "NOT_RUN"   # NOT_RUN | CLEAN | PARTIAL | LOW
    correction_count: int = 0
    access_policy: str = "CASE_MEMBERS"
    retention: str = "CASE_LIFECYCLE"
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = {}
        for k in self.__dataclass_fields__:
            v = getattr(self, k)
            d[k] = v.isoformat() if isinstance(v, datetime) else v
        return d


# Fields that must never be routine intake inputs (requirement §4).
_SECRET_FIELD_PATTERNS = (
    re.compile(r"password|passphrase", re.I),
    re.compile(r"\bOTP\b|one[- ]time[- ]code|verification code", re.I),
    re.compile(r"seed phrase|private key|recovery phrase|mnemonic", re.I),
    re.compile(r"session[ _-]?cookie|api[ _-]?key", re.I),
    re.compile(r"\bCVV\b|\bCVC\b", re.I),
)


def scan_intake_for_secrets(text: str) -> tuple[str, ...]:
    """Return secret-like strings DETECTED in submitted text.

    Policy: flag & prompt redaction — do not store raw secrets. Detection here
    is deterministic regex over intake material, not credential use.
    """
    hits = []
    for pat in _SECRET_FIELD_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0))
    return tuple(hits)


# --------------------------------------------------------------------------
# Victim statements (requirement §3/§12): claims, not findings
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class VictimStatement:
    """One attributed assertion by the submitter. Explicitly epistemic class CLAIM."""
    statement_id: ID = field(default_factory=lambda: new_id("stmt"))
    case_id: ID = ""
    speaker: str = ""                     # "victim" / role label — personhood minimized
    text: str = ""
    event_time: Optional[datetime] = None      # when the described thing happened
    reported_at: Optional[datetime] = None     # when told to us
    evidence_id: Optional[ID] = None           # artifact where the statement lives
    independent_support: str = "NONE"          # NONE | PARTIAL | SUPPORTED (set by review)

    @property
    def epistemic_class(self) -> str:
        return "CLAIM"  # never OBSERVATION/VERIFIED_FINDING by construction
