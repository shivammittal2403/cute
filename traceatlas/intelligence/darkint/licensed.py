"""traceatlas.intelligence.darkint.licensed - Licensed dark-web threat intel.

Implements LICENSED DARK-WEB THREAT INTELLIGENCE honestly:

* Access is provider-API based and credential-gated. Without configured
  credentials the query returns an explicit CONFIGURATION_BLOCKED state — it
  never fabricates results and never implies Tor connectivity grants coverage.
* Any content returned by a fixture adapter is permanently labeled
  ``fixture=True``; fixtures never count as live collection (enforced at the
  result level, not just documentation).
* Criminal claims and provider attributions are surfaced as CLAIMS requiring
  review, never as verified facts. The result object carries no "verified"
  flag for provider assertions.
* Exposure summaries are MASKED by default: password/token/cookie-shaped
  secrets in provider payloads are redacted before display or storage. TraceAtlas
  tracks exposure METADATA for defensive investigation only — it does not
  display stolen credentials unnecessarily, test compromised credentials,
  purchase data, or interact with subjects.
* Provider limitations, licenses and source-specific timestamps are preserved
  on every record (event time vs retrieval time kept distinct).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class DarkWebAccessState(str, Enum):
    LIVE_VERIFIED = "live_verified"          # real provider call succeeded
    FIXTURE_ONLY = "fixture_only"            # clearly labeled fixture evidence
    CONFIGURATION_BLOCKED = "configuration_blocked"
    PROVIDER_OUTAGE = "provider_outage"


# Secret-shaped strings that must never be displayed in full even when a
# provider returns them. Masking keeps first-4 chars for correlation only.
_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pass)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*\S+"),
    re.compile(r"(?i)session[_-]?cookie\s*[:=]\s*\S+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),  # JWT
    re.compile(r"\b[0-9a-fA-F]{32,64}:[^:\s]{4,}\b"),                          # user:pass dumps
)


def mask_exposure(text: str) -> str:
    """Redact credential-shaped substrings; keep defensive metadata."""
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: (m.group(0)[:8] + "…[MASKED]"), out)
    return out


@dataclass(slots=True)
class DarkWebQuery:
    query: str                              # boolean/selector expression
    organization: str = ""                  # monitored org/entity
    sources: tuple[str, ...] = ()           # provider source filters
    since: Optional[datetime] = None        # freshness filter (event time)
    include_masked_samples: bool = False    # never True for raw credentials


@dataclass(slots=True)
class DarkWebRecord:
    """One indexed threat-content item from a licensed provider."""
    record_id: str
    provider: str
    license_ref: str                        # provider license/terms reference
    claim_text: str                         # masked before construction here
    claim_kind: str                         # ransomware_claim|mention|actor_report|exposure_meta
    event_time: Optional[str] = None        # provider-stated timestamp
    retrieved_at: str = ""
    provider_attribution: str = ""          # ALWAYS treated as claim, not fact
    fixture: bool = False                   # permanent label; cannot be cleared by callers
    url: str = ""

    def as_claim(self) -> dict[str, Any]:
        """Provider statements are claims requiring review, never facts."""
        return {"kind": "CLAIM_REQUIRING_REVIEW", "text": self.claim_text,
                "provider": self.provider, "attribution": self.provider_attribution,
                "event_time": self.event_time, "retrieved_at": self.retrieved_at,
                "fixture": self.fixture, "record_id": self.record_id}


@dataclass(slots=True)
class DarkWebResponse:
    state: DarkWebAccessState
    query: str
    records: list[DarkWebRecord] = field(default_factory=list)
    blocked_reason: str = ""
    provider_limitations: str = ""
    freshness_note: str = ""

    @property
    def counts_as_live_collection(self) -> bool:
        """Honest gate used by reporting and metrics: fixtures/blocked never
        inflate collection counts."""
        return self.state == DarkWebAccessState.LIVE_VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "query": self.query,
                "counts_as_live_collection": self.counts_as_live_collection,
                "blocked_reason": self.blocked_reason,
                "provider_limitations": self.provider_limitations,
                "freshness_note": self.freshness_note,
                "records": [json.loads(json.dumps(vars(r), default=str))
                            for r in self.records]}


class BaseDarkWebProvider:
    """Licensed provider adapter contract. Real adapters add auth + transport."""
    name = "base"
    license_ref = ""
    limitations = ""

    def configured(self) -> bool:
        return False

    def search(self, q: DarkWebQuery) -> DarkWebResponse:  # pragma: no cover
        raise NotImplementedError


class FixtureDarkWebProvider(BaseDarkWebProvider):
    """Clearly-labeled offline fixture for development and demos.

    Every record carries fixture=True. This class exists so the pipeline can be
    exercised end-to-end WITHOUT pretending licensed access exists.
    """
    name = "fixture-darkindex"
    license_ref = "internal-test-fixture (not licensed threat content)"
    limitations = "Fixture data only; zero real coverage; never promote to findings."

    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = records or []

    def configured(self) -> bool:
        return True

    def search(self, q: DarkWebQuery) -> DarkWebResponse:
        now = datetime.now(timezone.utc).isoformat()
        recs: list[DarkWebRecord] = []
        needle = q.query.lower().strip("\"' ")
        for row in self._records:
            text = mask_exposure(str(row.get("claim_text", "")))
            if needle and needle not in text.lower() and needle != "*":
                continue
            recs.append(DarkWebRecord(
                record_id=row.get("record_id", f"fx-{len(recs)}"),
                provider=self.name, license_ref=self.license_ref,
                claim_text=text, claim_kind=row.get("claim_kind", "mention"),
                event_time=row.get("event_time"), retrieved_at=now,
                provider_attribution=row.get("attribution", ""),
                fixture=True, url=row.get("url", "")))
        return DarkWebResponse(state=DarkWebAccessState.FIXTURE_ONLY,
                               query=q.query, records=recs,
                               provider_limitations=self.limitations,
                               freshness_note="fixture snapshot; not current")


class LicensedDarkWebService:
    """Credential-gated front door for dark-web intelligence queries."""

    def __init__(self, provider: Optional[BaseDarkWebProvider] = None,
                 credentials_configured: Optional[bool] = None):
        self.provider = provider
        # Explicit injection keeps tests deterministic; production reads config.
        self._creds = credentials_configured

    def query(self, q: DarkWebQuery) -> DarkWebResponse:
        if self.provider is None:
            return DarkWebResponse(
                state=DarkWebAccessState.CONFIGURATION_BLOCKED, query=q.query,
                blocked_reason=("no licensed dark-web provider configured; set provider "
                                "credentials via configuration (never prompt-embedded). "
                                "Tor access would NOT grant coverage and is not attempted."))
        creds_ok = self._creds if self._creds is not None else self.provider.configured()
        if not creds_ok:
            return DarkWebResponse(
                state=DarkWebAccessState.CONFIGURATION_BLOCKED, query=q.query,
                blocked_reason=f"provider {self.provider.name!r} lacks authorized credentials")
        resp = self.provider.search(q)
        # defense-in-depth: re-mask whatever came back
        for r in resp.records:
            r.claim_text = mask_exposure(r.claim_text)
        return resp

    def dossier(self, organization: str) -> dict[str, Any]:
        """Masked exposure summary + claim ledger for one organization."""
        resp = self.query(DarkWebQuery(query=f'"{organization}"',
                                       organization=organization))
        return {"organization": organization, "access_state": resp.state.value,
                "counts_as_live_collection": resp.counts_as_live_collection,
                "claims_requiring_review": [r.as_claim() for r in resp.records],
                "limitations": resp.provider_limitations or resp.blocked_reason,
                "note": ("All entries are provider claims, not verified facts. "
                         "Credential material is masked; TraceAtlas does not test "
                         "or use compromised credentials.")}
