"""traceatlas.geoint.evidence - Evidence, observations, facts, fact gate.

Sections 5/6: strict epistemic layering. RAW INPUT -> EVIDENCE -> METADATA ->
OBSERVATIONS -> FACT CANDIDATES -> source checks -> FACT GATE. A FACT is only
something directly contained in retained evidence (an EXIF coordinate pair,
visible sign text, map provider geometry, an imagery acquisition date).
Anything requiring interpretation is an OBSERVATION or INFERENCE — never a
fact. Low-confidence OCR must not become fact (section 8).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from traceatlas.core.identifiers import new_id


class GeoEvidenceKind(str, Enum):
    MEDIA = "MEDIA"                       # image/video bytes retained
    METADATA = "METADATA"                 # EXIF/embedded fields
    VISUAL_CLUE = "VISUAL_CLUE"           # structured clue record
    OCR_TEXT = "OCR_TEXT"                 # raw OCR output + confidences
    MAP_FEATURE = "MAP_FEATURE"           # OSM/provider feature snapshot
    GEOCODE_RESULT = "GEOCODE_RESULT"     # forward/reverse geocode payload
    SATELLITE_SCENE = "SATELLITE_SCENE"   # scene metadata + footprint
    TERRAIN_SAMPLE = "TERRAIN_SAMPLE"     # elevation/landcover sample
    DOCUMENT_TEXT = "DOCUMENT_TEXT"       # extracted location-bearing text
    USER_STATEMENT = "USER_STATEMENT"     # operator-provided context
    PUBLIC_POST = "PUBLIC_POST"           # public social/news content
    ARCHIVE_SNAPSHOT = "ARCHIVE_SNAPSHOT" # historical page/map capture


class EpistemicLevel(str, Enum):
    EVIDENCE = "EVIDENCE"          # retained raw artifact
    OBSERVATION = "OBSERVATION"    # direct reading of an artifact
    FACT_CANDIDATE = "FACT_CANDIDATE"
    FACT = "FACT"                  # passed the gate
    INFERENCE = "INFERENCE"        # interpretation layered on facts
    HYPOTHESIS = "HYPOTHESIS"      # competing explanation under test


@dataclass(slots=True)
class GeoEvidence:
    """Pointer to retained raw input. Bytes live in the evidence store; this
    record keeps provenance and the four time dimensions (section 18)."""
    evidence_id: str
    kind: GeoEvidenceKind
    source_uri: str
    sha256: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_time: Optional[datetime] = None      # what the content is *about*
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    case_id: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id, "kind": self.kind.value,
            "source_uri": self.source_uri, "sha256": self.sha256,
            "collected_at": self.collected_at.isoformat(),
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_to": self.valid_to.isoformat() if self.valid_to else None,
            "case_id": self.case_id, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GeoEvidence":
        def _dt(key):
            v = d.get(key)
            return datetime.fromisoformat(v) if v else None
        return cls(evidence_id=d["evidence_id"], kind=GeoEvidenceKind(d["kind"]),
                   source_uri=d["source_uri"], sha256=d.get("sha256", ""),
                   collected_at=datetime.fromisoformat(d["collected_at"]),
                   event_time=_dt("event_time"), valid_from=_dt("valid_from"),
                   valid_to=_dt("valid_to"), case_id=d.get("case_id", ""),
                   notes=d.get("notes", ""))


@dataclass(slots=True)
class GeoObservation:
    """Direct reading of an artifact ('sign text reads XYZ', 'sampled
    elevation ~310 m'). Carries confidence and links to its evidence."""
    observation_id: str
    evidence_id: str
    kind: str                                   # ocr.text, exif.latlon, map.geometry...
    value: Any
    confidence: str = "MODERATE"                # GeoConfidence value
    epistemic_level: EpistemicLevel = EpistemicLevel.OBSERVATION
    method: str = ""                            # deterministic | ai:<model> | human
    notes: str = ""

    def to_dict(self) -> dict:
        out = {}
        for k, v in self.__dict__.items():
            out[k] = v.value if isinstance(v, Enum) else v
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "GeoObservation":
        dd = dict(d)
        dd["epistemic_level"] = EpistemicLevel(dd.get("epistemic_level", "OBSERVATION"))
        return cls(**dd)


@dataclass(slots=True)
class GeoFactCandidate:
    """Proposed fact awaiting the gate. Must cite evidence; records source
    reliability/bias/independence inputs for the gate."""
    fact_id: str
    statement: str
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    reliability: str = "UNKNOWN"     # A-F style source grading
    independence_count: int = 1      # distinct independent sources observed
    contradicted_by: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FactGateDecision:
    accepted: bool
    reason: str
    downgraded_to: EpistemicLevel = EpistemicLevel.FACT
    requires: list[str] = field(default_factory=list)


def evaluate_fact_gate(candidate: GeoFactCandidate,
                       observations: list[GeoObservation]) -> FactGateDecision:
    """Section 5 FACT GATE. A fact candidate is accepted only when:
      * it cites at least one retained evidence id,
      * no supporting OCR observation is low-confidence (weak OCR stays an
        observation and can never silently harden into a fact),
      * contradictions are absent or explicitly resolved elsewhere.
    Single-source facts may pass but are flagged SINGLE_SOURCE — they are
    never promoted to multi-source certainty."""
    if not candidate.evidence_ids:
        return FactGateDecision(False, "no retained evidence cited",
                                EpistemicLevel.FACT_CANDIDATE, ["retain raw evidence first"])
    obs = [o for o in observations if o.evidence_id in candidate.evidence_ids]
    weak_ocr = [o for o in obs
                if o.kind.startswith("ocr") and o.confidence in ("VERY_LOW", "LOW")]
    if weak_ocr:
        return FactGateDecision(
            False, "low-confidence OCR must remain an observation, not a fact",
            EpistemicLevel.OBSERVATION,
            ["re-run OCR with different engine/settings",
             "seek independent confirmation of the text"])
    requires: list[str] = []
    if candidate.independence_count < 2:
        requires.append("single-source: seek independent corroboration before promotion")
    if candidate.contradicted_by:
        return FactGateDecision(False,
                                f"contradicted by: {', '.join(candidate.contradicted_by)}",
                                EpistemicLevel.HYPOTHESIS,
                                ["resolve contradiction explicitly before any use"])
    return FactGateDecision(True,
                            "accepted" + (" (SINGLE_SOURCE)" if requires else ""),
                            EpistemicLevel.FACT, requires)


def new_geo_evidence(kind: GeoEvidenceKind | str, source_uri: str, sha256: str = "",
                     case_id: str = "", event_time: Optional[datetime] = None,
                     notes: str = "") -> GeoEvidence:
    return GeoEvidence(evidence_id=new_id("evidence"), kind=GeoEvidenceKind(str(kind)),
                       source_uri=source_uri, sha256=sha256, case_id=case_id,
                       event_time=event_time, notes=notes)
