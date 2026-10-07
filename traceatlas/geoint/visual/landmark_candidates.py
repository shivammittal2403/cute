"""traceatlas.geoint.visual.landmark_candidates - Landmark detection workflow.

Section 14: a model saying it "looks like" a landmark is only a CANDIDATE. The
workflow (candidate -> references -> map lookup -> structural/perspective
comparison -> surrounding features -> temporal consistency -> verification)
is represented here as explicit verification stages; a candidate cannot be
promoted past UNVERIFIED without deterministic checks recorded against it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from traceatlas.core.identifiers import new_id


class LandmarkVerificationStage(str, Enum):
    DETECTED = "DETECTED"                        # model/analyst proposes a landmark
    REFERENCE_SOURCED = "REFERENCE_SOURCED"      # public reference images found
    MAP_LOOKUP = "MAP_LOOKUP"                    # feature exists in map data
    STRUCTURE_MATCH = "STRUCTURE_MATCH"          # geometry/details compared
    PERSPECTIVE_MATCH = "PERSPECTIVE_MATCH"      # viewing angle/orientation fits
    SURROUNDINGS_MATCH = "SURROUNDINGS_MATCH"    # nearby features consistent
    TEMPORAL_CONSISTENT = "TEMPORAL_CONSISTENT"  # existed at capture time
    VERIFIED = "VERIFIED"


_STAGE_ORDER = [s.value for s in LandmarkVerificationStage]


@dataclass(slots=True)
class LandmarkCandidate:
    candidate_id: str
    name: str
    evidence_id: str                     # the media it was seen in
    method: str                          # ai:<model> | human | similarity
    confidence: str = "LOW"              # initial detection confidence
    stage: LandmarkVerificationStage = LandmarkVerificationStage.DETECTED
    completed_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    map_feature_id: str = ""
    coordinates_hint: tuple[float, float] | None = None
    notes: str = ""

    def record_check(self, check: str, passed: bool) -> None:
        if check not in self.completed_checks:
            self.completed_checks.append(check)
        if not passed and check not in self.failed_checks:
            self.failed_checks.append(check)

    @property
    def usable_as_fact(self) -> bool:
        """Only fully verified landmarks may ground a location fact."""
        return self.stage == LandmarkVerificationStage.VERIFIED and not self.failed_checks

    def to_dict(self) -> dict:
        return {"candidate_id": self.candidate_id, "name": self.name,
                "evidence_id": self.evidence_id, "method": self.method,
                "confidence": self.confidence, "stage": self.stage.value,
                "completed_checks": list(self.completed_checks),
                "failed_checks": list(self.failed_checks),
                "map_feature_id": self.map_feature_id,
                "coordinates_hint": list(self.coordinates_hint) if self.coordinates_hint else None,
                "notes": self.notes}


def new_landmark_candidate(name: str, evidence_id: str, method: str,
                           confidence: str = "LOW") -> LandmarkCandidate:
    return LandmarkCandidate(candidate_id=new_id("entity"), name=name,
                             evidence_id=evidence_id, method=method,
                             confidence=confidence)
