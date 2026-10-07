"""traceatlas.geoint.state - Pipeline state machine for a GEOINT mission.

Mirrors the section 49 auto-investigation loop; stages are strictly ordered so
a report can show exactly where an analysis stopped and why (stage skips are
recorded with reasons — e.g. VISUAL_CLUES skipped when no vision model and no
deterministic clue source is available).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class GeoStage(str, Enum):
    INTAKE = "INTAKE"
    METADATA = "METADATA"
    DETERMINISTIC_CHECKS = "DETERMINISTIC_CHECKS"
    VISUAL_CLUES = "VISUAL_CLUES"
    CANDIDATE_GENERATION = "CANDIDATE_GENERATION"
    MAP_SEARCH = "MAP_SEARCH"
    IMAGERY_SEARCH = "IMAGERY_SEARCH"
    CANDIDATE_COMPARISON = "CANDIDATE_COMPARISON"
    AI_PASS_1 = "AI_PASS_1"
    AI_PASS_2 = "AI_PASS_2"
    FALSIFICATION = "FALSIFICATION"
    SOURCE_INDEPENDENCE = "SOURCE_INDEPENDENCE"
    CONTRADICTION = "CONTRADICTION"
    REFINEMENT = "REFINEMENT"
    GAP_DETECTION = "GAP_DETECTION"
    VERIFICATION = "VERIFICATION"
    REPORT = "REPORT"
    DONE = "DONE"


ORDER = [s for s in GeoStage]


@dataclass(slots=True)
class GeoState:
    stage: GeoStage = GeoStage.INTAKE
    completed: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)   # stage -> reason
    errors: list[str] = field(default_factory=list)

    def advance_to(self, stage: GeoStage) -> None:
        if self.stage != stage:
            self.completed.append(self.stage.value)
            self.stage = stage

    def skip(self, stage: GeoStage, reason: str) -> None:
        self.skipped[stage.value] = reason

    def to_dict(self) -> dict:
        return {"stage": self.stage.value, "completed": list(self.completed),
                "skipped": dict(self.skipped), "errors": list(self.errors)}

    @classmethod
    def from_dict(cls, d: dict) -> "GeoState":
        return cls(stage=GeoStage(d.get("stage", "INTAKE")),
                   completed=list(d.get("completed", [])),
                   skipped=dict(d.get("skipped", {})),
                   errors=list(d.get("errors", [])))
