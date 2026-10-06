"""traceatlas.core.confidence - Calibrated confidence values."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .enums import ConfidenceBand


@dataclass(frozen=True, slots=True)
class Confidence:
    score: float
    band: ConfidenceBand
    calibrated: bool = False
    rationale: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"confidence score out of range: {self.score!r}")
        object.__setattr__(self, "band", ConfidenceBand.from_score(self.score))

    @classmethod
    def of(cls, score: float, rationale: str = "", calibrated: bool = False) -> "Confidence":
        return cls(score=score, band=ConfidenceBand.from_score(score),
                   calibrated=calibrated, rationale=rationale)

    @classmethod
    def unknown(cls) -> "Confidence":
        return cls(score=0.0, band=ConfidenceBand.VERY_LOW, rationale="no evidence")

    def to_dict(self) -> dict[str, Any]:
        return {"score": round(self.score, 4), "band": self.band.value,
                "calibrated": self.calibrated, "rationale": self.rationale}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Confidence":
        return cls.of(float(d["score"]), d.get("rationale", ""),
                      bool(d.get("calibrated", False)))


def combine_confidences(scores: list[float], mode: str = "mean") -> float:
    if not scores:
        return 0.0
    if mode == "min":
        return min(scores)
    if mode == "noisy_or":
        p = 1.0
        for s in scores:
            p *= (1.0 - max(0.0, min(1.0, s)))
        return 1.0 - p
    return sum(scores) / len(scores)
