"""traceatlas.ingestion.confidence - Calibrated confidence for detections/mappings.

Confidence is kept as an explicit float plus a band so downstream policy
(review thresholds, AI routing) can act on it without re-deriving numbers.
Combination rules are deterministic and documented — no vibes-based scoring.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Band(str, Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


def band_for(value: float) -> Band:
    if value < 0.2:
        return Band.VERY_LOW
    if value < 0.45:
        return Band.LOW
    if value < 0.7:
        return Band.MODERATE
    if value < 0.9:
        return Band.HIGH
    return Band.VERY_HIGH


# Below this, mappings/detections must be surfaced for human review.
REVIEW_THRESHOLD = 0.6
# Below this, we refuse to auto-map at all (field stays unresolved).
AUTO_MAP_THRESHOLD = 0.85


@dataclass(frozen=True, slots=True)
class Confidence:
    value: float
    basis: str = ""            # short machine-readable justification
    signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", max(0.0, min(1.0, float(self.value))))

    @property
    def band(self) -> Band:
        return band_for(self.value)

    @property
    def requires_review(self) -> bool:
        return self.value < REVIEW_THRESHOLD

    def combine(self, other: "Confidence") -> "Confidence":
        """Independent-corroboration rule (noisy-OR), capped at 0.99.

        Two weak-but-independent signals agreeing beats one strong signal;
        exactly two agreeing sources cap below 'certain' because both could
        share an upstream error.
        """
        v = 1.0 - (1.0 - self.value) * (1.0 - other.value)
        return Confidence(min(v, 0.99), basis="corroborated",
                          signals=tuple(sorted(set(self.signals) | set(other.signals))))

    def decay(self, factor: float = 0.5) -> "Confidence":
        return Confidence(self.value * factor, basis=f"{self.basis}+decay",
                          signals=self.signals)

    def to_dict(self) -> dict:
        return {"value": round(self.value, 4), "band": self.band.value,
                "basis": self.basis, "signals": list(self.signals)}

    @classmethod
    def from_dict(cls, d: dict) -> "Confidence":
        return cls(float(d.get("value", 0.0)), d.get("basis", ""),
                   tuple(d.get("signals", ())))


def strongest(candidates: Iterable[Confidence]) -> Confidence:
    best: Confidence | None = None
    for c in candidates:
        if best is None or c.value > best.value:
            best = c
    return best or Confidence(0.0, "none")
