"""traceatlas.geoint.visual.visual_clues - Structured visual clue records.

Section 7: every clue carries clue_id, type, observation, evidence_id,
confidence, geographic_scope, candidate_regions and limitations. Clue
producers are pluggable (deterministic metadata readers, OCR adapters, vision
models, human analysts); the record shape is identical regardless of producer
so downstream ranking never trusts a clue more because an AI made it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from traceatlas.core.identifiers import new_id


@dataclass(slots=True)
class VisualClue:
    clue_id: str
    clue_type: str                       # keys from clue_weighting.CLUE_TYPE_WEIGHTS
    observation: str                     # what was seen (never a conclusion)
    evidence_id: str
    confidence: str = "MODERATE"         # GeoConfidence value
    geographic_scope: str = "GLOBAL"     # GLOBAL|COUNTRY|REGION|CITY|SITE
    candidate_regions: list[str] = field(default_factory=list)  # ISO codes / region tags
    method: str = "human"                # deterministic | ai:<model> | ocr:<engine> | human
    uniqueness: float = 1.0              # 0..1 (1 == rare/generic 0 == everywhere)
    limitations: list[str] = field(default_factory=list)   # limitation codes
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "clue_id": self.clue_id, "clue_type": self.clue_type,
            "observation": self.observation, "evidence_id": self.evidence_id,
            "confidence": self.confidence, "geographic_scope": self.geographic_scope,
            "candidate_regions": list(self.candidate_regions), "method": self.method,
            "uniqueness": self.uniqueness, "limitations": list(self.limitations),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "VisualClue":
        return cls(clue_id=d["clue_id"], clue_type=d["clue_type"],
                   observation=d["observation"], evidence_id=d["evidence_id"],
                   confidence=d.get("confidence", "MODERATE"),
                   geographic_scope=d.get("geographic_scope", "GLOBAL"),
                   candidate_regions=list(d.get("candidate_regions", [])),
                   method=d.get("method", "human"),
                   uniqueness=float(d.get("uniqueness", 1.0)),
                   limitations=list(d.get("limitations", [])),
                   notes=d.get("notes", ""))


def make_clue(clue_type: str, observation: str, evidence_id: str, *,
              confidence: str = "MODERATE", geographic_scope: str = "GLOBAL",
              candidate_regions: Optional[list[str]] = None, method: str = "human",
              uniqueness: float = 1.0, limitations: Optional[list[str]] = None,
              notes: str = "") -> VisualClue:
    return VisualClue(clue_id=new_id("observation"), clue_type=clue_type,
                      observation=observation, evidence_id=evidence_id,
                      confidence=confidence, geographic_scope=geographic_scope,
                      candidate_regions=list(candidate_regions or []),
                      method=method, uniqueness=uniqueness,
                      limitations=list(limitations or []), notes=notes)
