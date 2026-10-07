"""traceatlas.geoint.uncertainty - Structured uncertainty representation.

Uncertainty is a first-class object: what is unknown, why, which action would
reduce it, and how severe the gap is. Reports must carry it (section 40
"Unknowns") rather than hiding it behind a single answer. JARVIS briefs read
directly from this structure (sections 38-39: "What remains uncertain?").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from traceatlas.core.identifiers import new_id


class UncertaintyKind(str, Enum):
    AMBIGUOUS_CLUE = "AMBIGUOUS_CLUE"              # clue fits many places
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    MISSING_METADATA = "MISSING_METADATA"          # no capture time -> no sun analysis
    MODEL_DISAGREEMENT = "MODEL_DISAGREEMENT"      # dual-AI split
    STALE_DATA = "STALE_DATA"                      # historical != current
    UNVERIFIED = "UNVERIFIED"                      # single-source / pre-fact-gate
    OUT_OF_SCOPE = "OUT_OF_SCOPE"                  # privacy/policy prevents refinement


@dataclass(slots=True)
class UncertaintyItem:
    uncertainty_id: str
    kind: UncertaintyKind
    description: str
    affects_granularity: str = "CITY"          # LocationGranularity value
    blocking_evidence_ids: list[str] = field(default_factory=list)
    resolving_action: str = ""                 # next-best-action that could reduce it
    severity: str = "MODERATE"                 # LOW | MODERATE | HIGH

    def to_dict(self) -> dict:
        return {
            "uncertainty_id": self.uncertainty_id,
            "kind": self.kind.value if isinstance(self.kind, UncertaintyKind) else self.kind,
            "description": self.description,
            "affects_granularity": self.affects_granularity,
            "blocking_evidence_ids": list(self.blocking_evidence_ids),
            "resolving_action": self.resolving_action,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "UncertaintyItem":
        return cls(
            uncertainty_id=d["uncertainty_id"],
            kind=UncertaintyKind(d["kind"]),
            description=d["description"],
            affects_granularity=d.get("affects_granularity", "CITY"),
            blocking_evidence_ids=list(d.get("blocking_evidence_ids", [])),
            resolving_action=d.get("resolving_action", ""),
            severity=d.get("severity", "MODERATE"),
        )


@dataclass(slots=True)
class UncertaintySet:
    """Aggregate view used by the verifier, report and JARVIS briefs."""
    items: list[UncertaintyItem] = field(default_factory=list)

    def add(self, kind: UncertaintyKind | str, description: str, **kw) -> UncertaintyItem:
        item = UncertaintyItem(uncertainty_id=new_id("hypothesis"),
                               kind=UncertaintyKind(str(kind)),
                               description=description, **kw)
        self.items.append(item)
        return item

    def by_granularity(self, granularity: str) -> list[UncertaintyItem]:
        return [i for i in self.items if i.affects_granularity == granularity]

    @property
    def high_severity(self) -> list[UncertaintyItem]:
        return [i for i in self.items if i.severity == "HIGH"]

    def summary_lines(self) -> list[str]:
        return [f"[{i.kind.value}] {i.description} -> "
                f"{i.resolving_action or 'no known resolution'}" for i in self.items]

    def to_dict(self) -> dict:
        return {"items": [i.to_dict() for i in self.items]}

    @classmethod
    def from_dict(cls, d: dict) -> "UncertaintySet":
        return cls(items=[UncertaintyItem.from_dict(i) for i in d.get("items", [])])
