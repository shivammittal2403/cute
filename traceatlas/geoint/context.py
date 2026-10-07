"""traceatlas.geoint.context - Case/mission context objects."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from traceatlas.geoint.confidence import PrecisionLevel


@dataclass(slots=True)
class GeoContext:
    """Operating context for a GEOINT task: who authorized what, how precise
    we may be, and which sources are permitted. Defaults are privacy-safe:
    cloud models OFF by default (never silently upload private evidence)."""
    case_id: str = ""
    objective: str = ""
    authorization: str = "public_open_source"   # public_open_source | client_authorized
    jurisdiction_note: str = ""
    privacy_classification: str = "standard"    # standard|sensitive_person|critical_infrastructure
    precision_policy: Optional[PrecisionLevel] = None  # hard cap even if evidence supports more
    allowed_source_classes: list[str] = field(
        default_factory=lambda: ["maps", "geocoding", "reverse_geocoding", "osm",
                                 "satellite", "terrain", "transport", "archives",
                                 "public_business_data"])
    allow_cloud_models: bool = False
    allow_vision_model: bool = True
    notes: str = ""

    def effective_precision_cap(self) -> PrecisionLevel:
        if self.precision_policy is not None:
            return self.precision_policy
        if self.privacy_classification in ("sensitive_person", "critical_infrastructure"):
            return PrecisionLevel.APPROXIMATE_AREA   # exact pins withheld by policy
        return PrecisionLevel.EXACT

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id, "objective": self.objective,
            "authorization": self.authorization,
            "jurisdiction_note": self.jurisdiction_note,
            "privacy_classification": self.privacy_classification,
            "precision_policy": self.precision_policy.value if self.precision_policy else None,
            "allowed_source_classes": list(self.allowed_source_classes),
            "allow_cloud_models": self.allow_cloud_models,
            "allow_vision_model": self.allow_vision_model,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GeoContext":
        pp = d.get("precision_policy")
        base = GeoContext()
        return cls(case_id=d.get("case_id", ""), objective=d.get("objective", ""),
                   authorization=d.get("authorization", "public_open_source"),
                   jurisdiction_note=d.get("jurisdiction_note", ""),
                   privacy_classification=d.get("privacy_classification", "standard"),
                   precision_policy=PrecisionLevel(pp) if pp else None,
                   allowed_source_classes=list(d.get("allowed_source_classes",
                                                     base.allowed_source_classes)),
                   allow_cloud_models=d.get("allow_cloud_models", False),
                   allow_vision_model=d.get("allow_vision_model", True),
                   notes=d.get("notes", ""))
