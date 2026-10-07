"""traceatlas.geoint.limitations - Explicit limitation registry.

Every GEOINT method carries known limitations; results must surface them.
Limitations are recorded per-analysis (not only globally) so a report can say
*which* conclusion is affected (section 40 "Source Bias/Limitations").
"""
from __future__ import annotations

from dataclasses import dataclass, field


# Canonical limitation catalogue (extensible per provider/analyst).
GEOINT_LIMITATIONS: dict[str, str] = {
    "generic_scene": "Road/storefront scenes lacking unique features cannot "
                     "support city-or-finer claims; keep candidates open.",
    "ocr_low_confidence": "Low-confidence OCR text must remain an observation; "
                          "it must not become a fact or seed a location alone.",
    "missing_capture_time": "Without reliable capture date/time, sun/shadow and "
                            "seasonal vegetation analysis is unavailable.",
    "sun_shadow_weak": "Shadow analysis constrains but cannot pinpoint a "
                       "location on its own.",
    "ip_geolocation_approximate": "IP/ASN geolocation marks hosting/network "
                                  "context, never a person's physical location.",
    "imagery_not_realtime": "Satellite/aerial scenes are dated; do not present "
                            "them as real-time unless the source is real-time.",
    "historical_is_historical": "An address valid in year Y is evidence about "
                                "year Y, not about now.",
    "model_vision_unavailable": "No vision model configured: visual clues fall "
                                "back to deterministic metadata/OCR/map analysis.",
    "single_source": "Conclusion rests on one source; mark SINGLE_SOURCE and "
                     "seek independence before promotion.",
    "restricted_provider": "Provider terms/rate limits restrict use; attribution "
                           "and freshness must be recorded with every result.",
    "privacy_precision_cap": "Case policy caps output precision; exact "
                             "coordinates withheld deliberately.",
    "look_alike_locations": "Visually similar cities/intersections exist; "
                            "similarity alone does not discriminate.",
    "cropped_media": "Cropping removes provenance and peripheral clues; treat "
                     "derived clues as weaker.",
    "video_frame_sampling": "Frame extraction samples the scene; transient "
                            "clues may be missed or duplicated.",
}


@dataclass(slots=True)
class LimitationRecord:
    code: str
    detail: str = ""
    affects: list[str] = field(default_factory=list)   # ids of conclusions affected

    def to_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail, "affects": list(self.affects)}

    @classmethod
    def from_dict(cls, d: dict) -> "LimitationRecord":
        return cls(code=d["code"], detail=d.get("detail", ""),
                   affects=list(d.get("affects", [])))


def catalog_text(code: str) -> str:
    return GEOINT_LIMITATIONS.get(code, f"Custom limitation: {code}")
