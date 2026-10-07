"""traceatlas.geoint.visual.terrain - Terrain/landform clue builders (section 12).

Combination reasoning: 'mountains to the east + coast to the west' is a
constraint pattern; each individual feature is recorded separately with its
own confidence and country plausibility, then combined by clue_fusion.
"""
from __future__ import annotations

from traceatlas.geoint.visual.visual_clues import VisualClue, make_clue

TERRAIN_NOTES = {
    "high_mountain_range_snowcapped": {"scope": "REGION", "uniqueness": 0.6},
    "rolling_hills": {"scope": "GLOBAL", "uniqueness": 0.1},
    "coastline_cliffs": {"scope": "REGION", "uniqueness": 0.45},
    "sandy_beach_flat": {"scope": "GLOBAL", "uniqueness": 0.1},
    "arid_flat_desert": {"scope": "REGION", "uniqueness": 0.35},
    "karst_limestone_pinnacles": {"scope": "REGION", "uniqueness": 0.7},
    "volcanic_cone": {"scope": "REGION", "uniqueness": 0.6},
    "glacial_valley_u_shape": {"scope": "REGION", "uniqueness": 0.65},
    "river_delta_flat": {"scope": "REGION", "uniqueness": 0.4},
    "dense_urban_flat": {"scope": "GLOBAL", "uniqueness": 0.05},
}


def terrain_clue(evidence_id: str, feature_key: str, confidence: str,
                 bearing_hint: str | None = None,
                 candidate_regions: list[str] | None = None,
                 method: str = "ai:vision") -> VisualClue:
    meta = TERRAIN_NOTES.get(feature_key, {"scope": "GLOBAL", "uniqueness": 0.1})
    obs = f"terrain consistent with '{feature_key}'"
    if bearing_hint:
        obs += f", observed toward the {bearing_hint}"
    return make_clue(
        "terrain", observation=obs, evidence_id=evidence_id, confidence=confidence,
        geographic_scope=meta["scope"],
        candidate_regions=list(candidate_regions or []),
        method=method, uniqueness=meta["uniqueness"],
        limitations=[] if meta["scope"] != "GLOBAL" else ["generic_scene"],
        notes="terrain combinations narrow candidates; single features rarely do")
