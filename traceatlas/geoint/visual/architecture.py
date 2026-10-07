"""traceatlas.geoint.visual.architecture - Built-environment clue builders.

Section 11: architecture/urban clues are SUPPORTING evidence only. The module
refuses to emit a clue whose observation text asserts a location; it describes
materials/forms and lists where such forms are common (broadly on purpose).
"""
from __future__ import annotations

from traceatlas.geoint.visual.visual_clues import VisualClue, make_clue

ARCHETYPE_NOTES = {
    "stucco_flat_roof_lowrise": {
        "regions": ["ME", "North Africa", "South Asia", "Latin America"],
        "countries": [], "uniqueness": 0.2},
    "brick_terraced_row_housing": {
        "regions": ["GB", "NL", "NE US"], "countries": ["GB", "NL"],
        "uniqueness": 0.5},
    "reinforced_concrete_apartment_blocks": {
        "regions": ["post-Soviet states", "South Asia", "China", "Brazil"],
        "countries": [], "uniqueness": 0.15},
    "wooden_two_storey_detached": {
        "regions": ["Nordics", "Japan", "Pacific NW US", "Alpine"],
        "countries": [], "uniqueness": 0.2},
    "glass_curtain_wall_towers": {
        "regions": ["global CBDs"], "countries": [], "uniqueness": 0.05},
    "load_bearing_masonry_with_sloped_tile_roof": {
        "regions": ["Southern Europe", "Anatolia", "Central Europe"],
        "countries": [], "uniqueness": 0.25},
    "tin_shack_informal_settlement": {
        "regions": ["global south urban peripheries"], "countries": [],
        "uniqueness": 0.1},
}


def architecture_clue(evidence_id: str, archetype_key: str, confidence: str,
                      method: str = "ai:vision") -> VisualClue:
    meta = ARCHETYPE_NOTES.get(archetype_key)
    if meta is None:
        return make_clue(
            "architecture.style",
            observation=f"unclassified building forms noted ({archetype_key})",
            evidence_id=evidence_id, confidence="LOW", geographic_scope="GLOBAL",
            method=method, uniqueness=0.05, limitations=["generic_scene"],
            notes="unknown archetype: no geographic constraint produced")
    generic = not meta["countries"]
    return make_clue(
        "architecture.style",
        observation=(f"built environment consistent with archetype '{archetype_key}' "
                     f"(common in: {', '.join(meta['regions'])})"),
        evidence_id=evidence_id, confidence=confidence,
        geographic_scope="GLOBAL" if generic else "COUNTRY",
        candidate_regions=list(meta["countries"]),
        method=method, uniqueness=meta["uniqueness"],
        limitations=["generic_scene"],
        notes="architecture is supporting evidence, never sole proof (section 11)")
