"""traceatlas.geoint.visual.clue_weighting - Discriminating-power weighting.

Section 48: weight discriminating evidence more heavily than generic clues.
A unique metro-station name outranks "asphalt road exists". Weights are
explicit and auditable — never hidden inside a single similarity number
(section 37 of the MALINT spec applies equally here).
"""
from __future__ import annotations

# Base weights by clue type (0..1). Values are *starting points*, adjusted by
# per-clue confidence and uniqueness at scoring time; they are exposed in the
# comparison matrix so humans can audit them.
CLUE_TYPE_WEIGHTS: dict[str, float] = {
    "landmark.unique": 1.0,          # verified unique structure
    "text.address": 0.95,            # readable address text
    "transit.network": 0.9,          # metro line/station branding
    "signage.language_script": 0.6,  # language+script narrows country sets
    "road.driving_side": 0.35,       # probabilistic only
    "road.sign_shape_color": 0.4,
    "road.number_format": 0.5,
    "plate_context": 0.25,           # general plate style (lawful context only)
    "architecture.style": 0.3,       # supporting evidence, never sole proof
    "utility_infrastructure": 0.35,
    "street_furniture": 0.3,
    "vegetation": 0.3,
    "terrain": 0.5,                  # strong when distinctive ranges/coastlines
    "coastline": 0.55,
    "climate.weather": 0.2,
    "shadow.sun": 0.3,               # requires reliable capture time
    "generic": 0.05,                 # asphalt, sky, ordinary sedan...
}


def effective_weight(clue_type: str, confidence_rank: int, uniqueness: float = 1.0) -> float:
    """weight = base * ordinal-confidence factor * uniqueness factor.

    confidence_rank: 0..4 (VERY_LOW..VERY_HIGH). LOW-confidence clues are
    damped hard so a shaky OCR cannot dominate a comparison."""
    base = CLUE_TYPE_WEIGHTS.get(clue_type, CLUE_TYPE_WEIGHTS["generic"])
    conf_factor = {0: 0.0, 1: 0.2, 2: 0.6, 3: 0.9, 4: 1.0}[max(0, min(4, confidence_rank))]
    return round(base * conf_factor * max(0.0, min(1.0, uniqueness)), 4)
