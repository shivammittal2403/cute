"""traceatlas.geoint.visual.roads - Road-intelligence clue builders.

Section 9: driving side, lane markings, sign shapes/colors, road-number
formats. All outputs are probabilistic evidence clues with explicit country
sets and limitation codes — never standalone proof of a location.
"""
from __future__ import annotations

from traceatlas.geoint.visual.visual_clues import VisualClue, make_clue

# Countries that drive on the LEFT (public knowledge; incomplete by design and
# framed as probabilistic). Left-hand traffic is common but not exclusive to
# these; historic vehicle exceptions exist everywhere -> limitation noted.
LEFT_TRAFFIC_COUNTRIES = ["GB", "IE", "JP", "AU", "NZ", "IN", "PK", "BD", "LK", "NP",
                          "ZA", "KE", "TZ", "UG", "ZM", "ZW", "MY", "SG", "TH",
                          "PG", "FJ", "CY", "MT", "TT", "GY", "BS", "BB"]
RIGHT_TRAFFIC_DOMINANT_NOTE = ("right-hand traffic is the global majority; an "
                               "observation of right-side driving constrains "
                               "almost nothing on its own")


def driving_side_clue(evidence_id: str, side: str, confidence: str,
                      method: str = "ai:vision") -> VisualClue:
    side = str(side).lower()
    if side == "left":
        return make_clue(
            "road.driving_side",
            observation="scene appears consistent with left-hand traffic",
            evidence_id=evidence_id, confidence=confidence,
            geographic_scope="COUNTRY", candidate_regions=LEFT_TRAFFIC_COUNTRIES,
            method=method, uniqueness=0.55,
            limitations=["generic_scene"],
            notes="probabilistic only; exceptions exist in every country")
    return make_clue(
        "road.driving_side",
        observation="scene appears consistent with right-hand traffic",
        evidence_id=evidence_id, confidence=confidence,
        geographic_scope="GLOBAL", candidate_regions=[],
        method=method, uniqueness=0.1,
        limitations=["generic_scene"],
        notes=RIGHT_TRAFFIC_DOMINANT_NOTE)


# Sign shape/color conventions (probabilistic, public reference knowledge).
SIGN_CONVENTIONS = {
    "red_octagon_stop": ["most countries"],
    "triangular_warning_yellow_red_border": ["IN", "GB", "AU", "NZ", "ZA", "SG", "MY", "TH"],
    "triangular_warning_white_red_border": ["US", "CA", "MX", "JP", "KR"],
    "blue_square_information": ["EU", "AT", "DE", "FR", "ES", "IT"],
    "green_highway_shields": ["US", "CA", "MX", "JP_expressway", "AU"],
    "white_shield_route_marker": ["US"],
    "orange_red_national_park": ["US", "IN"],
}


def sign_convention_clue(evidence_id: str, convention_key: str, confidence: str,
                         method: str = "ai:vision") -> VisualClue:
    regions = SIGN_CONVENTIONS.get(convention_key, [])
    generic = not regions or regions == ["most countries"]
    return make_clue(
        "road.sign_shape_color",
        observation=f"signage matches convention '{convention_key}'",
        evidence_id=evidence_id, confidence=confidence,
        geographic_scope="GLOBAL" if generic else "COUNTRY",
        candidate_regions=[] if generic else [r for r in regions],
        method=method, uniqueness=0.2 if generic else 0.6,
        limitations=["generic_scene"] if generic else [],
        notes="sign conventions overlap across jurisdictions")


LANE_MARKING_NOTES = {
    "double_yellow_centerline": "used by US/Canada and several others",
    "broken_white_centerline": "globally common; low discrimination",
    "yellow_edge_lines": "common in US rural interstates",
    "cats_eyes_studs": "historically UK/commonwealth, now widespread",
}


def lane_marking_clue(evidence_id: str, marking: str, confidence: str,
                      method: str = "ai:vision") -> VisualClue:
    note = LANE_MARKING_NOTES.get(marking, "unrecognized marking convention")
    generic = marking != "double_yellow_centerline"
    return make_clue(
        "road.lane_markings",
        observation=f"lane markings appear to be '{marking}' ({note})",
        evidence_id=evidence_id, confidence=confidence,
        geographic_scope="GLOBAL" if generic else "COUNTRY",
        candidate_regions=[] if generic else ["US", "CA"],
        method=method, uniqueness=0.15 if generic else 0.4,
        limitations=["generic_scene"],
        notes="marking styles converge globally; supporting evidence only")
