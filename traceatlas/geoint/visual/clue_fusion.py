"""traceatlas.geoint.visual.clue_fusion - Fuse visual clues into constraints.

Clues are combined as *constraints on candidate regions*, not votes for one
answer (section 48: do not choose by simple count). Each clue contributes a
set of plausible ISO country codes / region hints plus a discriminating power.
Fusion intersects where clues are geographic; non-geographic clues (weather,
generic architecture) only narrow weakly and are marked as such.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class GeoConstraint:
    """What a clue implies geographically."""
    clue_id: str
    countries: set[str] | None = None      # None => no country constraint
    subnational_regions: set[str] = field(default_factory=set)
    driving_side: str | None = None        # left|right|None
    script_hint: str | None = None
    climate_hint: str | None = None        # tropical|temperate|arid|cold|unknown
    elevation_hint: str | None = None      # mountainous|coastal|flat|unknown
    discriminating_power: float = 0.5      # 0..1: how much this clue narrows
    generic: bool = False                  # fits almost everywhere


def intersect_constraints(constraints: list[GeoConstraint]) -> dict:
    """Combine constraints conservatively. Empty intersection => contradiction
    signal (returned explicitly so the pipeline can flag it instead of
    silently dropping clues)."""
    countries: set[str] | None = None
    contradiction = False
    driving_sides: set[str] = set()
    for c in constraints:
        if c.generic:
            continue
        if c.countries is not None:
            countries = c.countries if countries is None else (countries & c.countries)
            if not countries:
                contradiction = True
        if c.driving_side:
            driving_sides.add(c.driving_side)
    driving_conflict = "left" in driving_sides and "right" in driving_sides
    return {
        "countries": sorted(countries) if countries is not None else None,
        "contradiction": contradiction or driving_conflict,
        "driving_sides": sorted(driving_sides),
        "note": ("constraint intersection empty — evidence conflicts; keep all "
                 "candidates and investigate before ranking" if
                 (contradiction or driving_conflict) else "consistent"),
    }
