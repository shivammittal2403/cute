"""traceatlas.geoint.confidence - Ordinal confidence, granularity, precision.

Sections 35-36: no meaningless "93% location confidence" unless genuinely
calibrated. Confidence is an ordinal scale (VERY_LOW..VERY_HIGH) tracked
separately at every geographic granularity. Section 37: output precision is
capped both by the strongest evidence-supported granularity and by case
policy, so a country-level assessment can never be rendered as an exact pin.
"""
from __future__ import annotations

from enum import Enum


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover
        return self.value


class GeoConfidence(_StrEnum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


_CONFIDENCE_ORDER = [
    GeoConfidence.VERY_LOW, GeoConfidence.LOW, GeoConfidence.MODERATE,
    GeoConfidence.HIGH, GeoConfidence.VERY_HIGH,
]


def confidence_rank(c: GeoConfidence | str) -> int:
    val = c if isinstance(c, GeoConfidence) else GeoConfidence(str(c).upper())
    return _CONFIDENCE_ORDER.index(val)


def min_confidence(*cs: GeoConfidence | str) -> GeoConfidence:
    """Weakest-link combination (used when chaining dependent claims)."""
    ranks = [confidence_rank(c) for c in cs]
    if not ranks:
        return GeoConfidence.VERY_LOW
    return _CONFIDENCE_ORDER[min(ranks)]


def combine_confidence(primary: GeoConfidence | str,
                       corroborating: list[GeoConfidence | str]) -> GeoConfidence:
    """Ordinal upgrade: independent corroboration may raise confidence by one
    step per usable corroborating source (max +2), capped at VERY_HIGH.
    Deliberately conservative — never arithmetic averaging of fake percentages.
    """
    rank = confidence_rank(primary)
    usable = [c for c in corroborating
              if confidence_rank(c) >= confidence_rank(GeoConfidence.LOW)]
    rank += min(len(usable), 2)
    return _CONFIDENCE_ORDER[min(rank, len(_CONFIDENCE_ORDER) - 1)]


class LocationGranularity(_StrEnum):
    COUNTRY = "COUNTRY"
    REGION = "REGION"
    CITY = "CITY"
    NEIGHBORHOOD = "NEIGHBORHOOD"
    SITE = "SITE"
    EXACT_COORDINATE = "EXACT_COORDINATE"


_GRANULARITY_ORDER = [
    LocationGranularity.COUNTRY, LocationGranularity.REGION,
    LocationGranularity.CITY, LocationGranularity.NEIGHBORHOOD,
    LocationGranularity.SITE, LocationGranularity.EXACT_COORDINATE,
]


def granularity_rank(g: LocationGranularity | str) -> int:
    val = g if isinstance(g, LocationGranularity) else LocationGranularity(str(g))
    return _GRANULARITY_ORDER.index(val)


class PrecisionLevel(_StrEnum):
    COUNTRY_ONLY = "COUNTRY_ONLY"
    REGION = "REGION"
    CITY = "CITY"
    APPROXIMATE_AREA = "APPROXIMATE_AREA"
    EXACT = "EXACT"


_PRECISION_ORDER = [
    PrecisionLevel.COUNTRY_ONLY, PrecisionLevel.REGION, PrecisionLevel.CITY,
    PrecisionLevel.APPROXIMATE_AREA, PrecisionLevel.EXACT,
]

# What each granularity, at each confidence band, is allowed to justify as
# output precision. Rows = granularity of the strongest *verified* claim,
# columns = confidence band (LOW-ish / MODERATE / HIGH+). This table encodes
# section 37: exact coordinates require site/exact-level support — country- or
# city-level inference must NEVER be converted into an exact pin placement.
_PRECISION_TABLE = {
    LocationGranularity.COUNTRY: (PrecisionLevel.COUNTRY_ONLY,) * 3,
    LocationGranularity.REGION: (PrecisionLevel.COUNTRY_ONLY, PrecisionLevel.REGION, PrecisionLevel.REGION),
    LocationGranularity.CITY: (PrecisionLevel.REGION, PrecisionLevel.CITY, PrecisionLevel.CITY),
    LocationGranularity.NEIGHBORHOOD: (PrecisionLevel.CITY, PrecisionLevel.APPROXIMATE_AREA, PrecisionLevel.APPROXIMATE_AREA),
    LocationGranularity.SITE: (PrecisionLevel.APPROXIMATE_AREA, PrecisionLevel.APPROXIMATE_AREA, PrecisionLevel.EXACT),
    LocationGranularity.EXACT_COORDINATE: (PrecisionLevel.APPROXIMATE_AREA, PrecisionLevel.EXACT, PrecisionLevel.EXACT),
}

_POLICY_CAP = {p: i for i, p in enumerate(_PRECISION_ORDER)}


def cap_precision(strongest_granularity: LocationGranularity | str,
                  confidence: GeoConfidence | str,
                  policy_cap: PrecisionLevel | str | None = None) -> PrecisionLevel:
    """Return the maximum output precision justified by evidence, then apply
    the case-policy cap (authorization / privacy classification)."""
    g = strongest_granularity if isinstance(strongest_granularity, LocationGranularity) \
        else LocationGranularity(str(strongest_granularity))
    rank = confidence_rank(confidence)
    band = 0 if rank <= 1 else (1 if rank == 2 else 2)  # LOW-ish / MODERATE / HIGH+
    evidence_precision = _PRECISION_TABLE[g][band]
    if policy_cap is not None:
        cap = policy_cap if isinstance(policy_cap, PrecisionLevel) else PrecisionLevel(str(policy_cap))
        if _POLICY_CAP[cap] < _POLICY_CAP[evidence_precision]:
            return cap
    return evidence_precision


def downgrade_precision(p: PrecisionLevel | str, steps: int = 1) -> PrecisionLevel:
    val = p if isinstance(p, PrecisionLevel) else PrecisionLevel(str(p))
    i = max(0, _PRECISION_ORDER.index(val) - steps)
    return _PRECISION_ORDER[i]
