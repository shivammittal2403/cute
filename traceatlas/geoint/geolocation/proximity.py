"""traceatlas.geoint.geolocation.proximity - Proximity checks between clues."""
from __future__ import annotations

from traceatlas.geoint.geolocation.coordinate_parser import LatLng
from traceatlas.geoint.geolocation.distance import haversine_meters


def within_meters(a: LatLng, b: LatLng, radius_m: float) -> bool:
    return haversine_meters(a, b) <= radius_m


def proximity_score(a: LatLng, b: LatLng, scale_m: float = 5000.0) -> float:
    """Decaying 0..1 proximity score (1 == co-located). Used as a *component*
    of candidate ranking — never as standalone proof of identity."""
    d = haversine_meters(a, b)
    return max(0.0, min(1.0, 1.0 - d / scale_m))


def cluster_center(points: list[LatLng]) -> LatLng:
    """Simple mean center (adequate for small-area clusters; documented limit)."""
    if not points:
        raise ValueError("empty cluster")
    return LatLng(lat=sum(p.lat for p in points) / len(points),
                  lon=sum(p.lon for p in points) / len(points))
