"""traceatlas.geoint.geolocation.bearing - Initial bearing & view-direction checks.

Used by visual verification: if an image claims to face a landmark, the
bearing from candidate position to landmark must be consistent with the
observed scene direction (compass EXIF heading or shadow/sun reasoning).
"""
from __future__ import annotations

import math

from traceatlas.geoint.geolocation.coordinate_parser import LatLng


def initial_bearing_deg(a: LatLng, b: LatLng) -> float:
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dl = math.radians(b.lon - a.lon)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def angular_difference_deg(a: float, b: float) -> float:
    """Smallest absolute difference between two bearings, 0..180."""
    d = abs((a - b) % 360.0)
    return min(d, 360.0 - d)


def bearing_consistent(expected: float, observed: float, tolerance_deg: float = 30.0) -> bool:
    return angular_difference_deg(expected, observed) <= tolerance_deg


def offset_point(origin: LatLng, bearing_deg: float, distance_m: float) -> LatLng:
    """Destination point given start, initial bearing and distance (spherical)."""
    R = 6_371_008.8
    br = math.radians(bearing_deg)
    p1, l1 = math.radians(origin.lat), math.radians(origin.lon)
    d = distance_m / R
    p2 = math.asin(math.sin(p1) * math.cos(d) + math.cos(p1) * math.sin(d) * math.cos(br))
    l2 = l1 + math.atan2(math.sin(br) * math.sin(d) * math.cos(p1),
                         math.cos(d) - math.sin(p1) * math.sin(p2))
    return LatLng(lat=math.degrees(p2), lon=(math.degrees(l2) + 540) % 360 - 180)
