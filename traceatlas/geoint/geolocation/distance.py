"""traceatlas.geoint.geolocation.distance - Great-circle distance helpers."""
from __future__ import annotations

import math

from traceatlas.geoint.geolocation.coordinate_parser import LatLng

EARTH_RADIUS_M = 6_371_008.8  # mean radius (IUGG)


def haversine_meters(a: LatLng, b: LatLng) -> float:
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dphi = math.radians(b.lat - a.lat)
    dlam = math.radians(b.lon - a.lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlam / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(h))


def vincenty_inverse_meters(a: LatLng, b: LatLng, tol: float = 1e-6,
                            max_iter: int = 200) -> float:
    """WGS84 ellipsoidal distance (Vincenty inverse). Falls back to haversine
    for antipodal/near-coincident points where the iteration may not converge."""
    if abs(a.lat - b.lat) < 1e-12 and abs(a.lon - b.lon) < 1e-12:
        return 0.0
    f, radii = _F_LOCAL, (6378137.0, 6356752.314245)
    L = math.radians(b.lon - a.lon)
    U1, U2 = math.atan((1 - f) * math.tan(math.radians(a.lat))), \
             math.atan((1 - f) * math.tan(math.radians(b.lat)))
    sinU1, cosU1, sinU2, cosU2 = math.sin(U1), math.cos(U1), math.sin(U2), math.cos(U2)
    lam = L
    for _ in range(max_iter):
        sin_lam, cos_lam = math.sin(lam), math.cos(lam)
        sin_sigma = math.sqrt((cosU2 * sin_lam) ** 2 +
                              (cosU1 * sinU2 - sinU1 * cosU2 * cos_lam) ** 2)
        if sin_sigma == 0:
            return 0.0
        cos_sigma = sinU1 * sinU2 + cosU1 * cosU2 * cos_lam
        sigma = math.atan2(sin_sigma, cos_sigma)
        sin_alpha = cosU1 * cosU2 * sin_lam / sin_sigma
        cos2_alpha = 1 - sin_alpha ** 2
        if cos2_alpha == 0:
            cos_2sigma_m = 0.0
        else:
            cos_2sigma_m = cos_sigma - 2 * sinU1 * sinU2 / cos2_alpha
        C = f / 16 * cos2_alpha * (4 + f * (4 - 3 * cos2_alpha))
        lam_prev = lam
        lam = (L + (1 - C) * f * sin_alpha *
               (sigma + C * sin_sigma *
                (cos_2sigma_m + C * cos_sigma * (-1 + 2 * cos_2sigma_m ** 2))))
        if abs(lam - lam_prev) < tol:
            u2 = cos2_alpha * (radii[0] ** 2 - radii[1] ** 2) / radii[1] ** 2
            A_ = 1 + u2 / 16384 * (4096 + u2 * (-768 + u2 * (320 - 175 * u2)))
            B_ = u2 / 1024 * (256 + u2 * (-128 + u2 * (74 - 47 * u2)))
            d_sigma = B_ * sin_sigma * (cos_2sigma_m + B_ / 4 * (
                cos_sigma * (-1 + 2 * cos_2sigma_m ** 2) -
                B_ / 6 * cos_2sigma_m * (-3 + 4 * sin_sigma ** 2) *
                (-3 + 4 * cos_2sigma_m ** 2)))
            return radii[1] * A_ * (sigma - d_sigma)
    return haversine_meters(a, b)  # non-convergent (antipodal): documented fallback


_F_LOCAL = 1 / 298.257222101


def meters_to_deg_lat(m: float) -> float:
    return m / 111_320.0


def meters_to_deg_lon(m: float, at_lat: float) -> float:
    return m / (111_320.0 * max(0.01, math.cos(math.radians(at_lat))))
