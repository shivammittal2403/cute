"""traceatlas.geoint.visual.sun_position - Deterministic solar geometry.

NOAA-accurate-to-~0.1° closed-form sun position (declination, equation of
time, hour angle) implemented in pure stdlib so shadow/sun analysis works
offline. Sections 13: sun/shadow is SUPPORTING evidence only; if capture time
is unknown the analysis is skipped and a limitation recorded — never guessed.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(slots=True)
class SunPosition:
    azimuth_deg: float     # clockwise from true north
    elevation_deg: float   # above horizon (negative => sun below horizon)
    source: str = "noaa_closed_form"


def _day_of_year(dt: datetime) -> int:
    return dt.timetuple().tm_yday


def sun_position(dt_utc: datetime, lat: float, lon: float) -> SunPosition:
    """Solar azimuth/elevation for a UTC datetime at (lat, lon)."""
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    doy = _day_of_year(dt_utc)
    # fractional year (radians)
    gamma = 2 * math.pi / 365 * (doy - 1 + (dt_utc.hour - 12) / 24)
    eqtime = 229.18 * (0.000075 + 0.001868 * math.cos(gamma)
                       - 0.032077 * math.sin(gamma)
                       - 0.014615 * math.cos(2 * gamma)
                       - 0.040849 * math.sin(2 * gamma))            # minutes
    decl = (0.006918 - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma)
            - 0.006758 * math.cos(2 * gamma) + 0.000907 * math.sin(2 * gamma)
            - 0.002697 * math.cos(3 * gamma) + 0.00148 * math.sin(3 * gamma))  # radians
    time_offset = eqtime + 4 * lon                                  # minutes
    tst = dt_utc.hour * 60 + dt_utc.minute + dt_utc.second / 60 + time_offset
    ha = math.radians(tst / 4 - 180)                                # hour angle deg->rad
    phi = math.radians(lat)
    cos_z = (math.sin(phi) * math.sin(decl)
             + math.cos(phi) * math.cos(decl) * math.cos(ha))
    cos_z = max(-1.0, min(1.0, cos_z))
    zenith = math.acos(cos_z)
    elev = 90.0 - math.degrees(zenith)
    # standard NOAA azimuth formula:
    sin_zenith = math.sin(zenith)
    if abs(sin_zenith) < 1e-12:      # sun at zenith: azimuth undefined
        return SunPosition(azimuth_deg=0.0, elevation_deg=round(elev, 2))
    cos_az = (math.sin(decl) - math.sin(phi) * math.cos(zenith)) / (math.cos(phi) * sin_zenith)
    cos_az = max(-1.0, min(1.0, cos_az))
    az = math.degrees(math.acos(cos_az))
    if ha > 0:
        az = 360 - az
    return SunPosition(azimuth_deg=round(az % 360, 2), elevation_deg=round(elev, 2))


def shadow_direction_from_sun(sun_az_deg: float) -> float:
    """Shadows point opposite the sun's azimuth."""
    return (sun_az_deg + 180.0) % 360.0


def shadow_length_factor(sun_elev_deg: float) -> float | None:
    """Vertical object height multiplier. None when sun at/below horizon."""
    if sun_elev_deg <= 0.5:
        return None
    return 1.0 / math.tan(math.radians(sun_elev_deg))


def consistent_shadow(observed_shadow_bearing_deg: float, dt_utc: datetime,
                      lat: float, lon: float, tolerance_deg: float = 25.0) -> dict:
    """Check whether an observed shadow direction is physically possible for a
    given candidate location/time. Returns a verdict dict used by falsification
    (section 22: 'Is sun direction impossible?')."""
    sp = sun_position(dt_utc, lat, lon)
    expected = shadow_direction_from_sun(sp.azimuth_deg)
    diff = abs((observed_shadow_bearing_deg - expected) % 360.0)
    diff = min(diff, 360.0 - diff)
    verdict = "IMPOSSIBLE" if diff > tolerance_deg else "CONSISTENT"
    return {"sun_azimuth": sp.azimuth_deg, "sun_elevation": sp.elevation_deg,
            "expected_shadow_bearing": round(expected, 1),
            "observed_shadow_bearing": observed_shadow_bearing_deg,
            "angular_error_deg": round(diff, 1), "verdict": verdict}
