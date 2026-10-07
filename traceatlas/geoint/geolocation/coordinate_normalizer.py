"""traceatlas.geoint.geolocation.coordinate_normalizer - Canonical coordinate form.

Normalizes parsed coordinates into the internal representation used by every
GEOINT component: WGS84 decimal degrees, clamped/validated, with an explicit
uncertainty radius when the source format implies one (e.g. DMS rounded to
whole seconds ~ 30 m; MGRS 4-digit precision ~ 10 m grid).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.geoint.geolocation.coordinate_parser import LatLng


@dataclass(slots=True)
class NormalizedCoordinate:
    point: LatLng
    crs: str = "EPSG:4326"
    uncertainty_radius_m: float | None = None
    source_format: str = "decimal"     # decimal|dms|utm|mgrs|geojson|exif...
    notes: str = ""

    def to_dict(self) -> dict:
        return {"lat": self.point.lat, "lon": self.point.lon, "crs": self.crs,
                "uncertainty_radius_m": self.uncertainty_radius_m,
                "source_format": self.source_format, "notes": self.notes}


# Rounding implied by format -> approximate positional uncertainty in meters.
_FORMAT_UNCERTAINTY = {
    "decimal_6dp": 0.11, "decimal_5dp": 1.1, "decimal_4dp": 11.0,
    "decimal_3dp": 110.0, "decimal_2dp": 1100.0, "decimal_1dp": 11000.0,
    "dms_seconds": 30.0, "dms_minutes": 1800.0,
    "mgrs_4digit": 10.0, "mgrs_5digit": 1.0, "utm_5digit": 1.0,
    "exif_dms": 30.0,
}


def normalize(pt: LatLng, source_format: str = "decimal",
              decimals: int | None = None) -> NormalizedCoordinate:
    pt.validate()
    unc = None
    if decimals is not None and 0 <= decimals <= 6:
        unc = _FORMAT_UNCERTAINTY.get(f"decimal_{decimals}dp")
    else:
        unc = _FORMAT_UNCERTAINTY.get(source_format)
    return NormalizedCoordinate(point=pt, source_format=source_format,
                                uncertainty_radius_m=unc)


def round_to_precision(nc: NormalizedCoordinate, decimals: int = 6) -> NormalizedCoordinate:
    """Deliberate precision reduction for privacy output (section 37): rounding
    is part of the evidence trail, recorded in notes."""
    lat = round(nc.point.lat, decimals)
    lon = round(nc.point.lon, decimals)
    nc2 = NormalizedCoordinate(point=LatLng(lat=lat, lon=lon), crs=nc.crs,
                               uncertainty_radius_m=_FORMAT_UNCERTAINTY.get(
                                   f"decimal_{decimals}dp"),
                               source_format=nc.source_format,
                               notes=f"rounded to {decimals} dp for precision policy")
    return nc2
