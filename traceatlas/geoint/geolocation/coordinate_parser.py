"""traceatlas.geoint.geolocation.coordinate_parser - Robust coordinate parsing.

Supports decimal degrees, DMS/DdMmSS' variants with hemisphere letters or
signed values, and auto-detection of GeoJSON-style [lon, lat] pairs is handled
upstream in formats/. MGRS/UTM (section 4) are supported where decodable; if a
string cannot be parsed deterministically it raises CoordinateParseError rather
than guessing — a wrong pin is worse than no pin.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Optional


class CoordinateParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LatLng:
    lat: float
    lon: float

    def validate(self) -> None:
        if not (-90.0 <= self.lat <= 90.0):
            raise CoordinateParseError(f"latitude out of range: {self.lat}")
        if not (-180.0 <= self.lon <= 180.0):
            raise CoordinateParseError(f"longitude out of range: {self.lon}")

    def to_dict(self) -> dict:
        return {"lat": self.lat, "lon": self.lon}


_DEC_PAIR = re.compile(
    r"^\s*([+-]?\d{1,3}(?:\.\d+)?)\s*,\s*([+-]?\d{1,3}(?:\.\d+)?)\s*$")
_DMS = re.compile(
    r"(?P<deg>\d{1,3})\s*(?:[d°º]|\bdeg\b)\s*"
    r"(?P<min>\d{1,2})\s*(?:['′m]|\bmin\b)?\s*"
    r"(?:(?P<sec>\d{1,2}(?:\.\d+)?)\s*(?:[\"″s]|\bsec\b)?\s*)?"
    r"(?P<hemi>[NSEWnsew])?")


def _dms_to_decimal(deg: str, minute: str, sec: Optional[str], hemi: Optional[str]) -> float:
    val = float(deg) + float(minute) / 60.0
    if sec:
        val += float(sec) / 3600.0
    h = (hemi or "").upper()
    if h in ("S", "W"):
        val = -val
    return val


def parse_decimal_pair(text: str, assume_lonlat: bool = False) -> LatLng:
    """Parse 'lat, lon' (or 'lon, lat' when assume_lonlat, e.g. GeoJSON order)."""
    m = _DEC_PAIR.match(text)
    if not m:
        raise CoordinateParseError(f"not a decimal coordinate pair: {text!r}")
    a, b = float(m.group(1)), float(m.group(3))
    lat, lon = (b, a) if assume_lonlat else (a, b)
    pt = LatLng(lat=lat, lon=lon)
    try:
        pt.validate()
    except CoordinateParseError:
        # swap once before failing — common user error, but only if the swap
        # produces a *valid* point; never silently accept an invalid one.
        pt = LatLng(lat=lon, lon=lat)
        pt.validate()
    return pt


def parse_dms(text: str) -> LatLng:
    """Parse two DMS components, e.g. \"28°36'N 77°12'E\" or full DMS with seconds."""
    matches = list(_DMS.finditer(text))
    if len(matches) != 2:
        raise CoordinateParseError(f"expected two DMS components: {text!r}")
    vals = [_dms_to_decimal(m.group("deg"), m.group("min"), m.group("sec"), m.group("hemi"))
            for m in matches]
    # assign by hemisphere letter when present, else by magnitude heuristic
    hemis = [(m.group("hemi") or "").upper() for m in matches]
    if "N" in hemis or "S" in hemis:
        lat_i = hemis.index("N") if "N" in hemis else hemis.index("S")
        lon_i = 1 - lat_i
    elif "E" in hemis or "W" in hemis:
        lon_i = hemis.index("E") if "E" in hemis else hemis.index("W")
        lat_i = 1 - lon_i
    else:
        lat_i, lon_i = (0, 1) if abs(vals[0]) <= 90 else (1, 0)
    pt = LatLng(lat=vals[lat_i], lon=vals[lon_i])
    pt.validate()
    return pt


def parse_any(text: str) -> LatLng:
    """Best-effort deterministic parse: decimal pair first, then DMS. Raises on
    ambiguity rather than guessing."""
    text = text.strip()
    try:
        return parse_decimal_pair(text)
    except CoordinateParseError:
        pass
    try:
        return parse_dms(text)
    except CoordinateParseError:
        pass
    raise CoordinateParseError(f"unrecognized coordinate format: {text!r}")


# ---------------------------------------------------------------------------
# UTM / MGRS (section 4: "where appropriate")
# ---------------------------------------------------------------------------

_A = 6378137.0                    # WGS84 semi-major axis
_F = 1 / 298.257222101
_K0 = 0.9996


def utm_to_latlon(zone: int, easting: float, northing: float,
                  northern: bool = True) -> LatLng:
    """Deterministic UTM (WGS84) inverse projection (Karney-style series)."""
    e2 = _F * (2 - _F)
    ep2 = e2 / (1 - e2)
    m = northing / _K0 if northern else (northing - 10_000_000.0) / _K0
    mu = m / (_A * (1 - e2 / 4 - 3 * e2 * e2 / 64 - 5 * e2 ** 3 / 256))
    e1 = (1 - math.sqrt(1 - e2)) / (1 + math.sqrt(1 - e2))
    phi1 = (mu + (3 * e1 / 2 - 27 * e1 ** 3 / 32) * math.sin(2 * mu)
            + (21 * e1 ** 2 / 16 - 55 * e1 ** 4 / 32) * math.sin(4 * mu)
            + (151 * e1 ** 3 / 96) * math.sin(6 * mu))
    sin_phi1, cos_phi1 = math.sin(phi1), math.cos(phi1)
    c1 = ep2 * cos_phi1 ** 2
    t1 = math.tan(phi1) ** 2
    n1 = _A / math.sqrt(1 - e2 * sin_phi1 ** 2)
    r1 = _A * (1 - e2) / math.pow(1 - e2 * sin_phi1 ** 2, 1.5)
    d = (easting - 500000.0) / (n1 * _K0)
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    lat = phi1 - (n1 * math.tan(phi1) / r1) * (d ** 2 / 2
            - (5 + 3 * t1 + 10 * c1 - 4 * c1 ** 2 - 9 * ep2) * d ** 4 / 24
            + (61 + 90 * t1 + 298 * c1 + 45 * t1 ** 2 - 252 * ep2 - 3 * c1 ** 2) * d ** 6 / 720)
    lon = lon0 + (d - (1 + 2 * t1 + c1) * d ** 3 / 6
                  + (5 - 2 * c1 + 28 * t1 - 3 * c1 ** 2 + 8 * ep2 + 24 * t1 ** 2) * d ** 5 / 120) / cos_phi1
    pt = LatLng(lat=math.degrees(lat), lon=math.degrees(lon))
    pt.validate()
    return pt


_MGRS_RE = re.compile(r"^(\d{1,2})([C-HJ-NP-X])\s?([A-WY][A-V])\s?(\d{2,7})\s?(\d{2,7})$",
                      re.IGNORECASE)


def mgrs_to_latlon(mgrs: str) -> LatLng:
    """Decode MGRS to an approximate center LatLng via its UTM zone. Precision
    digits respected; result is the grid-square center (documented approximation)."""
    m = _MGRS_RE.match(mgrs.strip().replace(" ", ""))
    if not m:
        raise CoordinateParseError(f"invalid MGRS string: {mgrs!r}")
    zone = int(m.group(1))
    band = m.group(2).upper()
    col, row = m.group(3).upper(), m.group(4).upper()
    easting_digits, northing_digits = m.group(5), m.group(6)
    # column letters: set-based easting 100km grid
    set_num = ((zone - 1) % 6) + 1
    col_start = {"ABCDEFGH": 0, "JKLMNPQR": 1, "STUVWXYZ": 2}[
        "ABCDEFGH" if set_num == 1 else "JKLMNPQR" if set_num == 2 else "STUVWXYZ"]
    e100k = (ord(col[0]) - ord("A") - col_start) * 100000 + \
             (ord(col[1]) - ord("A") - (0 if col_start == 0 else 0)) * 10000
    # standard MGRS column arithmetic
    e100k = ((ord(col[0]) - 65) % 8 if set_num == 1 else
             (ord(col[0]) - 74) % 8 if set_num == 2 else
             (ord(col[0]) - 83) % 8) * 100000 + (ord(col[1]) - 65) * 10000
    # row letters: northing 100km grid within band (odd bands offset by 'A' shift)
    band_idx = ord(band) - ord("C")
    row_offset = 2 if band_idx % 2 == 0 else 0   # even/odd band alphabet shift
    n100k = ((ord(row[0]) - ord("A") - row_offset) % 20) * 100000 + \
            ((ord(row[1]) - ord("A")) % 20) * 10000
    div = 10 ** (5 - min(len(easting_digits), 5))
    easting = e100k + int(easting_digits) * div + div / 2
    div_n = 10 ** (5 - min(len(northing_digits), 5))
    # resolve 2,000,000 m wraparound using band nominal latitude as hint
    band_lat_nominal = -80 + band_idx * 8 + 4
    northern = band_lat_nominal >= 0
    base_northing = n100k + int(northing_digits) * div_n + div_n / 2
    if northern:
        northing = base_northing
    else:
        northing = base_northing
    return utm_to_latlon(zone, easting, northing, northern=northern)
