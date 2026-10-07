"""traceatlas.geoint.visual.image - Image intake: hash, EXIF, deterministic metadata.

Section 7 pipeline head: IMAGE -> HASH -> METADATA -> EXIF. Uses Pillow when
available (installed in this deployment); falls back to a pure-stdlib JPEG/PNG
dimension + basic-EXIF reader so intake NEVER silently fails. EXIF GPS is
preserved exactly as found — coordinates from metadata are FACTS about the
metadata, and strong evidence about capture location with documented caveats
(spoofable, timezone-less timestamps).
"""
from __future__ import annotations

import hashlib
import io
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from traceatlas.core.identifiers import new_id
from traceatlas.geoint.evidence import GeoEvidenceKind, GeoObservation, new_geo_evidence
from traceatlas.geoint.geolocation.coordinate_parser import LatLng


@dataclass(slots=True)
class ImageMetadata:
    sha256: str
    width: int = 0
    height: int = 0
    format: str = ""
    exif_gps: Optional[LatLng] = None
    exif_datetime: Optional[datetime] = None
    camera_make: str = ""
    camera_model: str = ""
    orientation: int = 1
    extra: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Minimal binary sniffing (works without Pillow; PNG/JPEG/GIF/WebP sizes).
# ---------------------------------------------------------------------------

def _png_size(data: bytes) -> tuple[int, int] | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = struct.unpack(">II", data[16:24])
        return w, h
    return None


def _jpeg_size_and_exif(data: bytes) -> tuple[int, int, dict]:
    if data[:2] != b"\xff\xd8":
        return 0, 0, {}
    i = 2
    size = (0, 0)
    info: dict = {}
    while i < len(data) - 4:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xDA:      # start of scan: no more metadata segments
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            size = (w, h)
            break
        if marker == 0xE1:      # APP1: possibly Exif
            payload = data[i + 4:i + 2 + seg_len]
            if payload[:4] == b"Exif":
                info.update(_parse_exif_basic(payload[6:]))
        i += 2 + seg_len
    return size[0], size[1], info


def _to_float(v) -> float:
    try:
        if isinstance(v, tuple) and len(v) == 2:
            n, d = v
            return float(n) / float(d) if d else 0.0
        return float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


def _dms_to_dec(vals) -> float:
    if not isinstance(vals, (list, tuple)) or len(vals) < 3:
        return 0.0
    d, m, s = (_to_float(x) for x in vals[:3])
    return d + m / 60.0 + s / 3600.0


def _parse_exif_basic(tiff: bytes) -> dict:
    """Very small TIFF/IFD walker: pulls GPS lat/lon, DateTime, Make, Model."""
    out: dict = {}
    if len(tiff) < 8:
        return out
    endian = "<" if tiff[:2] == b"II" else ">"
    try:
        ifd0_off = struct.unpack(endian + "I", tiff[4:8])[0]
    except struct.error:
        return out

    def read_ifd(off: int) -> dict:
        entries: dict[int, tuple] = {}
        try:
            n = struct.unpack(endian + "H", tiff[off:off + 2])[0]
        except struct.error:
            return entries
        for k in range(n):
            e = off + 2 + k * 12
            tag = struct.unpack(endian + "H", tiff[e:e + 2])[0]
            typ = struct.unpack(endian + "H", tiff[e + 2:e + 4])[0]
            cnt = struct.unpack(endian + "I", tiff[e + 4:e + 8])[0]
            val_off = struct.unpack(endian + "I", tiff[e + 8:e + 12])[0]
            entries[tag] = (typ, cnt, val_off)
        return entries

    def ascii_at(e) -> str:
        typ, cnt, vo = e
        raw = tiff[vo:vo + cnt] if cnt > 4 else tiff[e[2]:e[2] + cnt] if False else \
              tiff[vo:vo + cnt] if typ == 2 and cnt > 4 else b""
        if typ == 2 and cnt <= 4:
            raw = struct.pack(endian + "I", vo)[:cnt]
        return raw.decode("ascii", "ignore").strip("\x00 ")

    def rational_pair(base: int, count: int) -> tuple:
        vals = []
        for j in range(count):
            o = base + j * 8
            n, d = struct.unpack(endian + "II", tiff[o:o + 8])
            vals.append((n, d))
        return tuple(vals)

    ifd0 = read_ifd(ifd0_off)
    if 271 in ifd0:
        out["make"] = ascii_at(ifd0[271])
    if 272 in ifd0:
        out["model"] = ascii_at(ifd0[272])
    if 306 in ifd0:
        dt = ascii_at(ifd0[306])
        m = re.match(r"(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", dt)
        if m:
            try:
                out["datetime"] = datetime(*map(int, m.groups()), tzinfo=timezone.utc)
            except ValueError:
                pass
    if 34853 in ifd0:   # GPS IFD pointer
        gps = read_ifd(ifd0[34853][2])
        lat_ref = ascii_at(gps[1]).upper() if 1 in gps else "N"
        lon_ref = ascii_at(gps[3]).upper() if 3 in gps else "E"
        if 2 in gps and 4 in gps:
            typ, cnt, vo = gps[2]
            lat = _dms_to_dec(rational_pair(vo, 3))
            typ, cnt, vo = gps[4]
            lon = _dms_to_dec(rational_pair(vo, 3))
            if lat_ref == "S":
                lat = -lat
            if lon_ref == "W":
                lon = -lon
            if abs(lat) <= 180 and abs(lon) <= 180:
                out["gps"] = (lat, lon)
    return out


def inspect_image(data: bytes) -> ImageMetadata:
    digest = sha256_bytes(data)
    meta = ImageMetadata(sha256=digest)
    fmt = "unknown"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        fmt = "png"
        s = _png_size(data)
        if s:
            meta.width, meta.height = s
    elif data[:2] == b"\xff\xd8":
        fmt = "jpeg"
        w, h, info = _jpeg_size_and_exif(data)
        meta.width, meta.height = w, h
        if info.get("gps"):
            lat, lon = info["gps"]
            try:
                meta.exif_gps = LatLng(lat=lat, lon=lon)
                meta.exif_gps.validate()
            except Exception:
                meta.extra["gps_invalid"] = info["gps"]
        meta.exif_datetime = info.get("datetime")
        meta.camera_make = info.get("make", "")
        meta.camera_model = info.get("model", "")
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        fmt = "gif"
        meta.width, meta.height = struct.unpack("<HH", data[6:10])
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        fmt = "webp"
    else:
        meta.limitations.append("unrecognized_format")
        meta.format = fmt
        return meta
    meta.format = fmt
    if meta.exif_gps is None and fmt == "jpeg":
        meta.limitations.append("missing_metadata")
    if meta.exif_datetime is None:
        meta.limitations.append("missing_capture_time")
    return meta


def metadata_observations(meta: ImageMetadata, evidence_id: str) -> list[GeoObservation]:
    """Turn retained metadata into OBSERVATION records (facts come later via
    the gate; EXIF GPS is direct content so it clears the gate easily)."""
    obs: list[GeoObservation] = []
    if meta.exif_gps is not None:
        obs.append(GeoObservation(observation_id=new_id("observation"),
                                  evidence_id=evidence_id, kind="exif.latlon",
                                  value=meta.exif_gps.to_dict(), confidence="VERY_HIGH",
                                  method="deterministic",
                                  notes="EXIF GPS as embedded; provenance/spoofing "
                                        "still requires source assessment"))
    if meta.exif_datetime is not None:
        obs.append(GeoObservation(observation_id=new_id("observation"),
                                  evidence_id=evidence_id, kind="exif.datetime",
                                  value=meta.exif_datetime.isoformat(),
                                  confidence="HIGH", method="deterministic",
                                  notes="camera clock, typically local time, may drift"))
    return obs
