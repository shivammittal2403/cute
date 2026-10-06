"""Nominatim (OpenStreetMap) geocoding connector — GEOINT, keyless.

Forward geocoding for place names and reverse geocoding for coordinates.
Respects Nominatim's usage policy: single request per call, descriptive UA,
5s timeout. Raw JSON bytes preserved as evidence. Coordinates emitted as
observations are treated as candidate locations until corroborated.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from .base import BaseConnector, CollectResult, is_safe_url


class NominatimConnector(BaseConnector):
    source_slug = "nominatim-osm"
    connector_type = "geocoding"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def collect(self, target: str, capability: str = "geocode") -> CollectResult:
        if capability == "reverse_geocode":
            m = re.match(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$", target)
            if not m:
                return CollectResult(ok=False, source_uri="",
                                     error="reverse_geocode needs 'lat,lon'")
            url = ("https://nominatim.openstreetmap.org/reverse"
                   f"?format=jsonv2&lat={m.group(1)}&lon={m.group(2)}")
        else:
            url = f"https://nominatim.openstreetmap.org/search?format=jsonv2&limit=5&q={quote(target)}"
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=self.timeout, headers={
                    "User-Agent": "TraceAtlas/0.1 (authorized OSINT research)"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}")
        try:
            data = json.loads(resp.content)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from nominatim")
        now = datetime.now(timezone.utc).isoformat()
        obs = []
        rows = data if isinstance(data, list) else [data]
        for r in rows:
            if not isinstance(r, dict):
                continue
            lat, lon = r.get("lat"), r.get("lon")
            if lat and lon:
                obs.append({"subject": target, "predicate": "location.candidate",
                            "value": {"display_name": r.get("display_name"),
                                      "lat": lat, "lon": lon,
                                      "class": r.get("class"), "type": r.get("type")},
                            "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "nominatim", "results": len(obs)})
