"""traceatlas.geoint.maps.geocoder - Forward geocoding with offline fallback.

Design: deterministic-first. An in-memory gazetteer (seeded with a small
public place list; extensible from packs/countries or user-supplied data)
answers offline. Network providers (Nominatim-compatible, Mapbox-compatible)
are used only when configured and policy-permitted. Every geocode result is
returned as *evidence* — including provider attribution and freshness notes —
and ambiguous queries ("Springfield") return ALL plausible matches instead of
silently picking one (section 34).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from traceatlas.core.identifiers import new_id
from traceatlas.geoint.geolocation.coordinate_parser import LatLng
from traceatlas.geoint.maps.provider import (BaseProvider, ProviderCapability,
                                             ProviderPolicy, ProviderRegistry)


@dataclass(slots=True)
class GeocodeMatch:
    match_id: str
    query: str
    display_name: str
    point: LatLng
    country: str = ""
    region: str = ""
    city: str = ""
    kind: str = "place"                 # address|place|poi|boundary
    provider_id: str = "offline_gazetteer"
    attribution: str = ""
    confidence_hint: str = "MODERATE"   # provider-side quality signal, ordinal
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"match_id": self.match_id, "query": self.query,
                "display_name": self.display_name, "lat": self.point.lat,
                "lon": self.point.lon, "country": self.country,
                "region": self.region, "city": self.city, "kind": self.kind,
                "provider_id": self.provider_id, "attribution": self.attribution,
                "confidence_hint": self.confidence_hint}


@dataclass(slots=True)
class GazetteerEntry:
    name: str
    aliases: tuple[str, ...]
    country: str
    region: str
    city: str
    point: LatLng
    kind: str = "city"


# Small public seed gazetteer (ISO country codes). Extendable at runtime via
# load_gazetteer(); intentionally tiny so offline behavior stays honest about
# coverage limits rather than pretending to be global.
_SEED_GAZETTEER: list[GazetteerEntry] = [
    GazetteerEntry("new delhi", ("delhi", "naya delhi"), "IN", "Delhi", "Delhi",
                   LatLng(28.6139, 77.2090)),
    GazetteerEntry("gurugram", ("gurgaon"), "IN", "Haryana", "Gurugram",
                   LatLng(28.4595, 77.0266)),
    GazetteerEntry("noida", (), "IN", "Uttar Pradesh", "Noida",
                   LatLng(28.5355, 77.3910)),
    GazetteerEntry("jaipur", (), "IN", "Rajasthan", "Jaipur",
                   LatLng(26.9124, 75.7873)),
    GazetteerEntry("mumbai", ("bombay"), "IN", "Maharashtra", "Mumbai",
                   LatLng(19.0760, 72.8777)),
    GazetteerEntry("springfield", (), "US", "Illinois", "Springfield",
                   LatLng(39.7817, -89.6501)),
    GazetteerEntry("springfield", (), "US", "Missouri", "Springfield",
                   LatLng(37.2089, -93.2923)),
    GazetteerEntry("springfield", (), "US", "Massachusetts", "Springfield",
                   LatLng(42.1015, -72.5898)),
    GazetteerEntry("london", (), "GB", "England", "London",
                   LatLng(51.5072, -0.1276)),
    GazetteerEntry("kyiv", ("kiev"), "UA", "Kyiv Oblast", "Kyiv",
                   LatLng(50.4501, 30.5234)),
    GazetteerEntry("moscow", (), "RU", "Moscow", "Moscow",
                   LatLng(55.7558, 37.6173)),
    GazetteerEntry("sao paulo", ("são paulo"), "BR", "São Paulo", "São Paulo",
                   LatLng(-23.5505, -46.6333)),
    GazetteerEntry("tokyo", (), "JP", "Kanto", "Tokyo",
                   LatLng(35.6762, 139.6503)),
    GazetteerEntry("sydney", (), "AU", "New South Wales", "Sydney",
                   LatLng(-33.8688, 151.2093)),
    GazetteerEntry("cairo", (), "EG", "Cairo Governorate", "Cairo",
                   LatLng(30.0444, 31.2357)),
    GazetteerEntry("lagos", (), "NG", "Lagos", "Lagos",
                   LatLng(6.5244, 3.3792)),
]


class OfflineGazetteer(BaseProvider):
    """Deterministic local gazetteer; safe default with zero network."""

    def __init__(self, entries: Optional[list[GazetteerEntry]] = None):
        super().__init__(
            provider_id="offline_gazetteer", display_name="TraceAtlas Offline Gazetteer",
            policy=ProviderPolicy(name="offline_gazetteer", license="internal",
                                  network_allowed=False,
                                  data_freshness_note="static seed + loaded packs"),
            capabilities=[ProviderCapability.FORWARD_GEOCODE,
                          ProviderCapability.PLACES_SEARCH])
        self.entries: list[GazetteerEntry] = list(entries or _SEED_GAZETTEER)

    def search(self, query: str) -> list[GeocodeMatch]:
        q = query.strip().lower()
        # support "city, region" and "city, country" disambiguation
        parts = [p.strip() for p in q.split(",")]
        primary = parts[0]
        qualifier = parts[1] if len(parts) > 1 else ""
        hits: list[GeocodeMatch] = []
        for e in self.entries:
            names = {e.name, *e.aliases}
            if primary not in names:
                continue
            if qualifier and qualifier not in (e.region.lower(), e.city.lower(),
                                               e.country.lower()):
                continue
            hits.append(GeocodeMatch(match_id=new_id("entity"), query=query,
                                     display_name=f"{e.city}, {e.region}, {e.country}",
                                     point=e.point, country=e.country, region=e.region,
                                     city=e.city, kind=e.kind,
                                     provider_id=self.provider_id,
                                     attribution="TraceAtlas offline gazetteer"))
        return hits


class NominatimStyleProvider(BaseProvider):
    """Adapter shape for OSM/Nominatim-compatible services. Network calls are
    performed through an injected fetcher so tests stay offline and real
    deployments can enforce rate limits/attribution (robots-compliant use)."""

    def __init__(self, endpoint: str, fetcher=None, api_key: Optional[str] = None):
        super().__init__(
            provider_id="nominatim_compatible", display_name="OSM-compatible geocoder",
            policy=ProviderPolicy(
                name="nominatim_compatible",
                license="ODbL (data) / provider terms (service)",
                terms_url=endpoint, attribution_required="© OpenStreetMap contributors",
                rate_limit_per_min=1,   # Nominatim usage policy: 1 req/s ~ 60/min max
                requires_api_key=False, allows_bulk_queries=False,
                data_freshness_note="OSM edit frequency varies by region"),
            capabilities=[ProviderCapability.FORWARD_GEOCODE,
                          ProviderCapability.REVERSE_GEOCODE,
                          ProviderCapability.PLACES_SEARCH],
            api_key=api_key)
        self.endpoint = endpoint
        self._fetch = fetcher   # callable(url, params) -> parsed json list

    def search(self, query: str) -> list[GeocodeMatch]:
        self._check_policy(ProviderCapability.FORWARD_GEOCODE)
        if self._fetch is None:
            return []
        payload = self._fetch(f"{self.endpoint}/search",
                              {"q": query, "format": "jsonv2", "limit": "10"}) or []
        out = []
        for item in payload:
            try:
                pt = LatLng(lat=float(item["lat"]), lon=float(item["lon"]))
                pt.validate()
            except (KeyError, ValueError):
                continue
            addr = item.get("address", {})
            out.append(GeocodeMatch(match_id=new_id("entity"), query=query,
                                    display_name=item.get("display_name", ""),
                                    point=pt, country=addr.get("country_code", "").upper(),
                                    region=addr.get("state", ""), city=addr.get("city") or
                                    addr.get("town") or addr.get("village", ""),
                                    kind=item.get("type", "place"),
                                    provider_id=self.provider_id,
                                    attribution=self.attribution(),
                                    raw={k: item[k] for k in
                                         ("osm_id", "class", "type", "importance")
                                         if k in item}))
        return out


def build_default_registry(extra_providers: Optional[list[BaseProvider]] = None) -> ProviderRegistry:
    reg = ProviderRegistry()
    reg.register(OfflineGazetteer())
    for p in extra_providers or []:
        reg.register(p)
    return reg


def forward_geocode(query: str, registry: ProviderRegistry,
                    prefer_network: bool = False) -> list[GeocodeMatch]:
    """Return ALL plausible matches (never silently narrowed). Offline results
    always included so ambiguity like multiple 'Springfield' stays visible."""
    results: list[GeocodeMatch] = []
    net = registry.default_for(ProviderCapability.FORWARD_GEOCODE)
    offline = registry.get("offline_gazetteer")
    if prefer_network and net is not None and net.provider_id != "offline_gazetteer":
        try:
            results.extend(net.search(query))
        except RuntimeError:
            pass  # policy/rate-limit blocked: fall back, recorded by caller
    if offline is not None:
        seen = {(m.point.lat, m.point.lon) for m in results}
        for m in offline.search(query):
            if (m.point.lat, m.point.lon) not in seen:
                results.append(m)
    return results
