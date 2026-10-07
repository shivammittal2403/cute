"""traceatlas.geoint.maps.reverse_geocoder - Coordinate -> place context.

Offline-first: nearest gazetteer entry with explicit distance and a large
documented uncertainty radius; network providers when configured. Results are
evidence records — reverse geocoding is *context*, not proof of anything about
a person or event (sections 31, 37).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.geoint.geolocation.coordinate_parser import LatLng
from traceatlas.geoint.geolocation.distance import haversine_meters
from traceatlas.geoint.maps.geocoder import GazetteerEntry, _SEED_GAZETTEER
from traceatlas.geoint.maps.provider import (BaseProvider, ProviderCapability,
                                             ProviderPolicy)


@dataclass(slots=True)
class ReverseGeocodeResult:
    result_id: str
    point: LatLng
    display_name: str
    country: str = ""
    region: str = ""
    city: str = ""
    distance_to_named_m: float | None = None   # how far from the nearest named place
    provider_id: str = "offline_gazetteer"
    attribution: str = ""
    accuracy_note: str = ("offline nearest-place estimate; treat as approximate "
                          "context only")
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"result_id": self.result_id, "lat": self.point.lat,
                "lon": self.point.lon, "display_name": self.display_name,
                "country": self.country, "region": self.region, "city": self.city,
                "distance_to_named_m": self.distance_to_named_m,
                "provider_id": self.provider_id, "accuracy_note": self.accuracy_note}


class OfflineReverseGeocoder(BaseProvider):
    def __init__(self, entries: list[GazetteerEntry] | None = None):
        super().__init__(
            provider_id="offline_reverse", display_name="Offline reverse geocoder",
            policy=ProviderPolicy(name="offline_reverse", license="internal",
                                  network_allowed=False),
            capabilities=[ProviderCapability.REVERSE_GEOCODE])
        self.entries = list(entries or _SEED_GAZETTEER)

    def reverse(self, pt: LatLng) -> ReverseGeocodeResult:
        best: tuple[float, GazetteerEntry] | None = None
        for e in self.entries:
            d = haversine_meters(pt, e.point)
            if best is None or d < best[0]:
                best = (d, e)
        if best is None:
            return ReverseGeocodeResult(result_id=new_id("entity"), point=pt,
                                        display_name="unknown (empty gazetteer)",
                                        provider_id=self.provider_id)
        dist, e = best
        return ReverseGeocodeResult(
            result_id=new_id("entity"), point=pt,
            display_name=f"{e.city}, {e.region}, {e.country}",
            country=e.country, region=e.region, city=e.city,
            distance_to_named_m=dist, provider_id=self.provider_id,
            accuracy_note=("nearest offline gazetteer place; no boundary check "
                           f"(distance {dist/1000:.1f} km); approximate context only"))


class NominatimReverseProvider(BaseProvider):
    def __init__(self, endpoint: str, fetcher=None):
        super().__init__(
            provider_id="nominatim_reverse", display_name="OSM-compatible reverse geocoder",
            policy=ProviderPolicy(name="nominatim_reverse",
                                  license="ODbL / provider terms",
                                  terms_url=endpoint,
                                  attribution_required="© OpenStreetMap contributors",
                                  rate_limit_per_min=1),
            capabilities=[ProviderCapability.REVERSE_GEOCODE],
            api_key=None)
        self.endpoint = endpoint
        self._fetch = fetcher

    def reverse(self, pt: LatLng) -> ReverseGeocodeResult:
        self._check_policy(ProviderCapability.REVERSE_GEOCODE)
        if self._fetch is None:
            raise RuntimeError("no fetcher configured for network reverse geocoding")
        item = self._fetch(f"{self.endpoint}/reverse",
                           {"lat": str(pt.lat), "lon": str(pt.lon),
                            "format": "jsonv2"}) or {}
        addr = item.get("address", {})
        return ReverseGeocodeResult(
            result_id=new_id("entity"), point=pt,
            display_name=item.get("display_name", ""),
            country=addr.get("country_code", "").upper(),
            region=addr.get("state", ""),
            city=addr.get("city") or addr.get("town") or addr.get("village", ""),
            provider_id=self.provider_id, attribution=self.attribution(),
            accuracy_note="provider-stated address context; still approximate",
            raw=item)


def reverse_geocode(pt: LatLng, provider: BaseProvider | None = None) -> ReverseGeocodeResult:
    prov = provider if isinstance(provider, (OfflineReverseGeocoder, NominatimReverseProvider)) \
        else OfflineReverseGeocoder()
    return prov.reverse(pt)
