"""traceatlas.geoint.maps.provider - Map/geocoder provider registry.

Section 15: every map provider must carry terms, license, rate limits,
attribution, data freshness and capabilities. Providers are pluggable; the
default deployment ships an offline deterministic provider so GEOINT works
with zero network access. Network providers require explicit configuration —
restricted map services are never scraped in violation of access controls.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProviderCapability(str, Enum):
    FORWARD_GEOCODE = "forward_geocode"
    REVERSE_GEOCODE = "reverse_geocode"
    PLACES_SEARCH = "places_search"
    ROUTING = "routing"
    ELEVATION = "elevation"
    IMAGERY = "imagery"
    TILES = "tiles"
    BOUNDARIES = "boundaries"


@dataclass(slots=True)
class ProviderPolicy:
    """License/terms envelope enforced at call time."""
    name: str
    license: str = ""
    terms_url: str = ""
    attribution_required: str = ""
    rate_limit_per_min: int = 60
    requires_api_key: bool = False
    allows_bulk_queries: bool = False
    robots_compliant: bool = True
    data_freshness_note: str = ""
    network_allowed: bool = True          # False => offline-only provider


class RateLimitExceeded(RuntimeError):
    pass


class ProviderNotPermitted(RuntimeError):
    pass


@dataclass(slots=True)
class BaseProvider:
    """Common provider object; subclasses implement concrete calls."""
    provider_id: str
    display_name: str
    policy: ProviderPolicy
    capabilities: list[ProviderCapability] = field(default_factory=list)
    api_key: Optional[str] = None
    _calls_this_minute: list[float] = field(default_factory=list)

    def supports(self, cap: ProviderCapability | str) -> bool:
        capv = cap if isinstance(cap, ProviderCapability) else ProviderCapability(str(cap))
        return capv in self.capabilities

    def _check_policy(self, cap: ProviderCapability) -> None:
        if not self.policy.network_allowed:
            raise ProviderNotPermitted(
                f"provider {self.provider_id} is offline-only by policy")
        if not self.supports(cap):
            raise ProviderNotPermitted(
                f"provider {self.provider_id} lacks capability {cap.value}")
        if self.policy.requires_api_key and not self.api_key:
            raise ProviderNotPermitted(
                f"provider {self.provider_id} requires an API key (not configured)")
        self._throttle()

    def _throttle(self) -> None:
        now = time.monotonic()
        self._calls_this_minute[:] = [t for t in self._calls_this_minute if now - t < 60]
        if len(self._calls_this_minute) >= self.policy.rate_limit_per_min:
            raise RateLimitExceeded(f"{self.provider_id}: rate limit "
                                    f"{self.policy.rate_limit_per_min}/min reached")
        self._calls_this_minute.append(now)

    def attribution(self) -> str:
        return self.policy.attribution_required or f"© {self.display_name}"


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, BaseProvider] = {}

    def register(self, provider: BaseProvider) -> None:
        self._providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> BaseProvider | None:
        return self._providers.get(provider_id)

    def capable(self, cap: ProviderCapability | str) -> list[BaseProvider]:
        return [p for p in self._providers.values() if p.supports(cap)]

    def default_for(self, cap: ProviderCapability | str) -> BaseProvider | None:
        cands = self.capable(cap)
        return cands[0] if cands else None
