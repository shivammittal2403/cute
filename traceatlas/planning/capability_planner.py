"""traceatlas.planning.capability_planner - Map disciplines to capabilities."""
from __future__ import annotations

from traceatlas.core.enums import IntelligenceDomain, TaskKind

# Capability names here MUST match what connectors actually serve and what
# SourceRegistry records advertise (see traceatlas/sources/registry.py).
CAPABILITY_BY_DOMAIN: dict[IntelligenceDomain, list[str]] = {
    IntelligenceDomain.DOMAININT: ["rdap.domain", "dns.A", "dns.NS", "certificates.by_domain"],
    IntelligenceDomain.INFRAINT: ["dns.AAAA"],
    IntelligenceDomain.CORPINT: ["registry.search", "officers.search", "filings.search"],
    IntelligenceDomain.PERSONINT: ["profile.search", "name.correlate"],
    IntelligenceDomain.USERNAMEINT: ["username.availability", "handle.correlate"],
    IntelligenceDomain.SOCMINT: ["public_profile.fetch", "public_posts.search"],
    IntelligenceDomain.CTI: ["ioc.lookup", "cve.lookup", "actor.search"],
    IntelligenceDomain.GEOINT: ["geocode", "reverse_geocode"],
    IntelligenceDomain.WEBINT: ["web.fetch"],
}

KIND_BY_CAPABILITY_PREFIX = {"rdap": TaskKind.COLLECT, "dns": TaskKind.COLLECT,
                             "whois": TaskKind.COLLECT, "ip": TaskKind.COLLECT,
                             "asn": TaskKind.COLLECT, "web": TaskKind.COLLECT,
                             "page": TaskKind.COLLECT, "archive": TaskKind.COLLECT,
                             "profile": TaskKind.COLLECT, "public_profile": TaskKind.COLLECT,
                             "public_posts": TaskKind.COLLECT, "username": TaskKind.COLLECT,
                             "registry": TaskKind.COLLECT, "officers": TaskKind.COLLECT,
                             "filings": TaskKind.COLLECT, "certificates": TaskKind.COLLECT,
                             "historical_dns": TaskKind.COLLECT, "hosting": TaskKind.COLLECT,
                             "ptr": TaskKind.COLLECT, "ioc": TaskKind.COLLECT,
                             "cve": TaskKind.COLLECT, "actor": TaskKind.COLLECT,
                             "geocode": TaskKind.COLLECT, "reverse_geocode": TaskKind.COLLECT,
                             "name": TaskKind.CORRELATE, "handle": TaskKind.CORRELATE}
