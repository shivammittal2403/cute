"""traceatlas.planning.capability_planner - Map disciplines to capabilities."""
from __future__ import annotations

from traceatlas.core.enums import IntelligenceDomain, TaskKind

CAPABILITY_BY_DOMAIN: dict[IntelligenceDomain, list[str]] = {
    IntelligenceDomain.DOMAININT: ["rdap.lookup", "dns.resolve", "cert_search",
                                   "historical_dns.search", "whois.snapshot"],
    IntelligenceDomain.INFRAINT: ["ip.geo", "asn.lookup", "ptr.lookup", "hosting.search"],
    IntelligenceDomain.CORPINT: ["registry.search", "officers.search", "filings.search"],
    IntelligenceDomain.PERSONINT: ["profile.search", "name.correlate"],
    IntelligenceDomain.USERNAMEINT: ["username.availability", "handle.correlate"],
    IntelligenceDomain.SOCMINT: ["public_profile.fetch", "public_posts.search"],
    IntelligenceDomain.CTI: ["ioc.lookup", "cve.lookup", "actor.search"],
    IntelligenceDomain.GEOINT: ["geocode", "reverse_geocode"],
    IntelligenceDomain.WEBINT: ["web.search", "page.fetch", "archive.snapshot"],
}

KIND_BY_CAPABILITY_PREFIX = {"rdap": TaskKind.COLLECT, "dns": TaskKind.COLLECT,
                             "whois": TaskKind.COLLECT, "ip": TaskKind.COLLECT,
                             "asn": TaskKind.COLLECT, "web": TaskKind.COLLECT,
                             "page": TaskKind.COLLECT, "archive": TaskKind.COLLECT,
                             "profile": TaskKind.COLLECT, "public_profile": TaskKind.COLLECT,
                             "public_posts": TaskKind.COLLECT, "username": TaskKind.COLLECT,
                             "registry": TaskKind.COLLECT, "officers": TaskKind.COLLECT,
                             "filings": TaskKind.COLLECT, "cert_search": TaskKind.COLLECT,
                             "historical_dns": TaskKind.COLLECT, "hosting": TaskKind.COLLECT,
                             "ptr": TaskKind.COLLECT, "ioc": TaskKind.COLLECT,
                             "cve": TaskKind.COLLECT, "actor": TaskKind.COLLECT,
                             "geocode": TaskKind.COLLECT, "reverse_geocode": TaskKind.COLLECT,
                             "name": TaskKind.CORRELATE, "handle": TaskKind.CORRELATE}
