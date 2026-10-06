"""traceatlas.planning.worker_planner - Assign tasks to workers."""
from __future__ import annotations

WORKER_FOR_CAPABILITY = {
    "rdap": "rdap_analyst", "dns": "dns_analyst", "whois": "domain_analyst",
    "historical_dns": "domain_analyst", "cert": "infrastructure_analyst",
    "ip": "ip_analyst", "asn": "asn_analyst", "hosting": "infrastructure_analyst",
    "ptr": "dns_analyst", "web": "web_osint", "page": "web_osint",
    "archive": "archive_analyst", "profile": "person_analyst",
    "public_profile": "socmint_analyst", "public_posts": "socmint_analyst",
    "username": "username_analyst", "registry": "registry_analyst",
    "officers": "company_analyst", "filings": "legal_analyst",
    "ioc": "cti_analyst", "cve": "vulnerability_analyst", "actor": "cti_analyst",
    "geocode": "geo_analyst", "reverse_geocode": "geo_analyst",
    "name": "person_analyst", "handle": "entity_resolution_analyst",
}


def worker_for(capability: str) -> str:
    head = capability.split(".", 1)[0]
    return WORKER_FOR_CAPABILITY.get(head, "search_analyst")
