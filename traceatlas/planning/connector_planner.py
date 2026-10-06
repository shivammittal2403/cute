"""traceatlas.planning.connector_planner - Bind capability -> connector type."""
from __future__ import annotations

CONNECTOR_FOR = {"rdap": "rdap", "dns": "dns", "whois": "rdap",
                 "historical_dns": "rest", "web": "rest", "page": "http",
                 "archive": "archive", "ioc": "stix", "cve": "rest",
                 "cert": "rest", "public_profile": "rest", "geocode": "rest",
                 "registry": "rest", "filings": "rest", "officers": "rest",
                 "hosting": "rest", "asn": "rest", "ip": "rest", "ptr": "dns",
                 "username": "rest", "actor": "rest", "name": "rest",
                 "handle": "rest", "profile": "rest", "public_posts": "rest",
                 "reverse_geocode": "rest"}


def connector_for(capability: str) -> str:
    return CONNECTOR_FOR.get(capability.split(".", 1)[0], "rest")
