"""Certificate Transparency log connector (crt.sh — public, no key needed)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from .base import BaseConnector, CollectResult, is_safe_url


class CertStreamConnector(BaseConnector):
    source_slug = "crtsh"
    connector_type = "rest"
    API = "https://crt.sh/"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def collect(self, target: str, capability: str = "certificates.by_domain") -> CollectResult:
        domain = target.strip().lower()
        url = f"{self.API}?q=%25.{domain}&output=json"
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=reason)
        try:
            with httpx.Client(timeout=self.timeout) as c:
                resp = c.get(url, headers={"User-Agent": "TraceAtlas/0.1"})
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url, error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}")
        try:
            rows = resp.json()
        except ValueError:
            return CollectResult(ok=False, source_uri=url, error="non-json ct response")
        now = datetime.now(timezone.utc).isoformat()
        names: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            for n in str(row.get("name_value", "")).split(","):
                n = n.strip().lower().lstrip("*.")
                if n:
                    names.add(n)
        obs = [{"subject": domain, "predicate": "domain.subdomain_seen_in_ct",
                "value": sorted(names), "observed_at": now}]
        return CollectResult(ok=True, observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"cert_count": len(rows) if isinstance(rows, list) else 0})
