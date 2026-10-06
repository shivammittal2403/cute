"""Wayback Machine availability + CDX connectors (public, keyless).

archive.org Wayback is a genuine ARCHIVEINT source. Two entry points:
 * availability  -> per-URL first/last snapshot timestamps
 * cdx           -> paged snapshot index for a domain (historical URLs)
Raw JSON bytes are preserved as evidence by the engine via CollectResult.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from .base import BaseConnector, CollectResult, is_safe_url


class WaybackAvailabilityConnector(BaseConnector):
    source_slug = "archive-org-wayback-availability"
    connector_type = "archive"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def collect(self, target: str, capability: str = "archive.availability") -> CollectResult:
        url = f"https://archive.org/wayback/available?url={quote(target, safe='')}"
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=self.timeout,
                              headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}")
        try:
            data = json.loads(resp.content)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from archive.org")
        snap = (data.get("archived_snapshots") or {}).get("closest") or {}
        now = datetime.now(timezone.utc).isoformat()
        obs: list[dict] = []
        if snap.get("url"):
            obs.append({"subject": target, "predicate": "archive.snapshot_available",
                        "value": {"url": snap["url"], "timestamp": snap.get("timestamp", ""),
                                  "status": snap.get("status", "")},
                        "observed_at": now})
        else:
            obs.append({"subject": target, "predicate": "archive.snapshot_available",
                        "value": {"url": None}, "observed_at": now})
        return CollectResult(ok=True, observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "archive.org", "has_snapshot": bool(snap)})
