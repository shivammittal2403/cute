"""traceatlas.sources.connectors.http - Governed HTTP GET collector.

Enforces the SSRF/url policy before any request, uses an explicit UA that
identifies TraceAtlas, honours timeouts, captures full response bytes as
evidence material, and never follows into private space blindly (re-checks
final URL host after redirects).
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from .base import BaseConnector, CollectResult, is_safe_url

USER_AGENT = "TraceAtlas/0.1 (authorized OSINT research; contact: security@traceatlas.dev)"
MAX_BYTES = 5 * 1024 * 1024  # 5 MB cap per fetch


class HTTPConnector(BaseConnector):
    source_slug = "web-direct"
    connector_type = "http"

    def __init__(self, allow_private: bool = False, timeout: float = 15.0):
        self.allow_private = allow_private
        self.timeout = timeout

    def collect(self, target: str, capability: str = "web.fetch") -> CollectResult:
        url = target if "://" in target else f"https://{target}"
        ok, reason = is_safe_url(url, self.allow_private)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True,
                              headers={"User-Agent": USER_AGENT}) as client:
                resp = client.get(url)
                final_ok, final_reason = is_safe_url(str(resp.url), self.allow_private)
                if not final_ok:
                    return CollectResult(ok=False, source_uri=str(resp.url),
                                         error=f"url_policy redirect: {final_reason}")
                body = resp.content[:MAX_BYTES]
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"{type(exc).__name__}: {exc}")
        retrieved_at = datetime.now(timezone.utc)
        obs = [{"subject": url, "predicate": "web.status", "value": resp.status_code,
                "observed_at": retrieved_at.isoformat(),
                "context": {"content_type": resp.headers.get("content-type", ""),
                            "server": resp.headers.get("server", "")}}]
        return CollectResult(ok=200 <= resp.status_code < 400, observations=obs,
                             raw_bytes=body,
                             media_type=resp.headers.get("content-type", "application/octet-stream"),
                             source_uri=str(resp.url),
                             meta={"status": resp.status_code,
                                   "retrieved_at": retrieved_at.isoformat(),
                                   "truncated": len(resp.content) > MAX_BYTES})
