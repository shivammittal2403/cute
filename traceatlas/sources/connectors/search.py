"""DuckDuckGo HTML lite search connector (SEARCHINT, keyless).

Uses the non-JS html.duckduckgo.com endpoint, parses result links with the
stdlib. This is a genuine public search capability: it emits candidate URLs
and snippets as observations; downstream verification treats them as leads,
not proof. Raw HTML bytes are preserved as evidence.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import quote_plus, unquote, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from .base import BaseConnector, CollectResult, is_safe_url


def _unwrap_ddg(href: str) -> str:
    # DDG routes outbound links via //duckduckgo.com/l/?uddg=<encoded>
    if "uddg=" in href:
        q = parse_qs(urlparse(href, scheme="https").query)
        if "uddg" in q:
            return unquote(q["uddg"][0])
    return href


class DuckDuckGoSearchConnector(BaseConnector):
    source_slug = "duckduckgo-html"
    connector_type = "search"
    ENDPOINT = "https://html.duckduckgo.com/html/"
    MAX_RESULTS = 15

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def collect(self, target: str, capability: str = "web.search") -> CollectResult:
        url = f"{self.ENDPOINT}?q={quote_plus(target)}"
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=self.timeout,
                              headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                resp = c.post(self.ENDPOINT, data={"q": target})
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}",
                                 raw_bytes=resp.content)
        soup = BeautifulSoup(resp.content, "html.parser")
        now = datetime.now(timezone.utc).isoformat()
        obs: list[dict] = []
        for res in soup.select(".result, .web-result")[: self.MAX_RESULTS]:
            a = res.select_one("a.result__a")
            sn = res.select_one(".result__snippet")
            if not a or not a.get("href"):
                continue
            link = _unwrap_ddg(a["href"])
            if not link.startswith("http"):
                continue
            obs.append({"subject": target, "predicate": "search.result",
                        "value": {"url": link, "title": a.get_text(strip=True),
                                  "snippet": sn.get_text(" ", strip=True) if sn else ""},
                        "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=resp.content,
                             media_type="text/html", source_uri=url,
                             meta={"provider": "duckduckgo-html", "results": len(obs)})
