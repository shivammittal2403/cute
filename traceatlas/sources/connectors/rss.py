"""RSS 2.0 / Atom feed connector (stdlib XML parsing, no extra deps).

Real, credential-free collection for RSS/Atom sources: Google News RSS
(per-entity news discovery), public government/news feeds. Raw XML bytes are
preserved as evidence; observations carry title/link/published so downstream
intake can create URL entities and NEWSINT relationships.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote_plus

import httpx

from .base import BaseConnector, CollectResult, is_safe_url

ATOM_NS = "{http://www.w3.org/2005/Atom}"


def _text(el) -> str:
    return (el.text or "").strip() if el is not None else ""


class RSSConnector(BaseConnector):
    source_slug = "rss-generic"
    connector_type = "rss"

    def __init__(self, timeout: float = 15.0, max_items: int = 40):
        self.timeout = timeout
        self.max_items = max_items

    def collect(self, target: str, capability: str = "feed.fetch") -> CollectResult:
        url = target if "://" in target else f"https://{target}"
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True,
                              headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}",
                                 raw_bytes=resp.content)
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            return CollectResult(ok=False, source_uri=url,
                                 error="malformed XML feed", raw_bytes=resp.content)
        now = datetime.now(timezone.utc).isoformat()
        obs: list[dict] = []
        for item in list(root.iter("item"))[: self.max_items]:
            title = _text(item.find("title"))
            link = _text(item.find("link"))
            pub = _text(item.find("pubDate"))
            if title or link:
                obs.append({"subject": url, "predicate": "feed.item",
                            "value": {"title": title, "link": link, "published": pub},
                            "observed_at": now})
        for entry in list(root.iter(f"{ATOM_NS}entry"))[: self.max_items]:
            title = _text(entry.find(f"{ATOM_NS}title"))
            link_el = entry.find(f"{ATOM_NS}link")
            link = link_el.get("href", "") if link_el is not None else ""
            updated = _text(entry.find(f"{ATOM_NS}updated"))
            if title or link:
                obs.append({"subject": url, "predicate": "feed.item",
                            "value": {"title": title, "link": link, "published": updated},
                            "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=resp.content,
                             media_type=resp.headers.get("content-type", "application/rss+xml"),
                             source_uri=url, meta={"items": len(obs)})


class GoogleNewsRSSConnector(RSSConnector):
    """Google News RSS - public, keyless news discovery per entity/query."""

    source_slug = "google-news-rss"
    connector_type = "rss"

    def collect(self, target: str, capability: str = "news.search") -> CollectResult:
        q = quote_plus(target.strip())
        url = f"https://news.google.com/rss/search?q={q}&hl=en&gl=US&ceid=US:en"
        res = super().collect(url, capability="feed.fetch")
        res.source_uri = url
        res.meta = {**res.meta, "provider": "news.google.com", "query": target}
        return res
