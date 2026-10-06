"""JSON dataset connector family: OpenCorporates + Wikidata.

Both are genuine, keyless public datasets used for CORPINT identity
resolution and entity enrichment:
 * opencorporates.com  -> company registry matches (jurisdiction, status)
 * wikidata.org        -> entity claims (instance-of, official website,
                         country) via the wbgetentities special page
Raw response bytes are preserved as evidence by the engine.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from .base import BaseConnector, CollectResult, is_safe_url


class OpenCorporatesConnector(BaseConnector):
    source_slug = "opencorporates"
    connector_type = "dataset"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def collect(self, target: str, capability: str = "registry.search") -> CollectResult:
        q = quote(target.strip())
        url = f"https://api.opencorporates.com/v0/companies/search?q={q}&jurisdiction_code=&per_page=10"
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
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from opencorporates")
        now = datetime.now(timezone.utc).isoformat()
        obs: list[dict] = []
        hits = ((data.get("results") or {}).get("companies") or [])
        for h in hits:
            co = h.get("company") or {}
            if not co.get("operational_name") and not co.get("name"):
                continue
            obs.append({"subject": target, "predicate": "company.registry_match",
                        "value": {"name": co.get("operational_name") or co.get("name"),
                                  "jurisdiction": co.get("jurisdiction_code"),
                                  "status": co.get("status"),
                                  "opencorporates_id": co.get("id"),
                                  "url": co.get("public_indexed_uri")},
                        "observed_at": now})
        return CollectResult(ok=True, observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "opencorporates", "hits": len(obs)})


class WikidataConnector(BaseConnector):
    source_slug = "wikidata"
    connector_type = "dataset"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def collect(self, target: str, capability: str = "entity.lookup") -> CollectResult:
        # Accept either a QID ("Q475") or a free-text label to search.
        term = target.strip()
        params = f"action=wbgetentities&ids={term}&props=claims|labels|sitelinks&format=json" \
            if term.upper().startswith("Q") else \
            f"action=wbsearchentities&search={quote(term)}&language=en&format=json&limit=5"
        url = f"https://www.wikidata.org/w/api.php?{params}"
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
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from wikidata")
        now = datetime.now(timezone.utc).isoformat()
        obs: list[dict] = []
        if term.upper().startswith("Q"):
            ent = (data.get("entities") or {}).get(term.upper()) or {}
            labels = (ent.get("labels") or {}).get("en", {}).get("value")
            sitelinks = ent.get("sitelinks") or {}
            obs.append({"subject": term, "predicate": "entity.wikidata_label",
                        "value": labels, "observed_at": now})
            for wiki, link in sorted(sitelinks.items()):
                if wiki == "enwiki":
                    obs.append({"subject": term, "predicate": "entity.wikipedia_link",
                                "value": link.get("title"), "observed_at": now})
        else:
            for hit in data.get("search") or []:
                obs.append({"subject": term, "predicate": "entity.wikidata_candidate",
                            "value": {"id": hit.get("id"), "label": hit.get("label"),
                                      "description": hit.get("description")},
                            "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "wikidata"})
