"""GitHub public REST connectors (CODEINT/SUPPLYCHAININT, keyless within rate limit).

 * repo.info        -> repository metadata + owner
 * repo.contributors-> contributor logins
 * org.repos        -> public repos of an organization
Used for company/person code footprint mapping. Raw bytes preserved as evidence.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import httpx

from .base import BaseConnector, CollectResult, is_safe_url

API = "https://api.github.com"


class GitHubConnector(BaseConnector):
    source_slug = "github-api"
    connector_type = "rest"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def _get(self, url: str) -> tuple[bytes | None, str]:
        ok, reason = is_safe_url(url)
        if not ok:
            return None, f"url_policy: {reason}"
        try:
            with httpx.Client(timeout=self.timeout, headers={
                    "User-Agent": "TraceAtlas/0.1", "Accept": "application/vnd.github+json"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return None, f"{type(exc).__name__}: {exc}"
        if resp.status_code == 403:
            return None, "rate_limited (github anonymous quota)"
        if resp.status_code != 200:
            return None, f"http {resp.status_code}"
        return resp.content, ""

    def collect(self, target: str, capability: str = "repo.info") -> CollectResult:
        now = datetime.now(timezone.utc).isoformat()
        m = re.match(r"^([\w.-]+)/([\w.-]+)$", target.strip())
        obs: list[dict] = []
        raw = b""
        err = ""
        url = ""
        if capability == "org.repos":
            url = f"{API}/orgs/{target.strip()}/repos?per_page=30"
            raw, err = self._get(url)
            if raw:
                for r in json.loads(raw):
                    obs.append({"subject": target, "predicate": "organization.repository",
                                "value": {"full_name": r.get("full_name"),
                                          "language": r.get("language"),
                                          "url": r.get("html_url")},
                                "observed_at": now})
        elif m and capability in ("repo.info", "repo.contributors"):
            full = f"{m.group(1)}/{m.group(2)}"
            if capability == "repo.contributors":
                url = f"{API}/repos/{full}/contributors?per_page=30"
                raw, err = self._get(url)
                if raw:
                    for u in json.loads(raw):
                        obs.append({"subject": full, "predicate": "repository.contributor",
                                    "value": {"login": u.get("login"), "type": u.get("type")},
                                    "observed_at": now})
            else:
                url = f"{API}/repos/{full}"
                raw, err = self._get(url)
                if raw:
                    d = json.loads(raw)
                    obs.append({"subject": full, "predicate": "repository.metadata",
                                "value": {"owner": (d.get("owner") or {}).get("login"),
                                          "description": (d.get("description") or "")[:300],
                                          "homepage": d.get("homepage"),
                                          "stars": d.get("stargazers_count")},
                                "observed_at": now})
        else:
            return CollectResult(ok=False, source_uri="",
                                 error=f"bad target for {capability}: {target!r}")
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=raw,
                             media_type="application/json", source_uri=url,
                             error=err, meta={"provider": "github"})
