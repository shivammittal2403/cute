"""Username availability connector (USERNAMEINT, keyless public profiles).

Checks a handle against a fixed allow-list of public profile endpoints that
return 200 for existing profiles and 404 for missing ones. No authentication,
no scraping of private data, no CAPTCHA bypass — just HTTP status probes on
public profile URLs, each response preserved as evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from .base import BaseConnector, CollectResult, is_safe_url

# Conservative, widely-documented public profile patterns.
PLATFORMS: dict[str, str] = {
    "github": "https://github.com/{u}",
    "gitlab": "https://gitlab.com/{u}",
    "reddit": "https://www.reddit.com/user/{u}",
    "x": "https://x.com/{u}",
    "instagram": "https://www.instagram.com/{u}/",
    "youtube": "https://www.youtube.com/@{u}",
}


class UsernameAvailabilityConnector(BaseConnector):
    source_slug = "username-probe"
    connector_type = "search"

    def __init__(self, timeout: float = 10.0, platforms: list[str] | None = None):
        self.timeout = timeout
        self.platforms = platforms or sorted(PLATFORMS)

    def collect(self, target: str, capability: str = "username.availability") -> CollectResult:
        user = target.strip().lstrip("@")
        if not user or len(user) > 64:
            return CollectResult(ok=False, source_uri="", error="invalid username")
        now = datetime.now(timezone.utc).isoformat()
        obs: list[dict] = []
        raw_parts: list[bytes] = []
        errors: list[str] = []
        for plat in self.platforms:
            url = PLATFORMS[plat].format(u=user)
            ok, reason = is_safe_url(url)
            if not ok:
                errors.append(f"{plat}: url_policy {reason}")
                continue
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True,
                                  headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                    resp = c.head(url, allow_redirects=True)
                    status = resp.status_code
                    if status in (403, 405, 400):  # some sites reject HEAD; retry GET
                        resp = c.get(url)
                        status = resp.status_code
            except httpx.HTTPError as exc:
                errors.append(f"{plat}: {type(exc).__name__}")
                continue
            exists = status == 200
            obs.append({"subject": user, "predicate": "username.profile_exists",
                        "value": {"platform": plat, "url": url, "http_status": status,
                                  "exists": exists},
                        "observed_at": now})
            raw_parts.append(f"{plat}\t{status}\t{len(resp.content)}\n".encode())
        meta = {"provider": "username-probe", "platforms": len(obs),
                "errors": errors[:8]}
        return CollectResult(ok=bool(obs), observations=obs,
                             raw_bytes=b"".join(raw_parts),
                             media_type="text/tab-separated-values",
                             source_uri=f"username://{user}", meta=meta)
