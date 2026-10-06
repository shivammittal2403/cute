"""CTI connectors: OSV vulnerability database + CVE record (keyless, official).

 * osv.dev           -> vulnerabilities affecting a software/package
                       (CODEINT/SUPPLYCHAININT/VULNINT)
 * cve.circl.lu      -> enriched CVE record (descriptions, refs, CVSS)
                       (VULNINT)  [public mirror of MITRE data]
Both preserve raw bytes as evidence; failures are reported honestly.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from .base import BaseConnector, CollectResult, is_safe_url


def _fetch(url: str, timeout: float = 15.0) -> tuple[bytes | None, int, str]:
    ok, reason = is_safe_url(url)
    if not ok:
        return None, 0, f"url_policy: {reason}"
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": "TraceAtlas/0.1"}) as c:
            resp = c.get(url)
    except httpx.HTTPError as exc:
        return None, 0, f"{type(exc).__name__}: {exc}"
    if resp.status_code != 200:
        return None, resp.status_code, f"http {resp.status_code}"
    return resp.content, resp.status_code, ""


class OSVConnector(BaseConnector):
    source_slug = "osv-dev"
    connector_type = "rest"

    def collect(self, target: str, capability: str = "vulnerabilities.by_package") -> CollectResult:
        # target: "ecosystem|package" e.g. "PyPI|requests" or "npm|lodash"
        url = "https://api.osv.dev/v1/query"
        if "|" in target:
            eco, pkg = target.split("|", 1)
            body = json.dumps({"package": {"name": pkg.strip(),
                                           "ecosystem": eco.strip()}}).encode()
        else:
            body = json.dumps({"package": {"name": target.strip()}}).encode()
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=15.0, headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                resp = c.post(url, content=body,
                              headers={"Content-Type": "application/json"})
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url, error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}")
        try:
            data = json.loads(resp.content)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from osv.dev")
        now = datetime.now(timezone.utc).isoformat()
        obs = []
        for v in data.get("vulns") or []:
            aliases = v.get("aliases") or []
            cve = next((a for a in aliases if a.upper().startswith("CVE-")), None)
            obs.append({"subject": target, "predicate": "package.vulnerability",
                        "value": {"osv_id": v.get("id"), "cve": cve,
                                  "summary": (v.get("summary") or "")[:300],
                                  "severity": (v.get("severity") or [])[:3]},
                        "observed_at": now})
        return CollectResult(ok=True, observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "osv.dev", "count": len(obs)})


class CVERecordConnector(BaseConnector):
    source_slug = "cve-circl"
    connector_type = "rest"

    def collect(self, target: str, capability: str = "cve.lookup") -> CollectResult:
        cve = target.strip().upper()
        if not cve.startswith("CVE-"):
            return CollectResult(ok=False, source_uri="", error=f"not a CVE id: {target!r}")
        url = f"https://cve.circl.lu/api/cve/{quote(cve)}"
        raw, status, err = _fetch(url)
        if raw is None:
            return CollectResult(ok=False, source_uri=url, error=err)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from cve.circl.lu")
        now = datetime.now(timezone.utc).isoformat()
        obs = []
        if isinstance(data, dict) and data.get("id"):
            obs.append({"subject": cve, "predicate": "vulnerability.record",
                        "value": {"summary": (data.get("summary") or "")[:400],
                                  "cvss": data.get("cvss"),
                                  "published": data.get("published")},
                        "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=raw,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "cve.circl.lu"})
