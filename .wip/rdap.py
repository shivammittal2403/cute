"""traceatlas.sources.connectors.rdap - Real RDAP (domain registration data).

Queries IANA bootstrap for the TLD base URL, then <tld>/domain/<name>.
No credentials required; official protocol. Captures raw JSON as evidence.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from .base import BaseConnector, CollectResult

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


class RDAPConnector(BaseConnector):
    source_slug = "rdap-iana-bootstrap"
    connector_type = "rdap"

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout
        self._bootstrap: dict[str, str] | None = None

    def collect(self, target: str, capability: str = "rdap.domain") -> CollectResult:
        domain = target.strip().lower().lstrip(".")
        tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
        retrieved_at = datetime.now(timezone.utc)
        try:
            base = self._tld_base(tld)
            if not base:
                return CollectResult(ok=False, source_uri=f"rdap://{domain}",
                                     error=f"no RDAP server bootstrapped for TLD {tld!r}")
            url = f"{base.rstrip('/')}/domain/{domain}"
            with httpx.Client(timeout=self.timeout,
                              headers={"Accept": "application/rdap+json"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=f"rdap://{domain}",
                                 error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"rdap http {resp.status_code}")
        try:
            data = resp.json()
        except ValueError:
            return CollectResult(ok=False, source_uri=url, error="rdap response not JSON")
        obs = []
        registrar = ""
        for ent in data.get("entities", []):
            roles = [r.lower() for r in ent.get("roles", [])]
            if "registrar" in roles:
                names = [v.get("handle", "") for v in ent.get("vcardArray", [[None, []]])[1]] if False else []
                vc = ent.get("vcardArray") or [None, []]
                for field in vc[1]:
                    if len(field) >= 2 and field[0] == "fn":
                        registrar = field[3]
                obs.append({"subject": domain, "predicate": "registrar",
                            "value": registrar or ent.get("handle", ""),
                            "observed_at": retrieved_at.isoformat()})
        status_list = data.get("status", [])
        if status_list:
            obs.append({"subject": domain, "predicate": "registration.status",
                        "value": list(status_list), "observed_at": retrieved_at.isoformat()})
        for ev_ in data.get("events", []):
            obs.append({"subject": domain, "predicate": f"registration.event.{ev_.get('eventAction','')}",
                        "value": ev_.get("eventDate"), "observed_at": retrieved_at.isoformat()})
        ns = [n.get("ldhName", "").rstrip(".") for n in data.get("nameservers", [])]
        if ns:
            obs.append({"subject": domain, "predicate": "domain.nameserver",
                        "value": ns, "observed_at": retrieved_at.isoformat()})
        return CollectResult(ok=True, observations=obs, raw_bytes=resp.content,
                             media_type="application/rdap+json", source_uri=url,
                             meta={"retrieved_at": retrieved_at.isoformat(),
                                  "rdap_base": base})

    # ---------------------------------------------------------------- bootstrap
    def _tld_base(self, tld: str) -> str | None:
        if self._bootstrap is None:
            with httpx.Client(timeout=self.timeout) as c:
                bj = c.get(BOOTSTRAP_URL).json()
            self._bootstrap = {}
            for entry in bj.get("services", []):
                bases = entry[1]
                for t in entry[0]:
                    self._bootstrap[t] = bases[0]
        return self._bootstrap.get(tld)
