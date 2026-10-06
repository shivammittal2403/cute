"""traceatlas.sources.connectors.dns - Real DNS record collection.

Uses dnspython when available; otherwise falls back to the stdlib resolver
for A/AAAA/CNAME via socket, and reports unsupported types honestly rather
than fabricating records. Emits typed observations + raw zone-like text as
evidence bytes.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone

from .base import BaseConnector, CollectResult


class DNSConnector(BaseConnector):
    source_slug = "dns-system"
    connector_type = "dns"
    SUPPORTED = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"}

    def collect(self, target: str, capability: str = "dns.records") -> CollectResult:
        rtype = capability.split(".", 1)[1].upper() if "." in capability[4:] else "A"
        rtype = capability.rsplit(".", 1)[-1].upper()
        if rtype not in self.SUPPORTED:
            return CollectResult(ok=False, source_uri=f"dns://{rtype}/{target}",
                                 error=f"record type {rtype} not supported by this connector")
        retrieved_at = datetime.now(timezone.utc)
        try:
            records = self._resolve(target, rtype)
        except Exception as exc:  # NXDOMAIN, timeout, no resolver
            return CollectResult(ok=False, source_uri=f"dns://{rtype}/{target}",
                                 error=f"{type(exc).__name__}: {exc}")
        obs = [{"subject": target, "predicate": f"dns.{rtype.lower()}",
                "value": v, "observed_at": retrieved_at.isoformat()}
               for v in records]
        raw = json.dumps({"qname": target, "rtype": rtype, "records": records,
                          "resolved_at": retrieved_at.isoformat()},
                         sort_keys=True).encode()
        return CollectResult(ok=True, observations=obs, raw_bytes=raw,
                             media_type="application/json",
                             source_uri=f"dns://{rtype}/{target}",
                             meta={"resolver": self._resolver_name()})

    # ------------------------------------------------------------------ resolve
    def _resolve(self, name: str, rtype: str) -> list[str]:
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(name, rtype, lifetime=5.0)
            return [str(a).rstrip(".") for a in answers]
        except ImportError:
            pass
        # stdlib fallback covers address family lookups only
        if rtype == "A":
            return sorted({i[4][0] for i in socket.getaddrinfo(name, None, socket.AF_INET)})
        if rtype == "AAAA":
            return sorted({i[4][0] for i in socket.getaddrinfo(name, None, socket.AF_INET6)})
        raise RuntimeError(f"dnspython required for {rtype} records")

    @staticmethod
    def _resolver_name() -> str:
        return "system"
