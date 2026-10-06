"""Real, credential-free REST connectors for the governed source fabric.

Each connector here hits a genuine public API over HTTPS, preserves raw bytes
as evidence, and emits typed observations. Nothing is fabricated: if an
endpoint fails or rate-limits, CollectResult.ok=False carries the honest error
and the investigation continues with other sources.

Providers implemented (all free, no key required):
  * ipwhois.co     -> IP geolocation + ASN owner context      (IPINT/ASNINT)
  * RIR whois      -> prefix allocation ownership (ARIN/RIPE/
                      APNIC/LACNIC/AFRINIC chosen by prefix)   (ASNINT/INFRAINT)
  * BGP.tools      -> ASN -> prefixes + name/country          (ASNINT)
  * crt.sh         -> certificate transparency by domain      (DOMAININT)
  * Wayback CDX    -> archive snapshot index                  (ARCHIVEINT)
  * HackerTarget   -> reverse DNS (PTR) per IP                (INFRAINT)
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

from .base import BaseConnector, CollectResult
from .http import HTTPConnector


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _RestConnector(BaseConnector):
    connector_type = "rest"

    def __init__(self, http: HTTPConnector | None = None, timeout: float = 15.0):
        self.http = http or HTTPConnector(timeout=timeout)

    # subclasses call this; returns the underlying CollectResult untouched so
    # raw response bytes are preserved as evidence by the engine.
    def _get_json(self, url: str) -> CollectResult:
        res = self.http.collect(url)
        res.source_uri = url
        return res


class IPGeoConnector(_RestConnector):
    """ipwhois.co JSON API: geolocation + ASN + org for an IPv4/IPv6 address."""

    source_slug = "ipwhois-co"

    def collect(self, target: str, capability: str = "ip.geo") -> CollectResult:
        url = f"https://ipwhois.co/{quote(target)}.json"
        res = self._get_json(url)
        if not res.ok or not res.raw_bytes:
            return res
        try:
            data = json.loads(res.raw_bytes)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url,
                                 error="invalid JSON from ipwhois.co")
        if data.get("success") is False:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"lookup failed: {data.get('error')}")
        ts = _now()
        obs: list[dict] = []
        if data.get("ip"):
            obs.append({"subject": target, "predicate": "ip.address",
                        "value": str(data["ip"]), "observed_at": ts})
        asn = data.get("asn")
        if asn and str(asn).upper().startswith("AS"):
            obs.append({"subject": target, "predicate": "ip.asn",
                        "value": str(asn), "observed_at": ts})
        if data.get("connection_type"):
            obs.append({"subject": target, "predicate": "ip.connection_type",
                        "value": str(data["connection_type"]), "observed_at": ts})
        org = data.get("org") or data.get("isp")
        if org:
            obs.append({"subject": target, "predicate": "ip.organization",
                        "value": str(org), "observed_at": ts})
        country = data.get("country_code") or data.get("country")
        if country:
            obs.append({"subject": target, "predicate": "ip.country",
                        "value": str(country), "observed_at": ts})
        lat, lon = data.get("lat"), data.get("lng")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            obs.append({"subject": target, "predicate": "ip.location",
                        "value": f"{lat},{lon}", "observed_at": ts})
        res.observations = obs
        res.meta = {**res.meta, "provider": "ipwhois.co"}
        return res


_RIR_ENDPOINTS = [
    ("https://rdap.arin.net/registry/ip/", r"^((38|54|6[4-9]|[7-8][0-9]|9[0-9]|[1-9][0-9]{2,3})\.)"),
    ("https://rdap.ripe.net/ip/", r"^(2[0-4][0-9]|19[3-9])\."),
    ("https://rdap.apnic.net/ip/", r"^(1|11|2[5-9]|3[0-7]|10[0-9]|11[0-9]|12[0-6])\."),
    ("https://rdap.lacnic.net/rdap/ip/", r"^(17[7-9]|18[0-9]|19[0-2]|2[0-4])\."),
    ("https://rdap.afrinic.net/rdap/ip/", r"^(41|10[2-5]|15[4-6])\."),
]


class PrefixWhoisConnector(_RestConnector):
    """Official RIR RDAP: which organization holds the prefix containing an IP."""

    source_slug = "rir-rdap-ip"

    def collect(self, target: str, capability: str = "prefix.owner") -> CollectResult:
        first = target.split(".")[0] if "." in target else ""
        for base, pat in _RIR_ENDPOINTS:
            if re.match(pat, first or ""):
                return self._finish(self._get_json(base + quote(target)), target)
        # default: ARIN covers most unallocated space historically
        return self._finish(self._get_json(
            "https://rdap.arin.net/registry/ip/" + quote(target)), target)

    @staticmethod
    def _finish(res: CollectResult, target: str) -> CollectResult:
        if not res.ok or not res.raw_bytes:
            return res
        try:
            data = json.loads(res.raw_bytes)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=res.source_uri,
                                 error="invalid RDAP JSON")
        ts = _now()
        obs: list[dict] = []
        handle = data.get("handle", "")
        name = ""
        for ent in data.get("entities", []):
            vcard = ent.get("vcardArray") or []
            for item in (vcard[1] if len(vcard) > 1 else []):
                if len(item) > 3 and item[0] == "fn":
                    name = name or str(item[3])
        if handle:
            obs.append({"subject": target, "predicate": "prefix.handle",
                        "value": str(handle), "observed_at": ts})
        if name:
            obs.append({"subject": target, "predicate": "prefix.owner",
                        "value": name, "observed_at": ts})
        res.observations = obs
        return res


class AsnInfoConnector(_RestConnector):
    """bgp.tools status API: ASN -> announced prefixes, name, country."""

    source_slug = "bgp-tools-asn"

    def collect(self, target: str, capability: str = "asn.info") -> CollectResult:
        asn = target.upper().replace("AS", "").strip()
        if not asn.isdigit():
            return CollectResult(ok=False, error=f"not an ASN: {target!r}")
        url = f"https://api.bgp.tools/status?asn={asn}"
        res = self._get_json(url)
        if not res.ok or not res.raw_bytes:
            return res
        try:
            data = json.loads(res.raw_bytes)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url,
                                 error="invalid JSON from bgp.tools")
        info = data.get(str(asn)) if isinstance(data, dict) else None
        if not info:
            return CollectResult(ok=False, source_uri=url,
                                 error=f"ASN AS{asn} not found")
        ts = _now()
        obs: list[dict] = [
            {"subject": f"AS{asn}", "predicate": "asn.name",
             "value": str(info.get("descr") or info.get("name") or ""),
             "observed_at": ts},
            {"subject": f"AS{asn}", "predicate": "asn.country",
             "value": str(info.get("country") or ""), "observed_at": ts},
        ]
        for pfx in info.get("prefixes", [])[:50]:
            obs.append({"subject": f"AS{asn}", "predicate": "asn.prefix",
                        "value": str(pfx), "observed_at": ts})
        res.observations = [o for o in obs if o["value"]]
        return res


class CertStreamConnector(_RestConnector):
    """crt.sh Certificate Transparency: subdomains + certs issued for a domain."""

    source_slug = "crtsh"

    def collect(self, target: str, capability: str = "certificates.by_domain") -> CollectResult:
        url = f"https://crt.sh/?q={quote(target)}&output=json"
        res = self._get_json(url)
        if not res.ok or not res.raw_bytes:
            return res
        try:
            rows = json.loads(res.raw_bytes)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url,
                                 error="crt.sh returned non-JSON (rate limited?)")
        if not isinstance(rows, list):
            return CollectResult(ok=False, source_uri=url,
                                 error="unexpected crt.sh payload")
        ts = _now()
        seen: set[tuple[str, str]] = set()
        obs: list[dict] = []
        for row in rows[:500]:
            issuer = str(row.get("issuer_name", ""))
            if "CA Cert" in issuer or "Test" in issuer or "(DV)" in issuer and False:
                pass  # keep all; analyst filters — we report what CT says
            for name in re.split(r"[,\n]", str(row.get("name_value", ""))):
                name = name.strip().lower().lstrip("*.")
                key = (name, str(row.get("id", "")))
                if not name or key in seen:
                    continue
                seen.add(key)
                obs.append({"subject": name, "predicate": "certificate.issued_for",
                            "value": f"id={row.get('id','')} issuer={issuer[:80]}",
                            "observed_at": ts})
        res.observations = obs
        return res


class WaybackConnector(_RestConnector):
    """Internet Archive CDX: historical snapshots of a URL/domain."""

    source_slug = "archive-org-wayback"

    def collect(self, target: str, capability: str = "archive.snapshots") -> CollectResult:
        url = (f"http://web.archive.org/cdx/search/cdx?url={quote(target)}"
               f"&matchType=domain&limit=25&output=json&collapse=timestamp:6")
        res = self._get_json(url)
        if not res.ok or not res.raw_bytes:
            return res
        try:
            rows = json.loads(res.raw_bytes)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid CDX JSON")
        if not isinstance(rows, list) or len(rows) < 2:
            return CollectResult(ok=True, source_uri=url, observations=[],
                                 meta={**res.meta, "note": "no snapshots"})
        header = rows[0]
        idx = {c: i for i, c in enumerate(header)}
        ts = _now()
        obs: list[dict] = []
        for row in rows[1:]:
            snap = str(row[idx.get("timestamp", 1)])
            orig = str(row[idx.get("original", 2)])
            obs.append({"subject": target, "predicate": "archive.snapshot",
                        "value": f"{snap} {orig}", "observed_at": ts})
        res.observations = obs
        return res


class ReverseDNSConnector(_RestConnector):
    """HackerTarget free PTR lookup: IP -> co-located hostnames."""

    source_slug = "hackertarget-reverse-dns"

    def collect(self, target: str, capability: str = "dns.ptr") -> CollectResult:
        url = f"https://api.hackertarget.com/reversedns/?q={quote(target)}"
        res = self._get_json(url)
        if not res.ok or not res.raw_bytes:
            return res
        text = res.raw_bytes.decode("utf-8", "replace").strip()
        if text.startswith("error") or not text:
            return CollectResult(ok=False, source_uri=url,
                                 error=text or "empty PTR response")
        ts = _now()
        obs = [{"subject": target, "predicate": "ptr.hostname",
                "value": line.strip(), "observed_at": ts}
               for line in text.splitlines() if line.strip()]
        res.observations = obs
        res.media_type = "text/plain"
        return res
