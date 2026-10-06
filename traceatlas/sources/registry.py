"""traceatlas.sources.registry - Governed source registry.

Loads YAML catalog files (sources/catalog/*.yaml) into SourceRecord objects
and exposes capability-based lookup with qualification filtering. A record in
the catalog is DOCUMENTED at best until a connector + live test proves more;
qualification here only controls planning eligibility, never truth claims.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

QUALIFICATION_ORDER = ["conceptual", "documented", "integration_tested",
                       "live_verified", "production_qualified"]


@dataclass(slots=True)
class SourceRecord:
    slug: str
    name: str = ""
    capabilities: tuple[str, ...] = ()
    entity_types: tuple[str, ...] = ()
    qualification: str = "conceptual"
    connector: str = ""
    base_url: str = ""
    requires_credentials: bool = False
    cost_class: str = "free"
    rate_limit: str = ""
    homepage: str = ""
    notes: str = ""

    def qualified_at_least(self, level: str) -> bool:
        try:
            return QUALIFICATION_ORDER.index(self.qualification) >= QUALIFICATION_ORDER.index(level)
        except ValueError:
            return False


class SourceRegistry:
    def __init__(self, records: list[SourceRecord] | None = None):
        self.records: list[SourceRecord] = records or []
        self._by_slug = {r.slug: r for r in self.records}

    @classmethod
    def load_default(cls, catalog_dir: str | Path | None = None) -> "SourceRegistry":
        root = Path(catalog_dir) if catalog_dir else _default_catalog_dir()
        records: list[SourceRecord] = []
        if root and root.exists():
            for path in sorted(root.glob("*.yaml")):
                try:
                    data = yaml.safe_load(path.read_text()) or {}
                except yaml.YAMLError:
                    continue
                entries = data.get("sources") if isinstance(data, dict) else data
                if not isinstance(entries, list):
                    continue
                for item in entries:
                    rec = _record_from_dict(item, default_file=path.stem)
                    if rec:
                        records.append(rec)
        # built-in connectors that are actually implemented in this repo
        builtin = [
            SourceRecord(slug="dns-system", name="System DNS resolver",
                         capabilities=("dns.A", "dns.AAAA", "dns.CNAME", "dns.MX",
                                       "dns.TXT", "dns.NS"),
                         entity_types=("domain", "ip_address"),
                         qualification="integration_tested", connector="dns"),
            SourceRecord(slug="rdap-iana-bootstrap", name="RDAP (IANA bootstrap)",
                         capabilities=("rdap.domain",),
                         entity_types=("domain", "organization"),
                         qualification="integration_tested", connector="rdap",
                         base_url="https://rdap.org"),
            SourceRecord(slug="web-direct", name="Direct HTTP(S) fetch",
                         capabilities=("web.fetch",),
                         entity_types=("url",),
                         qualification="integration_tested", connector="http"),
            SourceRecord(slug="crtsh", name="crt.sh Certificate Transparency",
                         capabilities=("certificates.by_domain",),
                         entity_types=("domain",),
                         qualification="integration_tested", connector="rest",
                         base_url="https://crt.sh"),
            SourceRecord(slug="ipwhois-co", name="ipwhois.co IP Intelligence",
                         capabilities=("ip.geo",), entity_types=("ip_address","asn","organization","location"),
                         qualification="integration_tested", connector="rest",
                         base_url="https://ipwhois.co", homepage="https://ipwhois.co"),
            SourceRecord(slug="rir-rdap-ip", name="RIR RDAP prefix whois (ARIN/RIPE/APNIC/LACNIC/AFRINIC)",
                         capabilities=("prefix.owner",), entity_types=("ip_address","organization","prefix"),
                         qualification="integration_tested", connector="rest",
                         base_url="https://rdap.arin.net"),
            SourceRecord(slug="bgp-tools-asn", name="BGP.tools ASN status",
                         capabilities=("asn.info",), entity_types=("asn","prefix"),
                         qualification="integration_tested", connector="rest",
                         base_url="https://api.bgp.tools"),
            SourceRecord(slug="hackertarget-reverse-dns", name="HackerTarget Reverse DNS",
                         capabilities=("dns.ptr",), entity_types=("ip_address","domain"),
                         qualification="integration_tested", connector="rest",
                         base_url="https://api.hackertarget.com"),
            SourceRecord(slug="archive-org-wayback", name="Internet Archive Wayback CDX",
                         capabilities=("archive.snapshots",), entity_types=("url","domain"),
                         qualification="integration_tested", connector="rest",
                         base_url="http://web.archive.org"),
            SourceRecord(slug="google-news-rss", name="Google News RSS",
                         capabilities=("news.search",), entity_types=("url","organization"),
                         qualification="integration_tested", connector="rss",
                         base_url="https://news.google.com/rss/search"),
            SourceRecord(slug="duckduckgo-html", name="DuckDuckGo HTML search",
                         capabilities=("web.search",), entity_types=("url",),
                         qualification="integration_tested", connector="search",
                         base_url="https://html.duckduckgo.com/html/"),
            SourceRecord(slug="opencorporates", name="OpenCorporates company registry",
                         capabilities=("registry.search",), entity_types=("company",),
                         qualification="integration_tested", connector="dataset",
                         base_url="https://api.opencorporates.com", requires_credentials=False,
                         notes="free tier; rate-limited anonymous access"),
            SourceRecord(slug="wikidata", name="Wikidata entity API",
                         capabilities=("entity.lookup",), entity_types=("person","company","organization"),
                         qualification="integration_tested", connector="dataset",
                         base_url="https://www.wikidata.org/w/api.php"),
            SourceRecord(slug="osv-dev", name="OSV vulnerability database",
                         capabilities=("vulnerabilities.by_package",), entity_types=("package","vulnerability"),
                         qualification="integration_tested", connector="rest",
                         base_url="https://api.osv.dev"),
            SourceRecord(slug="cve-circl", name="CVE Program mirror (CIRCL)",
                         capabilities=("cve.lookup",), entity_types=("vulnerability",),
                         qualification="integration_tested", connector="rest",
                         base_url="https://cve.circl.lu/api/cve/"),
            SourceRecord(slug="nominatim-osm", name="Nominatim (OpenStreetMap) geocoder",
                         capabilities=("geocode", "reverse_geocode"), entity_types=("location",),
                         qualification="integration_tested", connector="geocoding",
                         base_url="https://nominatim.openstreetmap.org"),
            SourceRecord(slug="blockstream-btc", name="Blockstream BTC explorer",
                         capabilities=("wallet.transactions",), entity_types=("wallet","transaction"),
                         qualification="integration_tested", connector="public_explorer",
                         base_url="https://blockstream.info/api"),
            SourceRecord(slug="etherscan-eth", name="Etherscan ETH explorer",
                         capabilities=("wallet.transactions.eth",), entity_types=("wallet","transaction"),
                         qualification="conceptual", connector="public_explorer",
                         base_url="https://api.etherscan.io", requires_credentials=True,
                         notes="requires TRACEATLAS_ETHERSCAN_KEY; honest credential_required failure without it"),
            SourceRecord(slug="github-api", name="GitHub public REST API",
                         capabilities=("repo.info", "repo.contributors", "org.repos"),
                         entity_types=("repository","person","organization"),
                         qualification="integration_tested", connector="rest",
                         base_url="https://api.github.com"),
            SourceRecord(slug="username-probe", name="Username availability probe",
                         capabilities=("username.availability",), entity_types=("username","account"),
                         qualification="integration_tested", connector="search",
                         base_url="https://github.com"),
            SourceRecord(slug="archive-org-wayback-availability", name="Wayback availability API",
                         capabilities=("archive.availability",), entity_types=("url",),
                         qualification="integration_tested", connector="archive",
                         base_url="https://archive.org/wayback/available"),
        ]
        for b in builtin:
            if b.slug not in {r.slug for r in records}:
                records.append(b)
        return cls(records)

    # ------------------------------------------------------------------ lookup
    def find(self, capability: str | None = None,
             min_qualification: str = "documented") -> list[SourceRecord]:
        out = []
        for r in self.records:
            if capability and capability not in r.capabilities:
                continue
            if not r.qualified_at_least(min_qualification):
                continue
            out.append(r)
        return out

    def get(self, slug: str) -> SourceRecord | None:
        return self._by_slug.get(slug)

    def __len__(self) -> int:
        return len(self.records)


def _record_from_dict(item: dict, default_file: str = "") -> SourceRecord | None:
    if not isinstance(item, dict):
        return None
    slug = str(item.get("slug") or item.get("source_id") or item.get("id") or "").strip()
    if not slug:
        return None
    caps = item.get("capabilities") or []
    if isinstance(caps, str):
        caps = [caps]
    ents = item.get("entity_types") or []
    if isinstance(ents, str):
        ents = [ents]
    return SourceRecord(
        slug=slug, name=str(item.get("name") or slug),
        capabilities=tuple(str(c) for c in caps),
        entity_types=tuple(str(e) for e in ents),
        qualification=str(item.get("qualification") or item.get("maturity") or "conceptual"),
        connector=str(item.get("connector") or ""),
        base_url=str(item.get("base_url") or item.get("homepage_api") or ""),
        requires_credentials=bool(item.get("requires_credentials") or item.get("api_key_required")),
        cost_class=str(item.get("cost_class") or "free"),
        rate_limit=str(item.get("rate_limit") or ""),
        homepage=str(item.get("homepage") or ""),
        notes=str(item.get("notes") or default_file))


def _default_catalog_dir() -> Path | None:
    for candidate in (Path("sources/catalog"), Path(__file__).resolve().parents[2] / "sources" / "catalog"):
        if candidate.exists():
            return candidate
    return None
