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
