"""traceatlas.intelligence.skills — shared skill registry/matcher (§11).

Skills constrain what a worker may do. A worker executes ONLY declared and
authorized skills; the matcher refuses tasks requiring skills nobody holds.
This is the authoritative registry: modules reference skill ids, they do not
fork their own copies.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SkillSpec:
    skill_id: str
    description: str
    # capabilities (source-registry style) this skill consumes when it needs data
    required_capabilities: tuple[str, ...] = ()
    # input kinds the skill can process (module accepted_inputs vocabulary)
    input_kinds: tuple[str, ...] = ()
    network: bool = False           # skill performs outbound collection itself
    offline_deterministic: bool = False


# ---------------------------------------------------------------- canonical list
_SKILLS: list[SkillSpec] = [
    SkillSpec("web_search", "Ranked public web search via configured providers.",
              required_capabilities=("web.search",), input_kinds=("query", "text"), network=True),
    SkillSpec("web_fetch", "Fetch and preserve a public/authorized URL.",
              required_capabilities=("web.fetch",), input_kinds=("url",), network=True),
    SkillSpec("dork_generation", "Compile provider-specific advanced search queries.",
              input_kinds=("query", "entity"), offline_deterministic=True),
    SkillSpec("archive_search", "Query historical captures (Wayback CDX/availability).",
              required_capabilities=("archive.snapshots", "archive.availability"),
              input_kinds=("url", "domain"), network=True),
    SkillSpec("public_social_search", "Search public social content within scope.",
              input_kinds=("query", "username", "url"), network=True),
    SkillSpec("username_analysis", "Normalize handle + probe public availability candidates.",
              required_capabilities=("username.availability",),
              input_kinds=("username",), network=True),
    SkillSpec("entity_extraction", "Extract typed entities from preserved evidence text.",
              input_kinds=("text", "document", "evidence")),
    SkillSpec("relationship_extraction", "Derive candidate relationships from co-occurrence/citations.",
              input_kinds=("text", "evidence")),
    SkillSpec("timeline_analysis", "Order events with layered time semantics.",
              input_kinds=("event", "text")),
    SkillSpec("graph_analysis", "k-hop / path / component analysis over case graph.",
              input_kinds=("entity",)),
    SkillSpec("dns_analysis", "Resolve and interpret DNS records with timestamps.",
              required_capabilities=("dns.A", "dns.AAAA", "dns.MX", "dns.NS", "dns.TXT", "dns.CNAME", "dns.ptr"),
              input_kinds=("domain", "ip_address"), network=True),
    SkillSpec("rdap_analysis", "Domain registration data via RDAP bootstrap.",
              required_capabilities=("rdap.domain",), input_kinds=("domain",), network=True),
    SkillSpec("certificate_analysis", "Certificate Transparency record retrieval/interpretation.",
              required_capabilities=("certificates.by_domain",), input_kinds=("domain",), network=True),
    SkillSpec("ip_analysis", "IP allocation/geolocation/reputation context (approximate by nature).",
              required_capabilities=("ip.geo", "prefix.owner"), input_kinds=("ip_address",), network=True),
    SkillSpec("asn_bgp_analysis", "ASN operator context and announced-prefix correlation.",
              required_capabilities=("asn.info",), input_kinds=("asn", "ip_address"), network=True),
    SkillSpec("cti_enrichment", "Enrich IOCs against threat-intel sources with freshness checks.",
              input_kinds=("ioc", "ip_address", "domain", "hash"), network=True),
    SkillSpec("malware_discovery", "Discover reports/samples metadata (never executes payloads).",
              input_kinds=("hash", "url", "report"), network=True),
    SkillSpec("malware_behavior_analysis", "Parse authorized sandbox-report behavior into observations.",
              input_kinds=("report", "document")),
    SkillSpec("mitre_attack_mapping", "Map behavior evidence to versioned ATT&CK objects.",
              input_kinds=("behavior", "report")),
    SkillSpec("ioc_analysis", "IOC normalization, provenance and staleness assessment.",
              input_kinds=("ioc", "hash", "ip_address", "domain", "url")),
    SkillSpec("geolocation", "Coordinate/place resolution and reverse geocoding.",
              required_capabilities=("geocode", "reverse_geocode"),
              input_kinds=("coordinates", "location", "address"), network=True),
    SkillSpec("satellite_analysis", "Licensed/public imagery scene interpretation.",
              input_kinds=("image",)),
    SkillSpec("ocr", "Text extraction from images/documents.", input_kinds=("image", "document")),
    SkillSpec("image_analysis", "Visible clue observation (non-biometric).", input_kinds=("image",)),
    SkillSpec("video_analysis", "Frame sampling and event coverage observation.",
              input_kinds=("video",)),
    SkillSpec("audio_transcription", "Speech-to-text with speaker-turn attribution.",
              input_kinds=("audio",)),
    SkillSpec("document_analysis", "Parse preserved documents into cited claims/tables/events.",
              input_kinds=("document", "text")),
    SkillSpec("code_analysis", "Static reading of public/authorized repositories (never runs repo code).",
              required_capabilities=("repo.info", "repo.contributors", "org.repos"),
              input_kinds=("repository", "url"), network=True),
    SkillSpec("package_analysis", "Registry/advisory lookups without installing packages.",
              required_capabilities=("vulnerabilities.by_package",),
              input_kinds=("package",), network=True),
    SkillSpec("blockchain_analysis", "Public chain data queries for addresses/transactions.",
              required_capabilities=("wallet.transactions",),
              input_kinds=("wallet", "transaction"), network=True),
    SkillSpec("registry_lookup", "Company registry searches (OpenCorporates/Wikidata etc.).",
              required_capabilities=("registry.search", "entity.lookup"),
              input_kinds=("company_name", "registry_id"), network=True),
    SkillSpec("news_search", "News query via RSS/API providers.",
              required_capabilities=("news.search",), input_kinds=("query", "organization"), network=True),
    SkillSpec("cve_lookup", "CVE record retrieval from mirrors/advisories.",
              required_capabilities=("cve.lookup",), input_kinds=("cve",), network=True),
    SkillSpec("evidence_capture", "Preserve raw bytes + hash + source URI for anything collected.",
              offline_deterministic=True),
    SkillSpec("source_bias_analysis", "Record bias/limitations per source (separate from reliability)."),
    SkillSpec("source_independence_analysis", "Cluster evidence into independence clusters."),
    SkillSpec("contradiction_analysis", "Detect conflicting observations on same subject/predicate."),
    SkillSpec("hypothesis_testing", "Score hypotheses against facts with ACH-style matrix."),
    SkillSpec("falsification", "Attack weak conclusions: what would make this false?"),
    SkillSpec("verification", "Adjudicate material findings through trust layers."),
    SkillSpec("report_writing", "Produce citation-linked reports; never upgrades hypothesis to fact."),
]


class SkillRegistry:
    def __init__(self, specs: list[SkillSpec] | None = None):
        self._by_id: dict[str, SkillSpec] = {}
        for s in specs if specs is not None else _SKILLS:
            self._by_id[s.skill_id] = s

    def get(self, skill_id: str) -> SkillSpec | None:
        return self._by_id.get(skill_id)

    def require(self, skill_id: str) -> SkillSpec:
        s = self.get(skill_id)
        if s is None:
            raise KeyError(f"unknown skill: {skill_id}")
        return s

    def all_ids(self) -> tuple[str, ...]:
        return tuple(self._by_id)

    def __len__(self) -> int:
        return len(self._by_id)


DEFAULT_SKILL_REGISTRY = SkillRegistry()


@dataclass(slots=True)
class SkillMatch:
    employee_id: str
    covered: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def fully_covered(self) -> bool:
        return not self.missing


def match_employee(employee_skills: tuple[str, ...], required_skills: tuple[str, ...]) -> SkillMatch:
    """Conservative matcher: an employee covers a task only if every required
    skill is declared by that employee."""
    have = set(employee_skills)
    need = set(required_skills)
    return SkillMatch(employee_id="", covered=tuple(sorted(need & have)),
                      missing=tuple(sorted(need - have)))
