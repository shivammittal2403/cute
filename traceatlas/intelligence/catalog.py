"""traceatlas.intelligence.catalog — the 65-module intelligence catalog (§1).

This is REGISTRATION DATA, not a capability claim. A module's real maturity is
its manifest status + passing tests (see registry.py and .ai ledgers). Aliases
are resolved here so CORPINT/COMPANYINT and CHATINT/MESSENGERINT never become
duplicate runtime modules; OSINT/CTI are umbrella groups, not modules.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ModuleSpec:
    module_id: str
    name: str
    category: str
    manager: str          # owning intelligence manager id
    summary: str          # one-line honest scope statement


# ---------------------------------------------------------------- categories
CATEGORIES = {
    "corporate": "Corporate / Regulatory / Commercial",
    "cyber": "Cyber Threat / Software",
    "discovery": "Discovery / Web",
    "geo": "Geography / Event / Transport",
    "identity": "Identity / Communication / Social",
    "infrastructure": "Internet Infrastructure",
    "media": "Media / Document / Verification",
    "mobile": "Mobile / IoT / Industrial",
    "fraud": "Scam / Brand / Exposure",
}

# Umbrella groups (planning/UI grouping only — NOT runnable modules).
UMBRELLA_GROUPS = ("osint", "cti")

# Canonical aliases -> module_id
ALIASES = {
    "corpint": "companyint",
    "chatint": "messengerint",
    "malint": "malwareint",
}


def resolve_module_id(raw: str) -> str:
    """Normalize alias/uppercase input to a canonical module id."""
    mid = raw.strip().lower()
    return ALIASES.get(mid, mid)


_BASE_PROHIBITED = (
    "auth_bypass", "captcha_bypass", "private_account_access",
    "credential_use", "session_token_use", "private_key_use",
    "unauthorized_scanning", "exploitation", "malware_execution_on_host",
    "illicit_purchase", "subject_contact", "publishing_allegations",
    "financial_action", "legal_action", "police_referral",
    "external_takedown", "production_remediation",
)


def base_prohibited(extra: tuple[str, ...] = ()) -> tuple[str, ...]:
    return _BASE_PROHIBITED + tuple(e for e in extra if e not in _BASE_PROHIBITED)


# ---------------------------------------------------------------- 65 modules
MODULES: tuple[ModuleSpec, ...] = (
    # Corporate / Regulatory / Commercial (9)
    ModuleSpec("regint", "REGINT", "corporate", "mgr_regint",
               "Official registry identifiers, status and filing history."),
    ModuleSpec("companyint", "COMPANYINT", "corporate", "mgr_companyint",
               "Organization dossier: affiliations and public identifiers."),
    ModuleSpec("ownershipint", "OWNERSHIPINT", "corporate", "mgr_ownershipint",
               "Disclosed ownership/control with temporal validity; owner != operator."),
    ModuleSpec("procurementint", "PROCUREMENTINT", "corporate", "mgr_procurementint",
               "Public awards/contracts; award != misconduct."),
    ModuleSpec("tradeint", "TRADEINT", "corporate", "mgr_tradeint",
               "Permitted trade/shipment context; no confidential customs access implied."),
    ModuleSpec("addressint", "ADDRESSINT", "corporate", "mgr_addressint",
               "Normalized public/submitted business addresses; shared address != common ownership."),
    ModuleSpec("legalint", "LEGALINT", "corporate", "mgr_legalint",
               "Cited filings/proceedings; allegation/finding/disposition kept separate."),
    ModuleSpec("sanctionsint", "SANCTIONSINT", "corporate", "mgr_sanctionsint",
               "Versioned list matching with disambiguation; name hit != confirmed entity."),
    ModuleSpec("finint", "FININT", "corporate", "mgr_finint",
               "Submitted/public financial records with explained calculations; no private accounts."),
    # Cyber Threat / Software (10)
    ModuleSpec("iocint", "IOCINT", "cyber", "mgr_cti",
               "IP/domain/URL/hash context with freshness and provenance."),
    ModuleSpec("vulnint", "VULNINT", "cyber", "mgr_cti",
               "CVE/software/version advisories with KEV/EPSS context; exposure != exploitation."),
    ModuleSpec("threatactorint", "THREATACTORINT", "cyber", "mgr_cti",
               "Published/provider actor reporting as assessments, never verified identity."),
    ModuleSpec("campaignint", "CAMPAIGNINT", "cyber", "mgr_cti",
               "Evidence-backed campaign clusters; similarity != common operator."),
    ModuleSpec("malwareint", "MALWAREINT", "cyber", "mgr_malware",
               "Family/variant/behavior/IOC/ATT&CK/detection intelligence; no host execution."),
    ModuleSpec("packageint", "PACKAGEINT", "cyber", "mgr_supplychain",
               "Registry/advisory/manifest intelligence; never installs suspicious packages."),
    ModuleSpec("repoint", "REPOINT", "cyber", "mgr_supplychain",
               "Public/authorized repo analysis; never harvests secrets or runs repo code."),
    ModuleSpec("supplychainint", "SUPPLYCHAININT", "cyber", "mgr_supplychain",
               "SBOM/dependency/vendor analysis; dependency != compromise."),
    ModuleSpec("incidentint", "INCIDENTINT", "cyber", "mgr_cti",
               "Authorized incident records plus permitted context; no production changes."),
    ModuleSpec("logint", "LOGINT", "cyber", "mgr_infrastructure",
               "Authorized log analysis with secret/PII protection."),
    # Discovery / Web (8)
    ModuleSpec("webint", "WEBINT", "discovery", "mgr_osint",
               "Public or authorized web content capture and analysis."),
    ModuleSpec("searchint", "SEARCHINT", "discovery", "mgr_osint",
               "Ranked search coverage; snippets are leads until preserved and checked."),
    ModuleSpec("dorkint", "DORKINT", "discovery", "mgr_osint",
               "Provider-specific advanced public search; no credential hunting or evasion."),
    ModuleSpec("usernameint", "USERNAMEINT", "discovery", "mgr_person",
               "Public account candidates; matching username != same person."),
    ModuleSpec("archiveint", "ARCHIVEINT", "discovery", "mgr_osint",
               "Historical captures; archive date != publication/event date."),
    ModuleSpec("newsint", "NEWSINT", "discovery", "mgr_osint",
               "Story deduplication and upstream-source identification."),
    ModuleSpec("academicint", "ACADEMICINT", "discovery", "mgr_osint",
               "Publications, methods, retractions and bibliographic metadata."),
    ModuleSpec("datasetint", "DATASETINT", "discovery", "mgr_osint",
               "Dataset license/methodology/freshness/sampling-bias assessment."),
    # Geography / Event / Transport (5)
    ModuleSpec("geoint", "GEOINT", "geo", "mgr_geoint",
               "Candidate locations from visual/geographic clues; no personal tracking."),
    ModuleSpec("mapint", "MAPINT", "geo", "mgr_geoint",
               "Geocoding/maps/boundaries/POIs with source and date attribution."),
    ModuleSpec("satint", "SATINT", "geo", "mgr_geoint",
               "Scene/acquisition/resolution/cloud context and change analysis on licensed imagery."),
    ModuleSpec("transportint", "TRANSPORTINT", "geo", "mgr_transport",
               "Public schedules/registries/submitted records; no unauthorized live tracking."),
    ModuleSpec("eventint", "EVENTINT", "geo", "mgr_event",
               "Deduplicated public events; reported time/place != verified fact."),
    # Identity / Communication / Social (5)
    ModuleSpec("emailint", "EMAILINT", "identity", "mgr_person",
               "Public references or authorized email artifacts; no inbox access."),
    ModuleSpec("phoneint", "PHONEINT", "identity", "mgr_person",
               "Normalized identifiers plus permitted references; no subscriber lookup."),
    ModuleSpec("socmint", "SOCMINT", "identity", "mgr_socmint",
               "Public/provider social content; no unsupported sensitive-trait inference."),
    ModuleSpec("messengerint", "MESSENGERINT", "identity", "mgr_socmint",
               "Authorized exports/permitted public channels; no private-group access."),
    ModuleSpec("interviewint", "INTERVIEWINT", "identity", "mgr_person",
               "Supplied/consented transcripts; testimony remains attributed."),
    # Internet Infrastructure (8)
    ModuleSpec("domainint", "DOMAININT", "infrastructure", "mgr_infrastructure",
               "Domain dossier from current/historical evidence; ownership != hosting."),
    ModuleSpec("dnsint", "DNSINT", "infrastructure", "mgr_infrastructure",
               "Timestamped DNS observations and history."),
    ModuleSpec("certint", "CERTINT", "infrastructure", "mgr_infrastructure",
               "CT/provider certificate records; shared cert != common ownership."),
    ModuleSpec("ipint", "IPINT", "infrastructure", "mgr_infrastructure",
               "Allocation/reputation/host context; IP geolocation approximate; owner != user."),
    ModuleSpec("asnint", "ASNINT", "infrastructure", "mgr_infrastructure",
               "Registry/operator context; allocation/announcement/control kept distinct."),
    ModuleSpec("bgpint", "BGPINT", "infrastructure", "mgr_infrastructure",
               "Routing history/anomalies; anomaly != malicious activity."),
    ModuleSpec("netint", "NETINT", "infrastructure", "mgr_infrastructure",
               "Authorized network records; no interception or probing beyond scope."),
    ModuleSpec("cloudint", "CLOUDINT", "infrastructure", "mgr_infrastructure",
               "Authorized inventory/config/provider observations; no tenant crossover."),
    # Media / Document / Verification (6)
    ModuleSpec("docint", "DOCINT", "media", "mgr_document",
               "Preserve originals; extract cited text/tables/claims/events."),
    ModuleSpec("metadataint", "METADATAINT", "media", "mgr_document",
               "Metadata/integrity context; metadata != proof of identity/authenticity."),
    ModuleSpec("imint", "IMINT", "media", "mgr_media",
               "Visible clue/object observation and non-biometric similarity; no covert face ID."),
    ModuleSpec("vidint", "VIDINT", "media", "mgr_media",
               "Frame/event/time coverage with editing/context uncertainty flagged."),
    ModuleSpec("audint", "AUDINT", "media", "mgr_media",
               "Transcript/speaker turns; diarization != identity or emotion truth."),
    ModuleSpec("disinfoint", "DISINFOINT", "media", "mgr_verification",
               "Provenance and claim verification with alternatives; model opinion != truth."),
    # Mobile / IoT / Industrial (4)
    ModuleSpec("appint", "APPINT", "mobile", "mgr_mobile",
               "Store/developer/public metadata plus supplied artifacts; no hostile installs."),
    ModuleSpec("mobileint", "MOBILEINT", "mobile", "mgr_mobile",
               "Authorized forensic exports/public threat context; no device compromise."),
    ModuleSpec("iotint", "IOTINT", "mobile", "mgr_iot_ot",
               "Authorized inventories/advisories/indexed observations; no unauthorized scanning."),
    ModuleSpec("otint", "OTINT", "mobile", "mgr_iot_ot",
               "Authorized industrial inventory/telemetry/advisories; no default interaction."),
    # Scam / Brand / Exposure (10)
    ModuleSpec("fraudint", "FRAUDINT", "fraud", "mgr_fraud",
               "Victim evidence chronology and scam hypotheses; statements/facts/conclusions separated."),
    ModuleSpec("paymentint", "PAYMENTINT", "fraud", "mgr_fraud",
               "Submitted/authorized payment records; receipt != settlement or recipient identity."),
    ModuleSpec("cryptoint", "CRYPTOINT", "fraud", "mgr_blockchain",
               "Public chain data plus licensed attribution; no recovery guarantees."),
    ModuleSpec("brandint", "BRANDINT", "fraud", "mgr_fraud",
               "Public impersonation/brand-abuse candidates; takedowns need authorization."),
    ModuleSpec("adint", "ADINT", "fraud", "mgr_fraud",
               "Public ad-library/supplied creative and landing-page claims."),
    ModuleSpec("marketplaceint", "MARKETPLACEINT", "fraud", "mgr_fraud",
               "Public listings plus submitted transactions; no private seller data."),
    ModuleSpec("jobint", "JOBINT", "fraud", "mgr_fraud",
               "Recruitment records and supplied communications; listing fraud != company guilt."),
    ModuleSpec("complaintint", "COMPLAINTINT", "fraud", "mgr_fraud",
               "Complaints as allegations; duplicates != independent cases."),
    ModuleSpec("exposureint", "EXPOSUREINT", "fraud", "mgr_darkint",
               "Masked exposure metadata from authorized feeds; never retrieve/use secrets."),
    ModuleSpec("darkwebint", "DARKWEBINT", "fraud", "mgr_darkint",
               "Licensed/indexed/explicitly authorized isolated sources; no illicit purchase/contact."),
)

MODULE_IDS = tuple(m.module_id for m in MODULES)
_BY_ID = {m.module_id: m for m in MODULES}

# Managers (§2): domain managers + responsibility-bearing layers.
MANAGER_IDS = (
    "chief_intelligence_manager",
    "mgr_osint", "mgr_socmint", "mgr_person", "mgr_companyint", "mgr_regint",
    "mgr_ownershipint", "mgr_procurementint", "mgr_tradeint", "mgr_addressint",
    "mgr_legalint", "mgr_sanctionsint", "mgr_finint",
    "mgr_infrastructure", "mgr_cti", "mgr_malware", "mgr_supplychain",
    "mgr_geoint", "mgr_media", "mgr_document", "mgr_event", "mgr_transport",
    "mgr_mobile", "mgr_iot_ot", "mgr_darkint", "mgr_blockchain", "mgr_fraud",
    "mgr_verification", "mgr_evidence", "mgr_reporting",
)


def spec(module_id: str) -> ModuleSpec | None:
    return _BY_ID.get(resolve_module_id(module_id))


def by_category(category: str) -> tuple[ModuleSpec, ...]:
    return tuple(m for m in MODULES if m.category == category)


def modules_for_manager(manager_id: str) -> tuple[ModuleSpec, ...]:
    return tuple(m for m in MODULES if m.manager == manager_id)


def catalog_counts() -> dict[str, int]:
    counts = {c: 0 for c in CATEGORIES}
    for m in MODULES:
        counts[m.category] += 1
    counts["total"] = len(MODULES)
    return counts
