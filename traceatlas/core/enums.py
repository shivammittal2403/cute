"""traceatlas.core.enums - Shared enumerations for the domain model."""
from enum import Enum


class _StrEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class CaseStatus(_StrEnum):
    DRAFT = "draft"; ACTIVE = "active"; PAUSED = "paused"
    CLOSED = "closed"; ARCHIVED = "archived"


class ObjectiveStatus(_StrEnum):
    DRAFT = "draft"; CLARIFYING = "clarifying"; APPROVED = "approved"
    SUPERSEDED = "superseded"


class InvestigationStatus(_StrEnum):
    PLANNED = "planned"; RUNNING = "running"; PAUSED = "paused"
    COMPLETED = "completed"; STOPPED = "stopped"; FAILED = "failed"


class TaskStatus(_StrEnum):
    PENDING = "pending"; READY = "ready"; RUNNING = "running"
    SUCCEEDED = "succeeded"; FAILED = "failed"; CANCELLED = "cancelled"
    SKIPPED = "skipped"


class TaskKind(_StrEnum):
    COLLECT = "collect"; EXTRACT = "extract"; RESOLVE = "resolve"
    CORRELATE = "correlate"; VERIFY = "verify"; CONTRADICT = "contradict"
    REASON = "reason"; REPORT = "report"; REVIEW = "review"


class EntityKind(_StrEnum):
    PERSON = "person"; ORGANIZATION = "organization"; USERNAME = "username"
    DOMAIN = "domain"; IP_ADDRESS = "ip_address"; ASN = "asn"; URL = "url"
    EMAIL = "email"; PHONE = "phone"; HASH = "hash"; DOCUMENT = "document"
    IMAGE = "image"; VIDEO = "video"; AUDIO = "audio"; LOCATION = "location"
    EVENT = "event"; CVE = "cve"; MALWARE = "malware"; THREAT_ACTOR = "threat_actor"
    ACCOUNT = "account"; UNKNOWN = "unknown"


class RelationshipKind(_StrEnum):
    MANAGES = "manages"; OWNS = "owns"; EMPLOYS = "employs"
    AFFILIATED_WITH = "affiliated_with"; RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"; REGISTRANT_OF = "registrant_of"
    ADMIN_CONTACT_OF = "admin_contact_of"; SAME_PERSON_AS = "same_person_as"
    SAME_ORG_AS = "same_org_as"; COMMUNICATED_WITH = "communicated_with"
    TRANSACTED_WITH = "transacted_with"; LOCATED_AT = "located_at"
    MENTIONED_IN = "mentioned_in"; DERIVED_FROM = "derived_from"
    EXPLOITS = "exploits"; ATTRIBUTED_TO = "attributed_to"; GENERIC = "generic"


class EvidenceState(_StrEnum):
    CAPTURED = "captured"; VERIFIED_INTEGRITY = "verified_integrity"
    PROCESSED = "processed"; CITED = "cited"; QUARANTINED = "quarantined"
    DISCARDED = "discarded"


class ClaimStatus(_StrEnum):
    PROPOSED = "proposed"; SUPPORTED = "supported"; CONTESTED = "contested"
    REFUTED = "refuted"; UNVERIFIABLE = "unverifiable"; WITHDRAWN = "withdrawn"


class HypothesisStatus(_StrEnum):
    OPEN = "open"; FAVOURED = "favoured"; REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class ContradictionSeverity(_StrEnum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"


class ConfidenceBand(_StrEnum):
    VERY_LOW = "very_low"; LOW = "low"; MODERATE = "moderate"
    HIGH = "high"; VERY_HIGH = "very_high"

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceBand":
        if score < 0.2:
            return cls.VERY_LOW
        if score < 0.45:
            return cls.LOW
        if score < 0.7:
            return cls.MODERATE
        if score < 0.9:
            return cls.HIGH
        return cls.VERY_HIGH


class VerificationDecision(_StrEnum):
    VERIFIED = "verified"; LIKELY = "likely"; INCONCLUSIVE = "inconclusive"
    CONTRADICTED = "contradicted"; REFUTED = "refuted"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class SourceTier(_StrEnum):
    PRIMARY_OFFICIAL = "primary_official"
    ESTABLISHED_PUBLISHER = "established_publisher"
    SECONDARY = "secondary"; COMMUNITY = "community"
    USER_GENERATED = "user_generated"; UNKNOWN = "unknown"


class IntelligenceDomain(_StrEnum):
    WEBINT = "webint"; SEARCHINT = "searchint"; SOCMINT = "socmint"
    PERSONINT = "personint"; USERNAMEINT = "usernameint"; CORPINT = "corpint"
    DOMAININT = "domainint"; INFRAINT = "infraint"; CTI = "cti"
    GEOINT = "geoint"; IMINT = "imint"; VIDINT = "vidint"; AUDINT = "audint"
    DOCINT = "docint"; CODEINT = "codeint"; ARCHIVEINT = "archiveint"
    DARKINT = "darkint"


class ProvenanceType(_StrEnum):
    COLLECTION = "collection"; TRANSFORMATION = "transformation"
    ANALYSIS = "analysis"; AGGREGATION = "aggregation"; EXPORT = "export"


class TemporalPrecision(_StrEnum):
    SECOND = "second"; MINUTE = "minute"; HOUR = "hour"; DAY = "day"
    MONTH = "month"; YEAR = "year"; DECADE = "decade"; UNKNOWN = "unknown"


class RiskLevel(_StrEnum):
    NONE = "none"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"
    CRITICAL = "critical"
