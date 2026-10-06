"""traceatlas.ingestion.request - Import request / profile / classification model."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .limits import DEFAULT_LIMITS, IngestionLimits


class ImportProfile(str, Enum):
    """Pipeline profiles (spec §15). AUTO picks per detected content."""
    AUTO = "auto"
    FORENSIC = "forensic"
    OSINT = "osint"
    CTI = "cti"
    SOCMINT = "socmint"
    CORPORATE = "corporate"
    INFRASTRUCTURE = "infrastructure"
    GEOINT = "geoint"
    MEDIA = "media"
    BLOCKCHAIN = "blockchain"
    DOCUMENT = "document"
    WEB_EVIDENCE = "web_evidence"
    DATABASE = "database"
    RAW_PRESERVATION = "raw_preservation"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    SENSITIVE_PII = "sensitive_pii"
    SECRET = "secret"
    UNKNOWN = "unknown"


# Classifications that must never leave to an external model without explicit policy.
NO_EXTERNAL_MODEL: frozenset[DataClassification] = frozenset({
    DataClassification.RESTRICTED, DataClassification.SENSITIVE_PII,
    DataClassification.SECRET})


class ImportMode(str, Enum):
    FULL = "full"                       # parse + extract + AI synthesis
    NO_AI = "no_ai"                     # deterministic pipeline only
    METADATA_ONLY = "metadata_only"     # preserve + detect + hash; no record parsing
    QUARANTINE = "quarantine"           # isolate; do not parse at all


@dataclass(frozen=True, slots=True)
class ImportRequest:
    """One ingestion request: what to import and under which constraints."""
    case_id: str
    tenant_id: str = "default"
    actor: str = "system"
    source_path: Optional[str] = None            # file or directory on disk
    source_bytes: Optional[bytes] = None         # direct upload payload
    original_filename: Optional[str] = None      # supplied name (never trusted)
    supplied_mime: Optional[str] = None          # claimed MIME (never trusted)
    profile: ImportProfile = ImportProfile.AUTO
    mode: ImportMode = ImportMode.FULL
    recursive: bool = True
    acquisition_context: str = ""                # how lawfully obtained, notes
    limits: IngestionLimits = field(default=DEFAULT_LIMITS, compare=False)
    labels: tuple[str, ...] = ()

    def effective_limits(self) -> IngestionLimits:
        return self.limits.clamp()

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "tenant_id": self.tenant_id,
                "actor": self.actor, "source_path": self.source_path,
                "original_filename": self.original_filename,
                "supplied_mime": self.supplied_mime, "profile": self.profile.value,
                "mode": self.mode.value, "recursive": self.recursive,
                "acquisition_context": self.acquisition_context,
                "labels": list(self.labels),
                "has_bytes": self.source_bytes is not None}


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_member_name(name: str) -> str:
    """Sanitize a member/suggested filename for local storage (defense in depth)."""
    name = name.replace("\\", "/").split("/")[-1]
    name = _SAFE_NAME.sub("_", name).strip("._") or "unnamed"
    return name[:200]
