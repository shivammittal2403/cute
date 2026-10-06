"""traceatlas.core.artifact - Derived artifacts (parsed, extracted, rendered)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .identifiers import ID, new_id
from .provenance import Provenance, utcnow


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: ID = field(default_factory=lambda: new_id("artifact"))
    case_id: Optional[ID] = None
    kind: str = ""
    media_type: str = "application/json"
    storage_key: str = ""
    sha256: str = ""
    derived_from_evidence_id: Optional[ID] = None
    provenance: Optional[Provenance] = None
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {"artifact_id": self.artifact_id, "case_id": self.case_id,
                "kind": self.kind, "media_type": self.media_type,
                "storage_key": self.storage_key, "sha256": self.sha256,
                "derived_from_evidence_id": self.derived_from_evidence_id,
                "provenance": self.provenance.to_dict() if self.provenance else None,
                "created_at": self.created_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Artifact":
        return cls(artifact_id=d["artifact_id"], case_id=d.get("case_id"),
                   kind=d.get("kind", ""),
                   media_type=d.get("media_type", "application/json"),
                   storage_key=d.get("storage_key", ""), sha256=d.get("sha256", ""),
                   derived_from_evidence_id=d.get("derived_from_evidence_id"),
                   provenance=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
                   created_at=datetime.fromisoformat(d["created_at"]))
