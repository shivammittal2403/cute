"""traceatlas.core.evidence - Evidence objects (immutable after capture)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import EvidenceState
from .identifiers import ID, new_id
from .provenance import Provenance, utcnow


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: ID = field(default_factory=lambda: new_id("evidence"))
    case_id: Optional[ID] = None
    sha256: str = ""
    size_bytes: int = 0
    media_type: str = "application/octet-stream"
    source_uri: str = ""
    captured_at: datetime = field(default_factory=utcnow)
    state: EvidenceState = EvidenceState.CAPTURED
    storage_key: str = ""
    provenance: Optional[Provenance] = None
    labels: tuple[str, ...] = ()
    quarantine_reason: str = ""

    @classmethod
    def from_bytes(cls, data: bytes, source_uri: str,
                   media_type: str = "application/octet-stream",
                   case_id: Optional[ID] = None) -> "Evidence":
        return cls(case_id=case_id, sha256=hashlib.sha256(data).hexdigest(),
                   size_bytes=len(data), media_type=media_type, source_uri=source_uri)

    def verify_integrity(self, data: bytes) -> bool:
        return hashlib.sha256(data).hexdigest() == self.sha256

    def to_dict(self) -> dict[str, Any]:
        return {"evidence_id": self.evidence_id, "case_id": self.case_id,
                "sha256": self.sha256, "size_bytes": self.size_bytes,
                "media_type": self.media_type, "source_uri": self.source_uri,
                "captured_at": self.captured_at.isoformat(),
                "state": self.state.value, "storage_key": self.storage_key,
                "labels": list(self.labels),
                "quarantine_reason": self.quarantine_reason,
                "provenance": self.provenance.to_dict() if self.provenance else None}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(evidence_id=d["evidence_id"], case_id=d.get("case_id"),
                   sha256=d["sha256"], size_bytes=d["size_bytes"],
                   media_type=d.get("media_type", "application/octet-stream"),
                   source_uri=d.get("source_uri", ""),
                   captured_at=datetime.fromisoformat(d["captured_at"]),
                   state=EvidenceState(d.get("state", "captured")),
                   storage_key=d.get("storage_key", ""),
                   provenance=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
                   labels=tuple(d.get("labels", ())),
                   quarantine_reason=d.get("quarantine_reason", ""))
