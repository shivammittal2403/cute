"""traceatlas.core.provenance - Provenance records for derived objects."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .enums import ProvenanceType
from .identifiers import ID, new_id


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class Provenance:
    provenance_id: ID = field(default_factory=lambda: new_id("provenance"))
    kind: ProvenanceType = ProvenanceType.TRANSFORMATION
    actor: str = ""
    tool: str = ""
    input_ids: tuple[ID, ...] = ()
    source_uri: Optional[str] = None
    collected_at: Optional[datetime] = None
    processed_at: datetime = field(default_factory=utcnow)
    parameters: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"provenance_id": self.provenance_id, "kind": self.kind.value,
                "actor": self.actor, "tool": self.tool,
                "input_ids": list(self.input_ids), "source_uri": self.source_uri,
                "collected_at": self.collected_at.isoformat() if self.collected_at else None,
                "processed_at": self.processed_at.isoformat(),
                "parameters": self.parameters, "notes": self.notes}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Provenance":
        return cls(provenance_id=d["provenance_id"], kind=ProvenanceType(d["kind"]),
                   actor=d.get("actor", ""), tool=d.get("tool", ""),
                   input_ids=tuple(d.get("input_ids", ())), source_uri=d.get("source_uri"),
                   collected_at=datetime.fromisoformat(d["collected_at"]) if d.get("collected_at") else None,
                   processed_at=datetime.fromisoformat(d["processed_at"]),
                   parameters=d.get("parameters", {}), notes=d.get("notes", ""))
