"""traceatlas.core.relationship - Typed directed edges between entities."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import RelationshipKind
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Relationship:
    relationship_id: ID = field(default_factory=lambda: new_id("relationship"))
    case_id: Optional[ID] = None
    source_entity_id: ID = ID("")
    target_entity_id: ID = ID("")
    kind: RelationshipKind = RelationshipKind.GENERIC
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_ids: tuple[ID, ...] = ()
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    asserted_at: datetime = field(default_factory=utcnow)

    def is_valid_at(self, when: datetime) -> bool:
        if self.valid_from and when < self.valid_from:
            return False
        if self.valid_to and when > self.valid_to:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        def _dt(v):
            return v.isoformat() if v else None
        return {"relationship_id": self.relationship_id, "case_id": self.case_id,
                "source_entity_id": self.source_entity_id,
                "target_entity_id": self.target_entity_id,
                "kind": self.kind.value, "properties": self.properties,
                "evidence_ids": list(self.evidence_ids),
                "valid_from": _dt(self.valid_from), "valid_to": _dt(self.valid_to),
                "asserted_at": self.asserted_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Relationship":
        def _dt(v):
            return datetime.fromisoformat(v) if v else None
        return cls(relationship_id=d["relationship_id"], case_id=d.get("case_id"),
                   source_entity_id=d["source_entity_id"],
                   target_entity_id=d["target_entity_id"],
                   kind=RelationshipKind(d.get("kind", "generic")),
                   properties=d.get("properties", {}),
                   evidence_ids=tuple(d.get("evidence_ids", ())),
                   valid_from=_dt(d.get("valid_from")), valid_to=_dt(d.get("valid_to")),
                   asserted_at=datetime.fromisoformat(d["asserted_at"]))
