"""traceatlas.core.entity - Canonical entities."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import EntityKind
from .identifiers import ID, new_id
from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Entity:
    entity_id: ID = field(default_factory=lambda: new_id("entity"))
    case_id: Optional[ID] = None
    kind: EntityKind = EntityKind.UNKNOWN
    display_name: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    alias_ids: tuple[ID, ...] = ()
    evidence_ids: tuple[ID, ...] = ()
    merged_from: tuple[ID, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    def attribute(self, name: str, default: Any = None) -> Any:
        return self.attributes.get(name, default)

    def to_dict(self) -> dict[str, Any]:
        return {"entity_id": self.entity_id, "case_id": self.case_id,
                "kind": self.kind.value, "display_name": self.display_name,
                "attributes": self.attributes, "alias_ids": list(self.alias_ids),
                "evidence_ids": list(self.evidence_ids),
                "merged_from": list(self.merged_from),
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Entity":
        return cls(entity_id=d["entity_id"], case_id=d.get("case_id"),
                   kind=EntityKind(d.get("kind", "unknown")),
                   display_name=d.get("display_name", ""),
                   attributes=d.get("attributes", {}),
                   alias_ids=tuple(d.get("alias_ids", ())),
                   evidence_ids=tuple(d.get("evidence_ids", ())),
                   merged_from=tuple(d.get("merged_from", ())),
                   created_at=datetime.fromisoformat(d["created_at"]),
                   updated_at=datetime.fromisoformat(d["updated_at"]))
