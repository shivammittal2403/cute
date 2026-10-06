"""traceatlas.core.event - Timeline events with layered time semantics."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import TemporalPrecision
from .identifiers import ID, new_id


@dataclass(frozen=True, slots=True)
class Event:
    event_id: ID = field(default_factory=lambda: new_id("event"))
    case_id: Optional[ID] = None
    title: str = ""
    description: str = ""
    entity_ids: tuple[ID, ...] = ()
    evidence_ids: tuple[ID, ...] = ()
    event_time: Optional[datetime] = None
    event_precision: TemporalPrecision = TemporalPrecision.UNKNOWN
    validity_start: Optional[datetime] = None
    validity_end: Optional[datetime] = None
    observation_time: Optional[datetime] = None
    retrieval_time: Optional[datetime] = None
    location: Optional[str] = None
    properties: dict[str, Any] = field(default_factory=dict)

    def effective_time(self) -> Optional[datetime]:
        return self.event_time or self.observation_time

    def overlaps_window(self, start: datetime, end: datetime) -> bool:
        vs = self.validity_start or self.effective_time()
        ve = self.validity_end
        if vs is None:
            return True
        if vs > end:
            return False
        if ve is not None and ve < start:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        def _dt(v):
            return v.isoformat() if v else None
        return {"event_id": self.event_id, "case_id": self.case_id,
                "title": self.title, "description": self.description,
                "entity_ids": list(self.entity_ids),
                "evidence_ids": list(self.evidence_ids),
                "event_time": _dt(self.event_time),
                "event_precision": self.event_precision.value,
                "validity_start": _dt(self.validity_start),
                "validity_end": _dt(self.validity_end),
                "observation_time": _dt(self.observation_time),
                "retrieval_time": _dt(self.retrieval_time),
                "location": self.location, "properties": self.properties}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        def _dt(v):
            return datetime.fromisoformat(v) if v else None
        return cls(event_id=d["event_id"], case_id=d.get("case_id"),
                   title=d.get("title", ""), description=d.get("description", ""),
                   entity_ids=tuple(d.get("entity_ids", ())),
                   evidence_ids=tuple(d.get("evidence_ids", ())),
                   event_time=_dt(d.get("event_time")),
                   event_precision=TemporalPrecision(d.get("event_precision", "unknown")),
                   validity_start=_dt(d.get("validity_start")),
                   validity_end=_dt(d.get("validity_end")),
                   observation_time=_dt(d.get("observation_time")),
                   retrieval_time=_dt(d.get("retrieval_time")),
                   location=d.get("location"), properties=d.get("properties", {}))
