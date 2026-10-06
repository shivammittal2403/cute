"""traceatlas.core.scope - Investigation scope boundaries (default-deny lists)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .enums import IntelligenceDomain


@dataclass(frozen=True, slots=True)
class Scope:
    entities_allowed: tuple[str, ...] = ()
    entities_denied: tuple[str, ...] = ()
    domains: tuple[IntelligenceDomain, ...] = ()
    jurisdictions: tuple[str, ...] = ()
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    max_depth: int = 3
    allow_dark_web: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def allows_domain(self, domain: IntelligenceDomain) -> bool:
        return (not self.domains) or domain in self.domains

    def allows_time(self, when: Optional[datetime]) -> bool:
        if when is None:
            return True
        if self.time_from and when < self.time_from:
            return False
        if self.time_to and when > self.time_to:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        def _dt(v):
            return v.isoformat() if v else None
        return {"entities_allowed": list(self.entities_allowed),
                "entities_denied": list(self.entities_denied),
                "domains": [d.value for d in self.domains],
                "jurisdictions": list(self.jurisdictions),
                "time_from": _dt(self.time_from), "time_to": _dt(self.time_to),
                "max_depth": self.max_depth, "allow_dark_web": self.allow_dark_web,
                "extra": self.extra}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Scope":
        def _dt(v):
            return datetime.fromisoformat(v) if v else None
        return cls(entities_allowed=tuple(d.get("entities_allowed", ())),
                   entities_denied=tuple(d.get("entities_denied", ())),
                   domains=tuple(IntelligenceDomain(x) for x in d.get("domains", ())),
                   jurisdictions=tuple(d.get("jurisdictions", ())),
                   time_from=_dt(d.get("time_from")), time_to=_dt(d.get("time_to")),
                   max_depth=int(d.get("max_depth", 3)),
                   allow_dark_web=bool(d.get("allow_dark_web", False)),
                   extra=d.get("extra", {}))
