"""traceatlas.core.authorization - Legal/ethical authorization record."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from .provenance import utcnow


@dataclass(frozen=True, slots=True)
class Authorization:
    """Basis permitting collection. TraceAtlas refuses to run without it."""

    granted_by: str = ""
    basis: str = ""
    reference: str = ""
    scopes: tuple[str, ...] = ()
    granted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    verified: bool = False

    def is_valid(self, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        if not self.granted_by or not self.basis or not self.scopes:
            return False
        if self.expires_at is not None and now > self.expires_at:
            return False
        return True

    def permits(self, activity: str) -> bool:
        return activity in self.scopes or "*" in self.scopes

    def to_dict(self) -> dict[str, Any]:
        def _dt(v):
            return v.isoformat() if v else None
        return {"granted_by": self.granted_by, "basis": self.basis,
                "reference": self.reference, "scopes": list(self.scopes),
                "granted_at": _dt(self.granted_at), "expires_at": _dt(self.expires_at),
                "verified": self.verified}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Authorization":
        def _dt(v):
            return datetime.fromisoformat(v) if v else None
        return cls(granted_by=d.get("granted_by", ""), basis=d.get("basis", ""),
                   reference=d.get("reference", ""), scopes=tuple(d.get("scopes", ())),
                   granted_at=_dt(d.get("granted_at")), expires_at=_dt(d.get("expires_at")),
                   verified=bool(d.get("verified", False)))
