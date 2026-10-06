"""traceatlas.core.citation - Citations binding claims to evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .identifiers import ID


@dataclass(frozen=True, slots=True)
class Citation:
    evidence_id: ID
    locator: str = ""
    quote: Optional[str] = None
    url: Optional[str] = None
    accessed_at: Optional[str] = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"evidence_id": self.evidence_id, "locator": self.locator,
                "quote": self.quote, "url": self.url,
                "accessed_at": self.accessed_at, "note": self.note}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Citation":
        return cls(evidence_id=d["evidence_id"], locator=d.get("locator", ""),
                   quote=d.get("quote"), url=d.get("url"),
                   accessed_at=d.get("accessed_at"), note=d.get("note", ""))
