"""traceatlas.core.source - Reference to a governed catalogued source."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import SourceTier
from .identifiers import ID, new_id


@dataclass(frozen=True, slots=True)
class SourceRef:
    source_id: ID = field(default_factory=lambda: new_id("source"))
    slug: str = ""
    name: str = ""
    tier: SourceTier = SourceTier.UNKNOWN
    base_url: str = ""
    domains: tuple[str, ...] = ()
    requires_credentials: bool = False
    qualification: str = "documented"
    publisher: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"source_id": self.source_id, "slug": self.slug, "name": self.name,
                "tier": self.tier.value, "base_url": self.base_url,
                "domains": list(self.domains),
                "requires_credentials": self.requires_credentials,
                "qualification": self.qualification, "publisher": self.publisher}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SourceRef":
        return cls(source_id=d["source_id"], slug=d.get("slug", ""),
                   name=d.get("name", ""), tier=SourceTier(d.get("tier", "unknown")),
                   base_url=d.get("base_url", ""), domains=tuple(d.get("domains", ())),
                   requires_credentials=bool(d.get("requires_credentials", False)),
                   qualification=d.get("qualification", "documented"),
                   publisher=d.get("publisher", ""))
