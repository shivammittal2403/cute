"""traceatlas.core.target - What/who the objective points at."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import EntityKind


@dataclass(frozen=True, slots=True)
class Target:
    kind: EntityKind = EntityKind.UNKNOWN
    value: str = ""
    hints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "value": self.value, "hints": self.hints}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Target":
        return cls(kind=EntityKind(d.get("kind", "unknown")), value=d.get("value", ""),
                   hints=d.get("hints", {}))
