"""ATT&CK technique store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class TechniqueStore(TypedStore):
    attack_type = "technique"
