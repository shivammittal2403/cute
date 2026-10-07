"""ATT&CK subtechnique store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class SubtechniqueStore(TypedStore):
    attack_type = "subtechnique"
