"""ATT&CK tactic store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class TacticStore(TypedStore):
    attack_type = "tactic"
