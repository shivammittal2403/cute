"""ATT&CK group store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class GroupStore(TypedStore):
    attack_type = "group"
