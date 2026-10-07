"""ATT&CK mitigation store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class MitigationStore(TypedStore):
    attack_type = "mitigation"
