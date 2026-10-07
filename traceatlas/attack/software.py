"""ATT&CK software store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class SoftwareStore(TypedStore):
    attack_type = "software"
