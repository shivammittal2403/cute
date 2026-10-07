"""ATT&CK detection store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class DetectionGuideStore(TypedStore):
    attack_type = "detection"
