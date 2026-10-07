"""ATT&CK campaign store (typed facade over the versioned client)."""
from __future__ import annotations

from ._store import TypedStore


class CampaignStore(TypedStore):
    attack_type = "campaign"
