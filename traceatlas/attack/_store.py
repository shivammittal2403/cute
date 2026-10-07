"""Shared typed-store facade over AttackClient for one attack_type."""
from __future__ import annotations

from .client import AttackClient

TYPE_BY_MODULE = {
    "tactics": "tactic", "techniques": "technique", "subtechniques": "subtechnique",
    "software": "software", "groups": "group", "campaigns": "campaign",
    "mitigations": "mitigation", "detections": "detection",
}


class TypedStore:
    attack_type = ""

    def __init__(self, client: AttackClient):
        self.client = client

    def list(self, *, matrix=None, version=None, include_deprecated=False):
        objs = self.client.objects(attack_type=self.attack_type, matrix=matrix,
                                   version=version)
        if not include_deprecated:
            objs = [o for o in objs if not o.get("deprecated") and not o.get("revoked")]
        return objs

    def get(self, external_id: str, **kw):
        return self.client.by_external_id(external_id, **kw)

    def exists(self, external_id: str, **kw) -> bool:
        return self.client.exists(external_id, **kw)
