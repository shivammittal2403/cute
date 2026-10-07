"""Relationship queries over ATT&CK snapshots (uses/detects/mitigates/subtechnique-of)."""
from __future__ import annotations

from collections import defaultdict
from .client import AttackClient


class RelationshipStore:
    def __init__(self, client: AttackClient):
        self.client = client

    def index(self, *, matrix=None, version=None) -> dict[str, list[dict]]:
        idx: dict[str, list[dict]] = defaultdict(list)
        for rel in self.client.relationships(matrix=matrix, version=version):
            idx[rel.get("source_ref", "")].append(rel)
        return idx

    def targets_of(self, stix_id: str, relationship_type: str | None = None, **kw):
        rels = self.index(**kw).get(stix_id, [])
        if relationship_type:
            rels = [r for r in rels if r.get("relationship_type") == relationship_type]
        return rels

    def techniques_used_by_software(self, software_stix_id: str, **kw):
        objs = self.client.objects(**kw)
        ext_by_stix = {o["stix_id"]: o["external_id"] for o in objs}
        out = []
        for r in self.targets_of(software_stix_id, "uses", **kw):
            t = ext_by_stix.get(r["target_ref"], "")
            if t.startswith("T"):
                out.append(t)
        return sorted(set(out))
