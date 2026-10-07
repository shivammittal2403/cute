"""ATT&CK procedure extraction from software usage relationships.

Official bundles encode "malware X uses technique Y" as relationship objects;
the description text is the canonical procedure statement. We keep it verbatim
and mark provenance SOURCE_PROVIDED (section 13: source-provided vs
TraceAtlas-derived must be distinguishable).
"""
from __future__ import annotations

import re
from .client import AttackClient


class ProcedureStore:
    def __init__(self, client: AttackClient):
        self.client = client

    def for_software(self, external_id: str, *, matrix=None, version=None) -> list[dict]:
        """Return {technique_id, procedure_text, origin} for a malware/tool id."""
        objs = self.client.objects(matrix=matrix, version=version)
        stix_by_ext = {o["external_id"]: o["stix_id"] for o in objs}
        name_by_stix = {o["stix_id"]: (o["external_id"], o["name"]) for o in objs}
        src = stix_by_ext.get(external_id)
        out = []
        if not src:
            return out
        for rel in self.client.relationships(matrix=matrix, version=version):
            if rel.get("relationship_type") != "uses":
                continue
            if rel.get("source_ref") != src:
                continue
            tgt = name_by_stix.get(rel.get("target_ref"), ("", ""))
            tid = tgt[0]
            if not re.match(r"^T\d{4}(\.\d{3})?$", tid or ""):
                continue
            out.append({"technique_id": tid,
                        "procedure_text": rel.get("description", "").strip(),
                        "origin": "source_provided"})
        return out
