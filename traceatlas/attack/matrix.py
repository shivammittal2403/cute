"""MatrixBuilder - Navigator-style internal views (section 20).

Produces tactic -> technique -> sub-technique trees with per-cell state
(OBSERVED / SOURCE_REPORTED / TRACEATLAS_MAPPED / SUPPORTED / DISPUTED /
INCONCLUSIVE), overlay support for comparisons, and time filtering.
"""
from __future__ import annotations

from collections import defaultdict

STATE_ORDER = ["observed", "source_reported", "traceatlas_mapped", "supported",
               "disputed", "inconclusive"]
# Weakest-visible wins so disputes never disappear under consensus cells.
_STATE_RANK = {s: i for i, s in enumerate(STATE_ORDER)}


class MatrixBuilder:
    def __init__(self, client, store):
        self.client = client      # AttackClient
        self.store = store        # MalwareStore

    def build(self, malware_ids: list[str] | str, *, matrix: str = "enterprise",
              version: str | None = None, start: str | None = None,
              end: str | None = None) -> dict:
        ids = [malware_ids] if isinstance(malware_ids, str) else list(malware_ids)
        tactics = {t["external_id"]: t["name"] for t in
                   self.client.tactics(matrix=matrix, version=version)}
        grid: dict[str, dict[str, dict]] = defaultdict(
            lambda: defaultdict(lambda: {"state": "", "evidence": [], "procedures": [],
                                         "sources": [], "campaigns": [], "times": [],
                                         "confidence": 0.0, "by_malware": {}}))
        used = 0
        for mid in ids:
            for m in self.store.find("attack_mappings",
                                     lambda r, _m=mid: r.get("malware_id") == _m):
                ts = m.get("created_at") or ""
                if (start and ts < start) or (end and ts > end):
                    continue
                tid = m.get("technique_id") or ""
                sid = m.get("subtechnique_id") or ""
                tac = m.get("tactic_id") or (
                    _phase_to_ta(self.client, tid or sid, matrix, version) or "TA??")
                cell = grid[tac][tid]
                st = m.get("cell_state", "traceatlas_mapped")
                if _STATE_RANK.get(st, 99) >= _STATE_RANK.get(cell["state"] or "observed", -1):
                    if not cell["state"] or _STATE_RANK.get(st, 99) >= \
                            _STATE_RANK.get(cell["state"], -1):
                        cell["state"] = st
                cell["evidence"].extend(m.get("evidence_ids", []))
                if m.get("procedure"):
                    cell["procedures"].append(m["procedure"])
                cell["sources"].extend(m.get("source_ids", []))
                cell["confidence"] = max(cell["confidence"], m.get("confidence", 0))
                cell["by_malware"][mid] = st
                used += 1
        out = {"matrix": matrix, "attack_version": version or self.client.version(matrix),
               "malware_ids": ids, "tactics": []}
        for tac_id in sorted(grid, key=lambda t: list(tactics).index(t)
                             if t in tactics else 99):
            out["tactics"].append({
                "tactic_id": tac_id, "tactic_name": tactics.get(tac_id, tac_id),
                "techniques": [{"technique_id": tid,
                                **{k: (sorted(set(v)) if isinstance(v, list) else v)
                                   for k, v in cell.items()}}
                               for tid, cell in sorted(grid[tac_id].items())]})
        out["mapping_count"] = used
        return out

    def overlay(self, malware_ids: list[str], **kw) -> dict:
        base = self.build(malware_ids, **kw)
        for tac in base["tactics"]:
            for tech in tac["techniques"]:
                tech["overlay"] = tech.pop("by_malware", {})
        return base


def _phase_to_ta(client, ext_id, matrix, version):
    obj = client.by_external_id(ext_id, matrix=matrix, version=version) if ext_id else None
    if not obj:
        return ""
    phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
    for t in client.tactics(matrix=matrix, version=version):
        if t.get("name", "").lower().replace(" ", "-") in \
                [p.lower() for p in phases]:
            return t["external_id"]
    return ""
