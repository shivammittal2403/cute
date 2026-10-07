"""AttackComparator - ATT&CK overlap matrix + comparison report (sections 19, 38).

Overlap is computed over *validated mappings* with their evidence/procedure/
source/campaign/time/confidence attached - never bare technique IDs.
"""
from __future__ import annotations

from collections import defaultdict


class AttackComparator:
    def __init__(self, store):
        """store: MalwareStore-like object exposing find('attack_mappings', pred)."""
        self.store = store

    def mappings_for(self, malware_id: str) -> list[dict]:
        return self.store.find("attack_mappings", lambda r: r.get("malware_id") == malware_id)

    def overlap_matrix(self, malware_ids: list[str]) -> dict:
        per: dict[str, dict[str, list[dict]]] = {}
        for mid in malware_ids:
            cells: dict[str, list[dict]] = defaultdict(list)
            for m in self.mappings_for(mid):
                key = m.get("subtechnique_id") or m.get("technique_id")
                if key:
                    cells[key].append(m)
            per[mid] = dict(cells)
        all_ids = sorted({t for cells in per.values() for t in cells})
        matrix = []
        for tid in all_ids:
            row = {"technique_id": tid, "cells": {}}
            for mid in malware_ids:
                ms = per.get(mid, {}).get(tid, [])
                row["cells"][mid] = {
                    "present": bool(ms),
                    "states": sorted({m.get("cell_state", "") for m in ms}),
                    "evidence_ids": sorted({e for m in ms for e in m.get("evidence_ids", [])}),
                    "procedures": [m.get("procedure", "") for m in ms if m.get("procedure")],
                    "sources": sorted({s for m in ms for s in m.get("source_ids", [])}),
                    "campaigns": sorted({c for c in (m.get("campaign_id") for m in ms) if c}),
                    "max_confidence": max((m.get("confidence", 0) for m in ms), default=0),
                    "worst_verification": _worst(ms),
                }
            matrix.append(row)
        return {"malware_ids": malware_ids, "matrix": matrix}

    def compare_report(self, id_a: str, id_b: str) -> dict:
        a = {m.get("subtechnique_id") or m.get("technique_id") for m in self.mappings_for(id_a)} \
            - {""}
        b = {m.get("subtechnique_id") or m.get("technique_id") for m in self.mappings_for(id_b)} \
            - {""}
        tech_a = {t.split(".")[0] for t in a}
        tech_b = {t.split(".")[0] for t in b}
        sub_a = {t for t in a if "." in t}
        sub_b = {t for t in b if "." in t}
        tac_a = {m.get("tactic_id") for m in self.mappings_for(id_a) if m.get("tactic_id")}
        tac_b = {m.get("tactic_id") for m in self.mappings_for(id_b) if m.get("tactic_id")}
        return {
            "common_subtechniques": sorted(sub_a & sub_b),
            "unique_subtechniques_a": sorted(sub_a - sub_b),
            "unique_subtechniques_b": sorted(sub_b - sub_a),
            "common_techniques": sorted(tech_a & tech_b),
            "unique_techniques_a": sorted(tech_a - tech_b),
            "unique_techniques_b": sorted(tech_b - tech_a),
            "common_tactics": sorted(tac_a & tac_b),
            "procedure_differences": self._proc_diff(id_a, id_b, tech_a & tech_b),
            "note": "shared techniques do NOT imply same family",
        }

    def _proc_diff(self, id_a: str, id_b: str, shared: set[str]) -> list[dict]:
        out = []
        for t in sorted(shared):
            pa = [m.get("procedure", "") for m in self.mappings_for(id_a)
                  if (m.get("subtechnique_id") or m.get("technique_id")) == t or
                  m.get("technique_id") == t]
            pb = [m.get("procedure", "") for m in self.mappings_for(id_b)
                  if (m.get("subtechnique_id") or m.get("technique_id")) == t or
                  m.get("technique_id") == t]
            if pa != pb:
                out.append({"technique_id": t, "procedures_a": pa, "procedures_b": pb})
        return out


def _worst(ms: list[dict]) -> str:
    order = ["inconclusive", "contested", "pending", "validated"]
    states = {m.get("verification", "pending") for m in ms}
    for o in order:
        if o in states:
            return o
    return ""
