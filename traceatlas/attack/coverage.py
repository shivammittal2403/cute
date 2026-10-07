"""CoverageAnalyzer - detection/evidence coverage + gaps over mappings."""
from __future__ import annotations

from collections import defaultdict


class CoverageAnalyzer:
    def __init__(self, store):
        self.store = store

    def tactic_coverage(self, malware_id: str) -> dict:
        cov: dict[str, dict] = {}
        for m in self.store.find("attack_mappings", lambda r: r.get("malware_id") == malware_id):
            t = m.get("tactic_id") or "unassigned"
            cell = cov.setdefault(t, {"techniques": set(), "states": set(),
                                      "with_evidence": 0, "total": 0})
            cell["techniques"].add(m.get("subtechnique_id") or m.get("technique_id"))
            cell["states"].add(m.get("cell_state", ""))
            cell["total"] += 1
            if m.get("evidence_ids"):
                cell["with_evidence"] += 1
        return {t: {"techniques": sorted(c["techniques"]), "states": sorted(c["states"]),
                   "mapped": c["total"], "evidence_backed": c["with_evidence"]}
                for t, c in cov.items()}

    def detection_coverage(self, malware_id: str) -> dict:
        """Which mapped techniques have linked Sigma/YARA/Suricata detections."""
        mapped = {(m.get("subtechnique_id") or m.get("technique_id"))
                  for m in self.store.find("attack_mappings",
                                           lambda r: r.get("malware_id") == malware_id)}
        covered = set()
        for coll in ("sigma_rules", "yara_rules"):
            for rule in self.store.all(coll):
                if malware_id in rule.get("linked_malware_ids", []):
                    covered |= {t for t in rule.get("attack_technique_ids", []) if t}
        return {"mapped_techniques": sorted(mapped),
                "covered_techniques": sorted(mapped & covered),
                "missing_coverage": sorted(mapped - covered)}

    def time_filtered(self, malware_id: str, *, start: str | None = None,
                      end: str | None = None) -> list[dict]:
        def keep(m):
            ts = m.get("created_at") or ""
            if start and ts < start:
                return False
            if end and ts > end:
                return False
            return True
        return self.store.find("attack_mappings",
                               lambda r: r.get("malware_id") == malware_id and keep(r))
