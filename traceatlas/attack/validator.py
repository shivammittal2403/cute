"""AttackValidator - deterministic ATT&CK ID validation against a pinned version.

Checks: object exists in the pinned snapshot; sub-technique parentage; tactic
membership; platform scope; deprecation/revocation awareness. This is the
third leg of the dual-AI cross-check (section 12).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .client import AttackClient


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resolved_technique_id: str = ""
    resolved_tactic_ids: list[str] = field(default_factory=list)
    deprecated: bool = False
    revoked_by: str = ""


class AttackValidator:
    def __init__(self, client: AttackClient):
        self.client = client

    def validate_mapping(self, *, technique_id: str, subtechnique_id: str = "",
                         tactic_id: str = "", matrix: str = "enterprise",
                         attack_version: str | None = None,
                         malware_platforms: list[str] | None = None) -> ValidationResult:
        v = ValidationResult(ok=False)
        eff = subtechnique_id or technique_id
        if not eff:
            v.errors.append("no technique or sub-technique id supplied")
            return v
        obj = self.client.by_external_id(eff, matrix=matrix, version=attack_version)
        if not obj:
            v.errors.append(f"{eff} does not exist in ATT&CK "
                            f"{attack_version or self.client.version(matrix)} ({matrix})")
            return v
        v.resolved_technique_id = obj["external_id"]
        v.deprecated = obj.get("deprecated", False)
        if obj.get("revoked"):
            v.revoked_by = obj.get("revoked_by", "") or "unknown target"
            v.errors.append(f"{eff} is REVOKED in this version (by {v.revoked_by}); "
                            "new mappings must point at the revoking object")
            return v
        if v.deprecated:
            v.warnings.append(f"{eff} is deprecated in this version; mapping allowed "
                              "for historical fidelity but flagged")
        phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
        v.resolved_tactic_ids = phases
        if tactic_id:
            ta = self.client.by_external_id(tactic_id, matrix=matrix, version=attack_version)
            if not ta:
                v.errors.append(f"tactic {tactic_id} not found in pinned version")
            elif ta.get("name", "").lower().replace(" ", "-") not in \
                    [p.lower() for p in phases] and ta.get("name", "").lower() not in \
                    [p.lower().replace("-", " ") for p in phases]:
                v.errors.append(
                    f"{eff} is not associated with tactic {tactic_id} in this version "
                    f"(known phases: {phases})")
        if "." in (subtechnique_id or ""):
            parent = subtechnique_id.split(".")[0]
            if not self.client.exists(parent, matrix=matrix, version=attack_version):
                v.errors.append(f"parent technique {parent} missing for {subtechnique_id}")
        plats = [p.lower() for p in obj.get("platforms", [])]
        if malware_platforms and plats and "all" not in plats:
            overlap = {str(p).lower() for p in malware_platforms} & set(plats)
            if not overlap:
                v.warnings.append(
                    f"platform scope mismatch: {eff} lists {plats}, malware on "
                    f"{sorted({str(p).lower() for p in malware_platforms})}; "
                    "do not force enterprise mappings onto mobile/ICS cases")
        v.ok = not v.errors
        return v
