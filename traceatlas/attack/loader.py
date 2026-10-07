"""STIX bundle loader for official ATT&CK content (versioned snapshots).

Supports the official x-mitre-* STIX 2.1 objects:
  x-mitre-tactic, attack-pattern (techniques/sub-techniques), x-mitre-matrix,
  intrusion-set (groups), campaign, course-of-action (mitigations),
  x-mitre-detection-strategy / analytic (detections), relationship objects.
Software usage records come from malware/tools STIX + uses-relationships.

The loader never mutates previously stored versions: each release is a new
immutable snapshot directory keyed by version string.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AttackObject:
    stix_id: str
    attack_type: str            # tactic|technique|subtechnique|matrix|group|...
    external_id: str            # T1059 / TA0002 / G0016 / ...
    name: str
    version: str                # ATT&CK entry version (x_mitre_version)
    created: str
    modified: str
    deprecated: bool = False
    revoked: bool = False
    platforms: list[str] = field(default_factory=list)
    kill_chain_phases: list[dict] = field(default_factory=list)   # tactic names
    data_sources: list[str] = field(default_factory=list)
    parent_ref: str = ""        # sub-technique -> technique stix ref
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"stix_id": self.stix_id, "attack_type": self.attack_type,
                "external_id": self.external_id, "name": self.name,
                "version": self.version, "created": self.created,
                "modified": self.modified, "deprecated": self.deprecated,
                "revoked": self.revoked, "platforms": self.platforms,
                "kill_chain_phases": self.kill_chain_phases,
                "data_sources": self.data_sources, "parent_ref": self.parent_ref}


def _classify(sdo: dict) -> str | None:
    t = sdo.get("type")
    ext_ids = [x.get("value") for x in sdo.get("external_references", [])]
    if t == "x-mitre-tactic":
        return "tactic"
    if t == "attack-pattern":
        return "subtechnique" if "." in (ext_ids[0] if ext_ids else "") else "technique"
    if t == "x-mitre-matrix":
        return "matrix"
    if t == "intrusion-set":
        return "group"
    if t == "campaign":
        return "campaign"
    if t == "course-of-action":
        return "mitigation"
    if t in ("malware", "tool"):
        return "software"
    if t.startswith("x-mitre-detection"):
        return "detection"
    if t == "relationship":
        return "relationship"
    return None


class StixLoader:
    MATRIX_BY_PREFIX = {"TA": "enterprise", "TAA": "ics"}

    def load_bundle(self, path_or_obj: str | Path | dict) -> tuple[str, list[AttackObject], list[dict]]:
        """Return (attack_version, objects, relationships) from one STIX bundle."""
        if isinstance(path_or_obj, dict):
            bundle = path_or_obj
        else:
            bundle = json.loads(Path(path_or_obj).read_text(encoding="utf-8"))
        if bundle.get("type") != "bundle":
            raise ValueError("not a STIX bundle")
        spec = bundle.get("spec_version", "2.1")
        if not str(spec).startswith("2."):
            raise ValueError(f"unsupported STIX spec {spec}")
        version = self._detect_version(bundle)
        objs: list[AttackObject] = []
        rels: list[dict] = []
        for sdo in bundle.get("objects", []):
            kind = _classify(sdo)
            if kind == "relationship":
                rels.append({
                    "source_ref": sdo.get("source_ref"),
                    "target_ref": sdo.get("target_ref"),
                    "relationship_type": sdo.get("relationship_type"),
                    "description": sdo.get("description", ""),
                })
                continue
            if not kind:
                continue
            ext_refs = sdo.get("external_references", []) or []
            external_id = ""
            mitre_version = ""
            for er in ext_refs:
                if str(er.get("source_name", "")).lower().startswith("mitre"):
                    external_id = er.get("external_id", "")
                    mitre_version = er.get("version", "") or mitre_version
            objs.append(AttackObject(
                stix_id=sdo.get("id", ""),
                attack_type=kind,
                external_id=external_id,
                name=sdo.get("name", ""),
                version=mitre_version or sdo.get("x_mitre_version", ""),
                created=sdo.get("created", ""),
                modified=sdo.get("modified", ""),
                deprecated=bool(sdo.get("x_mitre_deprecated", False)),
                revoked=bool(sdo.get("x_mitre_revoked", False)),
                platforms=list(sdo.get("x_mitre_platforms", []) or []),
                kill_chain_phases=[{"phase_name": p.get("phase_name"),
                                    "kill_chain_name": p.get("kill_chain_name")}
                                   for p in sdo.get("kill_chain_phases", []) or []],
                data_sources=list(sdo.get("x_mitre_data_sources", []) or []),
                parent_ref=sdo.get("x_mitre_is_subtechnique_of", "") or \
                    self._parent_from_external(sdo),
                raw={},
            ))
        return version, objs, rels

    @staticmethod
    def _parent_from_external(sdo: dict) -> str:
        for er in sdo.get("external_references", []) or []:
            url = er.get("url", "")
            if url.endswith("/") and ".0" in (er.get("external_id") or ""):
                parent = er["external_id"].split(".")[0]
                return f"attack-pattern--{parent}"      # resolved by id later
        return ""

    @staticmethod
    def _detect_version(bundle: dict) -> str:
        """Version comes from bundle metadata; fall back to matrix refs scan."""
        meta = str(bundle.get("x_traceatlas_attack_version", "") or
                   bundle.get("x_mitre_version", ""))
        if meta:
            return meta
        ext = json.dumps(bundle)[:200000]
        import re
        m = re.search(r"attack\.mil/data/versions/(\d+(?:\.\d+)?)/", ext)
        if m:
            return m.group(1)
        raise ValueError("cannot determine ATT&CK version from bundle; "
                         "set x_traceatlas_attack_version or use an official bundle URL")
