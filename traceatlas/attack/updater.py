"""ATT&CK updater: fetch/refresh pinned official snapshots.

Network access is policy-gated exactly like OSINT: disabled unless explicitly
enabled; default behaviour validates a *provided* bundle file rather than
fetching. The updater keeps every historical version side-by-side so old
mappings remain resolvable against the version they were made on.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .loader import StixLoader


class AttackUpdater:
    OFFICIAL_BUNDLE_URLS = {
        # Official MITRE ATT&CK STIX 2.1 bundles (public knowledge base).
        "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    }

    def __init__(self, root: str | Path, *, network_enabled: bool = False):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.network_enabled = network_enabled
        self.loader = StixLoader()

    def update_from_file(self, matrix: str, bundle_path: str | Path) -> dict:
        """Ingest an already-downloaded official bundle into a version snapshot."""
        version, objs, rels = self.loader.load_bundle(bundle_path)
        snap_dir = self.root / matrix / version
        snap_dir.mkdir(parents=True, exist_ok=True)
        out = {"attack_version": version, "matrix": matrix,
               "ingested_at": datetime.now(timezone.utc).isoformat(),
               "object_count": len(objs), "relationship_count": len(rels)}
        (snap_dir / "objects.json").write_text(
            json.dumps([o.to_dict() for o in objs]), encoding="utf-8")
        (snap_dir / "relationships.json").write_text(
            json.dumps(rels), encoding="utf-8")
        (snap_dir / "manifest.json").write_text(json.dumps(out), encoding="utf-8")
        return out

    def update_from_network(self, matrix: str) -> dict:
        if not self.network_enabled:
            raise PermissionError(
                "ATT&CK network update disabled by policy; download the official "
                "bundle separately and call update_from_file()")
        import urllib.request
        url = self.OFFICIAL_BUNDLE_URLS[matrix]
        tmp = self.root / f"_download_{matrix}.json"
        with urllib.request.urlopen(url, timeout=120) as resp:   # noqa: S310 - fixed host allowlist
            tmp.write_bytes(resp.read())
        try:
            return self.update_from_file(matrix, tmp)
        finally:
            tmp.unlink(missing_ok=True)

    def available_versions(self, matrix: str) -> list[str]:
        d = self.root / matrix
        return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.exists() else []

    def latest(self, matrix: str) -> str | None:
        vs = self.available_versions(matrix)
        return vs[-1] if vs else None
