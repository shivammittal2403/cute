"""traceatlas.evidence.store - Content-addressed evidence store + registry.

Bytes are stored under a content-hash path (dedup for free), Evidence records
are persisted in an append-only JSONL registry, and integrity is verifiable at
any time. Case-scoped listing; no cross-case leakage by construction.
Production target: S3/MinIO-compatible object storage behind this interface.
"""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Optional

from traceatlas.core.evidence import Evidence


class EvidenceStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.blobs_dir = self.root / "blobs"
        self.registry_path = self.root / "evidence_registry.jsonl"
        os.makedirs(self.blobs_dir, exist_ok=True)
        self._index: dict[str, Evidence] = {}
        self._load_index()

    # ------------------------------------------------------------------ write
    def put_bytes(self, data: bytes, source_uri: str,
                  media_type: str = "application/octet-stream",
                  case_id: Optional[str] = None,
                  provenance=None) -> Evidence:
        ev = Evidence.from_bytes(data, source_uri=source_uri,
                                 media_type=media_type, case_id=case_id)
        storage_key = f"blobs/{ev.sha256[:2]}/{ev.sha256}"
        blob_path = self.root / storage_key
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        if not blob_path.exists():
            tmp = blob_path.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, blob_path)  # atomic publish
        changes = {"storage_key": storage_key}
        if provenance is not None:
            changes["provenance"] = provenance
        ev = replace(ev, **changes)
        self._index[ev.evidence_id] = ev
        with open(self.registry_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev.to_dict()) + "\n")
        return ev

    # ------------------------------------------------------------------- read
    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._index.get(evidence_id)

    def get_by_hash(self, sha256: str) -> Optional[Evidence]:
        for ev in self._index.values():
            if ev.sha256 == sha256:
                return ev
        return None

    def read_bytes(self, evidence_id: str) -> bytes:
        ev = self._index[evidence_id]
        return (self.root / ev.storage_key).read_bytes()

    def verify(self, evidence_id: str) -> bool:
        ev = self._index[evidence_id]
        return ev.verify_integrity(self.read_bytes(evidence_id))

    def list_for_case(self, case_id: str) -> list[Evidence]:
        return [e for e in self._index.values() if e.case_id == case_id]

    # -------------------------------------------------------------- internals
    def _load_index(self) -> None:
        if not self.registry_path.exists():
            return
        with open(self.registry_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = Evidence.from_dict(json.loads(line))
                except Exception:
                    continue
                self._index[ev.evidence_id] = ev
