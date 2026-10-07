"""AttackClient - version-aware query surface over ingested ATT&CK snapshots."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .version import pin_version


class AttackClient:
    def __init__(self, root: str | Path, *, default_matrix: str = "enterprise"):
        self.root = Path(root)
        self.default_matrix = default_matrix
        self._cache: dict[tuple[str, str], list[dict]] = {}

    # ------------------------------------------------------------- snapshot io
    def _snapshot(self, matrix: str, version: str | None) -> list[dict]:
        version = pin_version(version) if version else self._latest(matrix)
        if not version:
            return []
        key = (matrix, version)
        if key not in self._cache:
            p = self.root / matrix / version / "objects.json"
            self._cache[key] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
        return self._cache[key]

    def _latest(self, matrix: str) -> str | None:
        d = self.root / matrix
        if not d.exists():
            return None
        dirs = [p.name for p in d.iterdir() if p.is_dir()]
        return sorted(dirs)[-1] if dirs else None

    def version(self, matrix: str | None = None) -> str | None:
        return self._latest(matrix or self.default_matrix)

    def objects(self, *, attack_type: str | None = None, matrix: str | None = None,
                version: str | None = None) -> list[dict]:
        matrix = matrix or self.default_matrix
        objs = self._snapshot(matrix, version)
        if attack_type:
            objs = [o for o in objs if o["attack_type"] == attack_type]
        return objs

    def tactics(self, **kw) -> list[dict]:
        return self.objects(attack_type="tactic", **kw)

    def techniques(self, **kw) -> list[dict]:
        return self.objects(attack_type="technique", **kw)

    def subtechniques(self, **kw) -> list[dict]:
        return self.objects(attack_type="subtechnique", **kw)

    def software(self, **kw) -> list[dict]:
        return self.objects(attack_type="software", **kw)

    def groups(self, **kw) -> list[dict]:
        return self.objects(attack_type="group", **kw)

    def mitigations(self, **kw) -> list[dict]:
        return self.objects(attack_type="mitigation", **kw)

    def by_external_id(self, external_id: str, *, matrix: str | None = None,
                       version: str | None = None) -> dict | None:
        for o in self.objects(matrix=matrix, version=version):
            if o.get("external_id") == external_id:
                return o
        return None

    def exists(self, external_id: str, *, matrix: str | None = None,
               version: str | None = None) -> bool:
        return self.by_external_id(external_id, matrix=matrix, version=version) is not None

    def relationships(self, matrix: str | None = None, version: str | None = None) -> list[dict]:
        matrix = matrix or self.default_matrix
        version = pin_version(version) if version else self._latest(matrix)
        if not version:
            return []
        p = self.root / matrix / version / "relationships.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []

    def parent_of_subtechnique(self, subtech_id: str, **kw) -> str:
        obj = self.by_external_id(subtech_id, **kw)
        if not obj:
            return ""
        return subtech_id.split(".")[0]
