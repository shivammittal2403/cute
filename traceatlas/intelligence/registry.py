"""traceatlas.intelligence.registry — authoritative module registry (§1, §5).

Holds ModuleManifests + worker callables for the 65 catalogued modules. A
manifest that fails validate() CANNOT be registered (InvalidManifestError), so
the planner/UI/API can trust everything they see here. Registration status is
data: it records what tests actually prove, never what we hope exists.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from traceatlas.intelligence import catalog
from traceatlas.intelligence.contracts import EmployeeResult, ModuleManifest, TaskSpec
from traceatlas.intelligence.errors import InvalidManifestError, UnknownModuleError


@dataclass(slots=True)
class RegisteredModule:
    manifest: ModuleManifest
    worker: Callable[[TaskSpec], EmployeeResult]
    spec: catalog.ModuleSpec | None = None


class IntelligenceRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._modules: dict[str, RegisteredModule] = {}

    # ------------------------------------------------------------------- write
    def register(self, manifest: ModuleManifest,
                 worker: Callable[[TaskSpec], EmployeeResult]) -> RegisteredModule:
        errors = manifest.validate()
        if errors:
            raise InvalidManifestError(
                f"manifest {manifest.module_id} invalid: {errors}", detail={"errors": errors})
        mid = manifest.module_id.lower()
        spec = catalog.spec(mid)
        with self._lock:
            entry = RegisteredModule(manifest=manifest, worker=worker, spec=spec)
            self._modules[mid] = entry
        return entry

    # -------------------------------------------------------------------- read
    def get(self, module_id: str) -> RegisteredModule:
        mid = catalog.resolve_module_id(module_id)
        with self._lock:
            entry = self._modules.get(mid)
        if entry is None:
            raise UnknownModuleError(f"module '{module_id}' not registered",
                                     detail={"resolved_id": mid,
                                             "in_catalog": catalog.spec(mid) is not None})
        return entry

    def contains(self, module_id: str) -> bool:
        try:
            self.get(module_id)
            return True
        except UnknownModuleError:
            return False

    def list_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._modules))

    def all_manifests(self) -> list[ModuleManifest]:
        with self._lock:
            return [m.manifest for m in self._modules.values()]

    def by_category(self, category: str) -> list[ModuleManifest]:
        return [m for m in self.all_manifests() if m.category == category]

    def unregistered_catalog_ids(self) -> tuple[str, ...]:
        """Honest gap view: catalogued but not yet implemented+registered."""
        reg = set(self.list_ids())
        return tuple(m for m in catalog.MODULE_IDS if m not in reg)

    def coverage(self) -> dict:
        ids = set(self.list_ids())
        statuses: dict[str, int] = {}
        for m in self.all_manifests():
            statuses[m.status] = statuses.get(m.status, 0) + 1
        return {"catalog_total": len(catalog.MODULES), "registered": len(ids),
                "by_status": statuses}

    def __len__(self) -> int:
        with self._lock:
            return len(self._modules)


# process-wide default registry (populated by traceatlas.intelligence.bootstrap)
DEFAULT_REGISTRY = IntelligenceRegistry()
