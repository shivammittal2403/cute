"""traceatlas.planning.source_planner - Choose sources per capability."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from traceatlas.sources.registry import SourceRegistry


def sources_for_capability(registry: "SourceRegistry", capability: str,
                           qualification_min: str = "documented") -> list:
    return registry.find(capability=capability, min_qualification=qualification_min)
