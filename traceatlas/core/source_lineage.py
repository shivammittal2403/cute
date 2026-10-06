"""traceatlas.core.source_lineage - Upstream/downstream lineage of sources."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .identifiers import ID


@dataclass(frozen=True, slots=True)
class SourceLineage:
    source_id: ID
    upstream_source_ids: tuple[ID, ...] = ()
    syndicated_from_id: Optional[ID] = None
    notes: str = ""

    def is_downstream_of(self, other_source_id: ID) -> bool:
        return (other_source_id in self.upstream_source_ids
                or self.syndicated_from_id == other_source_id)
