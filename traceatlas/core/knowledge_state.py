"""traceatlas.core.knowledge_state - Snapshot of everything known for a case."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .claim import Claim
from .contradiction import Contradiction
from .entity import Entity
from .fact import Fact
from .hypothesis import Hypothesis
from .identifiers import ID
from .information_gap import InformationGap
from .relationship import Relationship


@dataclass(slots=True)
class KnowledgeState:
    case_id: Optional[ID] = None
    entities: dict[ID, Entity] = field(default_factory=dict)
    relationships: dict[ID, Relationship] = field(default_factory=dict)
    facts: dict[ID, Fact] = field(default_factory=dict)
    claims: dict[ID, Claim] = field(default_factory=dict)
    hypotheses: dict[ID, Hypothesis] = field(default_factory=dict)
    contradictions: dict[ID, Contradiction] = field(default_factory=dict)
    gaps: dict[ID, InformationGap] = field(default_factory=dict)

    def open_gaps(self) -> list[InformationGap]:
        return [g for g in self.gaps.values() if g.open]

    def blocking_gaps(self) -> list[InformationGap]:
        return [g for g in self.open_gaps() if g.blocking]

    def unresolved_contradictions(self) -> list[Contradiction]:
        return [c for c in self.contradictions.values() if not c.resolved]

    def supported_claims(self) -> list[Claim]:
        return [c for c in self.claims.values() if c.is_supported()]

    def completion_ratio(self) -> float:
        supported = len(self.supported_claims())
        contested = sum(1 for c in self.claims.values()
                        if c.status.value in ("proposed", "contested"))
        gaps = len(self.open_gaps())
        total = supported + contested + gaps
        return supported / total if total else 0.0
