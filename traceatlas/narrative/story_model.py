"""traceatlas.narrative.story_model - Typed narrative primitives.

Every sentence in a story is a NarrativeStatement with an epistemic type and
mandatory citation contract enforced by validation.py:
  FACT        -> requires evidence_ids (non-empty)
  HYPOTHESIS  -> requires hypothesis_id
  INFERENCE   -> requires evidence_ids
  SPECULATION -> must be labeled; excluded from executive findings
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.synthesis.state import StatementType


@dataclass(slots=True)
class NarrativeStatement:
    statement_id: ID = field(default_factory=lambda: new_id("nstmt"))
    stype: StatementType = StatementType.OBSERVATION
    text: str = ""
    evidence_ids: list[ID] = field(default_factory=list)
    entity_ids: list[ID] = field(default_factory=list)
    relationship_ids: list[ID] = field(default_factory=list)
    hypothesis_id: Optional[ID] = None
    graph_highlight: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"statement_id": self.statement_id, "type": self.stype.value,
                "text": self.text, "evidence_ids": list(self.evidence_ids),
                "entity_ids": list(self.entity_ids),
                "relationship_ids": list(self.relationship_ids),
                "hypothesis_id": self.hypothesis_id,
                "graph_highlight": self.graph_highlight}


@dataclass(slots=True)
class Scene:
    scene_id: ID = field(default_factory=lambda: new_id("scene"))
    title: str = ""
    statements: list[NarrativeStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"scene_id": self.scene_id, "title": self.title,
                "statements": [s.to_dict() for s in self.statements]}


@dataclass(slots=True)
class Chapter:
    chapter_id: ID = field(default_factory=lambda: new_id("chapter"))
    number: int = 0
    title: str = ""
    scenes: list[Scene] = field(default_factory=list)

    @property
    def statements(self) -> list[NarrativeStatement]:
        return [s for sc in self.scenes for s in sc.statements]

    def to_dict(self) -> dict[str, Any]:
        return {"chapter_id": self.chapter_id, "number": self.number,
                "title": self.title, "scenes": [s.to_dict() for s in self.scenes]}


@dataclass(slots=True)
class Story:
    story_id: ID = field(default_factory=lambda: new_id("story"))
    case_id: Optional[ID] = None
    mode: str = "investigator"     # executive|investigator|timeline|entity|...
    title: str = ""
    chapters: list[Chapter] = field(default_factory=list)

    @property
    def all_statements(self) -> list[NarrativeStatement]:
        return [s for c in self.chapters for sc in c.scenes for s in sc.statements]

    def to_dict(self) -> dict[str, Any]:
        return {"story_id": self.story_id, "case_id": self.case_id,
                "mode": self.mode, "title": self.title,
                "chapters": [c.to_dict() for c in self.chapters]}


# Canonical chapter plan (spec §12)
CHAPTER_TITLES = {
    1: "Objective",
    2: "Initial Picture",
    3: "Key Entities",
    4: "Important Relationships",
    5: "Timeline",
    6: "Critical Evidence",
    7: "Patterns",
    8: "Contradictions",
    9: "Hypotheses",
    10: "Competing Explanations",
    11: "Unknown Information",
    12: "Next Investigative Moves",
    13: "Current Assessment",
}
