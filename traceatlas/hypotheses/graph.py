"""traceatlas.hypotheses.graph - Hypothesis nodes in the analytical graph.

Spec §10: hypotheses live in the graph but are typed distinctly from real
entities so the UI can never render them identically to facts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from traceatlas.core.identifiers import ID, new_id
from traceatlas.core.provenance import utcnow


class AnalyticalEdgeKind(str, Enum):
    """Edges that only ever touch analytical objects (never asserted as facts)."""
    SUPPORTED_BY = "supported_by"
    OPPOSED_BY = "opposed_by"
    DEPENDS_ON = "depends_on"          # hypothesis -> assumption
    COMPETES_WITH = "competes_with"    # hypothesis <-> hypothesis
    EXPLAINS = "explains"              # hypothesis -> observation
    REQUIRES = "requires"              # hypothesis -> missing evidence
    TESTED_BY = "tested_by"            # hypothesis -> investigation task


@dataclass(slots=True)
class AnalyticalNode:
    node_id: str
    ntype: str                     # hypothesis | assumption | missing_evidence | task
    label: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "ntype": self.ntype, "label": self.label,
                "payload": self.payload, "created_at": self.created_at.isoformat()}


@dataclass(slots=True)
class AnalyticalEdge:
    edge_id: ID = field(default_factory=lambda: new_id("aedge"))
    src: str = ""
    kind: AnalyticalEdgeKind = AnalyticalEdgeKind.SUPPORTED_BY
    dst: str = ""
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"edge_id": self.edge_id, "src": self.src, "kind": self.kind.value,
                "dst": self.dst, "rationale": self.rationale}


class HypothesisGraph:
    """Separate analytical overlay; the entity KnowledgeGraph stays fact-only."""

    def __init__(self) -> None:
        self._nodes: dict[str, AnalyticalNode] = {}
        self._edges: list[AnalyticalEdge] = []

    def add_hypothesis_node(self, hypothesis_id: str, statement: str,
                            status: str, confidence: str) -> AnalyticalNode:
        node = AnalyticalNode(node_id=hypothesis_id, ntype="hypothesis",
                              label=statement,
                              payload={"status": status, "confidence": confidence})
        self._nodes[hypothesis_id] = node
        return node

    def add_edge(self, src: str, kind: AnalyticalEdgeKind, dst: str,
                 rationale: str = "") -> AnalyticalEdge:
        e = AnalyticalEdge(src=src, kind=kind, dst=dst, rationale=rationale)
        self._edges.append(e)
        return e

    def link_hypothesis(self, h) -> None:
        """Populate overlay edges from a Hypothesis object (idempotent-ish)."""
        self.add_hypothesis_node(h.hypothesis_id, h.statement,
                                 h.status.value, h.confidence.value)
        for eid in h.supporting_evidence_ids:
            self.add_edge(h.hypothesis_id, AnalyticalEdgeKind.SUPPORTED_BY, eid,
                          "evidence supports hypothesis")
        for eid in h.opposing_evidence_ids:
            self.add_edge(h.hypothesis_id, AnalyticalEdgeKind.OPPOSED_BY, eid,
                          "evidence opposes hypothesis")
        for i, a in enumerate(h.assumptions):
            aid = f"{h.hypothesis_id}-assumption-{i}"
            self._nodes[aid] = AnalyticalNode(aid, "assumption", a)
            self.add_edge(h.hypothesis_id, AnalyticalEdgeKind.DEPENDS_ON, aid,
                          "unverified assumption")
        for i, r in enumerate(h.required_evidence):
            rid = f"{h.hypothesis_id}-missing-{i}"
            self._nodes[rid] = AnalyticalNode(rid, "missing_evidence", r)
            self.add_edge(h.hypothesis_id, AnalyticalEdgeKind.REQUIRES, rid,
                          "required to test hypothesis")
        for other in h.competing_with:
            self.add_edge(h.hypothesis_id, AnalyticalEdgeKind.COMPETES_WITH, other,
                          "ACH competing explanation")

    def neighbors_of(self, node_id: str) -> list[AnalyticalEdge]:
        return [e for e in self._edges if e.src == node_id or e.dst == node_id]

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": {k: v.to_dict() for k, v in self._nodes.items()},
                "edges": [e.to_dict() for e in self._edges]}
