"""traceatlas.hypotheses.ach - Analysis of Competing Hypotheses matrix (spec §7).

For each evidence item classify CONSISTENT / INCONSISTENT / NEUTRAL / UNKNOWN
against every hypothesis in a competing set. Ranking prefers FEWER important
inconsistencies, not more supporting counts: one discriminating contradiction
outranks ten weak supportive observations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .model import Hypothesis


class ACHVerdict(str, Enum):
    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"
    NEUTRAL = "neutral"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class EvidenceItem:
    evidence_id: str
    description: str
    weight: float = 1.0            # importance; discriminating facts weigh more
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ACHMatrix:
    question: str
    hypotheses: list[Hypothesis]
    evidence: list[EvidenceItem]
    cells: dict[tuple[str, str], ACHVerdict] = field(default_factory=dict)

    def verdict(self, hyp_id: str, ev_id: str) -> ACHVerdict:
        return self.cells.get((hyp_id, ev_id), ACHVerdict.UNKNOWN)

    def inconsistency_score(self, hyp_id: str) -> float:
        """Weighted sum of INCONSISTENT cells — LOWER is better."""
        ev_by_id = {e.evidence_id: e for e in self.evidence}
        total = 0.0
        for (h, e), v in self.cells.items():
            if h == hyp_id and v is ACHVerdict.INCONSISTENT:
                total += ev_by_id[e].weight
        return total

    def ranked(self) -> list[tuple[Hypothesis, float]]:
        scored = [(h, self.inconsistency_score(h.hypothesis_id))
                  for h in self.hypotheses]
        return sorted(scored, key=lambda t: t[1])

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "hypotheses": [h.hypothesis_id for h in self.hypotheses],
            "evidence": [e.evidence_id for e in self.evidence],
            "cells": {f"{h}|{e}": v.value for (h, e), v in self.cells.items()},
            "ranking": [{"hypothesis_id": h.hypothesis_id,
                         "weighted_inconsistency": s}
                        for h, s in self.ranked()],
        }


_TOKEN = re.compile(r"[a-z0-9_]{3,}")


def _tokens(s: str) -> set[str]:
    return set(_TOKEN.findall(s.lower()))


def default_consistency(hyp: Hypothesis, ev: EvidenceItem) -> ACHVerdict:
    """Deterministic lexical classifier used until a calibrated model exists.

    Explicit lists win; otherwise token overlap decides consistent vs neutral.
    Never fabricates INCONSISTENT without an opposing marker.
    """
    for eid in hyp.opposing_evidence_ids:
        if eid == ev.evidence_id:
            return ACHVerdict.INCONSISTENT
    for eid in hyp.supporting_evidence_ids:
        if eid == ev.evidence_id:
            return ACHVerdict.CONSISTENT
    ht, et = _tokens(hyp.statement + " " + hyp.description), _tokens(ev.description)
    if not ht or not et:
        return ACHVerdict.UNKNOWN
    jaccard = len(ht & et) / max(1, len(ht | et))
    if jaccard >= 0.25:
        return ACHVerdict.CONSISTENT
    if jaccard <= 0.05:
        return ACHVerdict.NEUTRAL
    return ACHVerdict.UNKNOWN


def build_matrix(question: str, hypotheses: list[Hypothesis],
                 evidence: list[EvidenceItem],
                 classifier=None) -> ACHMatrix:
    """Populate the full H x E matrix with explicit IDs taking precedence."""
    clf = classifier or default_consistency
    m = ACHMatrix(question=question, hypotheses=hypotheses, evidence=evidence)
    for h in hypotheses:
        for e in evidence:
            m.cells[(h.hypothesis_id, e.evidence_id)] = clf(h, e)
    return m
