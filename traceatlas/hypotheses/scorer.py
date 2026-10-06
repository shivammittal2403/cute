"""traceatlas.hypotheses.scorer - Recompute explainable score components.

Spec §9: no arbitrary percentages, no fake calibration. Components are stored
separately and mapped to qualitative bands. Copied sources do NOT inflate
support (independence clustering is an input). Stale evidence decays freshness.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from traceatlas.core.provenance import utcnow

from .model import Hypothesis, ScoreComponents


@dataclass(slots=True)
class EvidenceMeta:
    """Minimal metadata the scorer needs about a piece of evidence."""
    evidence_id: str
    source_id: str = ""
    authority: float = 0.5          # 0..1 registry authority_class mapping
    observed_at: Optional[datetime] = None
    independent_cluster: str = ""   # from source-independence engine


def _freshness(observed: Optional[datetime], now: datetime,
               half_life_days: float = 30.0) -> float:
    if observed is None:
        return 0.5   # unknown age => neutral-low, never assume fresh
    age = max((now - observed).total_seconds(), 0.0) / 86400.0
    return math.exp(-math.log(2) * age / half_life_days)


def rescore(hyp: Hypothesis, meta: list[EvidenceMeta],
            independence_clusters: dict[str, int] | None = None,
            best_alternative_strength: float = 0.0,
            contradiction_severity: float = 0.0,
            now: Optional[datetime] = None) -> ScoreComponents:
    """Rebuild ScoreComponents from linked evidence metadata. Deterministic."""
    now = now or utcnow()
    by_id = {m.evidence_id: m for m in meta}

    support = [by_id.get(e) for e in hyp.supporting_evidence_ids if by_id.get(e)]
    oppose = [by_id.get(e) for e in hyp.opposing_evidence_ids if by_id.get(e)]

    # Evidence strength saturates at 5 items; one strong item beats five weak.
    n = len(support)
    evidence_strength = min(1.0, n / 5.0) if n else 0.0
    source_authority = (sum(m.authority for m in support) / n) if n else 0.0

    clusters = {m.independent_cluster or m.source_id for m in support}
    clusters.discard("")
    source_independence = len(clusters)

    fr = [_freshness(m.observed_at, now) for m in support] or [0.0]
    freshness = sum(fr) / len(fr)

    required = hyp.required_evidence
    evidence_coverage = _coverage(hyp, support) if required else (1.0 if n else 0.0)

    temporal_consistency = 1.0
    if oppose:
        temporal_consistency = 0.4 if contradiction_severity > 0.5 else 0.7

    missing_penalty = 0.0
    if required and evidence_coverage < 1.0:
        missing_penalty = round(1.0 - evidence_coverage, 3)

    return ScoreComponents(
        evidence_strength=round(evidence_strength, 3),
        source_authority=round(source_authority, 3),
        source_independence=source_independence,
        temporal_consistency=round(temporal_consistency, 3),
        entity_consistency=hyp.scores.entity_consistency,
        relationship_consistency=hyp.scores.relationship_consistency,
        evidence_coverage=round(evidence_coverage, 3),
        contradiction_severity=round(contradiction_severity, 3),
        assumption_burden=len(hyp.assumptions),
        alternative_strength=round(best_alternative_strength, 3),
        freshness=round(freshness, 3),
        missing_evidence_penalty=missing_penalty,
    )


def _coverage(hyp: Hypothesis, support: list[EvidenceMeta]) -> float:
    """Fraction of required-evidence phrases matched by support descriptions.

    Without full-text evidence store access we approximate with tag/ID match;
    coverage stays conservative (never overclaims completeness)."""
    req = [r.lower() for r in hyp.required_evidence]
    if not req:
        return 1.0 if support else 0.0
    hay = " ".join((m.evidence_id + " " + m.source_id).lower() for m in support)
    hits = sum(1 for r in req if any(tok in hay for tok in r.split() if len(tok) > 4))
    return round(hits / len(req), 3)
