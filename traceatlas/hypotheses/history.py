"""traceatlas.hypotheses.history - Append-only hypothesis state history.

Supports 'what changed since the last run?' for hypotheses: strengthened,
weakened, falsified, newly added, newly competing.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from traceatlas.core.provenance import utcnow

from .model import Hypothesis, HypothesisLifecycle, QualitativeConfidence


@dataclass(slots=True)
class HypothesisSnapshot:
    hypothesis_id: str
    statement: str
    status: str
    confidence: str
    supporting_count: int
    opposing_count: int
    assumption_burden: int
    recorded_at: str


@dataclass(slots=True)
class HypothesisChange:
    hypothesis_id: str
    kind: str            # added | strengthened | weakened | falsified | status
    from_status: str
    to_status: str
    detail: str


def snapshot(h: Hypothesis, when: Optional[datetime] = None) -> HypothesisSnapshot:
    return HypothesisSnapshot(
        hypothesis_id=h.hypothesis_id, statement=h.statement,
        status=h.status.value, confidence=h.confidence.value,
        supporting_count=len(h.supporting_evidence_ids),
        opposing_count=len(h.opposing_evidence_ids),
        assumption_burden=h.scores.assumption_burden,
        recorded_at=(when or utcnow()).isoformat())


def diff_snapshots(old: dict[str, HypothesisSnapshot],
                   new: dict[str, HypothesisSnapshot]) -> list[HypothesisChange]:
    """Compare two {hypothesis_id: snapshot} maps (previous run vs current)."""
    changes: list[HypothesisChange] = []
    for hid, ns in new.items():
        os_ = old.get(hid)
        if os_ is None:
            changes.append(HypothesisChange(hid, "added", "", ns.status,
                                            f"new hypothesis: {ns.statement[:80]}"))
            continue
        if ns.status != os_.status:
            kind = "status"
            if ns.status == HypothesisLifecycle.FALSIFIED.value:
                kind = "falsified"
            elif _rank(ns.confidence) > _rank(os_.confidence):
                kind = "strengthened"
            elif _rank(ns.confidence) < _rank(os_.confidence):
                kind = "weakened"
            changes.append(HypothesisChange(hid, kind, os_.status, ns.status,
                                            f"{os_.status}->{ns.status} "
                                            f"({os_.confidence}->{ns.confidence})"))
    for hid, os_ in old.items():
        if hid not in new:
            changes.append(HypothesisChange(hid, "removed", os_.status, "",
                                            "hypothesis no longer tracked"))
    return changes


_CONF_ORDER = [QualitativeConfidence.VERY_LOW, QualitativeConfidence.LOW,
               QualitativeConfidence.MODERATE, QualitativeConfidence.HIGH,
               QualitativeConfidence.VERY_HIGH]


def _rank(c: str) -> int:
    try:
        return _CONF_ORDER.index(QualitativeConfidence(c))
    except ValueError:
        return -1


class HypothesisHistory:
    def __init__(self, persist_path: str | Path | None = None):
        self._runs: list[dict[str, HypothesisSnapshot]] = []
        self._persist = Path(persist_path) if persist_path else None

    def record_run(self, hypotheses: list[Hypothesis]) -> list[HypothesisChange]:
        cur = {h.hypothesis_id: snapshot(h) for h in hypotheses}
        prev = self._runs[-1] if self._runs else {}
        changes = diff_snapshots(prev, cur)
        self._runs.append(cur)
        if self._persist:
            self._persist.parent.mkdir(parents=True, exist_ok=True)
            with self._persist.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"snapshots": {k: asdict(v) for k, v in cur.items()},
                                    "changes": [asdict(c) for c in changes]},
                                   default=str) + "\n")
        return changes
