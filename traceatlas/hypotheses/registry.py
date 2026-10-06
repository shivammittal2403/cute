"""traceatlas.hypotheses.registry - Persisted hypothesis store per case.

JSONL append-only history + current-state snapshot, consistent with the
evidence/graph persistence pattern already used in TraceAtlas.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .model import Hypothesis, HypothesisLifecycle


class HypothesisRegistry:
    def __init__(self, persist_path: str | Path | None = None):
        self._by_id: dict[str, Hypothesis] = {}
        self._persist = Path(persist_path) if persist_path else None
        if self._persist and self._persist.exists():
            self._load()

    # -- CRUD ---------------------------------------------------------------
    def register(self, hyp: Hypothesis) -> Hypothesis:
        if hyp.hypothesis_id in self._by_id:
            raise ValueError(f"duplicate hypothesis id {hyp.hypothesis_id}")
        self._by_id[hyp.hypothesis_id] = hyp
        self._append({"op": "register", "hypothesis": hyp.to_dict()})
        return hyp

    def get(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self._by_id.get(hypothesis_id)

    def update(self, hyp: Hypothesis) -> Hypothesis:
        if hyp.hypothesis_id not in self._by_id:
            raise KeyError(hyp.hypothesis_id)
        self._by_id[hyp.hypothesis_id] = hyp
        self._append({"op": "update", "hypothesis": hyp.to_dict()})
        return hyp

    def all(self, case_id: Optional[str] = None,
            statuses: Optional[Iterable[HypothesisLifecycle]] = None) -> list[Hypothesis]:
        out = []
        status_set = set(statuses) if statuses else None
        for h in self._by_id.values():
            if case_id and h.case_id != case_id:
                continue
            if status_set and h.status not in status_set:
                continue
            out.append(h)
        return sorted(out, key=lambda h: h.created_at)

    def active(self, case_id: Optional[str] = None) -> list[Hypothesis]:
        live = {HypothesisLifecycle.ACTIVE, HypothesisLifecycle.TESTING,
                HypothesisLifecycle.STRENGTHENED, HypothesisLifecycle.WEAKENED,
                HypothesisLifecycle.SUPPORTED, HypothesisLifecycle.DISPUTED}
        return self.all(case_id=case_id, statuses=live)

    def link_competing(self, a_id: str, b_id: str) -> None:
        """Symmetric COMPETES_WITH link (spec §10)."""
        a, b = self.get(a_id), self.get(b_id)
        if not a or not b:
            raise KeyError("unknown hypothesis in competing link")
        if b_id not in a.competing_with:
            a.competing_with.append(b_id)
        if a_id not in b.competing_with:
            b.competing_with.append(a_id)
        self.update(a)
        self.update(b)

    # -- persistence --------------------------------------------------------
    def _append(self, record: dict) -> None:
        if not self._persist:
            return
        self._persist.parent.mkdir(parents=True, exist_ok=True)
        with self._persist.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def _load(self) -> None:
        assert self._persist is not None
        with self._persist.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("op") in ("register", "update"):
                    h = Hypothesis.from_dict(rec["hypothesis"])
                    self._by_id[h.hypothesis_id] = h
