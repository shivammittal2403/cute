"""traceatlas.patterns.engine - Deterministic pattern detection (spec §17).

Finds structural/temporal/infrastructure patterns over observations:
shared identifiers, repeated infrastructure, temporal coincidences.
Pattern != causation — every emitted pattern carries an explicit caution.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from traceatlas.core.observation import Observation


@dataclass(slots=True)
class Pattern:
    pattern_id: str
    ptype: str                 # shared_value | temporal_coincidence | repetition
    description: str
    entity_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    strength: float = 0.0      # 0..1 heuristic support fraction
    caution: str = "pattern does not imply causation or common control"

    def to_dict(self) -> dict[str, Any]:
        return {"pattern_id": self.pattern_id, "type": self.ptype,
                "description": self.description, "entity_ids": self.entity_ids,
                "evidence_ids": self.evidence_ids, "strength": round(self.strength, 3),
                "caution": self.caution}


def _day(dt: Optional[datetime]) -> str:
    return dt.date().isoformat() if dt else ""


class PatternEngine:
    def detect(self, case_id: str, observations: Iterable[Observation]
               ) -> list[Pattern]:
        obs = list(observations)
        out: list[Pattern] = []
        out += self._shared_values(obs)
        out += self._temporal_coincidences(obs)
        out += self._repetition(obs)
        for i, p in enumerate(out):
            p.pattern_id = f"{case_id}-pat-{i}"
        return out

    # ------------------------------------------------------------- detectors
    def _shared_values(self, obs: list[Observation]) -> list[Pattern]:
        """>=2 distinct subjects sharing one predicate+value."""
        groups: dict[tuple, set[str]] = defaultdict(set)
        evmap: dict[tuple, list[str]] = defaultdict(list)
        for o in obs:
            key = (o.predicate, str(o.value))
            if o.subject_id:
                groups[key].add(str(o.subject_id))
            if o.evidence_id:
                evmap[key].append(str(o.evidence_id))
        pats = []
        for (pred, val), subjects in groups.items():
            if len(subjects) >= 2:
                pats.append(Pattern(
                    pattern_id="", ptype="shared_value",
                    description=(f"{len(subjects)} subjects share {pred}='{val}' "
                                 f"(co-occurrence only)"),
                    entity_ids=sorted(subjects) + [val],
                    evidence_ids=sorted(set(evmap[(pred, val)])),
                    strength=min(1.0, len(subjects) / 5.0)))
        return pats

    def _temporal_coincidences(self, obs: list[Observation]) -> list[Pattern]:
        """Same-day observations across DIFFERENT predicates on same subject."""
        by_subj_day: dict[tuple, set[str]] = defaultdict(set)
        for o in obs:
            d = _day(o.observed_at)
            if d and o.subject_id:
                by_subj_day[(str(o.subject_id), d)].add(o.predicate)
        pats = []
        for (subj, day), preds in by_subj_day.items():
            if len(preds) >= 3:
                pats.append(Pattern(
                    pattern_id="", ptype="temporal_coincidence",
                    description=(f"{subj} has {len(preds)} distinct observation types "
                                 f"on {day}; sequence unconfirmed"),
                    entity_ids=[subj],
                    strength=min(1.0, len(preds) / 6.0),
                    caution="co-occurrence is not sequence; event time vs observation "
                            "time must be separated before interpretation"))
        return pats

    def _repetition(self, obs: list[Observation]) -> list[Pattern]:
        """Repeated identical claims from many sources (syndication candidate)."""
        by_key: dict[tuple, list[Observation]] = defaultdict(list)
        for o in obs:
            by_key[o.key() + (str(o.value),)].append(o)
        pats = []
        for (subj, pred, val), group in by_key.items():
            srcs = {str(o.source_id) for o in group if o.source_id}
            if len(group) >= 3 and len(srcs) >= 2:
                pats.append(Pattern(
                    pattern_id="", ptype="repetition",
                    description=(f"'{subj} {pred} {val}' appears {len(group)}x across "
                                 f"{len(srcs)} raw sources; independence unverified"),
                    entity_ids=[subj],
                    evidence_ids=sorted({str(o.evidence_id) for o in group
                                         if o.evidence_id}),
                    strength=min(1.0, len(group) / 5.0),
                    caution="repeated mentions may share one upstream; check the "
                            "source-independence engine before counting corroboration"))
        return pats
