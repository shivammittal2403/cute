"""traceatlas.verification.contradictions - Contradiction detection.

Scans evidence-linked observations for conflicting values on the same
(subject, predicate). Conflicting observations are PRESERVED (never silently
overwritten); each contradiction records both sides with their evidence and a
classification: value / temporal / identity / relationship / source_disagreement.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from traceatlas.core.observation import Observation


@dataclass(slots=True)
class Contradiction:
    contradiction_id: str
    subject: str
    predicate: str
    kind: str                       # value | temporal | source_disagreement
    sides: list[dict[str, Any]] = field(default_factory=list)  # [{value, observation_id, evidence_id, source_id}]
    status: str = "OPEN"            # OPEN | RESOLVED | UNRESOLVABLE
    detected_at: str = ""


def _canon(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return json.dumps(sorted(str(v).lower() for v in value))
    return str(value).strip().lower()


class ContradictionDetector:
    def detect(self, observations: Iterable[Observation]) -> list[Contradiction]:
        groups: dict[tuple[str, str], list[Observation]] = defaultdict(list)
        for o in observations:
            if not o.subject_id or not o.predicate:
                continue
            groups[(o.subject_id.lower(), o.predicate.lower())].append(o)
        out: list[Contradiction] = []
        now = datetime.now(timezone.utc).isoformat()
        for (subject, predicate), obs in groups.items():
            by_value: dict[str, list[Observation]] = defaultdict(list)
            for o in obs:
                by_value[_canon(o.value)].append(o)
            if len(by_value) <= 1:
                continue
            # temporal? predicates carrying dates compared as events
            kind = "value"
            if any(k in predicate for k in ("date", "time", "valid", "created", "updated")):
                kind = "temporal"
            elif len({o.source_id for o in obs}) > 1:
                kind = "source_disagreement"
            sides = [{"value": o.value, "observation_id": o.observation_id,
                      "evidence_id": o.evidence_id, "source_id": o.source_id}
                     for val_obs in by_value.values() for o in val_obs[:3]]
            cid = f"contra_{abs(hash((subject, predicate, tuple(by_value)))) % 10**12:012d}"
            out.append(Contradiction(contradiction_id=cid, subject=subject,
                                     predicate=predicate, kind=kind, sides=sides,
                                     detected_at=now))
        return sorted(out, key=lambda c: c.contradiction_id)

    def persist(self, path: str | Path, contradictions: list[Contradiction]) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            for c in contradictions:
                fh.write(json.dumps({"contradiction_id": c.contradiction_id,
                                     "subject": c.subject, "predicate": c.predicate,
                                     "kind": c.kind, "sides": c.sides,
                                     "status": c.status, "detected_at": c.detected_at}) + "\n")
