"""traceatlas.entities.resolver - Entity Resolution V3 (deterministic core).

Pipeline: normalize -> exact-key match -> guarded fuzzy scoring -> decision +
explanation. Never merges PERSON/USERNAME from a single weak signal; every
decision carries evidence-linked explanation and is reversible via the merge
history log.
"""
from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from traceatlas.core.entity import Entity
from traceatlas.core.enums import EntityKind


@dataclass(slots=True)
class ERDecision:
    left_id: str
    right_id: str
    state: str                 # VERIFIED_MATCH | PROBABLE_MATCH | POSSIBLE_MATCH | UNRESOLVED | LIKELY_DISTINCT
    score: float
    reasons: list[str] = field(default_factory=list)
    at: str = ""


def normalize_value(kind: EntityKind, value: str) -> str:
    v = (value or "").strip().lower()
    if kind == EntityKind.DOMAIN:
        v = v.removeprefix("www.").rstrip(".")
    elif kind in (EntityKind.EMAIL, EntityKind.IP_ADDRESS):
        pass
    elif kind == EntityKind.ASN:
        v = v.upper().replace("AS", "AS")
    elif kind in (EntityKind.PERSON, EntityKind.USERNAME, EntityKind.ORGANIZATION):
        v = " ".join(v.replace(".", " ").split())
    return v


class EntityResolver:
    """Deterministic resolver with conservative person policy."""

    FUZZY_THRESHOLD_PROBABLE = 0.93
    FUZZY_THRESHOLD_POSSIBLE = 0.85
    # kinds where a name-similarity match alone may NEVER trigger a merge
    WEAK_SIGNAL_KINDS = {EntityKind.PERSON, EntityKind.USERNAME, EntityKind.EMAIL}

    def __init__(self, history_path: str | Path | None = None):
        self.history_path = Path(history_path) if history_path else None

    # ------------------------------------------------------------------ decide
    def compare(self, a: Entity, b: Entity,
                corroborating_evidence_ids: tuple[str, ...] = ()) -> ERDecision:
        now = datetime.now(timezone.utc).isoformat()
        if a.kind != b.kind:
            return ERDecision(a.entity_id, b.entity_id, "LIKELY_DISTINCT", 0.0,
                              [f"kind mismatch {a.kind.value} vs {b.kind.value}"], now)
        na, nb = normalize_value(a.kind, a.display_name), normalize_value(b.kind, b.display_name)
        if not na or not nb:
            return ERDecision(a.entity_id, b.entity_id, "UNRESOLVED", 0.0,
                              ["missing display names"], now)
        reasons: list[str] = []
        if na == nb:
            score = 1.0
            reasons.append(f"exact normalized match {na!r}")
        else:
            score = difflib.SequenceMatcher(None, na, nb).ratio()
            reasons.append(f"normalized similarity {score:.3f}")
        # shared attribute corroboration (registrant, org, location...)
        shared = [k for k in set(a.attributes) & set(b.attributes)
                  if a.attributes[k] == b.attributes[k] and a.attributes[k]]
        if shared:
            score = min(1.0, score + 0.05 * len(shared))
            reasons.append(f"shared attributes: {sorted(shared)}")

        if a.kind in self.WEAK_SIGNAL_KINDS and score < 1.0 and not corroborating_evidence_ids:
            return ERDecision(a.entity_id, b.entity_id, "UNRESOLVED", score,
                              reasons + ["weak-signal kind requires corroboration before merge"], now)
        if score >= 1.0 and (corroborating_evidence_ids or len({*a.evidence_ids, *b.evidence_ids}) >= 2):
            state = "VERIFIED_MATCH"
        elif score >= self.FUZZY_THRESHOLD_PROBABLE:
            state = "PROBABLE_MATCH"
        elif score >= self.FUZZY_THRESHOLD_POSSIBLE:
            state = "POSSIBLE_MATCH"
        elif score >= 0.6:
            state = "UNRESOLVED"
        else:
            state = "LIKELY_DISTINCT"
        return ERDecision(a.entity_id, b.entity_id, state, round(score, 4), reasons, now)

    # ------------------------------------------------------------------- merge
    def apply_merge(self, graph, decision: ERDecision, survivor: Optional[str] = None) -> bool:
        """Merge only on VERIFIED/PROBABLE matches; record reversible entry."""
        if decision.state not in ("VERIFIED_MATCH", "PROBABLE_MATCH"):
            return False
        keep = survivor or decision.left_id
        drop = decision.right_id if keep == decision.left_id else decision.left_id
        kept, dropped = graph.entities.get(keep), graph.entities.get(drop)
        if not kept or not dropped:
            return False
        merged_attrs = {**dropped.attributes, **kept.attributes}
        ev = tuple(dict.fromkeys(kept.evidence_ids + dropped.evidence_ids))
        from dataclasses import replace
        graph.add_entity(replace(kept, attributes=merged_attrs, evidence_ids=ev,
                                 merged_from=tuple(kept.merged_from) + (drop,)))
        # re-point edges
        from traceatlas.core.relationship import Relationship
        for rel in list(graph.relationships.values()):
            if rel.source_entity_id == drop or rel.target_entity_id == drop:
                new_rel = Relationship(
                    case_id=rel.case_id,
                    source_entity_id=keep if rel.source_entity_id == drop else rel.source_entity_id,
                    target_entity_id=keep if rel.target_entity_id == drop else rel.target_entity_id,
                    kind=rel.kind, properties=dict(rel.properties),
                    evidence_ids=rel.evidence_ids, valid_from=rel.valid_from,
                    valid_to=rel.valid_to)
                if new_rel.source_entity_id != new_rel.target_entity_id:
                    graph.add_relationship(new_rel)
                graph.relationships.pop(rel.relationship_id, None)
        graph.entities.pop(drop, None)
        self._log({"action": "merge", "keep": keep, "drop": drop,
                   "state": decision.state, "score": decision.score,
                   "reasons": decision.reasons, "at": decision.at})
        return True

    def _log(self, record: dict) -> None:
        if not self.history_path:
            return
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.history_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
