"""traceatlas.graph.model - Case-scoped temporal knowledge graph.

Stores canonical Entity/Relationship objects plus evidence links. Every edge
exposes evidence_ids/source provenance; the graph is rebuildable from stored
records (JSONL persistence). Provides k-hop expansion, shortest path,
connected components, bridges, and time-slice queries.
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Optional

from traceatlas.core.entity import Entity
from traceatlas.core.relationship import Relationship


class KnowledgeGraph:
    def __init__(self, persist_path: str | Path | None = None):
        self.entities: dict[str, Entity] = {}
        self.relationships: dict[str, Relationship] = {}
        self._adj: dict[str, set[str]] = defaultdict(set)      # undirected adjacency
        self._out: dict[str, list[str]] = defaultdict(list)    # edge ids by src
        self.persist_path = Path(persist_path) if persist_path else None
        if self.persist_path and self.persist_path.exists():
            self._load()

    # ---------------------------------------------------------------- mutation
    def add_entity(self, ent: Entity) -> Entity:
        existing = self.find_entity(ent.kind, ent.display_name)
        if existing is not None:
            merged_attrs = {**existing.attributes, **ent.attributes}
            ev = tuple(dict.fromkeys(existing.evidence_ids + ent.evidence_ids))
            updated = replace(existing, attributes=merged_attrs,
                              evidence_ids=ev, updated_at=ent.updated_at)
            self.entities[updated.entity_id] = updated
            self._persist_record("entity", updated.to_dict())
            return updated
        self.entities[ent.entity_id] = ent
        self._adj[ent.entity_id]  # touch
        self._persist_record("entity", ent.to_dict())
        return ent

    def add_relationship(self, rel: Relationship) -> Relationship:
        if rel.source_entity_id not in self.entities or rel.target_entity_id not in self.entities:
            raise ValueError("relationship endpoints must exist in graph")
        self.relationships[rel.relationship_id] = rel
        self._adj[rel.source_entity_id].add(rel.target_entity_id)
        self._adj[rel.target_entity_id].add(rel.source_entity_id)
        self._out[rel.source_entity_id].append(rel.relationship_id)
        self._persist_record("relationship", rel.to_dict())
        return rel

    # ------------------------------------------------------------------ lookup
    def find_entity(self, kind, name: str) -> Optional[Entity]:
        key = (kind.value if hasattr(kind, "value") else str(kind), name.strip().lower())
        for ent in self.entities.values():
            ek = ent.kind.value if hasattr(ent.kind, "value") else str(ent.kind)
            if (ek, ent.display_name.strip().lower()) == key:
                return ent
        return None

    def neighbors(self, entity_id: str) -> list[Entity]:
        return [self.entities[n] for n in self._adj.get(entity_id, ()) if n in self.entities]

    def edges_for(self, entity_id: str) -> list[Relationship]:
        return [r for r in self.relationships.values()
                if r.source_entity_id == entity_id or r.target_entity_id == entity_id]

    # ----------------------------------------------------------------- analysis
    def khop(self, start_id: str, depth: int = 2) -> set[str]:
        seen = {start_id}
        frontier = {start_id}
        for _ in range(max(0, depth)):
            nxt: set[str] = set()
            for node in frontier:
                for nb in self._adj.get(node, ()):
                    if nb not in seen:
                        seen.add(nb)
                        nxt.add(nb)
            frontier = nxt
            if not frontier:
                break
        return seen

    def shortest_path(self, a: str, b: str) -> list[str]:
        if a == b:
            return [a]
        prev: dict[str, str] = {}
        q = deque([a])
        while q:
            node = q.popleft()
            for nb in self._adj.get(node, ()):
                if nb not in prev and nb != a:
                    prev[nb] = node
                    if nb == b:
                        path = [b]
                        while path[-1] != a:
                            path.append(prev[path[-1]])
                        return list(reversed(path))
                    q.append(nb)
        return []

    def connected_components(self) -> list[set[str]]:
        comps: list[set[str]] = []
        seen: set[str] = set()
        for node in list(self._adj):
            if node in seen:
                continue
            comp: set[str] = set()
            q = deque([node])
            seen.add(node)
            while q:
                cur = q.popleft()
                comp.add(cur)
                for nb in self._adj.get(cur, ()):
                    if nb not in seen:
                        seen.add(nb)
                        q.append(nb)
            comps.append(comp)
        return comps

    def at_time(self, when: datetime) -> list[Relationship]:
        return [r for r in self.relationships.values() if r.is_valid_at(when)]

    def to_dict(self) -> dict:
        return {"entities": [e.to_dict() for e in self.entities.values()],
                "relationships": [r.to_dict() for r in self.relationships.values()]}

    # -------------------------------------------------------------- persistence
    def _persist_record(self, kind: str, payload: dict) -> None:
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.persist_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"_record": kind, **payload}) + "\n")

    def _load(self) -> None:
        assert self.persist_path
        with open(self.persist_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = rec.pop("_record", None)
                if kind == "entity":
                    ent = Entity.from_dict(rec)
                    self.entities[ent.entity_id] = ent
                    self._adj[ent.entity_id]
                elif kind == "relationship":
                    rel = Relationship.from_dict(rec)
                    self.relationships[rel.relationship_id] = rel
                    self._adj[rel.source_entity_id].add(rel.target_entity_id)
                    self._adj[rel.target_entity_id].add(rel.source_entity_id)
                    self._out[rel.source_entity_id].append(rel.relationship_id)
