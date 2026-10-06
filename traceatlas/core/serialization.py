"""traceatlas.core.serialization - JSON round-tripping for domain objects."""
from __future__ import annotations

import json
from typing import Any

from .case import Case
from .claim import Claim
from .entity import Entity
from .evidence import Evidence
from .investigation import Investigation
from .observation import Observation
from .relationship import Relationship
from .task import Task

_REGISTRY = {
    "case": Case, "claim": Claim, "entity": Entity, "evidence": Evidence,
    "investigation": Investigation, "observation": Observation,
    "relationship": Relationship, "task": Task,
}


def dumps(obj: Any) -> str:
    d = obj.to_dict()
    d["_type"] = type(obj).__name__.lower()
    return json.dumps(d, ensure_ascii=False, default=str)


def loads(text: str) -> Any:
    d = json.loads(text)
    t = d.pop("_type", None)
    cls = _REGISTRY.get(t)
    if cls is None:
        raise ValueError(f"unknown serialized type: {t!r}")
    return cls.from_dict(d)
