"""traceatlas.core.cost - Accumulated spend accounting."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Cost:
    cost_usd: float = 0.0
    model_tokens: int = 0
    http_requests: int = 0
    tasks: int = 0
    per_source: dict[str, int] = field(default_factory=dict)

    def add_request(self, source_slug: str, usd: float = 0.0) -> None:
        self.http_requests += 1
        self.cost_usd += usd
        self.per_source[source_slug] = self.per_source.get(source_slug, 0) + 1

    def add_model_usage(self, tokens: int, usd: float) -> None:
        self.model_tokens += tokens
        self.cost_usd += usd

    def to_dict(self) -> dict[str, Any]:
        return {"cost_usd": round(self.cost_usd, 6), "model_tokens": self.model_tokens,
                "http_requests": self.http_requests, "tasks": self.tasks,
                "per_source": self.per_source}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Cost":
        return cls(cost_usd=float(d.get("cost_usd", 0.0)),
                   model_tokens=int(d.get("model_tokens", 0)),
                   http_requests=int(d.get("http_requests", 0)),
                   tasks=int(d.get("tasks", 0)),
                   per_source=dict(d.get("per_source", {})))
