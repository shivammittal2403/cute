"""traceatlas.core.objective_spec - Structured machine-checkable objective."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .authorization import Authorization
from .scope import Scope
from .target import Target


@dataclass(frozen=True, slots=True)
class ObjectiveSpec:
    raw_text: str = ""
    question: str = ""
    targets: tuple[Target, ...] = ()
    scope: Scope = field(default_factory=Scope)
    authorization: Authorization = field(default_factory=Authorization)
    requirements: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    ambiguities: tuple[str, ...] = ()
    success_criteria: tuple[str, ...] = ("answer supported by >=2 independent sources",)

    @property
    def ready_for_planning(self) -> bool:
        return bool(self.question and self.targets and not self.ambiguities
                    and self.authorization.is_valid())

    def blocking_questions(self) -> list[str]:
        qs = list(self.ambiguities)
        if not self.authorization.is_valid():
            qs.append("Valid authorization (basis + granter + scopes) required before collection.")
        if not self.targets:
            qs.append("No concrete target identified in the objective.")
        return qs

    def to_dict(self) -> dict[str, Any]:
        return {"raw_text": self.raw_text, "question": self.question,
                "targets": [t.to_dict() for t in self.targets],
                "scope": self.scope.to_dict(),
                "authorization": self.authorization.to_dict(),
                "requirements": list(self.requirements),
                "constraints": list(self.constraints),
                "stop_conditions": list(self.stop_conditions),
                "ambiguities": list(self.ambiguities),
                "success_criteria": list(self.success_criteria)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ObjectiveSpec":
        return cls(raw_text=d.get("raw_text", ""), question=d.get("question", ""),
                   targets=tuple(Target.from_dict(t) for t in d.get("targets", [])),
                   scope=Scope.from_dict(d.get("scope", {})),
                   authorization=Authorization.from_dict(d.get("authorization", {})),
                   requirements=tuple(d.get("requirements", ())),
                   constraints=tuple(d.get("constraints", ())),
                   stop_conditions=tuple(d.get("stop_conditions", ())),
                   ambiguities=tuple(d.get("ambiguities", ())),
                   success_criteria=tuple(d.get("success_criteria",
                                                ("answer supported by >=2 independent sources",))))
