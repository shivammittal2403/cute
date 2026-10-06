"""traceatlas.objectives.parser - Natural-language objective -> ObjectiveSpec."""
from __future__ import annotations

import re

from traceatlas.core.authorization import Authorization
from traceatlas.core.enums import EntityKind
from traceatlas.core.objective_spec import ObjectiveSpec
from traceatlas.core.scope import Scope
from traceatlas.core.target import Target

from .classifier import classify
from .target_extractor import extract_targets
from .constraint_extractor import extract_constraints
from .requirement_extractor import extract_requirements
from .ambiguity_detector import detect_ambiguities
from .normalizer import normalize_text
from .validator import validate_spec


class ObjectiveParser:
    """Deterministic first-pass parser. AI refinement is optional downstream."""

    def parse(self, text: str, authorization: Authorization | None = None,
              scope: Scope | None = None) -> ObjectiveSpec:
        clean = normalize_text(text)
        targets = extract_targets(clean)
        kind = classify(clean, targets)
        requirements = extract_requirements(clean, kind)
        constraints = extract_constraints(clean)
        ambiguities = detect_ambiguities(clean, targets)
        spec = ObjectiveSpec(
            raw_text=text,
            question=self._canonical_question(clean, targets),
            targets=tuple(targets),
            scope=scope or Scope(),
            authorization=authorization or Authorization(),
            requirements=requirements,
            constraints=constraints,
            ambiguities=ambiguities,
        )
        errors = validate_spec(spec)
        if errors:
            spec = ObjectiveSpec(**{**spec.__dict__, "ambiguities": ambiguities + tuple(errors)})
        return spec

    @staticmethod
    def _canonical_question(text: str, targets: list[Target]) -> str:
        sentence = text.split("?")[0].strip() or text.strip()
        if not sentence.endswith("?"):
            sentence += "?"
        return sentence
