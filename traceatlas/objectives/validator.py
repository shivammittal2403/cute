"""traceatlas.objectives.validator - Structural validation of ObjectiveSpec."""
from __future__ import annotations

from traceatlas.core.objective_spec import ObjectiveSpec


def validate_spec(spec: ObjectiveSpec) -> list[str]:
    errors = []
    if not spec.question:
        errors.append("objective produced no canonical question")
    if spec.scope.max_depth > 6:
        errors.append("scope.max_depth too large (>6); confirm intent with user")
    if spec.scope.allow_dark_web:
        errors.append("dark-web collection requires explicit compliance approval")
    return errors
