"""traceatlas.core.validation - Cross-object invariant checks."""
from __future__ import annotations

from typing import Iterable

from .claim import Claim
from .entity import Entity
from .identifiers import is_valid_id
from .relationship import Relationship


def validate_entity(e: Entity) -> list[str]:
    errors = []
    if not is_valid_id(e.entity_id):
        errors.append(f"invalid entity_id {e.entity_id!r}")
    if not e.display_name and not e.attributes:
        errors.append("entity has neither display_name nor attributes")
    return errors


def validate_relationship(r: Relationship, known: Iterable[str]) -> list[str]:
    errors = []
    ids = set(known)
    if r.source_entity_id not in ids:
        errors.append(f"unknown source entity {r.source_entity_id}")
    if r.target_entity_id not in ids:
        errors.append(f"unknown target entity {r.target_entity_id}")
    if r.valid_from and r.valid_to and r.valid_from > r.valid_to:
        errors.append("valid_from after valid_to")
    return errors


def validate_claim(c: Claim, known_evidence: Iterable[str]) -> list[str]:
    errors = []
    ev = set(known_evidence)
    for cit in c.citations:
        if cit.evidence_id not in ev:
            errors.append(f"citation references unknown evidence {cit.evidence_id}")
    if c.status.value == "supported" and not c.citations:
        errors.append("supported claim without citations (invariant violation)")
    return errors
