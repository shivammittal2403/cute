"""traceatlas.core.relationship_type - Allowed subject/object kinds per relation."""
from __future__ import annotations

from dataclasses import dataclass

from .enums import EntityKind, RelationshipKind


@dataclass(frozen=True, slots=True)
class RelationshipTypeSpec:
    kind: RelationshipKind
    subject_kinds: frozenset[EntityKind]
    object_kinds: frozenset[EntityKind]
    transitive: bool = False


ALL_KINDS = frozenset(EntityKind)

REGISTRY: dict[RelationshipKind, RelationshipTypeSpec] = {
    RelationshipKind.RESOLVES_TO: RelationshipTypeSpec(
        RelationshipKind.RESOLVES_TO,
        frozenset({EntityKind.DOMAIN}), frozenset({EntityKind.IP_ADDRESS})),
    RelationshipKind.MANAGES: RelationshipTypeSpec(
        RelationshipKind.MANAGES,
        frozenset({EntityKind.PERSON, EntityKind.ORGANIZATION}), ALL_KINDS),
    RelationshipKind.EMPLOYS: RelationshipTypeSpec(
        RelationshipKind.EMPLOYS,
        frozenset({EntityKind.ORGANIZATION}), frozenset({EntityKind.PERSON})),
    RelationshipKind.EXPLOITS: RelationshipTypeSpec(
        RelationshipKind.EXPLOITS,
        frozenset({EntityKind.THREAT_ACTOR, EntityKind.MALWARE}),
        frozenset({EntityKind.CVE})),
}


def validate_types(kind: RelationshipKind, subj: EntityKind, obj: EntityKind) -> bool:
    spec = REGISTRY.get(kind)
    if spec is None:
        return True
    return subj in spec.subject_kinds and obj in spec.object_kinds
