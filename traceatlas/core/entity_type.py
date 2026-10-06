"""traceatlas.core.entity_type - Entity-kind schema registry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .enums import EntityKind


@dataclass(frozen=True, slots=True)
class EntityTypeSchema:
    kind: EntityKind
    required_attributes: tuple[str, ...] = ()
    optional_attributes: tuple[str, ...] = ()
    normalizers: tuple[str, ...] = ()


DEFAULT_SCHEMAS: dict[EntityKind, EntityTypeSchema] = {
    EntityKind.DOMAIN: EntityTypeSchema(EntityKind.DOMAIN, ("value",),
                                        ("registrant", "created"),
                                        ("lowercase", "strip_dot", "idna")),
    EntityKind.IP_ADDRESS: EntityTypeSchema(EntityKind.IP_ADDRESS, ("value",),
                                            ("asn", "country"), ("ip_normalize",)),
    EntityKind.PERSON: EntityTypeSchema(EntityKind.PERSON, (),
                                        ("name", "dob_hint", "location"),
                                        ("name_casefold", "unicode_nfc")),
    EntityKind.USERNAME: EntityTypeSchema(EntityKind.USERNAME, ("value",), (),
                                          ("lowercase", "strip_leading_at")),
    EntityKind.ORGANIZATION: EntityTypeSchema(EntityKind.ORGANIZATION, (),
                                              ("legal_name", "jurisdiction"),
                                              ("org_suffix_strip", "unicode_nfc")),
}


def schema_for(kind: EntityKind) -> EntityTypeSchema:
    return DEFAULT_SCHEMAS.get(kind, EntityTypeSchema(kind))


def missing_required(kind: EntityKind, attrs: dict[str, Any]) -> list[str]:
    s = schema_for(kind)
    return [a for a in s.required_attributes if a not in attrs or attrs[a] in (None, "")]
