"""traceatlas.objectives.classifier - Determine investigation type."""
from __future__ import annotations

from traceatlas.core.enums import EntityKind, IntelligenceDomain

_PATTERNS: list[tuple[str, tuple[IntelligenceDomain, ...]]] = [
    ("company", (IntelligenceDomain.CORPINT, IntelligenceDomain.DOMAININT)),
    ("companion", (IntelligenceDomain.PERSONINT, IntelligenceDomain.USERNAMEINT)),
    ("who owns", (IntelligenceDomain.DOMAININT, IntelligenceDomain.CORPINT)),
    ("infrastructure", (IntelligenceDomain.INFRAINT, IntelligenceDomain.DOMAININT)),
    ("malware", (IntelligenceDomain.CTI,)),
    ("breach", (IntelligenceDomain.CTI, IntelligenceDomain.EXPOSURE if hasattr(IntelligenceDomain, 'EXPOSURE') else IntelligenceDomain.CTI)),
    ("person", (IntelligenceDomain.PERSONINT, IntelligenceDomain.USERNAMEINT)),
    ("username", (IntelligenceDomain.USERNAMEINT, IntelligenceDomain.SOCMINT)),
    ("location", (IntelligenceDomain.GEOINT, IntelligenceDomain.IMINT)),
]


def classify(text: str, targets) -> str:
    low = text.lower()
    for needle, domains in _PATTERNS:
        if needle in low:
            return domains[0].value
    kinds = {t.kind for t in targets}
    if EntityKind.DOMAIN in kinds:
        return IntelligenceDomain.DOMAININT.value
    if EntityKind.IP_ADDRESS in kinds:
        return IntelligenceDomain.INFRAINT.value
    if EntityKind.PERSON in kinds or EntityKind.USERNAME in kinds:
        return IntelligenceDomain.PERSONINT.value
    return IntelligenceDomain.WEBINT.value
