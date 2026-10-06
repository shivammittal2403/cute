"""traceatlas.planning.intelligence_domain_planner - Disciplines for a spec."""
from __future__ import annotations

from traceatlas.core.enums import EntityKind, IntelligenceDomain

BY_TARGET = {
    EntityKind.DOMAIN: [IntelligenceDomain.DOMAININT, IntelligenceDomain.INFRAINT,
                         IntelligenceDomain.WEBINT, IntelligenceDomain.ARCHIVEINT],
    EntityKind.IP_ADDRESS: [IntelligenceDomain.INFRAINT, IntelligenceDomain.DARKINT],
    EntityKind.PERSON: [IntelligenceDomain.PERSONINT, IntelligenceDomain.USERNAMEINT,
                        IntelligenceDomain.SOCMINT],
    EntityKind.USERNAME: [IntelligenceDomain.USERNAMEINT, IntelligenceDomain.SOCMINT],
    EntityKind.ORGANIZATION: [IntelligenceDomain.CORPINT, IntelligenceDomain.DOMAININT],
    EntityKind.URL: [IntelligenceDomain.WEBINT, IntelligenceDomain.DOCINT],
    EntityKind.HASH: [IntelligenceDomain.CTI],
    EntityKind.CVE: [IntelligenceDomain.CTI],
}


def domains_for(kinds: set[EntityKind]) -> list[IntelligenceDomain]:
    out: list[IntelligenceDomain] = []
    for k in kinds:
        for d in BY_TARGET.get(k, [IntelligenceDomain.WEBINT]):
            if d not in out:
                out.append(d)
    return out or [IntelligenceDomain.WEBINT]
