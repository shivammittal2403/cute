"""traceatlas.objectives.requirement_extractor - What a complete answer needs."""
from __future__ import annotations

_BASE = ["identify primary entities", "collect supporting evidence per claim",
         "cross-check across >=2 independent sources", "record contradictions",
         "state confidence and unknowns"]

_EXTRA = {
    "domainint": ["registration record", "DNS resolution history"],
    "corpint": ["registry filing reference", "officer list"],
    "personint": ["disambiguation between same-name individuals"],
    "cti": ["MITRE ATT&CK mapping", "IOC timestamps"],
    "geoint": ["coordinate provenance", "imagery capture date"],
}


def extract_requirements(objective_text: str, discipline: str) -> tuple[str, ...]:
    reqs = list(_BASE)
    reqs.extend(_EXTRA.get(discipline, []))
    low = objective_text.lower()
    if "timeline" in low or "when" in low:
        reqs.append("build dated event timeline")
    if "map" in low or "where" in low or "location" in low:
        reqs.append("attach geolocation with confidence")
    return tuple(dict.fromkeys(reqs))
