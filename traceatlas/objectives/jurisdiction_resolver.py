"""traceatlas.objectives.jurisdiction_resolver - Infer jurisdictions from text."""
from __future__ import annotations

from traceatlas.core.jurisdiction import Jurisdiction

_CUES = {
    "india": "IN", "bharat": "IN", "netherlands": "NL", "eu": "EU",
    "european union": "EU", "united states": "US", "usa": "US",
    "united kingdom": "GB", "uk": "GB", "singapore": "SG", "germany": "DE",
    "france": "FR", "australia": "AU", "canada": "CA", "japan": "JP",
}


def resolve_jurisdictions(text: str) -> list[Jurisdiction]:
    low = text.lower()
    codes = [code for cue, code in _CUES.items() if cue in low]
    return [Jurisdiction.parse(c) for c in sorted(set(codes))]
