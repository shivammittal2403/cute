"""traceatlas.core.jurisdiction - Jurisdiction handling helpers."""
from __future__ import annotations

from dataclasses import dataclass

KNOWN = {
    "IN": "India", "US": "United States", "GB": "United Kingdom",
    "EU": "European Union (supranational)", "DE": "Germany", "FR": "France",
    "SG": "Singapore", "AE": "United Arab Emirates", "AU": "Australia",
    "CA": "Canada", "JP": "Japan", "CN": "China", "RU": "Russia", "BR": "Brazil",
}


@dataclass(frozen=True, slots=True)
class Jurisdiction:
    code: str
    name: str

    @classmethod
    def parse(cls, code: str) -> "Jurisdiction":
        c = code.strip().upper()
        return cls(code=c, name=KNOWN.get(c, code))

    @property
    def known(self) -> bool:
        return self.code in KNOWN
