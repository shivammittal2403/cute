"""ATT&CK version handling: never assume the current release forever."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class AttackVersion:
    major: int
    minor: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"

    @classmethod
    def parse(cls, s: str) -> "AttackVersion":
        parts = str(s).split(".")
        if len(parts) != 2:
            raise ValueError(f"bad ATT&CK version {s!r} (expected 'major.minor')")
        return cls(int(parts[0]), int(parts[1]))

    def __ge__(self, other: "AttackVersion") -> bool:
        return (self.major, self.minor) >= (other.major, other.minor)

    def __lt__(self, other: "AttackVersion") -> bool:
        return (self.major, self.minor) < (other.major, other.minor)


# Snapshot registry of versions TraceAtlas has ingested/can validate against.
# This is *metadata about releases*, not a technique list.
CURRENT_KNOWN_VERSIONS: dict[str, date] = {
    "14.0": date(2023, 10, 26),
    "14.1": date(2024, 1, 11),
    "14.2": date(2024, 4, 23),
    "15.0": date(2024, 7, 30),
    "15.1": date(2024, 10, 29),
}

DEFAULT_PIN = "15.1"


def pin_version(value: str | None) -> str:
    """Validate/normalize a requested ATT&CK version pin."""
    if not value:
        return DEFAULT_PIN
    v = str(value).strip()
    AttackVersion.parse(v)          # raises on garbage
    return v
