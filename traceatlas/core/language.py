"""traceatlas.core.language - Language pack references."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class Language:
    code: str
    name: str = ""

    PACKS = {"en": "packs/languages/english.yaml",
             "hi": "packs/languages/hindi.yaml",
             "hi-Latn": "packs/languages/roman_hindi.yaml"}

    @property
    def pack_path(self) -> Optional[str]:
        return self.PACKS.get(self.code)
