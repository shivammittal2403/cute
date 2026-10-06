"""traceatlas.objectives.normalizer - Text normalisation before parsing."""
from __future__ import annotations

import re
import unicodedata

_WS_RX = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).strip()
    return _WS_RX.sub(" ", t)
