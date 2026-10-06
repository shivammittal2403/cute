"""traceatlas.objectives.ambiguity_detector - Flag unresolved questions."""
from __future__ import annotations

import re

_AMBIG = [
    (re.compile(r"\b(his|her|their|it)\b", re.I),
     "Pronoun reference unclear - which entity is meant?"),
    (re.compile(r"\brecently\b", re.I), "'Recently' undefined - what time window?"),
    (re.compile(r"\bsimilar\b", re.I), "'Similar' undefined - similar by what attribute?"),
]


def detect_ambiguities(text: str, targets) -> tuple[str, ...]:
    notes = [note for rx, note in _AMBIG if rx.search(text)]
    if not targets:
        notes.append("No concrete target found; ask the user for a domain/handle/name.")
    return tuple(notes)
