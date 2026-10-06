"""traceatlas.objectives.constraint_extractor - Hard limits stated by user."""
from __future__ import annotations

import re

_RX_NO_LOGIN = re.compile(r"no login|without logging in|only public", re.I)
_RX_PASSIVE = re.compile(r"\bpassive\b", re.I)
_RX_BUDGET = re.compile(r"budget[^0-9]*\$?([0-9]+)", re.I)
_RX_NO_CONTACT = re.compile(r"do not contact|avoid contacting", re.I)
_RX_GDPR = re.compile(r"\bGDPR\b", re.I)

_RULES = [
    (_RX_NO_LOGIN, "public data only; no authenticated collection"),
    (_RX_PASSIVE, "passive collection only (no direct probing)"),
    (_RX_NO_CONTACT, "no outbound contact with target"),
    (_RX_GDPR, "apply EU privacy minimisation rules"),
]


def extract_constraints(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for rx, note in _RULES:
        if rx.search(text):
            out.append(note)
    m = _RX_BUDGET.search(text)
    if m:
        out.append(f"cost budget: ${m.group(1)}")
    return tuple(out)
