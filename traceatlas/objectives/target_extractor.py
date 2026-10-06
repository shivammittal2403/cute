"""traceatlas.objectives.target_extractor - Strings -> Target objects."""
from __future__ import annotations

import re

from traceatlas.core.enums import EntityKind
from traceatlas.core.target import Target

from .entity_extractor import extract_strings

_KIND_MAP = {"url": EntityKind.URL, "domain": EntityKind.DOMAIN,
             "ip_address": EntityKind.IP_ADDRESS, "email": EntityKind.EMAIL,
             "asn": EntityKind.ASN}

_QUOTE_CHARS = ['"', "'", "\u201c", "\u201d", "\u2018", "\u2019"]


def extract_targets(text: str) -> list[Target]:
    """Recognise literal entities plus quoted names as candidate targets."""
    found = extract_strings(text)
    targets: list[Target] = []
    seen: set[tuple[str, str]] = set()
    for kind_name, values in found.items():
        kind = _KIND_MAP[kind_name]
        for v in values:
            key = (kind.value, v.lower())
            if key in seen:
                continue
            seen.add(key)
            targets.append(Target(kind=kind, value=v))
    for q in _quoted(text):
        key = ("unknown", q.lower())
        if key not in seen:
            seen.add(key)
            targets.append(Target(kind=EntityKind.UNKNOWN, value=q,
                                  hints={"source": "quoted"}))
    return targets


def _quoted(text: str) -> list[str]:
    alt = "|".join(re.escape(q) for q in _QUOTE_CHARS)
    rx = re.compile("(?:" + alt + ")([^" + alt + "]{3,80})(?:" + alt + ")")
    return [m.group(1).strip() for m in rx.finditer(text)]
