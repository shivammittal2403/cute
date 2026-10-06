"""traceatlas.core.identifiers - ULID-style sortable identifiers."""
from __future__ import annotations

import re
import time
import uuid
from typing import NewType

ID = NewType("ID", str)

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32
_PATTERN = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_PREFIXES = {
    "case": "cas", "objective": "obj", "spec": "spc", "investigation": "inv",
    "task": "tsk", "result": "res", "evidence": "evd", "artifact": "art",
    "entity": "ent", "relationship": "rel", "claim": "clm", "hypothesis": "hyp",
    "contradiction": "ctr", "verification": "vrf", "event": "evt",
    "timeline": "tml", "source": "src", "citation": "cit", "provenance": "prv",
    "observation": "obs", "fact": "fct", "gap": "gap", "action": "act",
    "report": "rpt", "employee": "emp", "session": "ses", "checkpoint": "ckp",
}


def _ulid() -> str:
    ts = int(time.time() * 1000)
    rand = uuid.uuid4().int & ((1 << 80) - 1)
    val = (ts << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_ALPHABET[val & 0x1F])
        val >>= 5
    return "".join(reversed(chars))


def new_id(kind: str = "") -> ID:
    suffix = _ulid()
    if kind:
        prefix = _PREFIXES.get(kind, kind[:3].lower())
        return ID(f"{prefix}_{suffix}")
    return ID(suffix)


def is_valid_id(value: str) -> bool:
    tail = value.split("_", 1)[-1] if "_" in value else value
    return bool(_PATTERN.match(tail))
