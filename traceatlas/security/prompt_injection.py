"""traceatlas.security.prompt_injection — injection detection + containment.

DETECTION here is advisory only (labels content for review/quarantine).
CONTAINMENT is enforced structurally elsewhere:
  * traceatlas.security.tool_grants.ToolGrantPolicy (default-deny tool calls),
  * sources/connectors SSRF guard,
  * evidence trust labels (QUARANTINE before canonical promotion).

Per AGENTS.md this docstring states exactly what is real: the scanner below is
a heuristic labeler, NOT a security boundary. The boundary is ToolGrantPolicy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Re-export so callers/tests can import the enforcement primitive from either
# location. Enforcement lives in tool_grants; this alias keeps documented
# import paths working.
from traceatlas.security.tool_grants import ToolGrant, ToolGrantPolicy, new_grant_id

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("override_instructions", re.compile(
        r"(ignore\s+(all\s+)?previous\s+instructions|disregard\s+the\s+system\s+prompt)",
        re.I)),
    ("fake_system_turn", re.compile(r"^\s*(SYSTEM|ASSISTANT|TOOL RESULT)\s*:", re.I | re.M)),
    ("grant_widening", re.compile(r"(grant\s+(me|this)\s+tool|execute\s+tool|run\s+connector\.)", re.I)),
    ("secret_exfiltration", re.compile(
        r"(reveal\s+(your\s+)?(secrets|api[_ ]?keys)|print\s+the\s+password)", re.I)),
    ("destructive_request", re.compile(r"(delete_all|drop\s+table|wipe\s+(the\s+)?evidence)", re.I)),
)


@dataclass(slots=True)
class InjectionScanResult:
    text_sha256: str
    flags: tuple[str, ...] = ()
    risk: str = "CLEAN"          # CLEAN | SUSPICIOUS | HOSTILE
    notes: list[str] = field(default_factory=list)

    @property
    def quarantined(self) -> bool:
        return self.risk != "CLEAN"


class PromptInjectionScanner:
    """Heuristic labeler. A hit does not block anything by itself; downstream
    code decides (quarantine, human review, refusal to promote to memory)."""

    def scan(self, text: str) -> InjectionScanResult:
        import hashlib
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        flags: list[str] = []
        for name, pat in _INJECTION_PATTERNS:
            if pat.search(text):
                flags.append(name)
        if not flags:
            risk = "CLEAN"
        elif "override_instructions" in flags or "destructive_request" in flags:
            risk = "HOSTILE"
        else:
            risk = "SUSPICIOUS"
        return InjectionScanResult(text_sha256=digest, flags=tuple(flags), risk=risk)


__all__ = [
    "ToolGrant",
    "ToolGrantPolicy",
    "new_grant_id",
    "InjectionScanResult",
    "PromptInjectionScanner",
]
