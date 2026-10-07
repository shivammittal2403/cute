"""BehaviorMatcher - deterministic behaviour -> ATT&CK *candidate* patterns.

These are candidates only: keyword/pattern hits never become mappings without
AI passes + validation (spec section 10: do not map from keyword matching
alone). The table is small, auditable and version-agnostic; each entry points
at a technique family that must then be resolved against the pinned KB.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CandidatePattern:
    behavior_regex: str
    technique_hint: str          # e.g. "T1059.001"
    tactic_hint: str             # e.g. "execution"
    requires_context: bool = True
    note: str = ""


# NOTE: hints are seeds for verification, not authoritative mappings.
DEFAULT_PATTERNS: tuple[CandidatePattern, ...] = (
    CandidatePattern(r"powershell\s+-[encw]", "T1059.001", "execution",
                     note="verify script intent before mapping"),
    CandidatePattern(r"scheduled task|schtasks", "T1053.005", "persistence"),
    CandidatePattern(r"currentversion\\run", "T1547.001", "persistence"),
    CandidatePattern(r"lsass|mimikatz|credential dump", "T1003.001", "credential_access",
                     note="keyword alone insufficient"),
    CandidatePattern(r"create mutex|openmutex", "", "defense_evasion",
                     note="mutex use maps to no single technique; needs context"),
    CandidatePattern(r"http post beacon|beacon interval", "T1071", "command_and_control"),
    CandidatePattern(r"virtual machine check|vmware|vbox|qemu detection",
                     "T1497.001", "defense_evasion"),
    CandidatePattern(r"file encryption|encrypt files with ransom note",
                     "T1486", "impact"),
    CandidatePattern(r"browser cookie theft|steal cookies", "T1539",
                     "credential_access"),
    CandidatePattern(r"arp scan|network discovery", "T1018", "discovery"),
    CandidatePattern(r"process injection|createremotethread", "T1055",
                     "defense_evasion"),
    CandidatePattern(r"exfiltration over (alt protocol|c2)", "T1048", "exfiltration"),
    CandidatePattern(r"disable windows defender|amsi bypass|etw bypass",
                     "T1562", "defense_evasion"),
)


class BehaviorMatcher:
    def __init__(self, patterns: tuple[CandidatePattern, ...] | None = None):
        self.patterns = patterns if patterns is not None else DEFAULT_PATTERNS

    def candidates_for(self, normalized_behavior: str, raw_text: str = "") -> list[dict]:
        """Return candidate technique hints for one behavior+evidence text."""
        hay = f"{normalized_behavior}\n{raw_text}".lower()
        out = []
        for p in self.patterns:
            if re.search(p.behavior_regex, hay, flags=re.I):
                out.append({"technique_hint": p.technique_hint,
                            "tactic_hint": p.tactic_hint,
                            "requires_context": p.requires_context,
                            "note": p.note,
                            "matched_pattern": p.behavior_regex})
        return out
