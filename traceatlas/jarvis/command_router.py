"""traceatlas.jarvis.command_router - Deterministic intent routing (spec §21).

Maps investigator questions to bounded analytical handlers. No free-form text
executes tools: commands select READ-ONLY briefings or task-suggestion
builders; nothing here performs collection itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class RoutedCommand:
    intent: str
    args: dict[str, str]
    confidence: str = "pattern"   # all routing is deterministic pattern-match


_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("explain_case",        re.compile(r"\b(explain|walk me through)\b.*\b(case|investigation)\b", re.I)),
    ("what_we_know",        re.compile(r"\b(what do we (actually )?know|known facts)\b", re.I)),
    ("verified_facts_only", re.compile(r"\bonly show (the )?verified facts\b", re.I)),
    ("assumptions",         re.compile(r"\b(what are we assuming|assumption)", re.I)),
    ("top_hypotheses",      re.compile(r"\b(top|best|strongest) hypothes", re.I)),
    ("challenge_hypothesis", re.compile(r"\bchallenge\b.*\bhypothes|\bdebunk\b", re.I)),
    ("contradictions",      re.compile(r"\b(what contradicts|contradiction)", re.I)),
    ("gaps",                re.compile(r"\b(what is missing|gaps?|unknowns?)\b", re.I)),
    ("next_action",         re.compile(r"\b(what should we (investigate|do) next|nba)\b", re.I)),
    ("why_connected",       re.compile(r"\bwhy (are|do|is)\b.*\bconnected|why.*link", re.I)),
    ("entity_story",        re.compile(r"\btell me the story of\b", re.I)),
    ("timeline_story",      re.compile(r"\b(what changed over time|timeline story)\b", re.I)),
    ("summarize_entity",    re.compile(r"\bsummarize\b", re.I)),
    ("independent_sources", re.compile(r"\bwhich sources are independent\b", re.I)),
    ("copied_claims",       re.compile(r"\b(copied|syndicat)\b.*\b(source|claim)", re.I)),
    ("weakest_link",        re.compile(r"\bweakest link\b", re.I)),
    ("falsify",             re.compile(r"\bfalsif|\bprove.*(wrong|false)\b", re.I)),
    ("rebuild_narrative_strict", re.compile(r"\brebuild the narrative\b", re.I)),
    ("changes_since_last_run", re.compile(r"\bwhat changed since\b", re.I)),
]


def route(text: str) -> Optional[RoutedCommand]:
    """Return the first matching intent, or None (assistant then says it does
    not know rather than hallucinating an answer)."""
    for intent, pat in _PATTERNS:
        m = pat.search(text)
        if m:
            args: dict[str, str] = {}
            hid = re.search(r"\bH(\d+)\b", text)
            if hid:
                args["hypothesis_ref"] = hid.group(0)
            eid = re.search(r"\b(?:domain|entity)\s+([A-Za-z0-9._-]+)", text, re.I)
            if eid:
                args["entity"] = eid.group(1)
            return RoutedCommand(intent=intent, args=args)
    return None
