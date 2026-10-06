"""traceatlas.narrative.validation - Story validator (spec §13).

Rejects narratives containing unsupported factual claims BEFORE display.
Rules:
  FACT / INFERENCE   -> must carry >=1 evidence_id
  HYPOTHESIS         -> must carry hypothesis_id
  SPECULATION        -> banned from executive-mode findings unless material flag
Also enforces the truth boundary: a statement whose text asserts certainty but
is typed HYPOTHESIS is rejected (hypothesis can never masquerade as fact).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from traceatlas.synthesis.state import StatementType

from .story_model import NarrativeStatement, Story

# Language that would upgrade an assessment into an unearned assertion.
_CERTAINTY = re.compile(
    r"\b(proves?|proved|confirmed|certainly|definitely|undoubtedly|is guilty|"
    r"is owned by|operates)\b", re.IGNORECASE)


@dataclass(slots=True)
class ValidationIssue:
    statement_id: str
    rule: str
    detail: str


@dataclass(slots=True)
class ValidationResult:
    ok: bool
    issues: list[ValidationIssue] = field(default_factory=list)

    def raise_if_invalid(self) -> "ValidationResult":
        if not self.ok:
            first = self.issues[0]
            raise NarrativeValidationError(
                f"narrative rejected ({first.rule}): {first.detail}")
        return self


class NarrativeValidationError(ValueError):
    pass


def validate_statement(s: NarrativeStatement, mode: str = "investigator"
                       ) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not s.text.strip():
        issues.append(ValidationIssue(s.statement_id, "empty", "blank statement"))
        return issues
    if s.stype in (StatementType.FACT, StatementType.INFERENCE) and not s.evidence_ids:
        issues.append(ValidationIssue(
            s.statement_id, "uncited_fact",
            f"{s.stype.value} without evidence citation: '{s.text[:80]}'"))
    if s.stype is StatementType.HYPOTHESIS and not s.hypothesis_id:
        issues.append(ValidationIssue(
            s.statement_id, "orphan_hypothesis",
            f"hypothesis statement without hypothesis id: '{s.text[:80]}'"))
    # Truth-boundary guard: hypothesis/speculation phrased as certainty.
    if s.stype in (StatementType.HYPOTHESIS, StatementType.SPECULATION,
                   StatementType.UNKNOWN) and _CERTAINTY.search(s.text):
        issues.append(ValidationIssue(
            s.statement_id, "certainty_mismatch",
            f"{s.stype.value} stated with certainty language: '{s.text[:80]}'"))
    if mode == "executive" and s.stype is StatementType.SPECULATION:
        issues.append(ValidationIssue(
            s.statement_id, "speculation_in_executive",
            "speculation excluded from executive findings"))
    return issues


def validate_story(story: Story) -> ValidationResult:
    issues: list[ValidationIssue] = []
    for s in story.all_statements:
        issues.extend(validate_statement(s, mode=story.mode))
    return ValidationResult(ok=not issues, issues=issues)
