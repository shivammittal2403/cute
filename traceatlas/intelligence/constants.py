"""traceatlas.intelligence.constants — shared vocabularies for the intelligence plane.

Single source of truth for module lifecycle, run statuses, fact-gate outcomes,
source-analysis states and dual-AI cross-check verdicts. Nothing here is a
capability claim: a module's real status is whatever its manifest + tests prove.
"""
from __future__ import annotations

from enum import Enum


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class ModuleLifecycle(_StrEnum):
    """Honest maturity ladder. CREATED != IMPLEMENTED; passing unit tests does
    not make a module LIVE_TESTED, and live testing does not make it
    PRODUCTION_QUALIFIED."""
    MISSING = "missing"
    CREATED = "created"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"
    UNIT_TESTED = "unit_tested"
    INTEGRATION_TESTED = "integration_tested"
    LIVE_TESTED = "live_tested"
    VALIDATED = "validated"
    PRODUCTION_QUALIFIED = "production_qualified"


LIFECYCLE_ORDER = [e.value for e in ModuleLifecycle]


def lifecycle_at_least(status: str, minimum: str) -> bool:
    try:
        return LIFECYCLE_ORDER.index(status) >= LIFECYCLE_ORDER.index(minimum)
    except ValueError:
        return False


class RunStatus(_StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED_INPUT = "blocked_input"
    BLOCKED_CONFIGURATION = "blocked_configuration"
    BLOCKED_PERMISSION = "blocked_permission"
    BLOCKED_BUDGET = "blocked_budget"
    SKIPPED_NOT_APPLICABLE = "skipped_not_applicable"


# Blocked/skipped work NEVER counts as successful intelligence.
TERMINAL_FAILURE_OR_BLOCKED = (
    RunStatus.FAILED.value, RunStatus.CANCELLED.value,
    RunStatus.BLOCKED_INPUT.value, RunStatus.BLOCKED_CONFIGURATION.value,
    RunStatus.BLOCKED_PERMISSION.value, RunStatus.BLOCKED_BUDGET.value,
    RunStatus.SKIPPED_NOT_APPLICABLE.value,
)
SUCCESSFUL_STATUSES = (RunStatus.SUCCEEDED.value, RunStatus.PARTIAL.value)


class FactGateOutcome(_StrEnum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    DISPUTED = "disputed"
    INCONCLUSIVE = "inconclusive"
    REJECTED_NO_EVIDENCE = "rejected_no_evidence"


class SourceIndependenceState(_StrEnum):
    INDEPENDENT = "independent"
    PARTIALLY_DEPENDENT = "partially_dependent"
    DEPENDENT = "dependent"
    UNKNOWN = "unknown"


class CrossCheckVerdict(_StrEnum):
    AGREE = "agree"
    PARTIAL_AGREEMENT = "partial_agreement"
    SEMANTIC_AGREEMENT = "semantic_agreement"
    DISAGREE = "disagree"
    PASS1_ONLY = "pass1_only"
    PASS2_ONLY = "pass2_only"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ExecutionMode(_StrEnum):
    RUN_ALONE = "run_alone"
    REVIEWED_SEQUENCE = "reviewed_sequence"
    APPROVED_PLAYBOOK = "approved_playbook"


class SearchExecutionMode(_StrEnum):
    SERIAL_AUDIT = "serial_audit"
    BALANCED = "balanced"
    FAST = "fast"
    VERIFICATION = "verification"


class AIExecutionMode(_StrEnum):
    LOCAL_ONLY = "local_only"
    HYBRID = "hybrid"
    CLOUD = "cloud"


class HypothesisStatus(_StrEnum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    TESTING = "testing"
    STRENGTHENED = "strengthened"
    WEAKENED = "weakened"
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    FALSIFIED = "falsified"
    INCONCLUSIVE = "inconclusive"
    ARCHIVED = "archived"


class AchCell(_StrEnum):
    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"
    NEUTRAL = "neutral"
    UNKNOWN = "unknown"


class RelationshipState(_StrEnum):
    OBSERVED = "observed"
    CANDIDATE = "candidate"
    PROBABLE = "probable"
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    HISTORICAL = "historical"
    EXPIRED = "expired"


class EntityResolutionState(_StrEnum):
    VERIFIED_MATCH = "verified_match"
    PROBABLE_MATCH = "probable_match"
    POSSIBLE_MATCH = "possible_match"
    UNRESOLVED = "unresolved"
    LIKELY_DISTINCT = "likely_distinct"
    VERIFIED_DISTINCT = "verified_distinct"


class NarrativeLabel(_StrEnum):
    FACT = "fact"
    OBSERVATION = "observation"
    INSIGHT = "insight"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"
    SPECULATION = "speculation"
    CONTRADICTION = "contradiction"
    UNKNOWN = "unknown"


class PrivacyClass(_StrEnum):
    PUBLIC = "public"
    AUTHORIZED = "authorized"
    RESTRICTED = "restricted"
    LOCAL_ONLY = "local_only"


# Actions that may NEVER be performed autonomously by any module (§34).
PROHIBITED_BASELINE = (
    "auth_bypass", "captcha_bypass", "private_account_access",
    "credential_use", "session_token_use", "private_key_use",
    "unauthorized_scanning", "exploitation", "malware_execution_on_host",
    "illicit_purchase", "subject_contact", "publishing_allegations",
    "financial_action", "legal_action", "police_referral",
    "external_takedown", "production_remediation",
)
