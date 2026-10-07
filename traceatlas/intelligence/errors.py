"""traceatlas.intelligence.errors — typed failure taxonomy for the intelligence plane.

Every blocked state (§6) has a distinct exception so callers can distinguish
"not configured" from "not authorized" from "out of budget" — an honest run
record must never collapse these into one generic failure.
"""
from __future__ import annotations


class IntelligenceError(Exception):
    """Base class for all intelligence-plane failures."""

    def __init__(self, message: str = "", *, detail: dict | None = None):
        super().__init__(message or self.__doc__)
        self.detail = detail or {}


class UnknownModuleError(IntelligenceError):
    """Requested module id is not in the catalog (aliases resolved first)."""


class InvalidManifestError(IntelligenceError):
    """A manifest failed ModuleManifest.validate(); it cannot be registered."""


class BlockedInput(IntelligenceError):
    """Task inputs do not satisfy the module's accepted_inputs contract."""


class BlockedConfiguration(IntelligenceError):
    """Required sources/skills are not configured or not qualified enough."""


class BlockedPermission(IntelligenceError):
    """Authorization/permission check failed; collection must not happen."""


class BlockedBudget(IntelligenceError):
    """Budget reservation refused; the run may not proceed."""


class SkillNotAuthorizedError(IntelligenceError):
    """Worker asked to execute a skill it does not declare/is not granted."""


class FactGateRejection(IntelligenceError):
    """Candidate fact rejected by the Fact Gate (e.g. no evidence linkage)."""
