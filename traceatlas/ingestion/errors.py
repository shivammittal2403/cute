"""traceatlas.ingestion.errors - Typed error/warning taxonomy for ingestion.

Errors are classified so the pipeline can decide between hard failure of one
artifact (never of the whole session) and soft warnings that flow into the
import report. Every code here is stable API surface: tests and the UI key off
these strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ErrorCode(str, Enum):
    # --- detection -------------------------------------------------------
    FORMAT_MISMATCH = "FORMAT_MISMATCH"            # extension vs content disagree
    ENCODING_AMBIGUOUS = "ENCODING_AMBIGUOUS"
    UNKNOWN_FORMAT = "UNKNOWN_FORMAT"
    LOW_CONFIDENCE_DETECTION = "LOW_CONFIDENCE_DETECTION"
    # --- security / quarantine ------------------------------------------
    ARCHIVE_BOMB = "ARCHIVE_BOMB"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    ABSOLUTE_MEMBER_PATH = "ABSOLUTE_MEMBER_PATH"
    SYMLINK_MEMBER = "SYMLINK_MEMBER"
    HARDLINK_MEMBER = "HARDLINK_MEMBER"
    ENCRYPTED_ARCHIVE = "ENCRYPTED_ARCHIVE"
    NESTED_ARCHIVE_LIMIT = "NESTED_ARCHIVE_LIMIT"
    MEMBER_TOO_LARGE = "MEMBER_TOO_LARGE"
    MALFORMED_ARCHIVE = "MALFORMED_ARCHIVE"
    EXECUTABLE_CONTENT = "EXECUTABLE_CONTENT"
    QUARANTINED = "QUARANTINED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    # --- parsing ---------------------------------------------------------
    NO_PARSER = "NO_PARSER"
    PARSER_ERROR = "PARSER_ERROR"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    TRUNCATED_INPUT = "TRUNCATED_INPUT"
    CORRUPT_RECORD = "CORRUPT_RECORD"
    # --- normalization / mapping ----------------------------------------
    UNMAPPED_FIELD = "UNMAPPED_FIELD"
    LOW_CONFIDENCE_MAPPING = "LOW_CONFIDENCE_MAPPING"
    TYPE_COERCION_FAILED = "TYPE_COERCION_FAILED"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    # --- session level ---------------------------------------------------
    CANCELLED = "CANCELLED"
    CHECKPOINT_CORRUPT = "CHECKPOINT_CORRUPT"
    DUPLICATE_ARTIFACT = "DUPLICATE_ARTIFACT"
    DB_READONLY_VIOLATION = "DB_READONLY_VIOLATION"
    POLICY_BLOCKED = "POLICY_BLOCKED"


@dataclass(frozen=True, slots=True)
class Issue:
    """A single warning or error attached to an artifact or the session."""
    code: ErrorCode
    severity: Severity = Severity.WARNING
    message: str = ""
    artifact_id: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "severity": self.severity.value,
                "message": self.message, "artifact_id": self.artifact_id,
                "detail": self.detail}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Issue":
        return cls(code=ErrorCode(d["code"]), severity=Severity(d.get("severity", "warning")),
                   message=d.get("message", ""), artifact_id=d.get("artifact_id"),
                   detail=d.get("detail", {}) or {})


class IngestionError(Exception):
    """Base class; carries an ErrorCode so callers can branch on it."""

    def __init__(self, code: ErrorCode, message: str = "",
                 artifact_id: Optional[str] = None, detail: Optional[dict] = None):
        super().__init__(message or code.value)
        self.code = code
        self.artifact_id = artifact_id
        self.detail = detail or {}

    def as_issue(self) -> Issue:
        return Issue(code=self.code, severity=Severity.ERROR,
                     message=str(self), artifact_id=self.artifact_id, detail=self.detail)


class QuarantineRequired(IngestionError):
    def __init__(self, message: str = "", code: ErrorCode = ErrorCode.QUARANTINED, **kw):
        super().__init__(code, message, **kw)


class ArchiveSecurityError(QuarantineRequired):
    pass


class ResourceLimitExceeded(IngestionError):
    def __init__(self, message: str = "", **kw):
        super().__init__(ErrorCode.RESOURCE_LIMIT, message, **kw)


class ParserError(IngestionError):
    def __init__(self, message: str = "", **kw):
        super().__init__(ErrorCode.PARSER_ERROR, message, **kw)


class UnsupportedFormat(IngestionError):
    def __init__(self, message: str = "", **kw):
        super().__init__(ErrorCode.UNSUPPORTED_FORMAT, message, **kw)
