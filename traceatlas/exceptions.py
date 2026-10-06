"""traceatlas.exceptions - Exception hierarchy."""


class TraceAtlasError(Exception):
    """Base class for all TraceAtlas errors."""


class ConfigurationError(TraceAtlasError):
    pass


class AuthorizationRequiredError(TraceAtlasError):
    """Raised when collection is attempted without a valid authorization."""


class ScopeViolationError(TraceAtlasError):
    pass


class PolicyViolationError(TraceAtlasError):
    pass


class ConnectorError(TraceAtlasError):
    def __init__(self, message: str, source_slug: str = "", retryable: bool = False):
        super().__init__(message)
        self.source_slug = source_slug
        self.retryable = retryable


class RateLimitedError(ConnectorError):
    def __init__(self, source_slug: str, retry_after_seconds: float = 1.0):
        super().__init__(f"rate limited by {source_slug}", source_slug, retryable=True)
        self.retry_after_seconds = retry_after_seconds


class SourceUnavailableError(ConnectorError):
    pass


class BudgetExhaustedError(TraceAtlasError):
    pass


class KillSwitchEngagedError(TraceAtlasError):
    pass


class ValidationError(TraceAtlasError):
    pass


class InvariantViolationError(ValidationError):
    pass


class ModelGatewayError(TraceAtlasError):
    pass


class PromptInjectionDetectedError(TraceAtlasError):
    pass
