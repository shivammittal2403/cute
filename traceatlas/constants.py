"""traceatlas.constants - Global constants and defaults."""
DEFAULT_PAGE_TIMEOUT_SECONDS = 30
DEFAULT_CONNECTOR_TIMEOUT_SECONDS = 20
MAX_EVIDENCE_BYTES_INLINE = 1 << 20          # 1 MiB inline, larger goes to blob store
MIN_INDEPENDENT_SOURCES_FOR_VERIFIED = 2
DEFAULT_CONFIDENCE_THRESHOLD = 0.7
MAX_TASK_RETRIES = 3
DEFAULT_WAVE_CONCURRENCY = 4
USER_AGENT = "TraceAtlas/0.1 (+https://example.invalid/traceatlas; governed-osint)"
QUALIFICATION_TIERS = ("documented", "integration_tested", "live_verified",
                       "production_qualified")
