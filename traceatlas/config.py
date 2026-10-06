
"""traceatlas.config - Typed settings loaded from environment."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    url: str = "sqlite:///traceatlas.db"
    pool_size: int = 5


@dataclass(frozen=True, slots=True)
class RedisSettings:
    url: str = ""


@dataclass(frozen=True, slots=True)
class AISettings:
    default_provider: str = "ollama"
    default_model: str = "llama3"
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    max_cost_usd_per_investigation: float = 10.0


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    secret_key: str = "dev-secret-change-me"
    access_token_ttl_minutes: int = 60
    require_authorization: bool = True


@dataclass(frozen=True, slots=True)
class StorageSettings:
    backend: str = "local"            # local|s3|minio
    local_dir: str = ".traceatlas/evidence"
    s3_bucket: str = ""
    s3_region: str = ""


@dataclass(frozen=True, slots=True)
class Settings:
    env: str = "dev"
    app_name: str = "TraceAtlas"
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    redis: RedisSettings = field(default_factory=RedisSettings)
    ai: AISettings = field(default_factory=AISettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    storage: StorageSettings = field(default_factory=StorageSettings)
    log_level: str = "INFO"


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def load_settings() -> Settings:
    """Build Settings from environment variables (see .env.example)."""
    return Settings(
        env=_env("TRACEATLAS_ENV", "dev"),
        log_level=_env("TRACEATLAS_LOG_LEVEL", "INFO"),
        database=DatabaseSettings(url=_env("TRACEATLAS_DB_URL", "sqlite:///traceatlas.db")),
        redis=RedisSettings(url=_env("TRACEATLAS_REDIS_URL")),
        ai=AISettings(
            default_provider=_env("TRACEATLAS_AI_PROVIDER", "ollama"),
            default_model=_env("TRACEATLAS_AI_MODEL", "llama3"),
            ollama_base_url=_env("TRACEATLAS_OLLAMA_URL", "http://localhost:11434"),
            openai_api_key=_env("OPENAI_API_KEY"),
            anthropic_api_key=_env("ANTHROPIC_API_KEY"),
        ),
        security=SecuritySettings(
            secret_key=_env("TRACEATLAS_SECRET_KEY", "dev-secret-change-me"),
            require_authorization=_env("TRACEATLAS_REQUIRE_AUTHORIZATION", "1") == "1",
        ),
        storage=StorageSettings(
            backend=_env("TRACEATLAS_STORAGE_BACKEND", "local"),
            local_dir=_env("TRACEATLAS_EVIDENCE_DIR", ".traceatlas/evidence"),
            s3_bucket=_env("TRACEATLAS_S3_BUCKET"),
            s3_region=_env("TRACEATLAS_S3_REGION"),
        ),
    )
