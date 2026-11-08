"""Application configuration and environment settings using Pydantic Settings."""

import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Ensure intelligence and shared modules are dynamically accessible across runtimes
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_BACKEND_ROOT = Path(__file__).resolve().parent.parent

for _base in [_REPO_ROOT, _BACKEND_ROOT]:
    for _sub in [
        _base / "shared",
        _base / "shared" / "contracts",
        _base / "intelligence",
        _base / "intelligence" / "certificate_analyzer" / "src",
        _base / "intelligence" / "certificate_dataset" / "src",
        _base / "intelligence" / "web_security_analysis",
        _base / "intelligence" / "web_security_analysis" / "analyzer",
    ]:
        if _sub.exists() and str(_sub) not in sys.path:
            sys.path.insert(0, str(_sub))


class Settings(BaseSettings):
    """TrustLens backend configuration model."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Core Application Settings
    PROJECT_NAME: str = "TrustLens Security Platform"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Security & Cryptography
    SECRET_KEY: str = Field(
        default="trustlens-default-insecure-dev-secret-key-32-bytes-minimum",
        description="Secret key for JWT generation and cryptographic signatures",
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database URLs
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://trustlens_user:trustlens_password@localhost:5432/trustlens_db",
        description="Async SQLAlchemy database connection string",
    )
    DATABASE_SYNC_URL: str = Field(
        default="",
        description="Sync SQLAlchemy database connection string for migrations/celery",
    )

    # Redis & Celery
    CELERY_ENABLED: bool = False
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # CORS Allowlist
    ALLOWED_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Scanner Safety & Operational Thresholds
    SCAN_TIMEOUT_SECONDS: int = 10
    SCAN_CONNECT_TIMEOUT_SECONDS: int = 3
    SCAN_MAX_REDIRECTS: int = 5
    SCAN_MAX_BODY_BYTES: int = 131072  # 128 KiB
    SCAN_ALLOWED_PORTS: list[int] = [80, 443]

    # Rate Limiting
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 5
    RATE_LIMIT_SCAN_PER_MINUTE: int = 10

    # Threat Intelligence Integrations
    URLHAUS_AUTH_KEY: str = ""
    OPENPHISH_ENABLED: bool = True

    # Certificate Analyzer Configuration
    TRUSTLENS_ROOT_STORE_PATH: str | None = None
    TRUSTLENS_CACHE_SIZE: int = 4096
    TRUSTLENS_ENABLE_ML_ADVISORY: bool = False
    TRUSTLENS_CERT_MAX_INPUT_BYTES: int = 10485760  # 10 MB limit
    TRUSTLENS_CERT_MAX_BUNDLE_CERTS: int = 50
    TRUSTLENS_CERT_MAX_SAN_COUNT: int = 10000

    # Web Security Analyzer Configuration
    WEB_SECURITY_TIMEOUT_SECONDS: float = 8.0
    WEB_SECURITY_MAX_REDIRECTS: int = 5

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: Any) -> str:
        """Normalize standard postgres:// and postgresql:// URLs to postgresql+asyncpg:// for async engine."""
        import os

        if isinstance(v, str):
            s = v.strip()
            # If running on Vercel without a configured remote database, fallback to /tmp SQLite
            if os.getenv("VERCEL") and ("localhost" in s or "127.0.0.1" in s):
                return "sqlite+aiosqlite:////tmp/trustlens.db"
            if s.startswith("postgres://"):
                return s.replace("postgres://", "postgresql+asyncpg://", 1)
            if s.startswith("postgresql://") and not s.startswith("postgresql+"):
                return s.replace("postgresql://", "postgresql+asyncpg://", 1)
            return s
        if v is None and os.getenv("VERCEL"):
            return "sqlite+aiosqlite:////tmp/trustlens.db"
        return str(v)

    @field_validator("DATABASE_SYNC_URL", mode="before")
    @classmethod
    def assemble_sync_db_url(cls, v: Any, info: Any) -> str:
        """Derive sync database URL from DATABASE_URL if omitted."""
        if isinstance(v, str) and v.strip():
            s = v.strip()
            if s.startswith("postgres://"):
                return s.replace("postgres://", "postgresql+psycopg://", 1)
            if s.startswith("postgresql://") and not s.startswith("postgresql+"):
                return s.replace("postgresql://", "postgresql+psycopg://", 1)
            return s
        data = info.data
        async_url = str(data.get("DATABASE_URL", ""))
        if "postgresql+asyncpg://" in async_url:
            return async_url.replace("postgresql+asyncpg://", "postgresql+psycopg://")
        elif "sqlite+aiosqlite://" in async_url:
            return async_url.replace("sqlite+aiosqlite://", "sqlite://")
        return async_url

    @field_validator("ALLOWED_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        """Parse list or JSON string of origins."""
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed: Any = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(origin).strip() for origin in parsed if str(origin).strip()]
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return []

    @property
    def is_production(self) -> bool:
        """Return True if running in production environment."""
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_testing(self) -> bool:
        """Return True if running in test environment."""
        return self.ENVIRONMENT.lower() in ("test", "testing")


@lru_cache
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()


settings = get_settings()
