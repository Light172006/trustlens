"""Application configuration and environment settings using Pydantic Settings."""

import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Ensure intelligence modules are dynamically accessible
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_CERT_ANALYZER_SRC = _REPO_ROOT / "intelligence" / "certificate_analyzer" / "src"
_CERT_DATASET_SRC = _REPO_ROOT / "intelligence" / "certificate_dataset" / "src"
_INTELLIGENCE_SRC = _REPO_ROOT / "intelligence"
_WEB_SECURITY_SRC = _REPO_ROOT / "intelligence" / "web_security_analysis"
_WEB_SECURITY_ANALYZER_SRC = _REPO_ROOT / "intelligence" / "web_security_analysis" / "analyzer"

for _src_path in [
    _INTELLIGENCE_SRC,
    _CERT_ANALYZER_SRC,
    _CERT_DATASET_SRC,
    _WEB_SECURITY_SRC,
    _WEB_SECURITY_ANALYZER_SRC,
]:
    if _src_path.exists() and str(_src_path) not in sys.path:
        sys.path.insert(0, str(_src_path))


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
    def assemble_db_url(cls, v: object, info: Any) -> str:
        """Normalize DATABASE_URL for asyncpg and auto-fallback to SQLite in local dev if PostgreSQL is closed."""
        raw_val = str(v).strip() if v else ""
        if not raw_val:
            raw_val = (
                "postgresql+asyncpg://trustlens_user:trustlens_password@localhost:5432/trustlens_db"
            )

        # Standardize cloud database protocols (e.g. Render/Heroku/Neon/Supabase) to asyncpg
        if raw_val.startswith("postgres://"):
            raw_val = raw_val.replace("postgres://", "postgresql+asyncpg://", 1)
        elif raw_val.startswith("postgresql://") and not raw_val.startswith("postgresql+"):
            raw_val = raw_val.replace("postgresql://", "postgresql+asyncpg://", 1)

        data_dict: dict[str, object] = dict(getattr(info, "data", {}) or {})
        env_val = str(data_dict.get("ENVIRONMENT", "development")).lower()

        # If running in local dev and targeting localhost:5432 when it's not active, fallback to SQLite
        if env_val != "production" and ("localhost:5432" in raw_val or "127.0.0.1:5432" in raw_val):
            is_open = False
            try:
                import socket

                with socket.create_connection(("127.0.0.1", 5432), timeout=0.2):
                    is_open = True
            except OSError:
                is_open = False

            if not is_open:
                sqlite_path = _REPO_ROOT / "backend" / "trustlens_dev.db"
                sqlite_url = f"sqlite+aiosqlite:///{sqlite_path.as_posix()}"
                return sqlite_url

        return raw_val

    @field_validator("DATABASE_SYNC_URL", mode="before")
    @classmethod
    def assemble_sync_db_url(cls, v: object, info: Any) -> str:
        """Derive sync database URL from DATABASE_URL if omitted."""
        data_dict: dict[str, object] = dict(getattr(info, "data", {}) or {})
        raw_async = str(data_dict.get("DATABASE_URL", ""))

        if isinstance(v, str) and v.strip():
            sync_val = v.strip()
            if sync_val.startswith("postgres://"):
                sync_val = sync_val.replace("postgres://", "postgresql+psycopg://", 1)
            elif sync_val.startswith("postgresql://") and not sync_val.startswith("postgresql+"):
                sync_val = sync_val.replace("postgresql://", "postgresql+psycopg://", 1)
            if "sqlite" in raw_async and "sqlite" not in sync_val:
                return raw_async.replace("sqlite+aiosqlite://", "sqlite://")
            return sync_val

        if "postgresql+asyncpg://" in raw_async:
            return raw_async.replace("postgresql+asyncpg://", "postgresql+psycopg://")
        if "sqlite+aiosqlite://" in raw_async:
            return raw_async.replace("sqlite+aiosqlite://", "sqlite://")
        return raw_async

    @field_validator("ALLOWED_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: object) -> list[str]:
        """Parse list or JSON string of origins."""
        if isinstance(v, str):
            s_val = v.strip()
            if s_val.startswith("[") and s_val.endswith("]"):
                try:
                    parsed_json: object = json.loads(s_val)
                    if isinstance(parsed_json, list):
                        return [
                            str(origin).strip() for origin in parsed_json if str(origin).strip()
                        ]
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in s_val.split(",") if origin.strip()]
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
