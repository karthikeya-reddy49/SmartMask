"""Application configuration.

Configuration is sourced from environment variables with documented defaults.
Real secrets (such as the HMAC key) are injected from configuration and are
never hard-coded. Missing required secrets cause fail-closed behavior rather
than silently substituting an insecure default.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class AppConfig:
    """Application configuration.

    All fields are optional and fall back to documented defaults. ``hmac_secret``
    is intentionally allowed to be empty: callers that require HMAC behavior
    must check for its presence and fail closed when it is missing.
    """

    source_db_url: str
    control_db_url: str
    max_sample_rows: int
    max_query_limit: int
    default_query_limit: int
    hmac_secret: str
    log_level: str
    api_environment: str = "development"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "smartmask"
    jwt_audience: str = "smartmask-api"
    jwt_lifetime_minutes: int = 15
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cors_origins: tuple[str, ...] = ()
    trusted_hosts: tuple[str, ...] = ()
    api_docs_enabled: bool = True
    postgres_schema: str = "public"
    postgres_connect_timeout: int = 5
    database_registry: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Build configuration from environment variables.

        Raises:
            ValueError: if numeric configuration values are invalid.
        """
        def _get(name: str, default: str) -> str:
            return os.environ.get(name, default)

        try:
            max_sample_rows = int(_get("SMARTMASK_MAX_SAMPLE_ROWS", "50"))
            max_query_limit = int(_get("SMARTMASK_MAX_QUERY_LIMIT", "100"))
            default_query_limit = int(_get("SMARTMASK_DEFAULT_QUERY_LIMIT", "20"))
        except ValueError as exc:  # pragma: no cover - config validation
            raise ValueError(
                "Invalid numeric configuration value. "
                "SMARTMASK_MAX_SAMPLE_ROWS, SMARTMASK_MAX_QUERY_LIMIT and "
                "SMARTMASK_DEFAULT_QUERY_LIMIT must be integers."
            ) from exc

        if max_sample_rows <= 0:
            raise ValueError("SMARTMASK_MAX_SAMPLE_ROWS must be a positive integer.")
        if max_sample_rows > 5000:
            raise ValueError("SMARTMASK_MAX_SAMPLE_ROWS cannot exceed 5000.")
        if max_query_limit <= 0:
            raise ValueError("SMARTMASK_MAX_QUERY_LIMIT must be a positive integer.")
        if max_query_limit > 10000:
            raise ValueError("SMARTMASK_MAX_QUERY_LIMIT cannot exceed 10000.")
        if default_query_limit <= 0:
            raise ValueError("SMARTMASK_DEFAULT_QUERY_LIMIT must be a positive integer.")
        log_level = _get("SMARTMASK_LOG_LEVEL", "INFO").upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("SMARTMASK_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL.")

        source_url = _get("SMARTMASK_SOURCE_DB_URL", "sqlite:///./data/demo_source.db")
        control_url = _get("SMARTMASK_CONTROL_DB_URL", "sqlite:///./data/control.db")
        if not source_url.startswith("sqlite:"):
            raise ValueError("SMARTMASK_SOURCE_DB_URL must be SQLite; configure PostgreSQL with SMARTMASK_POSTGRES_DB_URL.")
        if source_url == control_url:
            raise ValueError("Source and control databases must use separate database URLs.")

        registry: list[tuple[str, str]] = [("sqlite_demo", source_url)]
        postgres_url = _get("SMARTMASK_POSTGRES_DB_URL", "").strip()
        if postgres_url:
            if not postgres_url.startswith("postgresql+psycopg://"):
                raise ValueError("SMARTMASK_POSTGRES_DB_URL must use postgresql+psycopg://.")
            registry.append(("postgresql_demo", postgres_url))
        for database_id, _ in registry:
            if not re.fullmatch(r"[a-z][a-z0-9_-]{1,49}", database_id):
                raise ValueError("Configured database identifiers must be safe lowercase identifiers.")
        try:
            lifetime = int(_get("SMARTMASK_JWT_LIFETIME_MINUTES", "15"))
            port = int(_get("SMARTMASK_API_PORT", "8000"))
            pg_timeout = int(_get("SMARTMASK_POSTGRES_CONNECT_TIMEOUT", "5"))
        except ValueError as exc:
            raise ValueError("API port, token lifetime, and PostgreSQL timeout must be integers.") from exc
        if not 1 <= lifetime <= 120:
            raise ValueError("SMARTMASK_JWT_LIFETIME_MINUTES must be between 1 and 120.")
        if not 1 <= port <= 65535 or not 1 <= pg_timeout <= 60:
            raise ValueError("API port or PostgreSQL connection timeout is outside its valid range.")
        algorithm = _get("SMARTMASK_JWT_ALGORITHM", "HS256")
        if algorithm != "HS256":
            raise ValueError("Only the explicitly supported HS256 JWT algorithm is allowed.")
        csv = lambda key: tuple(value.strip() for value in _get(key, "").split(",") if value.strip())
        cors = csv("SMARTMASK_CORS_ORIGINS")
        if "*" in cors:
            raise ValueError("Wildcard CORS origins are not supported; configure explicit origins.")
        environment = _get("SMARTMASK_ENVIRONMENT", "development").lower()
        if environment not in {"development", "test", "staging", "production"}:
            raise ValueError("SMARTMASK_ENVIRONMENT must be development, test, staging, or production.")
        if not _get("SMARTMASK_JWT_ISSUER", "smartmask").strip() or not _get("SMARTMASK_JWT_AUDIENCE", "smartmask-api").strip():
            raise ValueError("JWT issuer and audience must be non-empty.")
        pg_schema = _get("SMARTMASK_POSTGRES_SCHEMA", "public")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", pg_schema):
            raise ValueError("SMARTMASK_POSTGRES_SCHEMA must be a valid single schema identifier.")

        return cls(
            source_db_url=source_url,
            control_db_url=control_url,
            max_sample_rows=max_sample_rows,
            max_query_limit=max_query_limit,
            default_query_limit=default_query_limit,
            hmac_secret=_get("SMARTMASK_HMAC_SECRET", ""),
            log_level=log_level,
            api_environment=environment,
            jwt_secret=_get("SMARTMASK_JWT_SECRET", ""),
            jwt_algorithm=algorithm,
            jwt_issuer=_get("SMARTMASK_JWT_ISSUER", "smartmask"),
            jwt_audience=_get("SMARTMASK_JWT_AUDIENCE", "smartmask-api"),
            jwt_lifetime_minutes=lifetime,
            api_host=_get("SMARTMASK_API_HOST", "127.0.0.1"),
            api_port=port,
            cors_origins=cors,
            trusted_hosts=csv("SMARTMASK_TRUSTED_HOSTS"),
            api_docs_enabled=_get(
                "SMARTMASK_API_DOCS",
                "false" if environment == "production" else "true",
            ).lower() == "true",
            postgres_schema=pg_schema,
            postgres_connect_timeout=pg_timeout,
            database_registry=tuple(registry),
        )

    def hmac_key_bytes(self) -> bytes:
        """Return the HMAC secret as bytes, or empty bytes if unset."""
        return self.hmac_secret.encode("utf-8")

    def hmac_configured(self) -> bool:
        """Return True when a non-empty HMAC secret is configured."""
        return bool(self.hmac_secret.strip())
