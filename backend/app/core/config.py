"""
MAILTRACE AI — Application configuration using Pydantic Settings.

Combines backend database, JWT, security, and CORS settings with
Gmail OAuth, Cloud Pub/Sub, and ML model configuration.

All configuration is sourced from environment variables or a .env file.
Real credentials (OAuth secrets, tokens) must NEVER be hardcoded here.

Usage:
    from backend.app.core.config import get_settings, settings
    # or
    from app.core.config import get_settings
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Union

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for MAILTRACE AI backend and intelligence pipeline."""

    # ------------------------------------------------------------------ #
    # Application & Server                                                 #
    # ------------------------------------------------------------------ #
    app_name: str = "MAILTRACE AI"
    app_version: str = "0.1.0"
    app_env: str = "development"
    debug: bool = False
    secret_key: str = "your-random-secret-key"
    database_url: str = "sqlite:///./mailtrace.db"
    model_path: str = "ml/models/dataset3_v1.0.0"

    # CORS configuration for React frontend development
    cors_origins: Union[list[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8081",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8081",
        "http://10.0.2.2:8000",
        "http://10.0.2.2:8081",
    ]

    # ------------------------------------------------------------------ #
    # Google OAuth / Gmail (Database & Webhook Pipeline)                   #
    # ------------------------------------------------------------------ #
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://127.0.0.1:8000/api/auth/google/callback"
    google_oauth_scopes: Union[list[str], str] = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ]
    google_pubsub_topic: str = "projects/mailtrace-ai/topics/gmail-notifications"

    # ------------------------------------------------------------------ #
    # Google OAuth / Gmail (Alternative File-Based Credentials)           #
    # ------------------------------------------------------------------ #
    GOOGLE_OAUTH_CLIENT_SECRETS_FILE: str = Field(
        default="credentials.json",
        description=(
            "Filesystem path to the OAuth 2.0 client-secrets JSON file downloaded "
            "from the Google Cloud Console. Never commit this file to version control."
        ),
    )

    GOOGLE_OAUTH_TOKEN_FILE: str = Field(
        default="backend/.secrets/token.json",
        description=(
            "Filesystem path where the local OAuth token is cached after the first "
            "browser-based authorisation flow. This directory is gitignored."
        ),
    )

    GOOGLE_CLOUD_PROJECT: str = Field(
        default="",
        description=(
            "Google Cloud project ID. Required when using Gmail watch "
            "(push notifications via Cloud Pub/Sub)."
        ),
    )

    GMAIL_PUBSUB_TOPIC: str = Field(
        default="",
        description=(
            "Pub/Sub topic name (short name, not the full resource path) "
            "used for Gmail push notification registrations."
        ),
    )

    # ------------------------------------------------------------------ #
    # Machine Learning / Inference                                        #
    # ------------------------------------------------------------------ #
    ML_MODEL_PATH: str = Field(
        default="ml/models/dataset3_v1.0.0",
        description=(
            "Filesystem path to the local directory containing the trained "
            "DistilBERT model (dataset3_v1.0.0) weights and tokenizer."
        ),
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Validators                                                           #
    # ------------------------------------------------------------------ #
    @field_validator("secret_key", mode="after")
    @classmethod
    def _validate_secret_key(cls, v: str, info) -> str:
        """
        Validate that in production (app_env=production), a real, secure SECRET_KEY
        must be supplied via environment variable rather than using default/sample values.
        """
        import os
        env = os.environ.get("APP_ENV", "").strip().lower()
        if hasattr(info, "data") and "app_env" in info.data:
            env = str(info.data.get("app_env", "")).strip().lower()

        insecure_keys = {
            "your-random-secret-key",
            "mailtrace_production_secret_key_sih2024",
            "secret",
            "changeme",
            "default",
            "",
        }

        if env == "production" and (not v or v in insecure_keys):
            raise ValueError(
                "In production configuration (APP_ENV=production), SECRET_KEY must be provided "
                "via a real environment variable and cannot use default/sample values."
            )
        return v

    @field_validator("GOOGLE_OAUTH_TOKEN_FILE", mode="before")
    @classmethod
    def _normalise_token_path(cls, v: str) -> str:
        """Expand user-home (~) and environment variable references."""
        return str(Path(v).expanduser())

    @field_validator("GOOGLE_OAUTH_CLIENT_SECRETS_FILE", mode="before")
    @classmethod
    def _normalise_secrets_path(cls, v: str) -> str:
        """Expand user-home (~) and environment variable references."""
        return str(Path(v).expanduser())

    @field_validator("ML_MODEL_PATH", "model_path", mode="before")
    @classmethod
    def _normalise_model_path(cls, v: str) -> str:
        """Resolve model path portably from repository root if relative."""
        if not v:
            return v
        p = Path(v).expanduser()
        if p.is_absolute():
            return str(p)
        current = Path(__file__).resolve().parent
        for parent in [current, *current.parents]:
            if (parent / "ml" / "models").is_dir() or (parent / "backend").is_dir():
                candidate = parent / p
                if candidate.exists():
                    return str(candidate.resolve())
        return str(p)

    # ------------------------------------------------------------------ #
    # Convenience properties                                               #
    # ------------------------------------------------------------------ #
    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS origins as a list of strings."""
        if isinstance(self.cors_origins, str):
            return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        return self.cors_origins

    @property
    def google_oauth_scopes_list(self) -> list[str]:
        """Return Google OAuth scopes as a list of strings."""
        if isinstance(self.google_oauth_scopes, str):
            return [scope.strip() for scope in self.google_oauth_scopes.split(",") if scope.strip()]
        return self.google_oauth_scopes

    @property
    def pubsub_topic_resource(self) -> str:
        """
        Returns the full Pub/Sub topic resource name:
            projects/{GOOGLE_CLOUD_PROJECT}/topics/{GMAIL_PUBSUB_TOPIC}

        Returns an empty string if either component is unset.
        """
        if self.GOOGLE_CLOUD_PROJECT and self.GMAIL_PUBSUB_TOPIC:
            return f"projects/{self.GOOGLE_CLOUD_PROJECT}/topics/{self.GMAIL_PUBSUB_TOPIC}"
        return ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()


settings = get_settings()
