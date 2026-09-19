"""
MAILTRACE AI — Application configuration.

All configuration is sourced from environment variables or a .env file.
Real credentials (OAuth secrets, tokens) must NEVER be hardcoded here.

Usage:
    from app.core.config import get_settings
    settings = get_settings()

Environment variables (set in .env or shell):
    GOOGLE_OAUTH_CLIENT_SECRETS_FILE  — path to credentials.json downloaded from GCP Console
    GOOGLE_OAUTH_TOKEN_FILE           — path where the dev OAuth token is cached (gitignored)
    GOOGLE_CLOUD_PROJECT              — GCP project ID (required for Gmail watch / Pub/Sub)
    GMAIL_PUBSUB_TOPIC                — Pub/Sub topic name for Gmail push notifications
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralised application settings.

    Values are read from the environment (or a .env file in the backend
    directory).  Every field with a sensitive value is kept out of source
    code and version control.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        # Extra fields in .env are silently ignored — forward-compatible.
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Google OAuth / Gmail                                                 #
    # ------------------------------------------------------------------ #

    GOOGLE_OAUTH_CLIENT_SECRETS_FILE: str = Field(
        default="credentials.json",
        description=(
            "Filesystem path to the OAuth 2.0 client-secrets JSON file downloaded "
            "from the Google Cloud Console.  Never commit this file to version control."
        ),
    )

    GOOGLE_OAUTH_TOKEN_FILE: str = Field(
        default="backend/.secrets/token.json",
        description=(
            "Filesystem path where the local OAuth token is cached after the first "
            "browser-based authorisation flow.  This directory is gitignored.  "
            "In production, replace the InstalledAppFlow with service-account "
            "credentials and remove this field."
        ),
    )

    # ------------------------------------------------------------------ #
    # Google Cloud / Pub/Sub (required for Gmail watch)                   #
    # ------------------------------------------------------------------ #

    GOOGLE_CLOUD_PROJECT: str = Field(
        default="",
        description=(
            "Google Cloud project ID.  Required when using Gmail watch "
            "(push notifications via Cloud Pub/Sub).  "
            "Obtain from the GCP Console."
        ),
    )

    GMAIL_PUBSUB_TOPIC: str = Field(
        default="",
        description=(
            "Pub/Sub topic name (short name, not the full resource path) "
            "used for Gmail push notification registrations.  "
            "The full topic resource is constructed as: "
            "projects/{GOOGLE_CLOUD_PROJECT}/topics/{GMAIL_PUBSUB_TOPIC}"
        ),
    )

    # ------------------------------------------------------------------ #
    # Machine Learning / Inference (Chunk 4)                              #
    # ------------------------------------------------------------------ #

    ML_MODEL_PATH: str = Field(
        default="ml/models/dataset3_v1.0.0",
        description=(
            "Filesystem path to the local directory containing the trained "
            "DistilBERT model (dataset3_v1.0.0) weights and tokenizer."
        ),
    )

    # ------------------------------------------------------------------ #
    # Validators                                                           #
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    # Convenience properties                                               #
    # ------------------------------------------------------------------ #

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
    """
    Return a cached singleton Settings instance.

    Using lru_cache ensures the .env file is parsed exactly once per
    process lifetime.  Tests can override by calling
    ``get_settings.cache_clear()`` before patching environment variables.
    """
    return Settings()
