"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Union
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for MAILTRACE AI backend."""

    app_name: str = "MAILTRACE AI"
    app_version: str = "0.1.0"
    debug: bool = False
    database_url: str = "sqlite:///./mailtrace.db"
    model_path: str = "ml/models"

    # CORS configuration for React frontend development
    cors_origins: Union[list[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS origins as a list of strings."""
        if isinstance(self.cors_origins, str):
            return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        return self.cors_origins


@lru_cache
def get_settings() -> Settings:
    """Return a cached instance of application settings."""
    return Settings()


settings = get_settings()
