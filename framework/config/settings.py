from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    BASE_URL: str = "http://localhost:31001"
    API_URL: str = "http://localhost:31001/api"
    REST_API_URL: str = "http://localhost:31001/rest"

    USERNAME: str | None = None
    PASSWORD: str | None = None
    JWT_TOKEN: str | None = None

    ZAP_URL: str = "http://zap:8080"
    ZAP_API_KEY: str | None = None
    ZAP_TARGET_URL: str = "http://juice-shop:3000"

    AI_PROVIDER: str = "deterministic"
    AI_MODEL: str = "gpt-5-mini"
    OPENAI_API_KEY: str | None = None

    LOG_LEVEL: str = "INFO"
    HEADLESS: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()