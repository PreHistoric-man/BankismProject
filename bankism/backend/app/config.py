"""Bankism application configuration module."""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides."""

    app_name: str = "Bankism AI Security Firewall"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # Risk thresholds
    risk_block_threshold: float = 0.70
    risk_review_threshold: float = 0.35
    high_amount_threshold: float = 10000.00

    # Firewall features
    enable_payment_metadata_checks: bool = True
    enable_heuristic_detection: bool = True
    mask_log_sensitive_data: bool = True

    # Security guardrails (Phase 1 legacy flag - kept for compatibility)
    allow_transaction_execution: bool = False

    # Phase 2 Database & Ledger Configuration
    database_path: str = "bankism_ledger.db"
    hmac_secret: str = "bankism-dev-hmac-secret-key-32bytes-min-isolated"
    ticket_expiry_seconds: int = 300
    high_risk_dual_approval_threshold: float = 10000.00
    dual_approval_expiry_seconds: int = 3600

    # Allowed CORS origins
    cors_origins: List[str] = ["*"]

    model_config = SettingsConfigDict(
        env_prefix="BANKISM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
