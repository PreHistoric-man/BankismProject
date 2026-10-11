"""Bankism application configuration module.

Provides documented development defaults for all numeric thresholds, feature flags,
and optional runtime settings so the simulated banking security demo runs
out-of-the-box without manual environment configuration while preserving all
fail-closed security invariants.
"""

from functools import lru_cache
from typing import Any, Dict, List
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides and safe development defaults."""

    # 1. Optional Runtime & Server Settings
    app_name: str = "Bankism AI Security Firewall"
    app_version: str = "0.1.0"
    environment: str = Field(
        default="development",
        validation_alias=AliasChoices("environment", "BANKISM_ENVIRONMENT", "BANKISM_ENV"),
    )
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # 2. Numeric Thresholds — Phase 1 AI Firewall & Policy Engine
    risk_block_threshold: float = 0.70
    risk_review_threshold: float = 0.35
    high_amount_threshold: float = 10000.00

    # 3. Feature Flags & Security Guardrails
    enable_payment_metadata_checks: bool = True
    enable_heuristic_detection: bool = True
    mask_log_sensitive_data: bool = True
    # Phase 1 legacy flag - /firewall/inspect permanently enforces execution_permitted=False
    allow_transaction_execution: bool = False

    # 4. Phase 2 Database, Ledger & Cryptographic Ticket Configuration
    database_path: str = "bankism_ledger.db"
    # Local sandbox HMAC-SHA256 signing key for AuthorizationTicket verification (minimum 16 chars; fails closed if blank)
    hmac_secret: str = "bankism-dev-hmac-secret-key-32bytes-min-isolated"
    ticket_expiry_seconds: int = 300
    high_risk_dual_approval_threshold: float = 10000.00
    dual_approval_expiry_seconds: int = 3600

    # 5. Phase 3 Behavioral Risk & User Threat Profiling Configuration
    behavioral_policy_version: str = "phase3-v1.0.0"
    min_history_transactions: int = 3
    behavioral_window_days: int = 30
    behavioral_risk_medium_threshold: float = 25.0
    behavioral_risk_high_threshold: float = 50.0
    behavioral_risk_critical_threshold: float = 75.0
    amount_spike_z_score_threshold: float = 2.5
    amount_spike_ratio_threshold: float = 3.0
    velocity_hourly_burst_threshold: int = 3
    velocity_daily_burst_threshold: int = 8
    repeated_failed_attempts_threshold: int = 3
    high_behavioral_risk_requires_dual_approval: bool = True
    enable_toctou_watermark_check: bool = True
    risk_assessment_retention_days: int = 90

    # Allowed CORS origins
    cors_origins: List[str] = ["*"]

    @model_validator(mode="before")
    @classmethod
    def ignore_blank_env_strings(cls, values: Any) -> Any:
        """If an environment variable is set to an empty string (e.g. `BANKISM_PORT=`),
        strip it so Pydantic uses the documented field default instead of failing validation.
        Note: Explicitly passing an empty `hmac_secret` directly to Ticket functions still fails closed.
        """
        if isinstance(values, dict):
            cleaned: Dict[str, Any] = {}
            for k, v in values.items():
                if isinstance(v, str) and v.strip() == "":
                    continue
                cleaned[k] = v
            return cleaned
        return values

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
