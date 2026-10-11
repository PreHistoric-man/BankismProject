"""
Bankism Backend Configuration Module
"""
import os
from typing import Optional


def _get_env_str(key: str, default: str) -> str:
    val = os.getenv(key)
    if val is None or val.strip() == "":
        return default
    return val.strip()


def _get_env_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


def _get_env_float(key: str, default: float) -> float:
    val = os.getenv(key)
    if val is None or val.strip() == "":
        return default
    try:
        return float(val.strip())
    except ValueError:
        return default


def _get_env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None or val.strip() == "":
        return default
    return val.strip().lower() in ("true", "1", "yes", "on")


class Settings:
    def __init__(self):
        self.host: str = _get_env_str("BANKISM_HOST", "0.0.0.0")
        self.port: int = _get_env_int("BANKISM_PORT", 8000)
        self.debug: bool = _get_env_bool("BANKISM_DEBUG", False)
        self.environment: str = _get_env_str("BANKISM_ENV", "development")
        self.database_path: str = _get_env_str("BANKISM_DATABASE_PATH", "bankism_ledger.db")
        self.hmac_secret: str = _get_env_str(
            "BANKISM_HMAC_SECRET",
            "bankism-dev-hmac-secret-key-32bytes-min-isolated"
        )
        self.ticket_expiry_seconds: int = _get_env_int("BANKISM_TICKET_EXPIRY_SECONDS", 300)
        self.dual_approval_expiry_seconds: int = _get_env_int("BANKISM_DUAL_APPROVAL_EXPIRY_SECONDS", 3600)
        self.high_amount_threshold: float = _get_env_float("BANKISM_HIGH_AMOUNT_THRESHOLD", 10000.0)
        self.high_risk_dual_approval_threshold: float = _get_env_float("BANKISM_HIGH_RISK_DUAL_APPROVAL_THRESHOLD", 10000.0)
        self.min_history_transactions: int = _get_env_int("BANKISM_MIN_HISTORY_TRANSACTIONS", 3)
        self.behavioral_window_days: int = _get_env_int("BANKISM_BEHAVIORAL_WINDOW_DAYS", 30)
        self.behavioral_risk_medium_threshold: float = _get_env_float("BANKISM_BEHAVIORAL_RISK_MEDIUM_THRESHOLD", 25.0)
        self.behavioral_risk_high_threshold: float = _get_env_float("BANKISM_BEHAVIORAL_RISK_HIGH_THRESHOLD", 50.0)
        self.behavioral_risk_critical_threshold: float = _get_env_float("BANKISM_BEHAVIORAL_RISK_CRITICAL_THRESHOLD", 75.0)
        self.amount_spike_z_score_threshold: float = _get_env_float("BANKISM_AMOUNT_SPIKE_Z_SCORE_THRESHOLD", 2.5)
        self.amount_spike_ratio_threshold: float = _get_env_float("BANKISM_AMOUNT_SPIKE_RATIO_THRESHOLD", 3.0)
        self.velocity_hourly_burst_threshold: int = _get_env_int("BANKISM_VELOCITY_HOURLY_BURST_THRESHOLD", 3)
        self.velocity_daily_burst_threshold: int = _get_env_int("BANKISM_VELOCITY_DAILY_BURST_THRESHOLD", 8)
        self.repeated_failed_attempts_threshold: int = _get_env_int("BANKISM_REPEATED_FAILED_ATTEMPTS_THRESHOLD", 3)
        self.mask_log_sensitive_data: bool = _get_env_bool("BANKISM_MASK_LOG_SENSITIVE_DATA", True)
        self.enable_payment_metadata_checks: bool = _get_env_bool("BANKISM_ENABLE_PAYMENT_METADATA_CHECKS", True)
        self.enable_heuristic_detection: bool = _get_env_bool("BANKISM_ENABLE_HEURISTIC_DETECTION", True)
        self.enable_toctou_watermark_check: bool = _get_env_bool("BANKISM_ENABLE_TOCTOU_WATERMARK_CHECK", True)
        self.allow_transaction_execution: bool = _get_env_bool("BANKISM_ALLOW_TRANSACTION_EXECUTION", False)
        self.behavioral_policy_version: str = _get_env_str("BANKISM_BEHAVIORAL_POLICY_VERSION", "phase3-v1.0.0")

        if len(self.hmac_secret) < 16:
            raise ValueError("BANKISM_HMAC_SECRET must be at least 16 characters for cryptographic safety")


settings = Settings()
