"""Firewall request and response schemas."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

from .common import RiskLevel, ThreatCategory, Verdict


class ProposedOperation(BaseModel):
    """Candidate banking action extracted or proposed from the user request."""

    action: str = Field(
        ...,
        description="Banking action type, e.g. VIEW_BALANCE, TRANSFER_FUNDS, LIST_TRANSACTIONS, UPDATE_BENEFICIARY",
        examples=["TRANSFER_FUNDS"],
    )
    source_account_id: Optional[str] = Field(
        None,
        description="Source bank account identifier",
        examples=["ACC-1001-CHK"],
    )
    destination_account_id: Optional[str] = Field(
        None,
        description="Destination account or counterparty handle",
        examples=["ACC-8921-EXT"],
    )
    amount: Optional[float] = Field(
        None,
        ge=0.0,
        description="Transaction amount if applicable",
        examples=[250.00],
    )
    currency: str = Field(
        default="USD",
        description="ISO currency code",
        examples=["USD"],
    )
    memo: Optional[str] = Field(
        None,
        max_length=500,
        description="Payment reference or memo note",
        examples=["Rent for October"],
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional contextual metadata",
    )


class ThreatDetail(BaseModel):
    """Detailed information on a single detected threat signature or anomaly."""

    category: ThreatCategory
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    matched_pattern: Optional[str] = None
    severity: RiskLevel = RiskLevel.LOW


class PolicyViolation(BaseModel):
    """Specific policy constraint violation."""

    rule_id: str
    rule_name: str
    description: str
    required_action: str


class FirewallInspectRequest(BaseModel):
    """Incoming request to be inspected by the Bankism firewall."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="Natural-language banking request from the user or client system.",
        examples=["Transfer $500 to my savings account for rent"],
    )
    user_id: Optional[str] = Field(
        None,
        max_length=100,
        description="Authenticated user identifier if known",
    )
    account_id: Optional[str] = Field(
        None,
        max_length=100,
        description="Primary active account identifier",
    )
    session_id: Optional[str] = Field(
        None,
        max_length=100,
        description="Client session tracking identifier",
    )
    channel: str = Field(
        default="web_chat",
        description="Origin channel, e.g. web_chat, mobile_app, voice_assistant, api_agent",
    )
    proposed_operation: Optional[ProposedOperation] = Field(
        None,
        description="Pre-parsed or candidate operational parameters",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional telemetry or request metadata",
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt_not_just_whitespace(cls, value: str) -> str:
        """Ensure prompt is not purely empty whitespace."""
        if not value or not value.strip():
            raise ValueError("Prompt must contain non-whitespace characters")
        return value


class FirewallInspectResponse(BaseModel):
    """Structured firewall inspection verdict and security evaluation."""

    inspection_id: str = Field(
        ...,
        description="Unique UUID for this inspection transaction and audit trail",
    )
    verdict: Verdict = Field(
        ...,
        description="Final deterministic verdict: APPROVE, BLOCK, or REVIEW",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Overall risk level: LOW, MEDIUM, HIGH, or CRITICAL",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite normalized risk score from 0.0 (safe) to 1.0 (critical threat)",
    )
    primary_threat: ThreatCategory = Field(
        ...,
        description="Dominant detected threat category",
    )
    threats_detected: List[ThreatDetail] = Field(
        default_factory=list,
        description="Individual threat heuristics or pattern matches",
    )
    policy_violations: List[PolicyViolation] = Field(
        default_factory=list,
        description="Evaluated policy violations",
    )
    sanitized_prompt: str = Field(
        ...,
        description="Cleaned, normalized prompt stripped of invisible and zero-width exploit bytes",
    )
    masked_prompt: str = Field(
        ...,
        description="Prompt with sensitive banking details (PAN, account numbers, SSN, secrets) masked",
    )
    requires_step_up_auth: bool = Field(
        default=False,
        description="Whether a multi-factor step-up confirmation is mandatory before execution",
    )
    execution_permitted: bool = Field(
        default=False,
        description="Safety guardrail: Always False in Phase 1; explicit permission gate for downstream executor",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable rationales justifying the verdict and risk score",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the inspection",
    )
    evaluation_latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Inspection latency in milliseconds",
    )


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="healthy")
    app_name: str
    version: str
    environment: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    subsystems: Dict[str, str] = Field(default_factory=dict)
