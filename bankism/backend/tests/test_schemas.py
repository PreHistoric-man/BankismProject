"""Unit tests for Pydantic schema validation."""

import sys
from pathlib import Path
import pytest
from pydantic import ValidationError

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.schemas.common import RiskLevel, ThreatCategory, Verdict
from app.schemas.firewall import FirewallInspectRequest, ProposedOperation


def test_valid_firewall_request():
    req = FirewallInspectRequest(
        prompt="Transfer $100 to savings",
        user_id="USR-01",
        proposed_operation=ProposedOperation(
            action="TRANSFER_FUNDS",
            amount=100.0,
            currency="USD",
        ),
    )
    assert req.prompt == "Transfer $100 to savings"
    assert req.proposed_operation.amount == 100.0


def test_empty_prompt_raises_validation_error():
    with pytest.raises(ValidationError):
        FirewallInspectRequest(prompt="   ")


def test_negative_amount_raises_validation_error():
    with pytest.raises(ValidationError):
        ProposedOperation(action="TRANSFER_FUNDS", amount=-50.0)


def test_enums_completeness():
    assert set(Verdict) == {Verdict.APPROVE, Verdict.BLOCK, Verdict.REVIEW}
    assert set(RiskLevel) == {RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert ThreatCategory.PROMPT_INJECTION in set(ThreatCategory)
    assert ThreatCategory.JAILBREAK_ATTEMPT in set(ThreatCategory)
    assert ThreatCategory.MALICIOUS_PAYMENT_METADATA in set(ThreatCategory)
    assert ThreatCategory.OBFUSCATION in set(ThreatCategory)
    assert ThreatCategory.AMBIGUOUS_INTENT in set(ThreatCategory)
    assert ThreatCategory.INVALID_INPUT in set(ThreatCategory)
    assert ThreatCategory.NO_DETECTED_THREAT in set(ThreatCategory)
