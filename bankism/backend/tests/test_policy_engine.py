"""Unit tests for PolicyEngine and decision governance."""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.policies.engine import PolicyEngine
from app.schemas.common import RiskLevel, ThreatCategory, Verdict
from app.schemas.firewall import ProposedOperation, ThreatDetail


def test_policy_engine_injection_forces_block():
    engine = PolicyEngine()
    threats = [
        ThreatDetail(
            category=ThreatCategory.PROMPT_INJECTION,
            confidence=0.95,
            description="System prompt hijack",
            severity=RiskLevel.CRITICAL,
        )
    ]
    verdict, risk, violations, reasons, step_up = engine.evaluate_policies(
        threats=threats,
        risk_score=0.95,
    )
    assert verdict == Verdict.BLOCK
    assert risk == RiskLevel.CRITICAL
    assert len(violations) > 0
    assert violations[0].rule_id == "POL-001"


def test_policy_engine_high_amount_requires_review_and_step_up():
    engine = PolicyEngine(high_amount_threshold=10000.0)
    threats = []
    op = ProposedOperation(
        action="TRANSFER_FUNDS",
        amount=15000.00,
    )
    verdict, risk, violations, reasons, step_up = engine.evaluate_policies(
        threats=threats,
        risk_score=0.10,
        operation=op,
    )
    assert verdict == Verdict.REVIEW
    assert step_up is True
    assert any(v.rule_id == "POL-006" for v in violations)


def test_policy_engine_fail_closed_on_corrupt_rule():
    """Verify that if an anomaly occurs, verdict defaults to BLOCK fail-closed."""
    engine = PolicyEngine()
    # Inject a buggy mock rule to test fail-closed behavior
    class FaultyRule:
        rule_id = "FAULTY-999"
        def evaluate(self, *args, **kwargs):
            raise RuntimeError("Simulated internal policy execution fault")

    engine.rules.append(FaultyRule())  # type: ignore

    verdict, risk, violations, reasons, step_up = engine.evaluate_policies(
        threats=[],
        risk_score=0.05,
    )
    assert verdict == Verdict.BLOCK
    assert risk == RiskLevel.CRITICAL
    assert any("Fail-closed" in r for r in reasons)
