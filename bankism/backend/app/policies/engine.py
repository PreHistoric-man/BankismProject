"""Policy Engine synthesizing firewall verdicts, risk levels, and violations."""

from typing import List, Optional, Tuple
from ..schemas.common import RiskLevel, ThreatCategory, Verdict
from ..schemas.firewall import PolicyViolation, ProposedOperation, ThreatDetail
from .rules import (
    AmbiguousIntentRule,
    HighAmountThresholdRule,
    InvalidInputRule,
    JailbreakRule,
    MaliciousMetadataRule,
    ObfuscationRule,
    PolicyRule,
    PromptInjectionRule,
)


class PolicyEngine:
    """Enforces deterministic security policies on banking requests."""

    def __init__(
        self,
        risk_block_threshold: float = 0.70,
        risk_review_threshold: float = 0.35,
        high_amount_threshold: float = 10000.0,
    ):
        self.risk_block_threshold = risk_block_threshold
        self.risk_review_threshold = risk_review_threshold
        self.high_amount_threshold = high_amount_threshold

        # Ordered rule hierarchy (highest severity first)
        self.rules: List[PolicyRule] = [
            PromptInjectionRule(),
            JailbreakRule(),
            MaliciousMetadataRule(),
            InvalidInputRule(),
            ObfuscationRule(),
            HighAmountThresholdRule(),
            AmbiguousIntentRule(),
        ]

    def evaluate_policies(
        self,
        threats: List[ThreatDetail],
        risk_score: float,
        operation: Optional[ProposedOperation] = None,
    ) -> Tuple[Verdict, RiskLevel, List[PolicyViolation], List[str], bool]:
        """Evaluate all policy rules against the inspection context.

        Returns:
            Tuple of:
            - verdict: Verdict (APPROVE, BLOCK, REVIEW)
            - risk_level: RiskLevel (LOW, MEDIUM, HIGH, CRITICAL)
            - policy_violations: List[PolicyViolation]
            - reasons: List[str]
            - requires_step_up_auth: bool
        """
        violations: List[PolicyViolation] = []
        reasons: List[str] = []
        requires_step_up = False

        # FAIL-CLOSED INVARIANT: Missing, unconfigured, or empty policy rules must fail closed.
        if not self.rules:
            return (
                Verdict.BLOCK,
                RiskLevel.CRITICAL,
                [
                    PolicyViolation(
                        rule_id="FAIL-CLOSED-RULES-MISSING",
                        rule_name="Missing Policy Rules Enforcement",
                        description="Security policy rule set is missing or empty. Operation blocked fail-closed.",
                        required_action="Quarantine request and alert administration.",
                    )
                ],
                ["Fail-closed security trigger: No policy rules configured or loaded."],
                False,
            )

        highest_verdict = Verdict.APPROVE
        highest_risk_level = self._risk_level_from_score(risk_score)

        # 1. Run through concrete rule chain
        for rule in self.rules:
            try:
                rule_verdict, rule_risk, violation, reason, step_up = rule.evaluate(
                    threats=threats,
                    risk_score=risk_score,
                    operation=operation,
                    high_amount_threshold=self.high_amount_threshold,
                )
                if violation:
                    violations.append(violation)
                if reason:
                    reasons.append(reason)
                if step_up:
                    requires_step_up = True

                # Upgrade verdict severity if rule triggered
                if rule_verdict == Verdict.BLOCK:
                    highest_verdict = Verdict.BLOCK
                elif rule_verdict == Verdict.REVIEW and highest_verdict != Verdict.BLOCK:
                    highest_verdict = Verdict.REVIEW

                # Upgrade risk level if rule reported higher
                if rule_risk:
                    highest_risk_level = self._max_risk(highest_risk_level, rule_risk)

            except Exception as exc:
                # Fail-closed principle: Any unexpected rule evaluation failure must force BLOCK
                highest_verdict = Verdict.BLOCK
                highest_risk_level = RiskLevel.CRITICAL
                reasons.append(f"Fail-closed safety trigger: Policy rule {rule.rule_id} error: {str(exc)}")

        # 2. Threshold-based check as defense-in-depth
        if risk_score >= self.risk_block_threshold:
            highest_verdict = Verdict.BLOCK
            highest_risk_level = self._max_risk(highest_risk_level, RiskLevel.HIGH)
            if "Risk score exceeds block threshold" not in reasons:
                reasons.append(f"Composite risk score ({risk_score:.2f}) exceeds block threshold ({self.risk_block_threshold:.2f})")
        elif risk_score >= self.risk_review_threshold:
            if highest_verdict != Verdict.BLOCK:
                highest_verdict = Verdict.REVIEW
                requires_step_up = True
            highest_risk_level = self._max_risk(highest_risk_level, RiskLevel.MEDIUM)
            if "Risk score requires review" not in reasons:
                reasons.append(f"Composite risk score ({risk_score:.2f}) requires human review and confirmation")

        # 3. Default reason if approved cleanly
        if highest_verdict == Verdict.APPROVE and not reasons:
            reasons.append("No security anomalies or adversarial patterns detected. Request within safe parameters.")

        return highest_verdict, highest_risk_level, violations, reasons, requires_step_up

    def _risk_level_from_score(self, score: float) -> RiskLevel:
        """Map raw numeric risk score to standard RiskLevel."""
        if score >= 0.85:
            return RiskLevel.CRITICAL
        if score >= 0.65:
            return RiskLevel.HIGH
        if score >= 0.35:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _max_risk(self, a: RiskLevel, b: RiskLevel) -> RiskLevel:
        """Return the higher severity between two RiskLevels."""
        order = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return a if order[a] >= order[b] else b
