"""Threat detector engine for the Bankism AI firewall."""

from typing import List, Optional, Tuple
from ..schemas.common import RiskLevel, ThreatCategory
from ..schemas.firewall import ProposedOperation, ThreatDetail
from ..security.sanitization import check_obfuscation_indicators
from .patterns import (
    AMBIGUOUS_INTENT_PATTERNS,
    JAILBREAK_PATTERNS,
    MALICIOUS_PAYMENT_METADATA_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
)


class ThreatDetector:
    """Multi-layer threat detection engine combining regex signatures,

    heuristic indicators, and structural metadata evaluation.
    """

    def __init__(self, enable_heuristics: bool = True, enable_metadata_checks: bool = True):
        self.enable_heuristics = enable_heuristics
        self.enable_metadata_checks = enable_metadata_checks

    def detect_threats(
        self,
        raw_prompt: str,
        sanitized_prompt: str,
        operation: Optional[ProposedOperation] = None,
    ) -> Tuple[List[ThreatDetail], float, ThreatCategory]:
        """Analyze prompt and operation context for threats.

        Returns:
            Tuple of:
            - threats_detected: List[ThreatDetail]
            - composite_risk_score: float (0.0 to 1.0)
            - primary_threat: ThreatCategory
        """
        threats: List[ThreatDetail] = []

        # 1. Check for Invalid or Malformed Input
        if not sanitized_prompt or len(sanitized_prompt.strip()) == 0:
            threats.append(
                ThreatDetail(
                    category=ThreatCategory.INVALID_INPUT,
                    confidence=1.0,
                    description="Input is empty or consists purely of whitespace/control bytes",
                    severity=RiskLevel.HIGH,
                )
            )
            return threats, 0.90, ThreatCategory.INVALID_INPUT

        # 2. Check for deliberate Obfuscation in raw text before sanitization
        if self.enable_heuristics:
            is_obfuscated, obf_reasons, obf_score = check_obfuscation_indicators(raw_prompt)
            if is_obfuscated:
                threats.append(
                    ThreatDetail(
                        category=ThreatCategory.OBFUSCATION,
                        confidence=min(0.95, obf_score),
                        description="; ".join(obf_reasons),
                        matched_pattern="obfuscation_heuristic",
                        severity=RiskLevel.HIGH if obf_score >= 0.6 else RiskLevel.MEDIUM,
                    )
                )

        # 3. Match Prompt Injection Signatures
        for pattern, cat, conf, sev, desc in PROMPT_INJECTION_PATTERNS:
            match = pattern.search(sanitized_prompt)
            if match:
                threats.append(
                    ThreatDetail(
                        category=cat,
                        confidence=conf,
                        description=desc,
                        matched_pattern=match.group(0)[:80],
                        severity=sev,
                    )
                )

        # 4. Match Jailbreak Patterns
        for pattern, cat, conf, sev, desc in JAILBREAK_PATTERNS:
            match = pattern.search(sanitized_prompt)
            if match:
                threats.append(
                    ThreatDetail(
                        category=cat,
                        confidence=conf,
                        description=desc,
                        matched_pattern=match.group(0)[:80],
                        severity=sev,
                    )
                )

        # 5. Check Malicious Payment Metadata in Prompt & Operation fields
        fields_to_check = [sanitized_prompt]
        if self.enable_metadata_checks and operation:
            if operation.memo:
                fields_to_check.append(operation.memo)
            if operation.source_account_id:
                fields_to_check.append(operation.source_account_id)
            if operation.destination_account_id:
                fields_to_check.append(operation.destination_account_id)
            if operation.action:
                fields_to_check.append(operation.action)

        for text_field in fields_to_check:
            for pattern, cat, conf, sev, desc in MALICIOUS_PAYMENT_METADATA_PATTERNS:
                match = pattern.search(text_field)
                if match:
                    threats.append(
                        ThreatDetail(
                            category=cat,
                            confidence=conf,
                            description=desc,
                            matched_pattern=match.group(0)[:80],
                            severity=sev,
                        )
                    )

        # 6. Match Ambiguous Intent Patterns
        for pattern, cat, conf, sev, desc in AMBIGUOUS_INTENT_PATTERNS:
            match = pattern.search(sanitized_prompt)
            if match:
                threats.append(
                    ThreatDetail(
                        category=cat,
                        confidence=conf,
                        description=desc,
                        matched_pattern=match.group(0)[:80],
                        severity=sev,
                    )
                )

        # Calculate composite risk score
        composite_score = self._compute_composite_score(threats)
        primary_threat = self._determine_primary_threat(threats)

        return threats, composite_score, primary_threat

    def _compute_composite_score(self, threats: List[ThreatDetail]) -> float:
        """Compute composite normalized risk score (0.0 to 1.0) from threats."""
        if not threats:
            return 0.05  # baseline nominal risk

        severity_weights = {
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.50,
            RiskLevel.HIGH: 0.80,
            RiskLevel.CRITICAL: 0.95,
        }

        # Take max base severity and compound with threat count
        max_threat_score = max(
            severity_weights.get(t.severity, 0.3) * t.confidence for t in threats
        )
        # Slight boost for multi-vector threat combinations
        compound_bonus = min(0.15, (len(threats) - 1) * 0.05) if len(threats) > 1 else 0.0

        return round(min(1.0, max_threat_score + compound_bonus), 3)

    def _determine_primary_threat(self, threats: List[ThreatDetail]) -> ThreatCategory:
        """Determine the dominant threat category based on severity priority."""
        if not threats:
            return ThreatCategory.NO_DETECTED_THREAT

        # Priority order
        priority_order = [
            ThreatCategory.PROMPT_INJECTION,
            ThreatCategory.JAILBREAK_ATTEMPT,
            ThreatCategory.MALICIOUS_PAYMENT_METADATA,
            ThreatCategory.OBFUSCATION,
            ThreatCategory.INVALID_INPUT,
            ThreatCategory.AMBIGUOUS_INTENT,
        ]

        categories = {t.category for t in threats}
        for category in priority_order:
            if category in categories:
                return category

        return threats[0].category
