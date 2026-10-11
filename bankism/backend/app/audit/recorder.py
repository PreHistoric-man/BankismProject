"""Inspection audit trail recorder (thread-safe, ready for persistence)."""

from collections import deque
from functools import lru_cache
from threading import Lock
from typing import Any, Dict, List, Optional
from ..schemas.firewall import FirewallInspectResponse


class AuditRecorder:
    """Stores recent firewall inspection records for security auditing and metrics."""

    def __init__(self, max_history: int = 1000):
        self._max_history = max_history
        self._records: deque = deque(maxlen=max_history)
        self._lock = Lock()

    def record_inspection(self, response: FirewallInspectResponse, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store an inspection event thread-safely."""
        entry = {
            "inspection_id": response.inspection_id,
            "verdict": response.verdict.value,
            "risk_level": response.risk_level.value,
            "risk_score": response.risk_score,
            "primary_threat": response.primary_threat.value,
            "masked_prompt": response.masked_prompt,
            "threats_count": len(response.threats_detected),
            "violations_count": len(response.policy_violations),
            "requires_step_up": response.requires_step_up_auth,
            "evaluation_latency_ms": response.evaluation_latency_ms,
            "timestamp": response.timestamp.isoformat(),
            "metadata": metadata or {},
        }
        with self._lock:
            self._records.appendleft(entry)

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent inspection events."""
        with self._lock:
            return list(self._records)[:limit]

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Calculate fast audit summary metrics."""
        with self._lock:
            records = list(self._records)

        total = len(records)
        if total == 0:
            return {
                "total_inspections": 0,
                "approved_count": 0,
                "blocked_count": 0,
                "reviewed_count": 0,
                "average_risk_score": 0.0,
            }

        approved = sum(1 for r in records if r["verdict"] == "APPROVE")
        blocked = sum(1 for r in records if r["verdict"] == "BLOCK")
        reviewed = sum(1 for r in records if r["verdict"] == "REVIEW")
        avg_risk = sum(r["risk_score"] for r in records) / total

        return {
            "total_inspections": total,
            "approved_count": approved,
            "blocked_count": blocked,
            "reviewed_count": reviewed,
            "average_risk_score": round(avg_risk, 3),
        }


@lru_cache()
def get_audit_recorder() -> AuditRecorder:
    """Return singleton audit recorder."""
    return AuditRecorder()
