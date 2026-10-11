"""Persistent Tamper-Evident Audit Trail with Cryptographic Hash Chaining."""

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from ..security.masking import mask_banking_dict, mask_sensitive_data

GENESIS_HASH = "0" * 64


def compute_event_hash(
    prev_hash: str,
    event_id: str,
    timestamp: str,
    event_type: str,
    principal_id: str,
    decision: str,
    transaction_id: Optional[str],
    details_json: str,
) -> str:
    """Compute cryptographic hash binding this event to the previous event in the chain."""
    content = (
        f"{prev_hash}|{event_id}|{timestamp}|{event_type}|{principal_id}|"
        f"{decision}|{transaction_id or ''}|{details_json}"
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class TamperEvidentAuditStore:
    """Manages append-only, tamper-evident audit records in SQLite."""

    def record_audit_event(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        principal_id: str,
        decision: str,
        details: Dict[str, Any],
        transaction_id: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> str:
        """Record an audit event, cryptographically chained to the previous record."""
        eid = event_id or f"evt_{uuid.uuid4().hex}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Sanitize and mask any sensitive data before serialization
        masked_details = mask_banking_dict(details)
        details_json = json.dumps(masked_details, sort_keys=True, separators=(",", ":"))

        # Fetch previous hash under active connection/transaction
        cursor = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence_num DESC LIMIT 1;"
        )
        row = cursor.fetchone()
        prev_hash = row["event_hash"] if row else GENESIS_HASH

        event_hash = compute_event_hash(
            prev_hash=prev_hash,
            event_id=eid,
            timestamp=timestamp,
            event_type=event_type,
            principal_id=principal_id,
            decision=decision,
            transaction_id=transaction_id,
            details_json=details_json,
        )

        conn.execute(
            """INSERT INTO audit_events
               (event_id, prev_hash, event_hash, timestamp, event_type, principal_id, decision, transaction_id, details_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            (
                eid,
                prev_hash,
                event_hash,
                timestamp,
                event_type,
                principal_id,
                decision,
                transaction_id,
                details_json,
            ),
        )

        return event_hash

    def verify_chain_integrity(self, conn: sqlite3.Connection) -> Tuple[bool, int, Optional[str]]:
        """Verify unbroken cryptographic integrity of the entire audit chain.

        Returns:
            (is_valid, verified_count, error_description)
        """
        cursor = conn.execute(
            """SELECT sequence_num, event_id, prev_hash, event_hash, timestamp,
                      event_type, principal_id, decision, transaction_id, details_json
               FROM audit_events ORDER BY sequence_num ASC;"""
        )
        rows = cursor.fetchall()
        expected_prev_hash = GENESIS_HASH
        count = 0

        for row in rows:
            seq = row["sequence_num"]
            eid = row["event_id"]
            prev_hash = row["prev_hash"]
            stored_event_hash = row["event_hash"]

            # 1. Verify sequence continuity (no deleted rows or gaps)
            expected_seq = count + 1
            if seq != expected_seq:
                return (
                    False,
                    count,
                    f"Sequence gap detected: expected sequence {expected_seq}, found {seq} (event {eid}). Deletion attack detected.",
                )

            # 2. Verify prev_hash continuity
            if prev_hash != expected_prev_hash:
                return (
                    False,
                    count,
                    f"Chain break at sequence {seq} (event {eid}): prev_hash '{prev_hash}' does not match expected '{expected_prev_hash}'.",
                )

            # 3. Recompute event_hash
            recomputed = compute_event_hash(
                prev_hash=prev_hash,
                event_id=eid,
                timestamp=row["timestamp"],
                event_type=row["event_type"],
                principal_id=row["principal_id"],
                decision=row["decision"],
                transaction_id=row["transaction_id"],
                details_json=row["details_json"],
            )

            if recomputed != stored_event_hash:
                return (
                    False,
                    count,
                    f"Tampering detected at sequence {seq} (event {eid}): stored hash '{stored_event_hash}' != recomputed '{recomputed}'.",
                )

            expected_prev_hash = stored_event_hash
            count += 1

        # 4. Verify against sqlite_sequence to detect tail-truncation attacks
        try:
            seq_row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'audit_events';").fetchone()
            if seq_row and seq_row["seq"] is not None and count > 0:
                max_recorded = int(seq_row["seq"])
                if count != max_recorded:
                    return (
                        False,
                        count,
                        f"Tail truncation detected: audit_events has {count} records, but sqlite_sequence recorded {max_recorded} events (tail records were deleted).",
                    )
        except Exception:
            pass

        return True, count, None

    def get_recent_events(self, conn: sqlite3.Connection, limit: int = 50) -> List[Dict]:
        """Fetch recent audit events."""
        cursor = conn.execute(
            """SELECT sequence_num, event_id, prev_hash, event_hash, timestamp,
                      event_type, principal_id, decision, transaction_id, details_json
               FROM audit_events ORDER BY sequence_num DESC LIMIT ?;""",
            (limit,),
        )
        events = []
        for r in cursor.fetchall():
            events.append({
                "sequence_num": r["sequence_num"],
                "event_id": r["event_id"],
                "prev_hash": r["prev_hash"],
                "event_hash": r["event_hash"],
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "principal_id": r["principal_id"],
                "decision": r["decision"],
                "transaction_id": r["transaction_id"],
                "details": json.loads(r["details_json"]),
            })
        return events


_audit_store = TamperEvidentAuditStore()


def get_tamper_evident_audit_store() -> TamperEvidentAuditStore:
    return _audit_store
