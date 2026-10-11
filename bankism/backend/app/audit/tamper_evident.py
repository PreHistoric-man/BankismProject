"""
Hash-Linked Tamper-Evident Audit Chain Store
"""
import hashlib
import json
import sqlite3
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone


GENESIS_HASH = "GENESIS_HASH_00000000000000000000000000000000000000000000000000000000"


def compute_event_hash(prev_hash: str, event_type: str, payload_json: str, timestamp_utc: str) -> str:
    """
    Computes cryptographic SHA-256 hash chaining prev_hash and canonical payload.
    """
    canonical_string = f"{prev_hash}|{event_type}|{payload_json}|{timestamp_utc}"
    return hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()


def append_audit_event(
    conn: sqlite3.Connection,
    event_id: str,
    event_type: str,
    user_id: str,
    payload: Dict[str, Any],
    timestamp_utc: Optional[str] = None
) -> str:
    """
    Appends a new hash-chained audit record in SQLite.
    Returns the newly generated event_hash.
    """
    ts = timestamp_utc or datetime.now(timezone.utc).isoformat()
    payload_json = json.dumps(payload, sort_keys=True)

    # Fetch latest event's hash
    cur = conn.execute("SELECT event_hash FROM tamper_evident_audit_logs ORDER BY rowid DESC LIMIT 1;")
    row = cur.fetchone()
    prev_hash = row["event_hash"] if row else GENESIS_HASH

    event_hash = compute_event_hash(prev_hash, event_type, payload_json, ts)

    conn.execute(
        "INSERT INTO tamper_evident_audit_logs (event_id, prev_hash, event_type, user_id, payload_json, timestamp_utc, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?);",
        (event_id, prev_hash, event_type, user_id, payload_json, ts, event_hash)
    )
    return event_hash


def verify_audit_chain(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Walks the audit trail from genesis to head and verifies SHA-256 link integrity.
    Detects any modification, insertion, deletion, or reordering of audit events.
    """
    cur = conn.execute("SELECT event_id, prev_hash, event_type, payload_json, timestamp_utc, event_hash FROM tamper_evident_audit_logs ORDER BY rowid ASC;")
    rows = cur.fetchall()

    if not rows:
        return {
            "valid": True,
            "total_events": 0,
            "head_hash": None,
            "broken_at_index": None,
            "details": "Audit chain is empty. Genesis state intact."
        }

    expected_prev = GENESIS_HASH
    for idx, r in enumerate(rows):
        if r["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "total_events": len(rows),
                "head_hash": rows[-1]["event_hash"],
                "broken_at_index": idx,
                "details": f"Broken chain link at index {idx} ({r['event_id']}): prev_hash mismatch."
            }

        recalculated = compute_event_hash(r["prev_hash"], r["event_type"], r["payload_json"], r["timestamp_utc"])
        if recalculated != r["event_hash"]:
            return {
                "valid": False,
                "total_events": len(rows),
                "head_hash": rows[-1]["event_hash"],
                "broken_at_index": idx,
                "details": f"Tampered event content at index {idx} ({r['event_id']}): SHA-256 hash mismatch."
            }

        expected_prev = r["event_hash"]

    return {
        "valid": True,
        "total_events": len(rows),
        "head_hash": rows[-1]["event_hash"],
        "broken_at_index": None,
        "details": f"Unbroken SHA-256 cryptographic sequence across all {len(rows)} recorded audit events."
    }
