"""
Cryptographic Authorization Ticket Issuer and Integrity Verifier
"""
import hmac
import hashlib
import time
import uuid
from typing import Dict, Any, Optional
from ..schemas.requests import CanonicalTransactionPayload, AuthorizationTicketModel
from ..config import settings


def compute_canonical_string(tx: CanonicalTransactionPayload) -> str:
    """
    Constructs deterministic pipeline representation for signing.
    """
    return f"{tx.transaction_nonce}|{tx.initiator_user_id}|{tx.source_account_id}|{tx.destination_account_id}|{tx.amount_cents}|{tx.currency}"


def sign_canonical_tx(tx: CanonicalTransactionPayload, secret: Optional[str] = None) -> str:
    """
    Generates HMAC-SHA256 signature over the canonical transaction payload.
    Fails closed if signing key is missing or shorter than 16 bytes.
    """
    key = secret or settings.hmac_secret
    if not key or len(key) < 16:
        raise ValueError("HMAC signing key is missing or of insufficient length (fail-closed)")
    canonical_data = compute_canonical_string(tx).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical_data, hashlib.sha256).hexdigest()


def create_authorization_ticket(
    tx: CanonicalTransactionPayload,
    fingerprint: str,
    history_watermark: str,
    expiry_seconds: Optional[int] = None,
    secret: Optional[str] = None
) -> AuthorizationTicketModel:
    """
    Issues a signed AuthorizationTicket bound to the transaction parameters and watermark.
    """
    ttl = expiry_seconds or settings.ticket_expiry_seconds
    expires_at = int(time.time()) + ttl
    sig = sign_canonical_tx(tx, secret)
    ticket_id = f"tkt_{uuid.uuid4().hex[:12]}"

    return AuthorizationTicketModel(
        ticket_id=ticket_id,
        fingerprint=fingerprint,
        history_watermark=history_watermark,
        canonical_tx=tx,
        expires_at=expires_at,
        signature=sig
    )


def verify_ticket_integrity(ticket: AuthorizationTicketModel, secret: Optional[str] = None) -> bool:
    """
    Verifies HMAC-SHA256 signature using constant-time comparison.
    Rejects tampered transaction parameters, expired tickets, or invalid formats.
    """
    key = secret or settings.hmac_secret
    if not key or len(key) < 16:
        return False

    now = int(time.time())
    if ticket.expires_at < now:
        return False

    try:
        expected_sig = sign_canonical_tx(ticket.canonical_tx, key)
        # Constant-time comparison
        return hmac.compare_digest(ticket.signature, expected_sig)
    except Exception:
        return False
