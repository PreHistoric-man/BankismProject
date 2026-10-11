"""Cryptographic Authorization Ticket binding using standard library HMAC-SHA256."""

import hashlib
import hmac
import json
import time
import uuid
from typing import Optional
from pydantic import BaseModel, Field


class CanonicalTransaction(BaseModel):
    """Canonical representation of a transaction to be authorized."""

    transaction_nonce: str = Field(..., min_length=1, max_length=120)
    initiator_user_id: str = Field(..., min_length=1, max_length=100)
    source_account_id: str = Field(..., min_length=1, max_length=100)
    destination_account_id: str = Field(..., min_length=1, max_length=100)
    amount_cents: int = Field(..., gt=0)
    currency: str = Field(default="USD", min_length=3, max_length=10)
    memo: Optional[str] = Field(None, max_length=500)


class AuthorizationTicket(BaseModel):
    """Unforgeable, short-lived, transaction-bound authorization ticket."""

    ticket_id: str = Field(..., min_length=1, max_length=100)
    fingerprint: str = Field(..., min_length=64, max_length=64)
    canonical_tx: CanonicalTransaction
    created_at: float
    expires_at: float
    signature: str = Field(..., min_length=64, max_length=64)


def compute_canonical_fingerprint(tx: CanonicalTransaction) -> str:
    """Compute deterministic SHA-256 hex digest of sorted canonical transaction JSON."""
    raw_dict = {
        "amount_cents": tx.amount_cents,
        "currency": tx.currency.upper(),
        "destination_account_id": tx.destination_account_id,
        "initiator_user_id": tx.initiator_user_id,
        "memo": tx.memo or "",
        "source_account_id": tx.source_account_id,
        "transaction_nonce": tx.transaction_nonce,
    }
    canonical_str = json.dumps(raw_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def sign_fingerprint(fingerprint: str, expires_at: float, secret_key: str, ticket_id: Optional[str] = None) -> str:
    """Generate HMAC-SHA256 signature binding the ticket, fingerprint and expiration timestamp.

    FAILS CLOSED if secret_key is empty or insufficient (< 16 bytes).
    """
    if not secret_key or len(secret_key.strip()) < 16:
        raise ValueError("CRITICAL SECURITY ERROR: HMAC secret key is missing or insecurely configured.")

    # Cryptographically bind ticket_id when provided, preventing ticket_id substitution replay attacks
    if ticket_id:
        payload = f"{ticket_id}:{fingerprint}:{int(expires_at)}"
    else:
        payload = f"{fingerprint}:{int(expires_at)}"

    mac = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=payload.encode("utf-8"),
        digestmod=hashlib.sha256,
    )
    return mac.hexdigest()


def create_authorization_ticket(
    tx: CanonicalTransaction,
    secret_key: str,
    lifetime_seconds: int = 300,
) -> AuthorizationTicket:
    """Construct and sign a short-lived authorization ticket."""
    now = time.time()
    expires_at = now + lifetime_seconds
    ticket_id = f"tkt_{uuid.uuid4().hex}"
    fingerprint = compute_canonical_fingerprint(tx)
    signature = sign_fingerprint(fingerprint, expires_at, secret_key, ticket_id=ticket_id)

    return AuthorizationTicket(
        ticket_id=ticket_id,
        fingerprint=fingerprint,
        canonical_tx=tx,
        created_at=now,
        expires_at=expires_at,
        signature=signature,
    )


def verify_ticket_integrity(ticket: AuthorizationTicket, secret_key: str) -> None:
    """Verify that the authorization ticket is authentic, unmodified, and unexpired.

    Raises:
        ValueError if signature mismatch, fingerprint mismatch, or ticket expired.
    """
    now = time.time()
    if now > ticket.expires_at:
        raise ValueError(f"Authorization ticket '{ticket.ticket_id}' has expired.")

    # 1. Recompute canonical fingerprint to detect any tampering with transaction parameters
    recomputed_fp = compute_canonical_fingerprint(ticket.canonical_tx)
    if not hmac.compare_digest(recomputed_fp, ticket.fingerprint):
        raise ValueError("Transaction parameter tampering detected: canonical fingerprint mismatch.")

    # 2. Verify HMAC signature binding ticket_id, fingerprint, and expires_at using constant-time comparison
    expected_sig = sign_fingerprint(ticket.fingerprint, ticket.expires_at, secret_key, ticket_id=ticket.ticket_id)
    if not hmac.compare_digest(expected_sig, ticket.signature):
        # Fallback check for legacy tickets without ticket_id binding
        legacy_sig = sign_fingerprint(ticket.fingerprint, ticket.expires_at, secret_key, ticket_id=None)
        if not hmac.compare_digest(legacy_sig, ticket.signature):
            raise ValueError("Invalid ticket signature: authorization cryptographic verification failed.")
