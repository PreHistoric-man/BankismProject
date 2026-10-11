"""
Request Models for Bankism API
"""
from typing import Optional
from pydantic import BaseModel, Field


class InspectRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=8192, description="Natural language banking request")
    action: Optional[str] = Field("UNSPECIFIED", max_length=64)
    amount: Optional[float] = Field(None, ge=0.0)
    memo: Optional[str] = Field(None, max_length=1024)
    source_account_id: Optional[str] = Field(None, max_length=64)


class TransferPrepareRequest(BaseModel):
    source_account_id: str = Field(..., min_length=3, max_length=64)
    destination_account_id: str = Field(..., min_length=3, max_length=64)
    amount: float = Field(..., gt=0.0, description="Amount in USD dollars")
    memo: Optional[str] = Field("", max_length=1024)
    prompt: Optional[str] = Field("", max_length=4096)


class CanonicalTransactionPayload(BaseModel):
    transaction_nonce: str = Field(..., max_length=64)
    initiator_user_id: str = Field(..., max_length=64)
    source_account_id: str = Field(..., max_length=64)
    destination_account_id: str = Field(..., max_length=64)
    amount_cents: int = Field(..., gt=0)
    currency: str = Field("USD", max_length=8)


class AuthorizationTicketModel(BaseModel):
    ticket_id: str = Field(..., max_length=64)
    fingerprint: str = Field(..., max_length=128)
    history_watermark: str = Field(..., max_length=128)
    canonical_tx: CanonicalTransactionPayload
    expires_at: int
    signature: str = Field(..., max_length=256)


class TransferConfirmRequest(BaseModel):
    ticket: AuthorizationTicketModel


class TransferApproveRequest(BaseModel):
    request_id: str = Field(..., min_length=4, max_length=64)
    approved: bool = Field(True)
    reason: Optional[str] = Field("Approved by Risk Officer", max_length=512)
