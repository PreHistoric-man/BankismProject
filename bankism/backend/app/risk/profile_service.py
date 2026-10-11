"""Profile service enforcing principal and account ownership isolation."""

import sqlite3
from typing import Optional, Tuple, List
from fastapi import HTTPException, status
from ..profiling.engine import get_behavioral_risk_engine
from ..schemas.auth import AuthenticatedPrincipal
from ..schemas.profiling import (
    HistoricalStats,
    RiskAssessment,
    UserProfileResponse,
)
from ..security.auth import authorize_account_ownership


class ProfileService:
    """Trusted server-side service for accessing user behavioral profiles and assessments."""

    def get_authenticated_profile(
        self,
        conn: sqlite3.Connection,
        principal: AuthenticatedPrincipal,
        account_id: Optional[str] = None,
    ) -> UserProfileResponse:
        """Return behavioral profile scoped strictly to the authenticated principal."""
        if account_id:
            authorize_account_ownership(principal, account_id)
        engine = get_behavioral_risk_engine()
        return engine.get_user_profile(
            conn=conn,
            user_id=principal.user_id,
            username=principal.username,
            account_id=account_id,
        )

    def get_authenticated_stats(
        self,
        conn: sqlite3.Connection,
        principal: AuthenticatedPrincipal,
        account_id: Optional[str] = None,
        days_window: int = 30,
    ) -> HistoricalStats:
        """Return historical stats scoped strictly to the authenticated principal."""
        if account_id:
            authorize_account_ownership(principal, account_id)
        engine = get_behavioral_risk_engine()
        return engine.get_historical_stats(
            conn=conn,
            user_id=principal.user_id,
            account_id=account_id,
            days_window=days_window,
        )

    def list_authenticated_assessments(
        self,
        conn: sqlite3.Connection,
        principal: AuthenticatedPrincipal,
        account_id: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[RiskAssessment], int]:
        """List persisted assessments scoped strictly to the authenticated principal."""
        if account_id:
            authorize_account_ownership(principal, account_id)
        engine = get_behavioral_risk_engine()
        return engine.get_user_assessments(
            conn=conn,
            user_id=principal.user_id,
            account_id=account_id,
            limit=limit,
            offset=offset,
        )

    def get_authenticated_assessment_by_id(
        self,
        conn: sqlite3.Connection,
        principal: AuthenticatedPrincipal,
        assessment_id: str,
    ) -> RiskAssessment:
        """Retrieve a specific assessment after verifying principal ownership."""
        engine = get_behavioral_risk_engine()
        assessment = engine.get_assessment_by_id(conn=conn, assessment_id=assessment_id)
        if not assessment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "ASSESSMENT_NOT_FOUND", "message": f"Assessment '{assessment_id}' was not found."},
            )
        if assessment.user_id != principal.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "ASSESSMENT_ACCESS_DENIED",
                    "message": (
                        f"Principal '{principal.username}' ({principal.user_id}) is not authorized to view "
                        f"assessment '{assessment_id}'."
                    ),
                },
            )
        return assessment


_profile_service = ProfileService()


def get_profile_service() -> ProfileService:
    return _profile_service
