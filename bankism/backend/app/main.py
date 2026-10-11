"""Bankism - Defensive AI Security Firewall FastAPI Application Entry Point.

Phase 1: Modular Security Foundation & Multi-Layer Request Inspection.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router
from .audit.logger import security_logger
from .config import get_settings


from .ledger.db import init_ledger_database


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for startup and shutdown procedures."""
    settings = get_settings()
    security_logger.info(
        f"Starting {settings.app_name} v{settings.app_version} "
        f"[env={settings.environment}, db={settings.database_path}]"
    )
    # Initialize SQLite ledger database and migrations idempotently
    try:
        init_ledger_database(settings.database_path)
        security_logger.info(f"SQLite ledger database initialized at '{settings.database_path}'")
    except Exception as exc:
        security_logger.error(f"Failed to initialize ledger database: {exc}")
        raise

    yield
    security_logger.info(f"Shutting down {settings.app_name}")


def create_app() -> FastAPI:
    """Application factory for the Bankism security firewall."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Defensive AI security firewall for banking applications. "
            "Intercepts untrusted natural-language prompts to detect prompt injections, "
            "jailbreaks, malicious payment metadata, and policy violations."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Configure CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Safe error handling for validation errors (Fail-Closed)
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        security_logger.warning(f"Request validation failure on {request.url.path}: {exc.errors()}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "INVALID_INPUT",
                "message": "The incoming payload failed schema validation.",
                "details": [
                    {"loc": err.get("loc", []), "msg": err.get("msg", ""), "type": err.get("type", "")}
                    for err in exc.errors()
                ],
                "verdict": "BLOCK",
            },
        )

    # Safe error handling for generic unhandled exceptions (No stack trace exposure)
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        security_logger.error(f"Unhandled exception on {request.url.path}: {str(exc)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SECURITY_EXCEPTION",
                "message": "An internal error occurred during security inspection. Operation rejected fail-closed.",
                "verdict": "BLOCK",
            },
        )

    # Mount routes at root level (for /health and /firewall/inspect)
    app.include_router(router)
    # Also mount under /api prefix for API clients
    app.include_router(router, prefix="/api")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
