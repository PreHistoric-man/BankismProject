"""
Bankism FastAPI Application Entrypoint
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .banking.database import init_db
from .api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and seed initial fictional accounts
    init_db(settings.database_path)
    yield


app = FastAPI(
    title="Bankism - Defensive AI Security Firewall & Secure Simulated Transaction Sandbox",
    description="Application security firewall architecture and secure transaction simulation sandbox governing untrusted natural-language banking requests.",
    version="0.3.0",
    lifespan=lifespan
)

# CORS configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://0.0.0.0:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "system": "Bankism Defensive AI Security Firewall",
        "version": "0.3.0",
        "status": "operational",
        "docs_url": "/docs",
        "health_url": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
