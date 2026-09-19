"""Main entry point for MAILTRACE AI FastAPI application."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.core.logging import logger, setup_logging
from backend.app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for startup and shutdown lifecycle hooks."""
    setup_logging()
    logger.info("Initializing database tables...")
    init_db()
    logger.info("Starting %s v%s (debug=%s)", settings.app_name, settings.app_version, settings.debug)
    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS configuration suitable for React frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API router
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    """Root endpoint returning service identity and execution status."""
    return {
        "service": "MAILTRACE AI",
        "status": "running",
    }
