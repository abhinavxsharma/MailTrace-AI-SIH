"""Main API router combining all modular endpoint routes."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.api.analysis import router as analysis_router
from backend.app.api.cases import router as cases_router
from backend.app.api.mail_events import router as mail_events_router
from backend.app.api.mailboxes import router as mailboxes_router
from backend.app.core.logging import logger
from backend.app.db.session import get_db

api_router = APIRouter()

# Register modular sub-routers
api_router.include_router(cases_router, prefix="/cases", tags=["cases"])
api_router.include_router(mailboxes_router, prefix="/mailboxes", tags=["mailboxes"])
api_router.include_router(analysis_router, prefix="/analysis", tags=["analysis"])
api_router.include_router(mail_events_router, prefix="/mail", tags=["mail"])


@api_router.get("/health", tags=["system"])
def health_check() -> Dict[str, str]:
    """Liveness probe confirming the application process is running."""
    return {
        "status": "ok",
        "service": "mailtrace-ai",
    }


@api_router.get("/ready", tags=["system"])
def readiness_check(db: Session = Depends(get_db)) -> Any:
    """Readiness probe verifying local backend dependencies and database connectivity."""
    try:
        db.execute(text("SELECT 1")).scalar()
        database_status = "ok"
    except Exception as e:
        logger.error("Readiness check failed - database unavailable: %s", str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "database": "error",
                "error": {
                    "code": "DATABASE_UNAVAILABLE",
                    "message": "Database readiness check failed",
                },
            },
        )

    return {
        "status": "ready",
        "database": database_status,
    }
