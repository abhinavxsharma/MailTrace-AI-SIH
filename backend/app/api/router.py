"""Main API router combining all modular endpoint routes."""

from fastapi import APIRouter

from backend.app.api.analysis import router as analysis_router
from backend.app.api.cases import router as cases_router
from backend.app.api.mail_events import router as mail_events_router
from backend.app.api.mailboxes import router as mailboxes_router

api_router = APIRouter()

# Register modular sub-routers
api_router.include_router(cases_router, prefix="/cases", tags=["cases"])
api_router.include_router(mailboxes_router, prefix="/mailboxes", tags=["mailboxes"])
api_router.include_router(analysis_router, prefix="/analysis", tags=["analysis"])
api_router.include_router(mail_events_router, prefix="/mail", tags=["mail"])


@api_router.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Health check endpoint confirming API operational status."""
    return {
        "status": "ok",
        "service": "mailtrace-ai",
    }
