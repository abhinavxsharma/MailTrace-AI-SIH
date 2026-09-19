"""Main API router combining all modular endpoint routes."""

from fastapi import APIRouter

from backend.app.api.cases import router as cases_router
from backend.app.api.mailboxes import router as mailboxes_router

api_router = APIRouter()

# Register modular sub-routers
api_router.include_router(cases_router, prefix="/cases", tags=["cases"])
api_router.include_router(mailboxes_router, prefix="/mailboxes", tags=["mailboxes"])


@api_router.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Health check endpoint confirming API operational status."""
    return {
        "status": "ok",
        "service": "mailtrace-ai",
    }
