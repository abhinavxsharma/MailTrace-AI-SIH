"""Main API router combining all modular endpoint routes."""

from fastapi import APIRouter

api_router = APIRouter()


@api_router.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Health check endpoint confirming API operational status."""
    return {
        "status": "ok",
        "service": "mailtrace-ai",
    }
