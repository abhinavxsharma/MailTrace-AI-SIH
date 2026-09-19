"""Global exception handlers providing consistent API error responses."""

from typing import Any, Dict
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger


def _status_to_code(status_code: int) -> str:
    """Map common HTTP status codes to standardized error code strings."""
    mapping = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        422: "VALIDATION_ERROR",
        500: "INTERNAL_SERVER_ERROR",
        502: "BAD_GATEWAY",
        503: "SERVICE_UNAVAILABLE",
    }
    return mapping.get(status_code, "ERROR")


def register_exception_handlers(app: FastAPI) -> None:
    """Register application-wide exception handlers on the FastAPI app instance."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _status_to_code(exc.status_code)
        message = str(exc.detail) if exc.detail else "An HTTP error occurred"

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": message,
                "error": {
                    "code": code,
                    "message": message,
                },
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        errors = exc.errors()
        message = "Request validation failed"

        return JSONResponse(
            status_code=422,
            content={
                "detail": message,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": message,
                    "details": errors,
                },
            },
        )

    @app.exception_handler(MailTraceException)
    async def mailtrace_exception_handler(
        request: Request,
        exc: MailTraceException,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.message,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                },
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log the full exception and traceback internally with request ID context
        logger.error("Unhandled internal server exception: %s", str(exc), exc_info=True)

        # Return sanitized message to client without exposing database or stack trace internals
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred. Please contact system administrator.",
                },
            },
        )
