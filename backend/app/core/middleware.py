"""HTTP middleware for request correlation tracing and security headers."""

import re
import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.app.core.logging import logger, request_id_ctx

REQUEST_ID_HEADER = "X-Request-ID"
SAFE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware ensuring every request has a validated correlation request ID."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming_id = request.headers.get(REQUEST_ID_HEADER)

        # Validate incoming request ID format; generate secure ID if missing or unsafe
        if incoming_id and SAFE_REQUEST_ID_REGEX.match(incoming_id.strip()):
            request_id = incoming_id.strip()
        else:
            request_id = f"req_{uuid.uuid4().hex[:16]}"

        # Bind to request state and async context
        request.state.request_id = request_id
        token = request_id_ctx.set(request_id)

        try:
            try:
                response = await call_next(request)
            except Exception as exc:
                logger.error("Unhandled internal server exception: %s", str(exc), exc_info=True)
                response = JSONResponse(
                    status_code=500,
                    content={
                        "detail": "Internal server error",
                        "error": {
                            "code": "INTERNAL_SERVER_ERROR",
                            "message": "An unexpected error occurred. Please contact system administrator.",
                        },
                    },
                )
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            request_id_ctx.reset(token)
