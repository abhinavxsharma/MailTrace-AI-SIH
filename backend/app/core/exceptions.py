"""Domain exceptions for MAILTRACE AI."""

from typing import Optional


class MailTraceException(Exception):
    """Base application exception."""

    def __init__(
        self,
        message: str,
        code: str = "APPLICATION_ERROR",
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class ResourceNotFoundError(MailTraceException):
    """Exception raised when a requested entity does not exist."""

    def __init__(self, message: str = "Resource not found", code: str = "NOT_FOUND") -> None:
        super().__init__(message=message, code=code, status_code=404)


class ResourceConflictError(MailTraceException):
    """Exception raised when a resource conflict or duplicate occurs."""

    def __init__(self, message: str = "Resource conflict", code: str = "CONFLICT") -> None:
        super().__init__(message=message, code=code, status_code=409)


class ValidationException(MailTraceException):
    """Exception raised when domain validation fails."""

    def __init__(self, message: str = "Validation failed", code: str = "VALIDATION_ERROR") -> None:
        super().__init__(message=message, code=code, status_code=422)


class DatabaseUnavailableError(MailTraceException):
    """Exception raised when database readiness check fails."""

    def __init__(
        self,
        message: str = "Database readiness check failed",
        code: str = "DATABASE_UNAVAILABLE",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)
