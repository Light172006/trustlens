"""Centralized application exception definitions and FastAPI exception handlers."""

import uuid
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import logger


class TrustLensException(Exception):
    """Base exception for all TrustLens domain exceptions."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or []


class EntityNotFoundException(TrustLensException):
    """Raised when a requested resource does not exist."""

    def __init__(
        self, message: str = "The requested resource was not found.", field: str | None = None
    ) -> None:
        details = [{"field": field, "issue": "Resource not found"}] if field else []
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class AuthenticationError(TrustLensException):
    """Raised when authentication fails or is missing."""

    def __init__(self, message: str = "A valid authenticated session is required.") -> None:
        super().__init__(
            message=message,
            code="AUTHENTICATION_REQUIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AuthorizationError(TrustLensException):
    """Raised when an authenticated user lacks permissions."""

    def __init__(self, message: str = "You do not have permission to perform this action.") -> None:
        super().__init__(
            message=message,
            code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ConflictError(TrustLensException):
    """Raised when a resource state conflict occurs (e.g. duplicate or invalid state transition)."""

    def __init__(self, message: str, field: str | None = None, issue: str | None = None) -> None:
        details = [{"field": field, "issue": issue}] if field and issue else []
        super().__init__(
            message=message,
            code="STATE_CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )


class TargetNotPublicException(TrustLensException):
    """Raised when a submitted URL resolves to a private, loopback, or non-public address."""

    def __init__(
        self,
        message: str = "The submitted hostname does not resolve exclusively to publicly routable IP addresses.",
        issue: str = "Private, loopback, link-local, reserved, and metadata destinations are not scanned.",
    ) -> None:
        super().__init__(
            message=message,
            code="TARGET_NOT_PUBLIC",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=[{"field": "url", "issue": issue}],
        )


class SSRFSecurityViolation(TrustLensException):
    """Raised when an SSRF attempt is detected during DNS, connection, or redirect phases."""

    def __init__(
        self, message: str = "Connection to non-public network destination was blocked."
    ) -> None:
        super().__init__(
            message=message,
            code="SSRF_PROTECTION_BLOCKED",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=[{"field": "url", "issue": "Destination rejected by egress security policy"}],
        )


class RateLimitExceededException(TrustLensException):
    """Raised when user or IP rate limit is exceeded."""

    def __init__(self, retry_after_seconds: int = 60) -> None:
        super().__init__(
            message="The request limit has been reached. Try again after the indicated interval.",
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=[{"field": "retry_after_seconds", "issue": str(retry_after_seconds)}],
        )


class ExternalServiceError(TrustLensException):
    """Raised when an external threat provider or dependency fails."""

    def __init__(self, message: str, provider: str) -> None:
        super().__init__(
            message=message,
            code="DEPENDENCY_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=[{"field": provider, "issue": "Service unavailable"}],
        )


def _get_request_id(request: Request) -> str:
    """Extract or generate request correlation ID."""
    return getattr(request.state, "request_id", f"req_{uuid.uuid4().hex[:16]}")


def create_error_response(
    code: str,
    message: str,
    status_code: int,
    request_id: str,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    """Format and return standard API error JSON response."""
    payload = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "details": details or [],
        }
    }
    return JSONResponse(status_code=status_code, content=payload)


def register_exception_handlers(app: FastAPI) -> None:
    """Register all centralized exception handlers on the FastAPI application."""

    @app.exception_handler(TrustLensException)
    async def handle_trustlens_exception(request: Request, exc: TrustLensException) -> JSONResponse:
        request_id = _get_request_id(request)
        logger.warning(
            f"TrustLensException: {exc.code} - {exc.message} | req_id: {request_id}",
            extra={"request_id": request_id},
        )
        return create_error_response(
            code=exc.code,
            message=exc.message,
            status_code=exc.status_code,
            request_id=request_id,
            details=exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = _get_request_id(request)
        formatted_details = []
        for error in exc.errors():
            loc = error.get("loc", ())
            field_name = str(loc[-1]) if loc else "body"
            formatted_details.append(
                {
                    "field": field_name,
                    "issue": error.get("msg", "Invalid value"),
                }
            )

        return create_error_response(
            code="VALIDATION_ERROR",
            message="The request could not be processed because one or more fields are invalid.",
            status_code=status.HTTP_400_BAD_REQUEST,
            request_id=request_id,
            details=formatted_details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = _get_request_id(request)
        code_mapping = {
            400: "BAD_REQUEST",
            401: "AUTHENTICATION_REQUIRED",
            403: "FORBIDDEN",
            404: "RESOURCE_NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            429: "RATE_LIMIT_EXCEEDED",
            500: "INTERNAL_ERROR",
            503: "DEPENDENCY_UNAVAILABLE",
        }
        code = code_mapping.get(exc.status_code, "ERROR")
        return create_error_response(
            code=code,
            message=(exc.detail),
            status_code=exc.status_code,
            request_id=request_id,
        )

    @app.exception_handler(Exception)
    async def handle_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        request_id = _get_request_id(request)
        logger.error(
            f"Unhandled exception on {request.method} {request.url.path}: {exc} | req_id: {request_id}",
            exc_info=True,
            extra={"request_id": request_id},
        )
        return create_error_response(
            code="INTERNAL_ERROR",
            message="TrustLens could not complete the request. Use the request ID when contacting support.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id,
        )
