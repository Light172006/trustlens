"""TrustLens FastAPI Application Entrypoint."""

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.router import api_v1_router
from app.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import logger, setup_logging
from app.database.session import async_engine, close_redis_client


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """Assigns or propagates X-Request-ID and injects baseline security headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Resolve or generate X-Request-ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id or len(request_id) > 64:
            request_id = f"req_{uuid.uuid4().hex}"
        request.state.request_id = request_id

        response = await call_next(request)

        # Attach request correlation ID and security headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for graceful startup and shutdown."""
    setup_logging(
        is_production=settings.is_production, log_level="DEBUG" if settings.DEBUG else "INFO"
    )
    logger.info(
        f"Starting {settings.PROJECT_NAME} v{settings.VERSION} in {settings.ENVIRONMENT} mode..."
    )

    yield

    logger.info("Gracefully shutting down TrustLens application...")
    await close_redis_client()
    await async_engine.dispose()
    logger.info("TrustLens shutdown complete.")


def create_application() -> FastAPI:
    """Application factory for TrustLens backend."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=(
            "TrustLens is a unified website security assessment platform providing "
            "automated threat detection, passive web security analysis, SSL/TLS certificate "
            "validation, and collaborative community intelligence."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Register centralized exception handlers
    register_exception_handlers(app)

    # Middleware stack
    app.add_middleware(RequestCorrelationMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    # Mount Root-level Health Probes (for load balancers & orchestrators)
    app.include_router(health_router, prefix="", tags=["Health"])

    # Mount API v1 Routes
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_application()
