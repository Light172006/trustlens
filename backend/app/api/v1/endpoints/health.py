"""Health probe endpoints for liveness, readiness, database, and Redis checks."""

from fastapi import APIRouter, Response, status

from app.config import settings
from app.database.session import check_database_health, check_redis_health
from app.schemas.common import DependencyHealthResponse, HealthCheckResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Application Health Probe",
    description="Returns base application health, version, and operating environment.",
)
async def get_health() -> HealthCheckResponse:
    """Check base application status."""
    return HealthCheckResponse(
        status="alive",
        service="trustlens-api",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
    )


@router.get(
    "/health/database",
    response_model=DependencyHealthResponse,
    summary="Database Health Probe",
    description="Probes PostgreSQL database connectivity without disclosing internal credentials.",
    responses={
        status.HTTP_200_OK: {"model": DependencyHealthResponse, "description": "Database healthy"},
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": DependencyHealthResponse,
            "description": "Database degraded or offline",
        },
    },
)
async def get_database_health(response: Response) -> DependencyHealthResponse:
    """Check database availability."""
    is_healthy, latency_ms, msg = await check_database_health()
    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return DependencyHealthResponse(
            status="unavailable",
            dependency="database",
            latency_ms=latency_ms,
            message=msg,
        )

    return DependencyHealthResponse(
        status="healthy",
        dependency="database",
        latency_ms=latency_ms,
        message=msg,
    )


@router.get(
    "/health/redis",
    response_model=DependencyHealthResponse,
    summary="Redis Cache & Queue Health Probe",
    description="Probes Redis connectivity and latency without disclosing internal credentials.",
    responses={
        status.HTTP_200_OK: {"model": DependencyHealthResponse, "description": "Redis healthy"},
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": DependencyHealthResponse,
            "description": "Redis degraded or offline",
        },
    },
)
async def get_redis_health(response: Response) -> DependencyHealthResponse:
    """Check Redis availability."""
    is_healthy, latency_ms, msg = await check_redis_health()
    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return DependencyHealthResponse(
            status="unavailable",
            dependency="redis",
            latency_ms=latency_ms,
            message=msg,
        )

    return DependencyHealthResponse(
        status="healthy",
        dependency="redis",
        latency_ms=latency_ms,
        message=msg,
    )


@router.get(
    "/health/live",
    response_model=HealthCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Kubernetes / Container Liveness Probe",
)
async def get_liveness() -> HealthCheckResponse:
    """Non-blocking liveness probe."""
    return HealthCheckResponse(
        status="alive",
        service="trustlens-api",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
    )


@router.get(
    "/health/ready",
    summary="Container Readiness Probe",
    description="Verifies both Database and Redis connectivity before routing traffic.",
)
async def get_readiness(response: Response) -> dict:
    """Composite readiness probe for container orchestrators."""
    db_healthy, db_lat, db_msg = await check_database_health()
    redis_healthy, redis_lat, redis_msg = await check_redis_health()

    is_ready = db_healthy and redis_healthy
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "degraded",
        "checks": {
            "database": "ok" if db_healthy else "failed",
            "redis": "ok" if redis_healthy else "failed",
        },
        "latencies_ms": {
            "database": db_lat,
            "redis": redis_lat,
        },
    }
