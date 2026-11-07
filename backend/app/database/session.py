"""Database engine, async session factory, Redis client, and health probes."""

import asyncio
import time
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings
from app.core.logging import logger

# Configure async engine with dialect-appropriate pooling
engine_kwargs: dict = {
    "echo": settings.DEBUG,
    "pool_pre_ping": True,
}
if "sqlite" in settings.DATABASE_URL:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    if ":memory:" in settings.DATABASE_URL:
        from sqlalchemy.pool import StaticPool

        engine_kwargs["poolclass"] = StaticPool
else:
    engine_kwargs.update(
        {
            "pool_size": 10,
            "max_overflow": 20,
            "pool_recycle": 3600,
        }
    )

async_engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    **engine_kwargs,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Global Redis client instance
_redis_client: aioredis.Redis | None = None


def get_redis_client() -> aioredis.Redis:
    """Retrieve or create singleton async Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=3.0,
            socket_connect_timeout=3.0,
        )
    return _redis_client


async def close_redis_client() -> None:
    """Close active Redis client connection pool."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for yielding an isolated async SQLAlchemy session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_database_health() -> tuple[bool, float, str]:
    """Check database connectivity and response latency without leaking credentials."""
    start_time = time.monotonic()
    try:

        async def _ping_db() -> None:
            async with async_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

        await asyncio.wait_for(_ping_db(), timeout=1.5)
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        return True, latency_ms, "Database connection operational"
    except Exception as exc:
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        logger.warning(f"Database health check failed: {type(exc).__name__}")
        return False, latency_ms, "Database connection failed or unavailable"


async def check_redis_health() -> tuple[bool, float, str]:
    """Check Redis connectivity and ping latency without leaking credentials."""
    start_time = time.monotonic()
    try:

        async def _ping_redis() -> bool:
            client = get_redis_client()
            return await client.ping()

        pong = await asyncio.wait_for(_ping_redis(), timeout=1.5)
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        if pong:
            return True, latency_ms, "Redis connection operational"
        return False, latency_ms, "Unexpected ping response from Redis"
    except Exception as exc:
        latency_ms = round((time.monotonic() - start_time) * 1000, 2)
        logger.warning(f"Redis health check failed: {type(exc).__name__}")
        return False, latency_ms, "Redis connection failed or unavailable"
