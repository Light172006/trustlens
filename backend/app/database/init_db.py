"""Database initialization and initial schema setup."""

import asyncio

from app.core.logging import logger
from app.database.base import Base
from app.database.session import async_engine


async def init_db() -> None:
    """Initialize database tables using SQLAlchemy metadata."""
    logger.info("Initializing database schema...")
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized successfully.")


if __name__ == "__main__":
    asyncio.run(init_db())
