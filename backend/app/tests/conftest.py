"""Pytest configuration and common testing fixtures."""

import os
from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# Set test environment
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["DATABASE_SYNC_URL"] = "sqlite:///:memory:"

import app.database.session as session_module
import app.models  # Register all ORM models on Base.metadata
import app.workers.scan_tasks as scan_tasks_module
from app.config import settings
from app.database.base import Base
from app.database.session import get_db
from app.main import app

# Test SQLite in-memory engine with StaticPool so in-memory DB persists across connections
test_async_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestAsyncSessionLocal = async_sessionmaker(
    bind=test_async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Rebind sessionmakers in application modules for test isolation
session_module.AsyncSessionLocal = TestAsyncSessionLocal
scan_tasks_module.AsyncSessionLocal = TestAsyncSessionLocal


@pytest.fixture(scope="session", autouse=True)
def override_settings() -> None:
    """Ensure test settings are active."""
    settings.ENVIRONMENT = "test"
    settings.DEBUG = True


@pytest.fixture(autouse=True)
async def init_test_database() -> AsyncGenerator[None, None]:
    """Ensure tables are created for tests."""
    async with test_async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a fresh database session for a test."""
    async with TestAsyncSessionLocal() as session:
        yield session


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Async test client with database dependency override."""

    async def _get_test_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _get_test_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client

    app.dependency_overrides.clear()
