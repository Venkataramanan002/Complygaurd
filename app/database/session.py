"""
Async database engine and session factory.

- Single engine instance created at import time (lazy-safe via module cache).
- ``get_db`` is a FastAPI dependency that yields one session per request.
- ``init_db`` creates tables (dev) or verifies connectivity (prod).
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from database.models import Base  # models stay in place — no churn

logger = logging.getLogger(__name__)

_settings = get_settings()

_connect_args = (
    {"check_same_thread": False}
    if _settings.database_url.startswith("sqlite")
    else {}
)

engine = create_async_engine(
    _settings.database_url,
    echo=False,
    connect_args=_connect_args,
    pool_pre_ping=True,
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    """FastAPI dependency — one session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create tables if they don't exist (idempotent)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialised")
