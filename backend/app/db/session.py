"""Database engine and session management."""

from collections.abc import Generator
from typing import Any
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import settings

# Configure connect_args for SQLite to support multi-threaded FastAPI execution
connect_args: dict[str, Any] = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    echo=settings.debug,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """Provide a transactional database session scope for FastAPI endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
