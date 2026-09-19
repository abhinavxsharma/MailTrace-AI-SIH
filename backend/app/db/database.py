"""SQLAlchemy 2.x declarative base configuration."""

from typing import Optional
from sqlalchemy import Engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""
    pass


def init_db(engine: Optional[Engine] = None) -> None:
    """Initialize database tables using SQLAlchemy metadata."""
    import backend.app.models  # noqa: F401
    from backend.app.db.session import engine as default_engine

    target_engine = engine or default_engine
    Base.metadata.create_all(bind=target_engine)
