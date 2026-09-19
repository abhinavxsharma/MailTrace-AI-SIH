"""SQLAlchemy 2.x declarative base configuration."""

from typing import Optional
from sqlalchemy import Engine, inspect, text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""
    pass


def init_db(engine: Optional[Engine] = None) -> None:
    """Initialize database tables using SQLAlchemy metadata and handle safe column updates."""
    import backend.app.models  # noqa: F401
    from backend.app.db.session import engine as default_engine

    target_engine = engine or default_engine
    Base.metadata.create_all(bind=target_engine)

    # Safe evolution for local SQLite development
    with target_engine.connect() as conn:
        inspector = inspect(conn)
        if "analyses" in inspector.get_table_names():
            columns = {col["name"] for col in inspector.get_columns("analyses")}
            for new_col in ["forensics", "authentication", "ml", "intelligence", "correlation", "risk"]:
                if new_col not in columns:
                    conn.execute(text(f"ALTER TABLE analyses ADD COLUMN {new_col} JSON;"))
                    conn.commit()
