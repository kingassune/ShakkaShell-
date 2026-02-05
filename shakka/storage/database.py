"""Database connection and session management."""

from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from shakka.storage.models import Base
from shakka.config import ShakkaConfig


# Global engine and session maker
_engine = None
_SessionLocal = None


def get_database_url(config: Optional[ShakkaConfig] = None) -> str:
    """Get database URL from configuration.
    
    Args:
        config: Optional ShakkaConfig instance
        
    Returns:
        SQLite database URL string
    """
    if config is None:
        config = ShakkaConfig()
    
    db_path = config.db_path
    
    # Ensure directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    return f"sqlite:///{db_path}"


def init_database(config: Optional[ShakkaConfig] = None) -> None:
    """Initialize database and create all tables.
    
    Args:
        config: Optional ShakkaConfig instance
    """
    global _engine, _SessionLocal
    
    database_url = get_database_url(config)
    
    _engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},  # Needed for SQLite
        echo=False
    )
    
    # Create all tables
    Base.metadata.create_all(bind=_engine)
    
    # Create session maker
    _SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=_engine
    )


def get_db_session(config: Optional[ShakkaConfig] = None) -> Session:
    """Get a database session.
    
    Args:
        config: Optional ShakkaConfig instance
        
    Returns:
        SQLAlchemy Session instance
    """
    global _engine, _SessionLocal
    
    # Initialize if not already done
    if _engine is None or _SessionLocal is None:
        init_database(config)
    
    return _SessionLocal()


def close_database() -> None:
    """Close database connection."""
    global _engine, _SessionLocal
    
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionLocal = None
