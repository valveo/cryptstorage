"""
database.py - SQLAlchemy setup with MariaDB/MySQL compatibility.

Uses MariaDB in production, SQLite for development.
Switch via DATABASE_URL environment variable.
"""

import config
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# No silent default: a forgotten DATABASE_URL used to fall back to a local SQLite
# file. For development set it explicitly, e.g. sqlite:///./cryptdb.sqlite
# MariaDB example: mysql+pymysql://user:password@host:3306/cryptdb
DATABASE_URL = config.require("DATABASE_URL")

# MariaDB requires different connect_args than SQLite
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,        # Reconnect on stale connections
        pool_recycle=3600,         # Recycle connections every hour
        pool_size=10,
        max_overflow=20,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist."""
    import models  # registers the models with Base.metadata
    _ = models.User
    Base.metadata.create_all(bind=engine)
