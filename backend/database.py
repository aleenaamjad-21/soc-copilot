"""
database.py
Sets up the SQLite database connection and session.
Switch SQLALCHEMY_DATABASE_URL to a MySQL/Postgres URL later if you outgrow SQLite —
nothing else in the app needs to change since we go through SQLAlchemy.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite:///./soc_copilot.db"

# check_same_thread=False is needed only for SQLite when used with FastAPI's
# multi-threaded request handling
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session per request and closes it after."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
