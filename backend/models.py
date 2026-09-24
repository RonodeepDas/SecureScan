"""
models.py — SQLAlchemy ORM models for SecureScan.

All sensitive fields are stored AES-256-GCM encrypted (via crypto_utils).
The DB file (securescan.db) is written to the /backend directory and is
excluded from version control via .gitignore.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

DATABASE_URL = "sqlite:///./securescan.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite + FastAPI
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency: yield a DB session, then close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


class PasswordHistory(Base):
    """
    Stores password-check metadata ONLY.
    The password itself is NEVER stored — not even hashed.

    Encrypted fields: score_enc, crack_time_enc
    """
    __tablename__ = "password_history"

    id = Column(Integer, primary_key=True, index=True)
    # AES-256-GCM encrypted JSON/string values
    score_enc = Column(String, nullable=False)         # encrypted int (0-4)
    crack_time_enc = Column(String, nullable=False)    # encrypted human-readable string
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class ScanHistory(Base):
    """
    Stores port scan results.

    Encrypted fields: target_enc, open_ports_enc, banners_enc
    """
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    target_enc = Column(String, nullable=False)       # encrypted hostname/IP
    open_ports_enc = Column(String, nullable=False)   # encrypted JSON list of ints
    banners_enc = Column(String, nullable=False)      # encrypted JSON dict {port: banner}
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
