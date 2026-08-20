"""Persistence. Only saved scans of signed-in users ever reach this module.

ponytail: sync SQLAlchemy, not async. Every query here is a single indexed
read or write behind an already-threadpooled endpoint; async sessions would
add a lifecycle to get wrong for no measured gain. Ceiling: if scan volume
ever makes DB waits the bottleneck, switch the engine and sessionmaker.
"""

import os
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql+psycopg://postgres:scamsathi@db:5432/scamsathi"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class Profile(Base):
    __tablename__ = "profiles"

    # Mirrors the Supabase auth user id; not generated here.
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    display_lang: Mapped[str] = mapped_column(String(8), default="en")
    role: Mapped[str] = mapped_column(String(16), default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True
    )
    input_type: Mapped[str] = mapped_column(String(16))
    band: Mapped[str] = mapped_column(String(24))
    score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    category: Mapped[str] = mapped_column(String(32))
    model_version: Mapped[str] = mapped_column(String(48))
    rule_version: Mapped[str] = mapped_column(String(48))
    # Masked before it ever gets here -- see history.sanitize.
    sanitized_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    indicators: Mapped[list["ScanIndicator"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class ScanIndicator(Base):
    __tablename__ = "indicators"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    code: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(16))

    scan: Mapped[Scan] = relationship(back_populates="indicators")


class Feedback(Base):
    """A user telling us a result was wrong.

    The error signal for Week 9-12 error analysis. Carries no content of its
    own -- it points at a scan the user already chose to save.
    """

    __tablename__ = "feedback"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("profiles.id", ondelete="CASCADE"), index=True
    )
    verdict: Mapped[str] = mapped_column(String(24))
    comment: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    """Administrative accountability trail.

    Records who changed what. Never contains scan content -- `meta` is for
    a status transition or a version identifier, not for user text.
    """

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    actor: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    meta: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


def get_session():
    """FastAPI dependency."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
