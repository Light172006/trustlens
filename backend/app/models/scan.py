"""SQLAlchemy ORM model for website security scan records."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, SmallInteger, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin


class Scan(Base, TimestampMixin):
    """Website security scan entity."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    canonical_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        index=True,
    )
    host: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
    )
    scheme: Mapped[str] = mapped_column(
        String(5),
        nullable=False,
    )
    is_sensitive: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="queued",
        nullable=False,
        index=True,
    )
    verdict: Mapped[str] = mapped_column(
        String(20),
        default="INCONCLUSIVE",
        nullable=False,
        index=True,
    )
    risk_score: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
    )
    scoring_version: Mapped[str] = mapped_column(
        String(32),
        default="trustlens-1.0",
        nullable=False,
    )
    checks_completed: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    failure_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    failure_message: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Relationships
    user = relationship("User", backref="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    redirects = relationship(
        "ScanRedirect",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanRedirect.hop_index",
    )
    provider_checks = relationship(
        "ProviderCheck", back_populates="scan", cascade="all, delete-orphan"
    )
    certificate = relationship(
        "Certificate", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_user_status_created", "user_id", "status", "created_at"),
        Index("ix_scans_dedup", "user_id", "canonical_url", "created_at"),
    )
