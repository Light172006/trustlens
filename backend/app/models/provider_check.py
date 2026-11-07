"""SQLAlchemy ORM model for threat intelligence provider check records."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ProviderCheck(Base):
    """Execution record of an external or local threat intelligence provider lookup."""

    __tablename__ = "provider_checks"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    result_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    matched: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationship
    scan = relationship("Scan", back_populates="provider_checks")

    __table_args__ = (Index("ix_provider_checks_scan_provider", "scan_id", "provider"),)
