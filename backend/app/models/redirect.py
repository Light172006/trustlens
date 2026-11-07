"""SQLAlchemy ORM model for redirect hops traversed during a scan."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, SmallInteger, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ScanRedirect(Base):
    """Specific redirect hop traversed during an HTTP website scan."""

    __tablename__ = "scan_redirects"

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
    hop_index: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
    )
    source_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    destination_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    http_status: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
    )
    resolved_host: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )
    resolved_ips: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    tls_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationship
    scan = relationship("Scan", back_populates="redirects")

    __table_args__ = (Index("ix_scan_redirects_hop", "scan_id", "hop_index"),)
