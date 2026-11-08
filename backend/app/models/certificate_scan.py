"""SQLAlchemy ORM model for standalone Certificate Scans."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, SmallInteger, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class CertificateScan(Base):
    """Authoritative certificate assessment record."""

    __tablename__ = "certificate_scans"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    certificate_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    trust_score: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    checks_completed: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    policy_evaluation: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    ml_advisory: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    assessment_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Optional relationship to user
    user = relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        Index("idx_cert_scans_sha256", "certificate_sha256"),
        Index("idx_cert_scans_hostname", "target_hostname"),
        Index("idx_cert_scans_verdict", "verdict"),
    )
