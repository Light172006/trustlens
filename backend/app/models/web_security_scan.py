"""SQLAlchemy ORM model for standalone Web Security Scans."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, SmallInteger, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class WebSecurityScan(Base):
    """Authoritative technical web security posture assessment record."""

    __tablename__ = "web_security_scans"

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
    target_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        index=True,
    )
    normalized_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    registrable_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    posture: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )
    security_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        index=True,
    )
    deterministic_posture: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )
    ml_predicted_posture: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )
    ml_confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    ml_abstained: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    consensus_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    total_findings: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    critical_count: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    high_count: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    medium_count: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    low_count: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    pass_count: Mapped[int] = mapped_column(
        SmallInteger,
        default=0,
        nullable=False,
    )
    findings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    remediations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    telemetry: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    raw_report: Mapped[dict[str, Any]] = mapped_column(
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
        Index("idx_web_sec_url", "target_url"),
        Index("idx_web_sec_domain", "normalized_domain"),
        Index("idx_web_sec_posture", "posture"),
        Index("idx_web_sec_score", "security_score"),
    )
