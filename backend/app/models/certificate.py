"""SQLAlchemy ORM models for TLS leaf certificate records and Certificate Analyzer scans."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, SmallInteger, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class Certificate(Base):
    """Leaf certificate snapshot recorded during TLS inspection."""

    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    host: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(
        SmallInteger,
        default=443,
        nullable=False,
    )
    leaf_fingerprint_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    subject_cn: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    san_dns: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )
    issuer: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    serial_number: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    not_before: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    not_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    signature_algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    public_key_algorithm: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
    )
    public_key_bits: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
    )
    chain_valid: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    hostname_match: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    sct_present: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Rich Certificate Analyzer Intelligence Fields
    trust_score: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
        default=100,
    )
    verdict: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        default="TRUSTED",
    )
    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        default=1.0,
    )
    checks_completed: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
        default=6,
    )
    policy_evaluation: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    ml_advisory: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    recommendations: Mapped[list[str] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    assessment_payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )

    # Relationship
    scan = relationship("Scan", back_populates="certificate")


class CertificateScan(Base):
    """Direct certificate inspection audit record per BACKEND_INTEGRATION.md specification."""

    __tablename__ = "certificate_scans"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
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
