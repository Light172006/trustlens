"""SQLAlchemy ORM models for collaborative threat intelligence community reports and votes."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin


class CommunityReport(Base, TimestampMixin):
    """Community threat intelligence report submitted by a user for moderation."""

    __tablename__ = "community_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    reporter_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
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
    category: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    claimed_verdict: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    evidence_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="pending",
        nullable=False,
        index=True,
    )
    moderator_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    moderation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    moderated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    reporter = relationship("User", foreign_keys=[reporter_user_id])
    moderator = relationship("User", foreign_keys=[moderator_user_id])
    scan = relationship("Scan", foreign_keys=[scan_id])
    votes: Mapped[list["CommunityVote"]] = relationship(
        "CommunityVote",
        back_populates="report",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        CheckConstraint(
            "category IN ('phishing', 'malware', 'scam', 'credential_harvesting', 'unsolicited_bulk', 'other')",
            name="check_report_category",
        ),
        CheckConstraint(
            "claimed_verdict IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS')",
            name="check_report_claimed_verdict",
        ),
        CheckConstraint(
            "status IN ('pending', 'confirmed', 'rejected', 'duplicate')",
            name="check_report_status",
        ),
        Index("ix_community_reports_reporter_created", "reporter_user_id", "created_at"),
        Index("ix_community_reports_canonical_status", "canonical_url", "status"),
    )

    def __repr__(self) -> str:
        return f"<CommunityReport id={self.id} host={self.host} status={self.status}>"


class CommunityVote(Base, TimestampMixin):
    """User vote endorsing or disputing a community report."""

    __tablename__ = "community_votes"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("community_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vote: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    # Relationship
    report: Mapped["CommunityReport"] = relationship("CommunityReport", back_populates="votes")
    user = relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        UniqueConstraint("report_id", "user_id", name="uq_community_votes_report_user"),
        CheckConstraint(
            "vote IN ('confirm', 'false_positive')",
            name="check_community_vote_type",
        ),
    )

    def __repr__(self) -> str:
        return f"<CommunityVote report_id={self.report_id} user_id={self.user_id} vote={self.vote}>"
