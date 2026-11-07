"""Domain service for community threat report submission, voting, and moderation."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import EntityNotFoundException, TrustLensException
from app.core.logging import logger
from app.models.audit_log import AuditEvent
from app.models.report import CommunityReport, CommunityVote
from app.models.scan import Scan
from app.scanners.url_validator import validate_and_canonicalize_url
from app.schemas.report import (
    AdminReportItem,
    CommunityReportCreateRequest,
    CommunityReportDetailData,
    CommunityReportDetailResponse,
    CommunityReportResponse,
    CommunityReportSubmitResponse,
    CommunityVoteCounts,
    CommunityVoteRequest,
    CommunityVoteResponse,
    ModeratedReportData,
    ModerationDecisionRequest,
    ModerationDecisionResponse,
    PublicCommunityReportItem,
    UserCommunityReportItem,
)


class ReportService:
    """Manages collaborative community threat reports, crowd votes, and moderation workflows."""

    async def submit_report(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        payload: CommunityReportCreateRequest,
        allow_private_for_tests: bool = False,
    ) -> CommunityReportSubmitResponse:
        """Submit a suspicious URL for community threat review with 30-day deduplication."""
        # 1. Canonicalize URL and verify SSRF protection
        target = validate_and_canonicalize_url(
            raw_url=payload.url,
            allow_private_for_tests=allow_private_for_tests,
        )

        # 2. If scan_id provided, verify ownership
        if payload.scan_id:
            scan_stmt = select(Scan).where(Scan.id == payload.scan_id)
            scan_result = await db.execute(scan_stmt)
            scan = scan_result.scalar_one_or_none()
            if not scan or scan.user_id != user_id:
                raise TrustLensException(
                    message="Associated scan not found or not owned by user.",
                    code="FORBIDDEN",
                    status_code=403,
                )

        # 3. 30-Day Duplicate Submission Check for same reporter and canonical URL
        cutoff = datetime.now(UTC) - timedelta(days=30)
        dedup_stmt = (
            select(CommunityReport)
            .where(
                CommunityReport.reporter_user_id == user_id,
                CommunityReport.canonical_url == target.canonical_url,
                CommunityReport.status.in_(["pending", "confirmed"]),
                CommunityReport.created_at >= cutoff,
            )
            .order_by(CommunityReport.created_at.desc())
        )
        dedup_result = await db.execute(dedup_stmt)
        existing = dedup_result.scalars().first()
        if existing:
            logger.info(
                f"Deduplicated community report for {target.canonical_url} to existing report {existing.id}"
            )
            return CommunityReportSubmitResponse(
                report=CommunityReportResponse.model_validate(existing),
                duplicate_submission=True,
            )

        # 4. Create fresh report in pending state
        report = CommunityReport(
            id=uuid.uuid4(),
            reporter_user_id=user_id,
            scan_id=payload.scan_id,
            original_url=target.original_url,
            canonical_url=target.canonical_url,
            host=target.host,
            category=payload.category,
            claimed_verdict=payload.claimed_verdict,
            evidence_text=payload.evidence_text,
            status="pending",
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)

        return CommunityReportSubmitResponse(
            report=CommunityReportResponse.model_validate(report),
            duplicate_submission=False,
        )

    async def list_public_reports(
        self,
        db: AsyncSession,
        category: str | None = None,
        host: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[PublicCommunityReportItem], int]:
        """List confirmed reports publicly with aggregated confirmation and false-positive counts."""
        base_query = select(CommunityReport).where(CommunityReport.status == "confirmed")
        count_query = select(func.count(CommunityReport.id)).where(
            CommunityReport.status == "confirmed"
        )

        if category:
            base_query = base_query.where(CommunityReport.category == category)
            count_query = count_query.where(CommunityReport.category == category)
        if host:
            base_query = base_query.where(CommunityReport.host.ilike(f"%{host}%"))
            count_query = count_query.where(CommunityReport.host.ilike(f"%{host}%"))

        total = (await db.execute(count_query)).scalar() or 0

        offset = (page - 1) * page_size
        query = (
            base_query.options(selectinload(CommunityReport.votes))
            .order_by(CommunityReport.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        reports = (await db.execute(query)).scalars().all()

        items = []
        for r in reports:
            conf_count = sum(1 for v in r.votes if v.vote == "confirm")
            fp_count = sum(1 for v in r.votes if v.vote == "false_positive")
            items.append(
                PublicCommunityReportItem(
                    id=r.id,
                    canonical_url=r.canonical_url,
                    host=r.host,
                    category=r.category,
                    claimed_verdict=r.claimed_verdict,
                    status=r.status,
                    evidence_summary=r.evidence_text[:200]
                    + ("..." if len(r.evidence_text) > 200 else ""),
                    confirmation_count=conf_count,
                    false_positive_count=fp_count,
                    created_at=r.created_at,
                    moderated_at=r.moderated_at,
                )
            )

        return items, total

    async def list_user_reports(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[UserCommunityReportItem], int]:
        """List personal report submissions for the current user across all moderation states."""
        base_query = select(CommunityReport).where(CommunityReport.reporter_user_id == user_id)
        count_query = select(func.count(CommunityReport.id)).where(
            CommunityReport.reporter_user_id == user_id
        )

        if status:
            base_query = base_query.where(CommunityReport.status == status)
            count_query = count_query.where(CommunityReport.status == status)

        total = (await db.execute(count_query)).scalar() or 0

        offset = (page - 1) * page_size
        query = (
            base_query.order_by(CommunityReport.created_at.desc()).offset(offset).limit(page_size)
        )
        reports = (await db.execute(query)).scalars().all()

        items = [UserCommunityReportItem.model_validate(r) for r in reports]
        return items, total

    async def get_report_detail(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        current_user_id: uuid.UUID | None = None,
        current_user_role: str | None = None,
    ) -> CommunityReportDetailResponse:
        """Fetch report details respecting visibility rules."""
        stmt = (
            select(CommunityReport)
            .where(CommunityReport.id == report_id)
            .options(selectinload(CommunityReport.votes))
        )
        report = (await db.execute(stmt)).scalar_one_or_none()

        if not report:
            raise EntityNotFoundException(message="Community report not found.", field="report_id")

        # Access check: public can only view confirmed reports;
        # owner can view own report in any state;
        # moderator/admin can view any report.
        is_owner = current_user_id is not None and report.reporter_user_id == current_user_id
        is_moderator = current_user_role in ("moderator", "admin")
        if report.status != "confirmed" and not is_owner and not is_moderator:
            raise EntityNotFoundException(message="Community report not found.", field="report_id")

        conf_count = sum(1 for v in report.votes if v.vote == "confirm")
        fp_count = sum(1 for v in report.votes if v.vote == "false_positive")

        return CommunityReportDetailResponse(
            report=CommunityReportDetailData(
                id=report.id,
                canonical_url=report.canonical_url,
                host=report.host,
                category=report.category,
                claimed_verdict=report.claimed_verdict,
                status=report.status,
                evidence_summary=report.evidence_text,
                confirmation_count=conf_count,
                false_positive_count=fp_count,
                moderation_reason=report.moderation_reason,
                created_at=report.created_at,
                moderated_at=report.moderated_at,
            )
        )

    async def cast_vote(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        report_id: uuid.UUID,
        payload: CommunityVoteRequest,
    ) -> CommunityVoteResponse:
        """Cast or update a user vote on a confirmed community report."""
        stmt = (
            select(CommunityReport)
            .where(CommunityReport.id == report_id)
            .options(selectinload(CommunityReport.votes))
        )
        report = (await db.execute(stmt)).scalar_one_or_none()

        if not report:
            raise EntityNotFoundException(message="Community report not found.", field="report_id")

        # Rule: User cannot vote on their own report
        if report.reporter_user_id == user_id:
            raise TrustLensException(
                message="You cannot vote on your own community report.",
                code="OWN_REPORT_VOTE_NOT_ALLOWED",
                status_code=403,
            )

        # Rule: Only confirmed reports can receive community votes
        if report.status != "confirmed":
            raise TrustLensException(
                message="Only confirmed community reports are eligible for community voting.",
                code="REPORT_NOT_VOTABLE",
                status_code=409,
            )

        vote_stmt = select(CommunityVote).where(
            CommunityVote.report_id == report_id,
            CommunityVote.user_id == user_id,
        )
        existing_vote = (await db.execute(vote_stmt)).scalar_one_or_none()

        updated = False
        if existing_vote:
            if existing_vote.vote != payload.vote:
                existing_vote.vote = payload.vote
                updated = True
            db.add(existing_vote)
        else:
            new_vote = CommunityVote(
                id=uuid.uuid4(),
                report_id=report_id,
                user_id=user_id,
                vote=payload.vote,
            )
            db.add(new_vote)

        await db.commit()

        # Re-tally votes
        tally_stmt = (
            select(CommunityVote.vote, func.count(CommunityVote.id))
            .where(CommunityVote.report_id == report_id)
            .group_by(CommunityVote.vote)
        )
        tally_rows = (await db.execute(tally_stmt)).all()

        counts = {"confirm": 0, "false_positive": 0}
        for v_type, cnt in tally_rows:
            if v_type in counts:
                counts[v_type] = cnt

        return CommunityVoteResponse(
            report_id=report_id,
            vote=payload.vote,
            updated=updated,
            counts=CommunityVoteCounts(**counts),
        )

    async def list_admin_reports(
        self,
        db: AsyncSession,
        status: str = "pending",
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[AdminReportItem], int]:
        """List reports in moderator triage queue."""
        base_query = select(CommunityReport).where(CommunityReport.status == status)
        count_query = select(func.count(CommunityReport.id)).where(CommunityReport.status == status)

        total = (await db.execute(count_query)).scalar() or 0

        offset = (page - 1) * page_size
        query = (
            base_query.options(selectinload(CommunityReport.votes))
            .order_by(CommunityReport.created_at.asc())
            .offset(offset)
            .limit(page_size)
        )
        reports = (await db.execute(query)).scalars().all()

        items = []
        for r in reports:
            conf_count = sum(1 for v in r.votes if v.vote == "confirm")
            fp_count = sum(1 for v in r.votes if v.vote == "false_positive")
            items.append(
                AdminReportItem(
                    id=r.id,
                    canonical_url=r.canonical_url,
                    host=r.host,
                    category=r.category,
                    claimed_verdict=r.claimed_verdict,
                    status=r.status,
                    evidence_text=r.evidence_text,
                    reporter_id=r.reporter_user_id,
                    confirmation_count=conf_count,
                    false_positive_count=fp_count,
                    created_at=r.created_at,
                )
            )

        return items, total

    async def moderate_report(
        self,
        db: AsyncSession,
        moderator_id: uuid.UUID,
        report_id: uuid.UUID,
        payload: ModerationDecisionRequest,
    ) -> ModerationDecisionResponse:
        """Atomically moderate a pending report and record an auditable decision event."""
        stmt = select(CommunityReport).where(CommunityReport.id == report_id)
        report = (await db.execute(stmt)).scalar_one_or_none()

        if not report:
            raise EntityNotFoundException(message="Community report not found.", field="report_id")

        if report.status != "pending":
            raise TrustLensException(
                message=f"Report cannot be moderated because its status is already '{report.status}'.",
                code="STATE_CONFLICT",
                status_code=409,
            )

        now = datetime.now(UTC)
        report.status = payload.decision
        report.moderator_user_id = moderator_id
        report.moderation_reason = payload.reason
        report.moderated_at = now

        # Create audit event atomically
        audit_event = AuditEvent(
            id=uuid.uuid4(),
            actor_user_id=moderator_id,
            action="report.moderated",
            target_type="community_report",
            target_id=report.id,
            reason=payload.reason,
            metadata_={
                "decision": payload.decision,
                "category": report.category,
                "canonical_url": report.canonical_url,
            },
            created_at=now,
        )
        db.add(audit_event)
        await db.commit()
        await db.refresh(report)

        return ModerationDecisionResponse(
            report=ModeratedReportData(
                id=report.id,
                status=report.status,
                moderator_user_id=moderator_id,
                moderation_reason=payload.reason,
                moderated_at=now,
            ),
            audit_event_id=audit_event.id,
        )


report_service = ReportService()
