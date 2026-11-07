"""Domain service for aggregated user dashboard metrics and scan summaries."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import CommunityReport
from app.models.scan import Scan
from app.schemas.dashboard import (
    DashboardRecentScanItem,
    DashboardSummaryMetrics,
    DashboardSummaryResponse,
)


class DashboardService:
    """Computes user-scoped security scan metrics, verdict distributions, and recent activity."""

    async def get_dashboard_summary(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
    ) -> DashboardSummaryResponse:
        """Fetch summary statistics and 10 most recent scans for the authenticated user."""
        now = datetime.now(UTC)
        thirty_days_ago = now - timedelta(days=30)

        # 1. Total scans count
        total_stmt = select(func.count(Scan.id)).where(Scan.user_id == user_id)
        total_scans = (await db.execute(total_stmt)).scalar() or 0

        # 2. Scans in last 30 days
        recent_30_stmt = select(func.count(Scan.id)).where(
            Scan.user_id == user_id,
            Scan.created_at >= thirty_days_ago,
        )
        scans_30_days = (await db.execute(recent_30_stmt)).scalar() or 0

        # 3. Active scans (queued or running)
        active_stmt = select(func.count(Scan.id)).where(
            Scan.user_id == user_id,
            Scan.status.in_(["queued", "running"]),
        )
        active_scans = (await db.execute(active_stmt)).scalar() or 0

        # 4. Verdict breakdown
        verdict_stmt = (
            select(Scan.verdict, func.count(Scan.id))
            .where(Scan.user_id == user_id)
            .group_by(Scan.verdict)
        )
        verdict_rows = (await db.execute(verdict_stmt)).all()
        verdict_counts = {
            "SAFE": 0,
            "SUSPICIOUS": 0,
            "MALICIOUS": 0,
            "INCONCLUSIVE": 0,
        }
        for v_name, count in verdict_rows:
            if v_name in verdict_counts:
                verdict_counts[v_name] = count

        # 5. Pending community reports submitted by this user
        pending_reports_stmt = select(func.count(CommunityReport.id)).where(
            CommunityReport.reporter_user_id == user_id,
            CommunityReport.status == "pending",
        )
        pending_reports = (await db.execute(pending_reports_stmt)).scalar() or 0

        # 6. Up to 10 most recent scans ordered by creation time descending
        recent_scans_stmt = (
            select(Scan).where(Scan.user_id == user_id).order_by(Scan.created_at.desc()).limit(10)
        )
        recent_scans_res = (await db.execute(recent_scans_stmt)).scalars().all()
        recent_items = [DashboardRecentScanItem.model_validate(scan) for scan in recent_scans_res]

        metrics = DashboardSummaryMetrics(
            total_scans=total_scans,
            scans_last_30_days=scans_30_days,
            verdict_counts=verdict_counts,
            active_scans=active_scans,
            pending_community_reports=pending_reports,
        )

        return DashboardSummaryResponse(
            summary=metrics,
            recent_scans=recent_items,
        )


dashboard_service = DashboardService()
