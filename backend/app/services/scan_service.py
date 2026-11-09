"""Domain service for website scan creation, deduplication, report retrieval, and findings."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.core.exceptions import EntityNotFoundException
from app.core.logging import logger
from app.core.permissions import verify_resource_ownership
from app.models.certificate import Certificate
from app.models.finding import Finding
from app.models.scan import Scan
from app.scanners.url_validator import validate_and_canonicalize_url
from app.schemas.scan import (
    CertificateDetailResponse,
    CertificateResponseItem,
    CoverageResponse,
    FindingResponseItem,
    ProviderCheckResponseItem,
    RedirectHopResponseItem,
    ScanCreateRequest,
    ScanDetailResponse,
    ScanRecordResponse,
    ScanSummaryItem,
)
from app.workers.scan_tasks import execute_scan_task, run_scan_pipeline


class ScanService:
    """Orchestrates scan submission, active deduplication, and owner-scoped report querying."""

    async def create_scan(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        payload: ScanCreateRequest,
        allow_private_for_tests: bool = False,
    ) -> tuple[Scan, bool]:
        """Submit a URL for asynchronous scanning with active deduplication within 60s."""
        # 1. Validate and canonicalize target URL
        target = validate_and_canonicalize_url(
            raw_url=payload.url,
            treat_as_sensitive=payload.treat_as_sensitive,
            allow_private_for_tests=allow_private_for_tests,
        )

        # 2. Check for active duplicate scan for same user within last 60 seconds
        cutoff_time = datetime.now(UTC) - timedelta(seconds=60)
        dedup_stmt = (
            select(Scan)
            .where(
                Scan.user_id == user_id,
                Scan.canonical_url == target.canonical_url,
                Scan.status.in_(["queued", "running"]),
                Scan.created_at >= cutoff_time,
            )
            .order_by(Scan.created_at.desc())
        )
        dedup_result = await db.execute(dedup_stmt)
        existing_scan = dedup_result.scalars().first()
        if existing_scan:
            logger.info(
                f"Deduplicated scan request for {target.canonical_url} to existing scan {existing_scan.id}"
            )
            return existing_scan, True

        # 3. Create fresh scan record with QUEUED status
        new_scan = Scan(
            id=uuid.uuid4(),
            user_id=user_id,
            original_url=target.original_url,
            canonical_url=target.canonical_url,
            host=target.host,
            scheme=target.scheme,
            is_sensitive=target.is_sensitive,
            status="queued",
            verdict="INCONCLUSIVE",
            scoring_version="trustlens-1.0",
            checks_completed=0,
            created_at=datetime.now(UTC),
        )
        db.add(new_scan)
        await db.commit()
        await db.refresh(new_scan)

        # 4. Schedule background scan execution
        enqueued = False
        if getattr(settings, "CELERY_ENABLED", False):
            try:
                execute_scan_task.delay(scan_id=str(new_scan.id))
                enqueued = True
            except Exception as exc:
                logger.warning(
                    f"Could not enqueue Celery task directly (broker offline?): {exc}. "
                    "Falling back to in-process background worker."
                )

        if not enqueued and settings.ENVIRONMENT != "test":
            # Standalone / in-process execution (ideal for local development without Redis/Celery)
            logger.info(f"Dispatching in-process background scan pipeline for scan {new_scan.id}")
            asyncio.create_task(
                run_scan_pipeline(
                    scan_id=new_scan.id, allow_private_for_tests=allow_private_for_tests
                )
            )

        return new_scan, False

    async def get_scan_detail(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        user_role: str,
        scan_id: uuid.UUID,
    ) -> ScanDetailResponse:
        """Fetch comprehensive scan report with owner isolation."""
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.provider_checks),
                selectinload(Scan.redirects),
            )
        )
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()

        if not scan:
            raise EntityNotFoundException(
                message="The requested scan was not found.", field="scan_id"
            )

        # Owner authorization check
        verify_resource_ownership(scan.user_id, user_id, user_role)

        # Compute coverage
        if scan.is_sensitive:
            threat_coverage = "partial"
        elif scan.status in ("succeeded", "partial"):
            threat_coverage = "complete"
        else:
            threat_coverage = "unavailable"

        web_coverage = "complete" if scan.checks_completed >= 2 else "unavailable"
        cert_coverage = (
            "complete"
            if scan.scheme == "https" and scan.checks_completed >= 3
            else ("not_applicable" if scan.scheme != "https" else "unavailable")
        )

        coverage = CoverageResponse(
            threat_intel=threat_coverage,
            web_security=web_coverage,
            certificate=cert_coverage,
            community="complete",
        )

        provider_items = [
            ProviderCheckResponseItem(
                provider=p.provider,
                result_status=p.result_status,
                matched=p.matched,
                checked_at=p.checked_at,
            )
            for p in scan.provider_checks
        ]

        redirect_items = [
            RedirectHopResponseItem(
                hop_index=r.hop_index,
                source_url=r.source_url,
                destination_url=r.destination_url,
                http_status=r.http_status,
                resolved_host=r.resolved_host,
                resolved_ips=r.resolved_ips,
                tls_verified=r.tls_verified,
            )
            for r in scan.redirects
        ]

        return ScanDetailResponse(
            scan=ScanRecordResponse.model_validate(scan),
            coverage=coverage,
            provider_checks=provider_items,
            redirects=redirect_items,
        )

    async def list_scans(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
        status_filter: str | None = None,
        verdict_filter: str | None = None,
    ) -> tuple[list[ScanSummaryItem], int]:
        """Retrieve paginated scan history scoped strictly to the current user."""
        query = select(Scan).where(Scan.user_id == user_id)

        if status_filter:
            query = query.where(Scan.status == status_filter.lower())
        if verdict_filter:
            query = query.where(Scan.verdict == verdict_filter.upper())

        # Total count
        count_query = select(func.count()).select_from(query.subquery())
        total_res = await db.execute(count_query)
        total = total_res.scalar_one()

        # Paginated items
        offset = (page - 1) * page_size
        paginated_query = query.order_by(Scan.created_at.desc()).offset(offset).limit(page_size)
        items_res = await db.execute(paginated_query)
        scans = items_res.scalars().all()

        items = [ScanSummaryItem.model_validate(s) for s in scans]
        return items, total

    async def get_scan_findings(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        user_role: str,
        scan_id: uuid.UUID,
    ) -> list[FindingResponseItem]:
        """Retrieve findings associated with an owned scan."""
        # Check scan ownership first
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise EntityNotFoundException(message="Scan not found.", field="scan_id")
        verify_resource_ownership(scan.user_id, user_id, user_role)

        stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.points.desc())
        result = await db.execute(stmt)
        findings = result.scalars().all()

        return [FindingResponseItem.model_validate(f) for f in findings]

    async def get_scan_certificate(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        user_role: str,
        scan_id: uuid.UUID,
    ) -> CertificateDetailResponse:
        """Retrieve leaf certificate details for an owned scan."""
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise EntityNotFoundException(message="Scan not found.", field="scan_id")
        verify_resource_ownership(scan.user_id, user_id, user_role)

        if scan.scheme != "https":
            return CertificateDetailResponse(
                scan_id=scan_id,
                available=False,
                reason="target_not_https",
            )

        stmt = select(Certificate).where(Certificate.scan_id == scan_id)
        result = await db.execute(stmt)
        cert = result.scalar_one_or_none()

        if not cert:
            return CertificateDetailResponse(
                scan_id=scan_id,
                available=False,
                reason="no_parseable_leaf_certificate",
            )

        return CertificateDetailResponse(
            scan_id=scan_id,
            available=True,
            certificate=CertificateResponseItem.model_validate(cert),
        )

    async def delete_scan(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        user_role: str,
        scan_id: uuid.UUID,
    ) -> None:
        """Delete an owned scan record and cascading child records."""
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise EntityNotFoundException(message="Scan not found.", field="scan_id")
        verify_resource_ownership(scan.user_id, user_id, user_role)

        await db.delete(scan)
        await db.commit()


scan_service = ScanService()
