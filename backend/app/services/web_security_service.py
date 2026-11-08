"""Service for managing web security posture assessments and persistence."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EntityNotFoundException, ValidationError
from app.integrations.web_security_client import web_security_client
from app.models.web_security_scan import WebSecurityScan
from app.schemas.web_security import (
    ConsensusItem,
    FindingsSummaryItem,
    MLPredictionItem,
    RemediationItem,
    SecurityFindingItem,
    WebSecurityAnalyzeRequest,
    WebSecurityAssessmentResponse,
    WebSecurityScanListResponse,
    WebSecurityScanSummaryItem,
)

logger = logging.getLogger("trustlens.services.web_security")


class WebSecurityService:
    """Service layer for technical web security analysis and assessment queries."""

    async def analyze_url(
        self,
        db: AsyncSession,
        request: WebSecurityAnalyzeRequest,
        user_id: uuid.UUID | None = None,
    ) -> WebSecurityAssessmentResponse:
        """Execute web security analysis on target URL, persist report, and return assessment."""
        target_url = request.url.strip()
        if not target_url:
            raise ValidationError("Target URL must not be empty.")

        # Invoke the WebSecurityAnalyzer engine asynchronously
        try:
            report = await web_security_client.analyze_async(target_url)
        except Exception as exc:
            logger.exception(f"WebSecurityAnalyzer execution failed: {exc}")
            raise ValidationError(f"Web security analysis failed: {exc}")

        now = datetime.now(UTC)
        scan_id = uuid.uuid4()

        # Serialize findings and remediations for DB persistence
        findings_data = [
            f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in report.findings
        ]
        remediations_data = [
            r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in report.remediations
        ]
        raw_report_dump = (
            report.model_dump(mode="json") if hasattr(report, "model_dump") else dict(report)
        )

        db_record = WebSecurityScan(
            id=scan_id,
            user_id=user_id,
            target_url=report.target_url,
            normalized_domain=report.normalized_domain,
            registrable_domain=report.registrable_domain,
            posture=report.posture,
            security_score=float(report.security_score),
            deterministic_posture=report.deterministic_posture,
            ml_predicted_posture=report.ml_prediction.predicted_posture
            if report.ml_prediction
            else None,
            ml_confidence=float(report.ml_prediction.confidence) if report.ml_prediction else None,
            ml_abstained=report.ml_prediction.abstained if report.ml_prediction else False,
            consensus_status=report.consensus.status if report.consensus else "UNKNOWN",
            total_findings=report.findings_summary.total_findings
            if report.findings_summary
            else len(findings_data),
            critical_count=report.findings_summary.critical_count if report.findings_summary else 0,
            high_count=report.findings_summary.high_count if report.findings_summary else 0,
            medium_count=report.findings_summary.medium_count if report.findings_summary else 0,
            low_count=report.findings_summary.low_count if report.findings_summary else 0,
            pass_count=report.findings_summary.pass_count if report.findings_summary else 0,
            findings=findings_data,
            remediations=remediations_data,
            telemetry=report.telemetry,
            raw_report=raw_report_dump,
            scanned_at=now,
        )

        db.add(db_record)
        await db.commit()
        await db.refresh(db_record)

        summary_text = report.to_summary_text() if hasattr(report, "to_summary_text") else None

        return WebSecurityAssessmentResponse(
            id=db_record.id,
            target_url=report.target_url,
            normalized_domain=report.normalized_domain,
            registrable_domain=report.registrable_domain,
            scan_timestamp=report.scan_timestamp,
            scanner_version=report.scanner_version,
            posture=report.posture,
            security_score=float(report.security_score),
            deterministic_posture=report.deterministic_posture,
            ml_prediction=MLPredictionItem(
                available=report.ml_prediction.available,
                predicted_posture=report.ml_prediction.predicted_posture,
                probabilities=report.ml_prediction.probabilities,
                confidence=report.ml_prediction.confidence,
                margin=report.ml_prediction.margin,
                abstained=report.ml_prediction.abstained,
                abstention_reason=report.ml_prediction.abstention_reason,
                model_name=report.ml_prediction.model_name,
                model_version=report.ml_prediction.model_version,
            ),
            consensus=ConsensusItem(
                status=report.consensus.status,
                discrepancy_explanation=report.consensus.discrepancy_explanation,
            ),
            findings_summary=FindingsSummaryItem(
                total_findings=report.findings_summary.total_findings,
                critical_count=report.findings_summary.critical_count,
                high_count=report.findings_summary.high_count,
                medium_count=report.findings_summary.medium_count,
                low_count=report.findings_summary.low_count,
                pass_count=report.findings_summary.pass_count,
                affected_categories=report.findings_summary.affected_categories,
            ),
            findings=[
                SecurityFindingItem(
                    finding_id=f.get("finding_id", ""),
                    category=f.get("category", ""),
                    name=f.get("name", ""),
                    severity=f.get("severity", ""),
                    status=f.get("status", ""),
                    evidence=f.get("evidence", ""),
                    detection_method=f.get("detection_method", "DETERMINISTIC_RULE_INSPECTION"),
                    confidence=float(f.get("confidence", 1.0)),
                    guidance=f.get("guidance"),
                    recommendation=f.get("recommendation"),
                )
                for f in findings_data
            ],
            remediations=[
                RemediationItem(
                    finding_id=r.get("finding_id", ""),
                    severity=r.get("severity", ""),
                    category=r.get("category", ""),
                    recommendation=r.get("recommendation", ""),
                )
                for r in remediations_data
            ],
            telemetry=report.telemetry,
            summary_text=summary_text,
            scanned_at=now,
        )

    async def get_scan_by_id(
        self,
        db: AsyncSession,
        scan_id: uuid.UUID,
    ) -> WebSecurityAssessmentResponse:
        """Retrieve previously executed web security assessment by ID."""
        stmt = select(WebSecurityScan).where(WebSecurityScan.id == scan_id)
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()

        if not record:
            raise EntityNotFoundException(f"Web security scan with ID {scan_id} not found.")

        raw = record.raw_report
        ml_data = raw.get("ml_prediction", {})
        consensus_data = raw.get("consensus", {})
        summary_data = raw.get("findings_summary", {})

        return WebSecurityAssessmentResponse(
            id=record.id,
            target_url=record.target_url,
            normalized_domain=record.normalized_domain,
            registrable_domain=record.registrable_domain,
            scan_timestamp=raw.get("scan_timestamp", record.scanned_at.isoformat()),
            scanner_version=raw.get("scanner_version", "1.0.0"),
            posture=record.posture,
            security_score=record.security_score,
            deterministic_posture=record.deterministic_posture,
            ml_prediction=MLPredictionItem(
                available=ml_data.get("available", False),
                predicted_posture=ml_data.get(
                    "predicted_posture", record.ml_predicted_posture or "UNKNOWN"
                ),
                probabilities=ml_data.get("probabilities", {}),
                confidence=ml_data.get("confidence", record.ml_confidence or 0.0),
                margin=ml_data.get("margin"),
                abstained=ml_data.get("abstained", record.ml_abstained),
                abstention_reason=ml_data.get("abstention_reason"),
                model_name=ml_data.get("model_name"),
                model_version=ml_data.get("model_version"),
            ),
            consensus=ConsensusItem(
                status=consensus_data.get("status", record.consensus_status),
                discrepancy_explanation=consensus_data.get("discrepancy_explanation"),
            ),
            findings_summary=FindingsSummaryItem(
                total_findings=summary_data.get("total_findings", record.total_findings),
                critical_count=summary_data.get("critical_count", record.critical_count),
                high_count=summary_data.get("high_count", record.high_count),
                medium_count=summary_data.get("medium_count", record.medium_count),
                low_count=summary_data.get("low_count", record.low_count),
                pass_count=summary_data.get("pass_count", record.pass_count),
                affected_categories=summary_data.get("affected_categories", []),
            ),
            findings=[SecurityFindingItem(**f) for f in record.findings],
            remediations=[RemediationItem(**r) for r in record.remediations],
            telemetry=record.telemetry or {},
            summary_text=None,
            scanned_at=record.scanned_at,
        )

    async def list_scans(
        self,
        db: AsyncSession,
        user_id: uuid.UUID | None = None,
        domain: str | None = None,
        posture: str | None = None,
        page: int = 1,
        limit: int = 20,
    ) -> WebSecurityScanListResponse:
        """Retrieve paginated collection of web security scans with optional filtering."""
        query = select(WebSecurityScan)

        if user_id is not None:
            query = query.where(WebSecurityScan.user_id == user_id)
        if domain:
            query = query.where(WebSecurityScan.normalized_domain.ilike(f"%{domain.strip()}%"))
        if posture:
            query = query.where(WebSecurityScan.posture == posture.strip().upper())

        # Count total matching
        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_stmt)).scalar() or 0

        # Apply ordering and pagination
        offset = (page - 1) * limit
        paginated_query = (
            query.order_by(desc(WebSecurityScan.scanned_at)).offset(offset).limit(limit)
        )
        result = await db.execute(paginated_query)
        records = result.scalars().all()

        items = [
            WebSecurityScanSummaryItem(
                id=rec.id,
                target_url=rec.target_url,
                normalized_domain=rec.normalized_domain,
                posture=rec.posture,
                security_score=rec.security_score,
                total_findings=rec.total_findings,
                critical_count=rec.critical_count,
                high_count=rec.high_count,
                scanned_at=rec.scanned_at,
            )
            for rec in records
        ]

        return WebSecurityScanListResponse(
            items=items,
            total=total,
            page=page,
            limit=limit,
        )


web_security_service = WebSecurityService()
