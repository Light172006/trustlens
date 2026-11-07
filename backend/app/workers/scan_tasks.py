"""Celery worker task for executing asynchronous website security scans."""

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.database.session import AsyncSessionLocal
from app.integrations.intelligence_client import intelligence_client
from app.models.certificate import Certificate
from app.models.finding import Finding
from app.models.provider_check import ProviderCheck
from app.models.redirect import ScanRedirect
from app.models.scan import Scan
from app.scanners.dns_scanner import dns_scanner
from app.scanners.http_scanner import http_scanner
from app.scanners.tls_scanner import tls_scanner
from app.scanners.url_validator import validate_and_canonicalize_url
from app.workers.celery_app import celery_app
from shared.contracts.ai_contracts import (
    CommunityIntelligenceObservation,
    DomainIntelligence,
    HttpObservation,
    ScanEvidence,
    ThreatIntelligenceObservation,
    TlsObservation,
)

logger = logging.getLogger("trustlens.workers.scan")


async def run_scan_pipeline(scan_id: str, allow_private_for_tests: bool = False) -> None:
    """Execute complete website scanning and threat intelligence assessment pipeline."""
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == uuid.UUID(scan_id))
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()

        if not scan:
            logger.error(f"Scan record {scan_id} not found.")
            return

        scan.status = "running"
        scan.started_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(scan)

        is_failed = False
        failure_code: str | None = None
        failure_msg: str | None = None

        http_result = None
        tls_result = None
        dns_result = None

        try:
            # 1. Validate target
            validated_target = validate_and_canonicalize_url(
                raw_url=scan.canonical_url,
                treat_as_sensitive=scan.is_sensitive,
                allow_private_for_tests=allow_private_for_tests,
            )

            # 2. Run DNS Scanner
            dns_result = dns_scanner.scan(host=validated_target.host)

            # 3. Run Safe HTTP Scanner with manual redirects
            http_result = await http_scanner.scan(
                target=validated_target,
                allow_private_for_tests=allow_private_for_tests,
            )

            # 4. Run TLS Scanner if target uses HTTPS
            if scan.scheme == "https":
                pinned_ip = (
                    validated_target.resolved_ips[0] if validated_target.resolved_ips else None
                )
                tls_result = tls_scanner.scan(
                    host=validated_target.host,
                    port=validated_target.port,
                    pinned_ip=pinned_ip,
                )

        except Exception as exc:
            logger.exception(f"Scanner pipeline error for scan {scan_id}: {exc}")
            is_failed = True
            failure_code = "SCAN_WORKER_ERROR"
            failure_msg = str(exc)

        # 5. Build Threat Intelligence telemetry
        # If sensitive scan, skip external URLhaus lookup
        urlhaus_status = "skipped_sensitive_url" if scan.is_sensitive else "no_match"
        openphish_status = "no_match"

        threat_obs = ThreatIntelligenceObservation(
            phishing_match=False,
            malware_match=False,
            openphish_status=openphish_status,
            urlhaus_status=urlhaus_status,
            details={
                "urlhaus_match": False,
                "url_status": "offline" if scan.is_sensitive else None,
            },
        )

        # 6. Map observations to ScanEvidence
        http_obs = HttpObservation(
            status_code=http_result.status_code if http_result else None,
            redirect_count=http_result.redirects.redirect_count if http_result else 0,
            final_url=http_result.final_url if http_result else scan.canonical_url,
            security_headers=http_result.security_headers.raw_headers if http_result else {},
            response_time_ms=http_result.response_time_ms if http_result else None,
            content_type=http_result.content_type if http_result else None,
            content_length=http_result.content_length if http_result else None,
        )

        tls_obs = TlsObservation(
            valid=tls_result.valid if tls_result else False,
            hostname_match=tls_result.hostname_match if tls_result else False,
            chain_valid=tls_result.chain_valid if tls_result else False,
            days_until_expiry=tls_result.certificate.days_until_expiry
            if (tls_result and tls_result.certificate)
            else None,
            issuer=tls_result.certificate.issuer
            if (tls_result and tls_result.certificate)
            else None,
            subject=tls_result.certificate.subject_cn
            if (tls_result and tls_result.certificate)
            else None,
            san_dns=tls_result.certificate.san_dns
            if (tls_result and tls_result.certificate)
            else [],
            protocol_version=tls_result.protocol_version if tls_result else None,
            cipher_suite=tls_result.cipher_suite if tls_result else None,
            error_message=tls_result.error_message if tls_result else None,
        )

        evidence = ScanEvidence(
            scan_id=str(scan.id),
            url=scan.canonical_url,
            domain=scan.host,
            is_sensitive=scan.is_sensitive,
            http=http_obs,
            tls=tls_obs,
            domain_intelligence=DomainIntelligence(
                nameservers=dns_result.ns_records if dns_result else []
            ),
            threat_intelligence=threat_obs,
            community_intelligence=CommunityIntelligenceObservation(),
        )

        # 7. Invoke AI Intelligence Engine
        assessment = intelligence_client.analyze(
            evidence=evidence,
            query_providers=False,
            is_scan_failed=is_failed,
        )

        # 8. Persist assessment and relational evidence
        now = datetime.now(UTC)
        scan.verdict = assessment.verdict.value
        scan.risk_score = assessment.risk_score
        scan.scoring_version = assessment.scoring_version
        scan.checks_completed = 4
        scan.completed_at = now
        scan.failure_code = failure_code
        scan.failure_message = failure_msg
        scan.status = (
            "failed"
            if is_failed
            else ("succeeded" if assessment.verdict != "INCONCLUSIVE" else "partial")
        )

        # Persist findings
        for f in assessment.findings:
            finding_record = Finding(
                id=uuid.uuid4(),
                scan_id=scan.id,
                category=f.category.value,
                code=f.code,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                points=f.points,
                evidence=f.evidence,
                remediation=f.remediation or "Review configuration.",
                source=f.source,
                created_at=now,
            )
            db.add(finding_record)

        # Persist provider checks
        for provider_name, status_val in [
            ("openphish", openphish_status),
            ("urlhaus", urlhaus_status),
            ("community", "no_match"),
        ]:
            p_check = ProviderCheck(
                id=uuid.uuid4(),
                scan_id=scan.id,
                provider=provider_name,
                result_status=status_val,
                matched=False,
                details={},
                checked_at=now,
            )
            db.add(p_check)

        # Persist certificate details
        if tls_result and tls_result.certificate:
            cert = tls_result.certificate
            cert_record = Certificate(
                id=uuid.uuid4(),
                scan_id=scan.id,
                host=scan.host,
                port=tls_result.port,
                leaf_fingerprint_sha256=cert.leaf_fingerprint_sha256,
                subject_cn=cert.subject_cn,
                san_dns=cert.san_dns,
                issuer=cert.issuer,
                serial_number=cert.serial_number,
                not_before=cert.not_before,
                not_after=cert.not_after,
                signature_algorithm=cert.signature_algorithm,
                public_key_algorithm=cert.public_key_algorithm,
                public_key_bits=cert.public_key_bits,
                chain_valid=tls_result.chain_valid,
                hostname_match=tls_result.hostname_match,
                sct_present=cert.sct_present,
                fetched_at=cert.fetched_at,
            )
            db.add(cert_record)

        # Persist redirect hops
        if http_result and http_result.redirects.hops:
            for hop in http_result.redirects.hops:
                hop_record = ScanRedirect(
                    id=uuid.uuid4(),
                    scan_id=scan.id,
                    hop_index=hop.hop_index,
                    source_url=hop.source_url,
                    destination_url=hop.destination_url,
                    http_status=hop.http_status,
                    resolved_host=hop.resolved_host,
                    resolved_ips=hop.resolved_ips,
                    tls_verified=hop.tls_verified,
                    created_at=now,
                )
                db.add(hop_record)

        await db.commit()
        logger.info(
            f"Scan {scan_id} finished: status={scan.status}, verdict={scan.verdict}, score={scan.risk_score}"
        )


@celery_app.task(name="app.workers.scan_tasks.execute_scan_task", bind=True, max_retries=2)
def execute_scan_task(self, scan_id: str) -> None:
    """Celery background worker entrypoint for website scan execution."""
    logger.info(f"Celery worker picked up scan task for scan_id: {scan_id}")
    try:
        asyncio.run(run_scan_pipeline(scan_id=scan_id))
    except Exception as exc:
        logger.exception(f"Unhandled worker error on scan {scan_id}: {exc}")
        raise self.retry(exc=exc, countdown=5)
