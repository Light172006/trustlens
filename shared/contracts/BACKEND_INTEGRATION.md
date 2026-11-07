# TrustLens — Backend Integration Guide

**Target Audience:** Backend Engineer (FastAPI, Celery workers, Scanning infrastructure, PostgreSQL persistence).  
**Author:** Principal Python Architect / AI Contract Engineer.  
**Package:** `trustlens-intelligence` (located at `intelligence/`).  
**Contracts Directory:** `shared/contracts/`.

---

## 1. Contract Ownership Summary

| Schema | File Path | Owner | Responsibility |
|---|---|---|---|
| **Scanner Evidence Schema** | `schemas/scanner-evidence.schema.json` | **Joint Ownership** | Defines what your scanner worker collects and supplies. |
| **AI Engine Input Schema** | `schemas/ai-engine-input.schema.json` | **AI/ML Engineer** | Defines what the intelligence engine accepts. |
| **AI Engine Output Schema** | `schemas/ai-engine-output.schema.json` | **AI/ML Engineer** | Defines what the engine returns and what the backend persists. |

> [!IMPORTANT]
> The backend scanner collects **factual technical observations**. The scanner must **never** calculate the final risk score or verdict. The AI intelligence engine (`trustlens-intelligence`) owns the deterministic scoring rules, explainability invariants, and verdict assignment.

---

## 2. Backend Scanner Output Construction

When your Celery scan worker runs, it executes network probes (DNS, bounded HTTP, TLS handshake, threat feed queries) and collects the normalized evidence.

### 2.1 Scanner Evidence Structure

Your worker should construct a Python dictionary conforming to `schemas/scanner-evidence.schema.json`:

```python
scanner_evidence_payload = {
    "scan_id": str(scan.id),
    "original_url": scan.original_url,
    "canonical_url": scan.canonical_url,
    "host": scan.host,
    "scheme": scan.scheme,
    "is_sensitive": scan.is_sensitive,
    
    # 1. HTTP Observations (from SafeHttpFetcher)
    "http": {
        "status_code": response.status,
        "final_url": str(response.url),
        "redirect_count": len(redirect_hops),
        "redirects": [
            {
                "hop_index": hop.index,
                "source_url": hop.source_url,
                "destination_url": hop.destination_url,
                "http_status": hop.status_code,
                "resolved_host": hop.resolved_host,
                "resolved_ips": hop.resolved_ips,
                "tls_verified": hop.tls_verified,
            }
            for hop in redirect_hops
        ],
        "security_headers": {
            # Normalize all header keys to lowercase
            k.lower(): v for k, v in response.headers.items()
        },
        "cookies": [
            {
                "name": c.name,
                "secure": c.secure,
                "httponly": c.httponly,
                "samesite": c.samesite,
            }
            for c in observed_cookies
        ],
        "http_to_https_redirect": check_http_to_https_redirect(scan.original_url, redirect_hops),
        "response_time_ms": response_duration_ms,
        "fetched_at": fetch_timestamp.isoformat(),
    },
    
    # 2. TLS Observations (from CertificateInspector)
    # If target is plain HTTP or TLS handshake failed, set to None or valid: false
    "tls": {
        "valid": tls_result.is_valid,
        "chain_valid": tls_result.chain_valid,
        "hostname_match": tls_result.hostname_match,
        "days_until_expiry": tls_result.days_until_expiry,
        "is_expired": tls_result.is_expired,
        "expires_soon": tls_result.expires_soon,
        "protocol_version": tls_result.protocol_version,  # e.g. "TLSv1.3"
        "cipher_suite": tls_result.cipher_suite,
        "subject_cn": tls_result.subject_cn,
        "issuer": tls_result.issuer,
        "san_dns": tls_result.san_dns,
        "sct_present": tls_result.sct_present,
        "certificate_details": {
            "leaf_fingerprint_sha256": tls_result.leaf_fingerprint_sha256,
            "serial_number": tls_result.serial_number,
            "not_before": tls_result.not_before.isoformat() if tls_result.not_before else None,
            "not_after": tls_result.not_after.isoformat() if tls_result.not_after else None,
            "signature_algorithm": tls_result.signature_algorithm,
            "public_key_algorithm": tls_result.public_key_algorithm,
            "public_key_bits": tls_result.public_key_bits,
            "revocation_status": "not_checked",
            "fetched_at": tls_result.fetched_at.isoformat() if tls_result.fetched_at else None,
            "unavailable_reason": tls_result.unavailable_reason,
        } if tls_result.has_leaf_certificate else None
    } if scan.scheme == "https" and tls_result.completed else None,
    
    # 3. Domain Intelligence (optional, if RDAP/WHOIS is configured)
    "domain_intelligence": {
        "domain_age_days": domain_info.age_days if domain_info else None,
        "registrar": domain_info.registrar if domain_info else None,
        "created_date": domain_info.created_date if domain_info else None,
        "nameservers": domain_info.nameservers if domain_info else [],
    } if domain_info else None,
    
    # 4. Threat Feed Observations (from ThreatIntelService)
    "threat_intelligence": {
        "openphish_match": openphish_result.matched,
        "openphish_status": openphish_result.result_status,  # "match", "no_match", "unavailable", "stale_cache"
        "urlhaus_match": urlhaus_result.matched,
        "urlhaus_status": urlhaus_result.result_status,      # "match", "no_match", "unavailable", "skipped_sensitive_url"
        "urlhaus_url_status": urlhaus_result.details.get("url_status"),  # "online", "offline", "unknown"
        "provider_checks": [
            {
                "provider": "openphish",
                "result_status": openphish_result.result_status,
                "matched": openphish_result.matched,
                "details": openphish_result.details,
                "checked_at": openphish_result.checked_at.isoformat(),
                "latency_ms": openphish_result.latency_ms,
            },
            {
                "provider": "urlhaus",
                "result_status": urlhaus_result.result_status,
                "matched": urlhaus_result.matched,
                "details": urlhaus_result.details,
                "checked_at": urlhaus_result.checked_at.isoformat(),
                "latency_ms": urlhaus_result.latency_ms,
            }
        ]
    },
    
    # 5. Community Intelligence (from CommunityIntelService database query)
    "community_intelligence": {
        "confirmed_report_count": community_stats.confirmed_count,
        "distinct_reporter_count": community_stats.distinct_reporters,
        "pending_report_count": community_stats.pending_count,
        "reports": community_stats.confirmed_reports,
    },
    
    # 6. Worker Operational Telemetry
    "scanner_execution": {
        "status": "succeeded",  # "queued", "running", "succeeded", "partial", "failed"
        "started_at": scan_started_at.isoformat(),
        "completed_at": scan_completed_at.isoformat(),
        "duration_ms": elapsed_ms,
        "checks_attempted": ["dns", "http", "tls", "threat_feeds", "community"],
        "checks_completed": ["dns", "http", "tls", "threat_feeds", "community"],
        "checks_unavailable": [],
        "failure_code": None,
        "failure_message": None,
    }
}
```

---

## 3. Invoking the AI Intelligence Engine

The intelligence engine package exposes clean, high-performance Python entrypoints.

### 3.1 Mapping Scanner Evidence to `ScanEvidence`

`ScanEvidence` is a Pydantic v2 model. It accepts the scanner evidence payload directly using `model_validate`:

```python
from trustlens_intelligence import ScanEvidence, analyze_website

# Pydantic validates the evidence and safely ignores extraneous scanner_execution fields
evidence = ScanEvidence.model_validate(scanner_evidence_payload)
```

### 3.2 Calling `analyze_website()`

Call the primary public analysis function:

```python
assessment = analyze_website(
    evidence=evidence,
    query_providers=False,      # Backend already queried feeds; set False so engine uses evidence.threat_intelligence
    is_scan_failed=False        # Set True only if worker crashed or encountered an unrecoverable internal error
)
```

The returned object is an instance of `ThreatAssessment`.

---

## 4. Processing and Persisting Engine Outputs

The `ThreatAssessment` object contains all data required to update the PostgreSQL database models defined in `API.md`.

### 4.1 Persistence Mapping

```python
from trustlens_intelligence import ThreatAssessment

# 1. Update scans table
scan.verdict = assessment.verdict.value          # "SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"
scan.risk_score = assessment.risk_score          # integer (0-100) or None (for failed scans)
scan.scoring_version = assessment.scoring_version# e.g. "trustlens-1.0"
scan.checks_completed = assessment.checks_completed
scan.status = "succeeded" if assessment.verdict != "INCONCLUSIVE" else "partial"
scan.completed_at = assessment.evaluated_at

# 2. Persist findings to findings table
for f in assessment.findings:
    db.add(
        FindingModel(
            id=uuid.UUID(f.id) if f.id else uuid.uuid4(),
            scan_id=scan.id,
            category=f.category.value,         # "threat_intel", "web_security", "certificate", "community"
            code=f.code,                       # e.g. "CERT_EXPIRED", "CSP_MISSING", "OPENPHISH_URL_MATCH"
            title=f.title,
            description=f.description,
            severity=f.severity.value,         # "info", "low", "medium", "high", "critical"
            points=f.points,                   # integer 0-100
            evidence=f.evidence,               # JSONB
            remediation=f.remediation,
            source=f.source,
            created_at=f.created_at,
        )
    )

# 3. Persist provider checks to provider_checks table
for p in assessment.provider_checks:
    db.add(
        ProviderCheckModel(
            scan_id=scan.id,
            provider=p.provider,               # "openphish", "urlhaus", "community"
            result_status=p.result_status.value,# "match", "no_match", "unavailable", etc.
            matched=p.matched,                 # bool
            details=p.details,                 # JSONB
            checked_at=p.checked_at,
        )
    )

# 4. Leaf certificate persistence (if TLS was available)
if scanner_evidence_payload.get("tls") and scanner_evidence_payload["tls"].get("certificate_details"):
    cert_details = scanner_evidence_payload["tls"]["certificate_details"]
    db.add(
        CertificateModel(
            scan_id=scan.id,
            host=scan.host,
            port=443,
            leaf_fingerprint_sha256=cert_details["leaf_fingerprint_sha256"],
            subject_cn=scanner_evidence_payload["tls"]["subject_cn"],
            san_dns=scanner_evidence_payload["tls"]["san_dns"],
            issuer=scanner_evidence_payload["tls"]["issuer"],
            serial_number=cert_details["serial_number"],
            not_before=cert_details["not_before"],
            not_after=cert_details["not_after"],
            signature_algorithm=cert_details["signature_algorithm"],
            public_key_algorithm=cert_details["public_key_algorithm"],
            public_key_bits=cert_details["public_key_bits"],
            chain_valid=scanner_evidence_payload["tls"]["chain_valid"],
            hostname_match=scanner_evidence_payload["tls"]["hostname_match"],
            sct_present=scanner_evidence_payload["tls"]["sct_present"],
            revocation_status=cert_details["revocation_status"],
            fetched_at=cert_details["fetched_at"],
        )
    )

# 5. Commit database transaction atomically
db.commit()
```

### 4.2 API Response Serialization

When serving `GET /api/v1/scans/{scan_id}`, use `assessment.to_api_dict()` or serialize the database relations directly to match the contract in `API.md`:

```python
response_payload = {
    "scan": {
        "id": str(scan.id),
        "original_url": scan.original_url,
        "canonical_url": scan.canonical_url,
        "host": scan.host,
        "scheme": scan.scheme,
        "is_sensitive": scan.is_sensitive,
        "status": scan.status,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "scoring_version": scan.scoring_version,
        "checks_completed": scan.checks_completed,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "failure_code": scan.failure_code,
        "failure_message": scan.failure_message,
    },
    "coverage": {k: v.value for k, v in assessment.coverage.items()},
    "provider_checks": [
        {
            "provider": p.provider,
            "result_status": p.result_status.value,
            "matched": p.matched,
            "checked_at": p.checked_at.isoformat(),
        }
        for p in assessment.provider_checks
    ],
    "redirects": [r.model_dump(mode="json") for r in evidence.http.redirects] if evidence.http else []
}
```

---

## 5. Error Handling and Edge Cases

The table below specifies how the backend worker must handle common operational scenarios:

| Scenario | Worker Action | Input Parameters to Engine | Engine Result | Backend Action |
|---|---|---|---|---|
| **Clean, normal website** | Collect HTTP, TLS, feeds | `is_scan_failed=False` | `verdict=SAFE`, `risk_score=0`, `confidence>=0.85` | Persist findings (empty), set status `succeeded` |
| **Missing TLS on HTTPS target** | Set `tls=None` or `valid=None` | `is_scan_failed=False` | `verdict=INCONCLUSIVE`, `coverage.certificate=unavailable` | Set status `partial`, persist findings |
| **Active Phishing Match** | Record `openphish_status="match"`, `openphish_match=True` | `is_scan_failed=False` | `verdict=MALICIOUS`, `risk_score=100`, finding `OPENPHISH_URL_MATCH` | Set status `succeeded`, persist findings |
| **URLhaus Feed Outage** | Record `urlhaus_status="unavailable"` | `is_scan_failed=False` | `verdict=INCONCLUSIVE`, `coverage.threat_intel=partial`, finding `COVERAGE_INSUFFICIENT` | Set status `partial`, explain outage in UI |
| **Sensitive URL Scan** | Skip URLhaus lookup, record `skipped_sensitive_url` | `is_scan_failed=False` | `verdict=INCONCLUSIVE`, `coverage.threat_intel=partial` | Set status `partial`, protects user credentials |
| **Unrecoverable Worker Crash** | Worker catches exception before completing | `is_scan_failed=True` | `verdict=INCONCLUSIVE`, `risk_score=None`, `confidence=0.0` | Set status `failed`, record `failure_code` |

---

## 6. Complete End-to-End Worker Example

Here is a complete, self-contained reference showing how a Celery worker task executes evidence collection, invokes the AI engine, and persists the results:

```python
"""Reference Celery Worker Scan Task implementation."""

import logging
import uuid
from datetime import datetime, timezone

from trustlens_intelligence import (
    ScanEvidence,
    HttpEvidence,
    TlsCertificateEvidence,
    ThreatIntelEvidence,
    analyze_website,
)

logger = logging.getLogger("trustlens.workers.scan")


def execute_scan_task(scan_id: str, db_session) -> None:
    """Execute asynchronous website scan and persist threat assessment."""
    scan = db_session.query(ScanModel).filter_by(id=scan_id).one()
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    db_session.commit()

    is_failed = False
    evidence_payload = None

    try:
        # Step 1: Execute DNS & bounded network HTTP probe
        # (Using aiohttp with connection pinning and manual redirects)
        http_obs = run_safe_http_fetcher(scan.canonical_url)

        # Step 2: Execute TLS handshake if scheme is HTTPS
        tls_obs = None
        if scan.scheme == "https":
            tls_obs = run_certificate_inspector(scan.host)

        # Step 3: Check threat feeds
        # If scan is sensitive, skip outbound URLhaus query!
        threat_obs = query_threat_feeds(
            url=scan.canonical_url,
            is_sensitive=scan.is_sensitive
        )

        # Step 4: Build normalized ScanEvidence payload
        evidence_payload = ScanEvidence(
            scan_id=str(scan.id),
            original_url=scan.original_url,
            canonical_url=scan.canonical_url,
            host=scan.host,
            scheme=scan.scheme,
            is_sensitive=scan.is_sensitive,
            http=http_obs,
            tls=tls_obs,
            threat_intelligence=threat_obs,
        )

    except Exception as exc:
        logger.exception("Worker encountered unrecoverable scanning failure for scan %s: %s", scan_id, exc)
        is_failed = True
        scan.failure_code = "SCAN_WORKER_ERROR"
        scan.failure_message = str(exc)
        evidence_payload = ScanEvidence(
            scan_id=str(scan.id),
            original_url=scan.original_url,
        )

    # Step 5: Invoke the Intelligence Engine
    assessment = analyze_website(
        evidence=evidence_payload,
        query_providers=False,
        is_scan_failed=is_failed
    )

    # Step 6: Persist results atomically
    scan.verdict = assessment.verdict.value
    scan.risk_score = assessment.risk_score
    scan.scoring_version = assessment.scoring_version
    scan.checks_completed = assessment.checks_completed
    scan.completed_at = datetime.now(timezone.utc)
    scan.status = "failed" if is_failed else ("succeeded" if assessment.verdict != "INCONCLUSIVE" else "partial")

    # Persist findings
    for f in assessment.findings:
        db_session.add(
            FindingModel(
                id=uuid.UUID(f.id) if f.id else uuid.uuid4(),
                scan_id=scan.id,
                category=f.category.value,
                code=f.code,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                points=f.points,
                evidence=f.evidence,
                remediation=f.remediation,
                source=f.source,
                created_at=f.created_at,
            )
        )

    # Persist provider checks
    for p in assessment.provider_checks:
        db_session.add(
            ProviderCheckModel(
                scan_id=scan.id,
                provider=p.provider,
                result_status=p.result_status.value,
                matched=p.matched,
                details=p.details,
                checked_at=p.checked_at,
            )
        )

    db_session.commit()
    logger.info("Scan %s completed: verdict=%s, score=%s", scan_id, scan.verdict, scan.risk_score)
```

