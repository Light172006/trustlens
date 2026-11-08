# TrustLens — Comprehensive Project Analysis & Feature Discovery Report

**Generated:** 2026-11-08  
**Scope:** Autonomous Full Repository Inspection, Architecture Audit, New Feature Discovery, and Integration Mapping  
**Author:** Antigravity Senior Engineering Team  

---

## 1. Repository Structure & Architecture Overview

### 1.1 Directory Organization

The repository is structured into distinct, modular functional layers:

```text
trustlens/
├── backend/                  # FastAPI 0.115+ REST API & Celery Task Worker
│   ├── app/
│   │   ├── api/v1/           # API version 1 routers and endpoints
│   │   │   ├── endpoints/    # admin, auth, dashboard, health, reports, scans, users
│   │   │   └── router.py     # Master v1 router
│   │   ├── core/             # Security, logging, exceptions, permissions, rate limiting
│   │   ├── database/         # SQLAlchemy 2.0 async sessions, Base, init_db
│   │   ├── integrations/     # AI Intelligence client adapter
│   │   ├── models/           # ORM models (AuditLog, Certificate, Finding, ProviderCheck, Redirect, Report, Scan, Session, User)
│   │   ├── scanners/         # Safe DNS, HTTP, redirect, security headers, TLS scanners
│   │   ├── schemas/          # Pydantic v2 validation and response schemas
│   │   ├── services/         # Business logic layer (auth, dashboard, report, scan)
│   │   ├── tests/            # 57 automated backend tests (All passing)
│   │   ├── workers/          # Celery background workers and scan task pipeline
│   │   ├── config.py         # Typed Pydantic Settings
│   │   └── main.py           # FastAPI application entrypoint
│   ├── alembic.ini           # Database migration configuration
│   ├── Dockerfile            # Container definition
│   └── requirements.txt      # Core Python dependencies
├── frontend/                 # React 19 + Vite web console (Pure CSS, Lucide, Ant Design)
│   ├── index.html            # Single Page Application entry HTML
│   ├── package.json          # Node dependencies (React 19.3.1, React Router 7.18.5, Lucide React)
│   ├── vite.config.js        # Vite build tool with /api reverse proxy to localhost:8000
│   └── src/                  # React components, pages, context, and API services
├── intelligence/             # Threat assessment & intelligence engine
│   ├── trustlens_intelligence/ # Core URL threat feeds & rule-based scoring engine
│   ├── certificate_analyzer/ # [NEW FEATURE] Independent PKI & TLS Security Intelligence Engine
│   └── certificate_dataset/  # [NEW FEATURE] Curated Web PKI dataset & Mozilla CCADB root store
├── shared/                   # Cross-boundary specifications & contracts
│   ├── contracts/            # Formal Pydantic & JSON schema contracts for AI integration
│   └── certificate-integration/ # [NEW FEATURE] Complete Backend & Frontend Integration Specs
├── API.md                    # Canonical REST API contract specification
├── ARCH.md                   # System architecture and data flow documentation
├── FRONTEND_REQUIREMENTS.md  # Frontend UX & API integration specification
├── PRD.md                    # Product Requirements Document
├── STARTUP_GUIDE.md          # Multi-environment deployment & execution instructions
└── UI.md                     # Visual tokens, typography, and UX design guide
```

---

## 2. Technology Stack & Key Libraries

- **Backend Runtime:** Python 3.11+ / 3.14 compatible, FastAPI 0.115, Uvicorn, Pydantic v2.
- **Database Layer:** SQLAlchemy 2.0 Async, PostgreSQL 16 (production) / SQLite via aiosqlite (isolated testing & local dev).
- **Background Tasks & Broker:** Celery 5.4+ with Redis 7.4 (production), with inline task dispatch for test/standalone operation.
- **Cryptography & Security:** `cryptography` 43+, `dnspython`, `pyjwt`, `pwdlib` (Argon2), strict SSRF validation with private/loopback IP rejection.
- **Frontend Stack:** React 19, JavaScript (JSX), Vite 8, Plain CSS, React Router v7, Lucide React, Ant Design components.
- **AI/ML & Scoring:** Scikit-learn, Joblib, NumPy, Mozilla Root Store CCADB, CA/Browser Forum BR v2.3.1 rules engine.

---

## 3. Automatic Discovery of the New Feature

### 3.1 Identification of the New Component

Through comparative diffs and recursive repository analysis, the newly developed capability is:

**The TrustLens Certificate Analyzer (`certificate_analyzer`)**
Located in:
- `intelligence/certificate_analyzer/`
- `intelligence/certificate_dataset/`
- `shared/certificate-integration/`

### 3.2 What the New Feature Does

The **Certificate Analyzer** is an independent, production-grade digital trust intelligence system that performs multi-dimensional security assessments of X.509 certificates and TLS endpoints:

1. **RFC 9525 Modern TLS Server Identity Verification:**
   - Evaluates Subject Alternative Names (`dNSName` and `iPAddress`).
   - Deprecates legacy Common Name fallback in compliance with RFC 9525 §6.
   - Strictly enforces single leftmost-label wildcard rules (`*.example.com`).
   - Full IDNA 2008 Punycode support.

2. **RFC 5280 Certification Path Validation:**
   - Traverses Authority Key Identifier (AKI) to Subject Key Identifier (SKI) graphs.
   - Enforces Basic Constraints (`is_ca=True` on parent nodes, path length limits).
   - Validates cryptographic digital signatures along the entire path up to Mozilla CCADB trust anchors.
   - Circular issuer loop detection and resilient handling of missing intermediates.

3. **RFC 6960 / RFC 5280 Revocation Verification:**
   - Ingests OCSP and CRL telemetry.
   - Enforces the invariant: confirmed revoked certificate unconditionally yields `trust_score = 0` and `verdict = DISTRUSTED`.

4. **RFC 6962 / RFC 9162 Certificate Transparency (CT):**
   - Audits embedded Signed Certificate Timestamps (SCTs) via OID `1.3.6.1.4.1.11129.2.4.2`.
   - Decodes RFC 6962 binary serialized SCT bodies.

5. **CA/Browser Forum Baseline Requirements v2.3.1:**
   - Tiered maximum validity duration schedule (398 days, 200 days, 100 days, 47 days).
   - Flags weak cryptography: SHA-1, MD5, RSA keys < 2048-bit.
   - Validates Key Usage and Extended Key Usage (`serverAuth`).

6. **Deterministic Trust Scoring:**
   - Base score of 100 with calibrated additive risk deductions.
   - Categorical verdicts: `TRUSTED` (80–100), `WARNING` (50–79), `DISTRUSTED` (0–49), `INCONCLUSIVE`.
   - Strictly decoupled score and confidence metrics.

7. **Auxiliary Machine Learning Advisory:**
   - Fast inference via bundled champion model and isolation forest anomaly detector.
   - Strictly advisory flag (`is_advisory: true`) that never overrides cryptographic verification.

---

## 4. Current Integration Gap Analysis

While the `certificate_analyzer` engine is complete with 69 unit/invariant tests passing, it is currently **disconnected from the running application**:

| Area | Current State | Required Integrated State |
|---|---|---|
| **Backend Handshake Scanning** | `tls_scanner.py` only extracts raw DER string metadata. | `tls_scanner.py` and `scan_tasks.py` must execute `analyze_endpoint_tls()` using the new engine. |
| **Database Persistence** | `certificates` table only stores basic fields (fingerprint, subject_cn, issuer). | Store the complete `CertificateAssessment` payload (`trust_score`, `verdict`, `confidence`, `policy_evaluation`, `ml_advisory`, `findings`, `recommendations`). |
| **API Endpoints** | `GET /scans/{scan_id}/certificate` returns legacy `CertificateDetailResponse`. No standalone endpoint. | 1. Enhance `GET /scans/{scan_id}/certificate` to return full `CertificateAssessment`.<br>2. Add `POST /api/v1/certificates/analyze` for direct PEM / hostname analysis. |
| **Frontend Source Code** | `frontend/src` was missing in this unzipped workspace folder (present in companion workspace `D:\hackmatrix frontend`). | Sync complete working frontend to `frontend/src`, update `CertificatePage.jsx` and `certificate.service.js` to render the rich Certificate Trust Intelligence Card, Score Gauge, CA/B Forum Compliance Pill, Ranked Findings, and ML Advisory drawer. |
| **Standalone Certificate Analysis** | No user-facing way to test arbitrary PEM or host. | Add a Certificate Analyzer tab / modal / direct testing workflow in the UI. |

---

## 5. Security & Invariant Audit

- **SSRF Defense:** Preserved — only public IP destinations are contacted; private/loopback/cloud-metadata addresses are blocked at validation layer.
- **Denial of Service Limits:** Enforced — 10 MB payload ceiling, 50 certs bundle limit, 10,000 SAN limit.
- **Fail-Safe Revocation:** Invariant strictly maintained — revoked certificates cannot receive positive scores.
- **Advisory Isolation:** ML model predictions are labeled advisory and cannot overturn cryptographic failures.
- **Clean Error Envelopes:** Standard `{ "error": { "code", "message", "request_id" } }` maintained.
