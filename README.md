# TrustLens — Unified Website Security & Certificate Trust Intelligence Platform

TrustLens is a production-grade cybersecurity intelligence platform designed to determine whether a website or endpoint is **SAFE**, **SUSPICIOUS**, **MALICIOUS**, or **INCONCLUSIVE**.

The platform couples high-throughput passive perimeter heuristics with a newly integrated, deterministic **X.509 Certificate Analyzer** and auxiliary machine learning compliance advisory engine.

---

## 🚀 Key Platform Capabilities

1. **Passive Web Security Assessment**: Strict HTTP perimeter inspections, DNS record enumeration, security header analysis (`HSTS`, `CSP`, `X-Frame-Options`), and SSRF-hardened redirect tracking.
2. **Threat Intelligence Correlation**: Real-time cross-referencing against OpenPhish, URLhaus, and local indicators of compromise.
3. **Deep X.509 Certificate Analyzer (New Feature)**:
   - **RFC 5280 Path Validation**: Full certification chain reconstruction anchored against the Mozilla CCADB (Common CA Database) root store.
   - **RFC 9525 Identity Matching**: Subject Alternative Name (`dNSName`, `iPAddress`) and Common Name SAN validation supporting internationalized domain names (IDN/Punycode) and wildcards.
   - **CA/Browser Forum Baseline Requirements v2.3.1**: Automated validation of certificate validity periods (enforcing the 200-day maximum lifetime limit for subscriber certificates).
   - **Certificate Transparency (RFC 6962)**: Embedded Signed Certificate Timestamp (SCT) presence and count verification.
   - **Deterministic Trust Scoring (0–100)**: Transparent score deduction framework cleanly decoupled from confidence metrics (0.0–1.0).
   - **Fail-Safe Revocation Invariant**: Any revoked certificate immediately yields a hard zero score (`trust_score = 0`) and `DISTRUSTED` verdict.
   - **Auxiliary Machine Learning Advisory**: Random Forest and anomaly detection models providing Web PKI baseline comparisons (`[ Advisory Signal Only ]`).
4. **Interactive Certificate Analysis Console**:
   - Live endpoint TLS handshake analysis for any public domain or FQDN.
   - Direct analysis of pasted PEM certificates and multi-certificate chains.
5. **Collaborative Threat Intelligence**: Community-sourced threat reporting with moderator audit trails.

---

## 🏗️ Architecture & Technology Stack

### Backend Stack
- **Python 3.12+ / 3.14**: High-concurrency async runtime.
- **FastAPI**: Asynchronous REST API framework with Pydantic v2 schemas.
- **SQLAlchemy 2.0**: Async ORM supporting PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`).
- **Celery 5.4+ & Redis 7.4+**: Distributed background scanning workers and broker.
- **Cryptography & OpenSSL**: X.509 leaf and chain DER parsing, cipher negotiation, and signature verification.
- **scikit-learn & pandas**: Auxiliary ML compliance classification and anomaly scoring.
- **HTTPX & dnspython**: SSRF-hardened HTTP client and DNS resolver.

### Frontend Stack
- **React 19 & Vite 8**: Dark-first, minimal cybersecurity investigation interface.
- **Plain CSS**: Modern scoped CSS tokens adhering to TrustLens visual identity (`globals.css` and `components.css`).
- **Lucide React & Ant Design**: Streamlined icons and accessible UI components.
- **Zero Heavy Overheads**: Strictly NO TypeScript, NO Tailwind CSS, NO Next.js, and NO Redux.

---

## 📂 Repository Structure

```text
trustlens/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application factory & middleware
│   │   ├── config.py                   # Pydantic Settings & environment bootstrapping
│   │   ├── api/v1/                     # REST API v1 routers & endpoints
│   │   │   ├── endpoints/
│   │   │   │   ├── certificates.py     # POST /api/v1/certificates/analyze
│   │   │   │   ├── scans.py            # POST /api/v1/scans & GET /scans/{id}/certificate
│   │   │   │   ├── auth.py             # User authentication & token management
│   │   │   │   └── ...
│   │   │   └── router.py               # Centralized v1 router registration
│   │   ├── core/                       # Security, logging, exceptions, SSRF protection
│   │   ├── database/                   # SQLAlchemy async engine & session management
│   │   ├── models/                     # Database models (Certificate, CertificateScan, Scan)
│   │   ├── schemas/                    # Pydantic v2 DTOs (CertificateAssessment, Policy)
│   │   ├── scanners/                   # tls_scanner.py (integrated with Certificate Analyzer)
│   │   ├── workers/                    # Celery scan pipeline and task orchestration
│   │   └── tests/                      # Automated test suite (62 passing integration tests)
│   ├── requirements.txt                # Pinned backend dependencies
│   └── .env.example                    # Backend environment template
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── CertificatePage.jsx     # Interactive Certificate Analyzer & Telemetry View
│   │   │   ├── ScanReportPage.jsx      # Scan report with Certificate Trust preview
│   │   │   ├── DashboardPage.jsx       # Overview & recent scan audits
│   │   │   └── ...
│   │   ├── components/layout/          # AppLayout with Certificate Analyzer navigation
│   │   ├── services/                   # certificate.service.js & scan.service.js
│   │   └── styles/                     # Design system (globals.css, components.css)
│   ├── package.json                    # React 19 & Vite configuration
│   └── vite.config.js
├── intelligence/
│   ├── certificate_analyzer/           # X.509 Certificate Analyzer Core Engine
│   │   ├── src/certificate_analyzer/   # RFC 5280, RFC 9525, CA/B Forum, Scoring & ML
│   │   └── tests/                      # 72 engine unit tests
│   └── certificate_dataset/            # Mozilla CCADB root store & training corpus
└── shared/
    └── certificate-integration/        # Engineering contracts, frontend & backend specs
```

---

## ⚡ Quickstart Guide

### 1. Backend Setup
```bash
cd backend

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install pandas scikit-learn asyncpg

# Configure environment
cp .env.example .env

# Run database migrations / initialization
# For local dev without Postgres, SQLite is supported out of the box:
# export DATABASE_URL="sqlite+aiosqlite:///./trustlens.db"

# Start the API server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup
```bash
cd frontend

# Install npm packages
npm install

# Start Vite development server
npm run dev
# The frontend console will be live at http://localhost:5173
```

### 3. Verify Health & OpenAPI Documentation
- Base Health Probe: `http://localhost:8000/health`
- Interactive OpenAPI Swagger Docs: `http://localhost:8000/docs`
- Certificate Analyzer Direct UI: `http://localhost:5173/certificates`

---

## 🧪 Automated Testing

### Backend Integration & Security Tests (62 Tests)
```bash
cd backend
python -m pytest app/tests/ -v
```
All 62 tests cover authentication, scans, reports, dashboard, health, scanners, SSRF protections, and certificate analysis.

### Certificate Engine Unit Tests (72 Tests)
```bash
cd intelligence/certificate_analyzer
python -m pytest tests/ -v
```
Verifies RFC 5280 path validation, RFC 9525 SAN matching, CA/B Forum v2.3.1 rules, trust scoring invariants, and ML model loading.

### Frontend Production Build
```bash
cd frontend
npm run build
```
Compiles and bundles the React 19 application with zero errors or warnings.

---

## 🛡️ Security Principles & Guardrails

1. **TLS ≠ Legitimacy**: A valid certificate encrypts communications; it does not prove a site is harmless. This distinction is prominently displayed across TrustLens.
2. **Strict SSRF Immunity**: The certificate analysis endpoint actively filters all inputs against private, loopback, link-local, multicast, and cloud metadata IP ranges (`169.254.169.254`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`).
3. **Payload Boundaries**: Direct PEM uploads are strictly capped at 10 MB to prevent resource exhaustion attacks.
4. **Advisory Machine Learning**: The ML advisory is strictly auxiliary and will never override cryptographic validity or deterministic path checks.

---

## 📜 License
TrustLens is proprietary software developed for enterprise website security and threat intelligence operations. All rights reserved.
