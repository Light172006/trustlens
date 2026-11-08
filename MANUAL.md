# TrustLens User & Operator Manual

Welcome to the comprehensive user and operational manual for **TrustLens**, the unified website security assessment and cryptographic trust intelligence platform.

---

## Table of Contents
1. [Platform Overview & Concepts](#1-platform-overview--concepts)
2. [Getting Started & Local Setup](#2-getting-started--local-setup)
3. [The Certificate Analyzer Feature](#3-the-certificate-analyzer-feature)
   - [Interactive Console: Endpoint TLS Handshake](#interactive-console-endpoint-tls-handshake)
   - [Interactive Console: PEM Certificate & Chain Analysis](#interactive-console-pem-certificate--chain-analysis)
   - [Interpreting Trust Scores & Verdicts](#interpreting-trust-scores--verdicts)
   - [CA/Browser Forum Baseline Requirements v2.3.1](#cabrowser-forum-baseline-requirements-v231)
   - [Certificate Transparency (RFC 6962) & Path Validation](#certificate-transparency-rfc-6962--path-validation)
   - [Machine Learning Advisory Drawer](#machine-learning-advisory-drawer)
4. [Running Website Security Scans](#4-running-website-security-scans)
   - [Submitting a New Target](#submitting-a-new-target)
   - [Navigating the Multi-Layer Security Report](#navigating-the-multi-layer-security-report)
5. [Developer API Reference](#5-developer-api-reference)
   - [POST /api/v1/certificates/analyze](#post-apiv1certificatesanalyze)
   - [GET /api/v1/scans/{id}/certificate](#get-apiv1scansidcertificate)
   - [POST /api/v1/scans](#post-apiv1scans)
   - [GET /api/v1/scans/{id}](#get-apiv1scansid)
6. [Operational Security & SSRF Safeguards](#6-operational-security--ssrf-safeguards)
7. [Troubleshooting & FAQs](#7-troubleshooting--faqs)

---

## 1. Platform Overview & Concepts

TrustLens provides unified cybersecurity intelligence across four specialized domains:
- **X.509 Cryptographic Identity**: Deep path validation, CA/B Forum compliance, and identity matching.
- **Passive Web Security**: HTTP headers, redirect chain re-validation, transport security.
- **Threat Intelligence**: Real-time correlation with confirmed malware/phishing feeds.
- **Collaborative Community Intelligence**: Analyst reports and community alerts.

### Critical Security Principle: TLS ≠ Legitimacy
> [!IMPORTANT]
> A valid TLS certificate guarantees only encryption in transit between client and server. **It is never proof that a website is genuine, legitimate, or harmless.** Modern phishing campaigns routinely obtain valid, free certificates issued by automated authorities. TrustLens explicitly communicates this distinction throughout all scan views.

---

## 2. Getting Started & Local Setup

### System Prerequisites
- **Python 3.12+ / 3.14** with `pip`
- **Node.js 18+ / 20+** with `npm`
- (Optional) PostgreSQL and Redis for production orchestration; SQLite and mock workers are supported for local development.

### Step 1: Starting the Backend API
```bash
cd backend

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
pip install pandas scikit-learn asyncpg

# Set configuration
copy .env.example .env

# Start FastAPI server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend API is now running at `http://localhost:8000`. You can inspect interactive OpenAPI documentation at `http://localhost:8000/docs`.

### Step 2: Starting the Frontend Web Console
```bash
cd frontend

# Install node dependencies
npm install

# Start development server
npm run dev
```
The React 19 web console will launch at `http://localhost:5173`.

---

## 3. The Certificate Analyzer Feature

The newly integrated **Certificate Analyzer** allows security analysts to perform cryptographic inspection of X.509 certificates either as part of a full website scan or as a standalone interactive utility.

### Interactive Console: Endpoint TLS Handshake
1. In the sidebar navigation, click **Certificate Analyzer** (or navigate to `/certificates`).
2. Select the **Live Endpoint TLS Handshake** tab.
3. Enter the target hostname (e.g. `github.com`, `api.trustlens.io`) and TLS port (default `443`).
4. (Optional) Use the quick preset buttons: `github.com`, `cloudflare.com`, or `expired.badssl.com`.
5. Click **Analyze Endpoint**.
6. TrustLens securely establishes a TLS connection, extracts the leaf certificate and peer chain, and performs comprehensive cryptographic checks.

### Interactive Console: PEM Certificate & Chain Analysis
1. Select the **Raw PEM Certificate / Bundle** tab.
2. Paste one or more PEM-encoded certificates (`-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----`).
3. (Optional) Provide a target hostname to test RFC 9525 Subject Alternative Name (SAN) matching.
4. (Optional) Click **Load Test Self-Signed PEM** to test a known self-signed sample.
5. Click **Evaluate PEM Certificate**.

---

### Interpreting Trust Scores & Verdicts

TrustLens evaluates certificates into four categorical verdicts:

| Verdict | Trust Score | Meaning | Visual Indicator |
|:---|:---:|:---|:---|
| **`TRUSTED`** | 80 – 100 | Certificate is structurally valid, unexpired, unrevoked, anchored in Mozilla CCADB, and matches the target hostname. | Emerald badge & gauge (`ShieldCheck`) |
| **`WARNING`** | 50 – 79 | Certificate is operational but has policy deviations (e.g. expiring in <14 days, weak parameters, or CA/B limit deviations). | Amber badge & gauge (`AlertTriangle`) |
| **`DISTRUSTED`** | 0 – 49 | Critical security flaw detected: expired, revoked, untrusted root, self-signed without trust, or hostname mismatch. | Rose badge & gauge (`ShieldAlert`) |
| **`INCONCLUSIVE`**| 0 | Input was corrupted, exceeded limits, or had ambiguous leaf certificates. | Slate badge & gauge (`HelpCircle`) |

> [!CAUTION]
> **Scoring Invariant**: Any revoked certificate unconditionally results in `trust_score = 0` and `verdict = DISTRUSTED`. Confidence (0.0 to 1.0) is strictly decoupled from the score and reflects evidence completeness.

---

### CA/Browser Forum Baseline Requirements v2.3.1
The analyzer automatically inspects validity windows against the CA/B Forum subscriber limit (maximum allowed validity of **200 days** for modern subscriber certificates).
- **Compliant**: Certificate duration is within the 200-day limit.
- **Validity Exceeds Limit**: Highlighted with an amber badge showing actual vs allowed lifetime.
- **CA Anchor / Exempt**: Root and intermediate authorities are exempt from subscriber limits.

---

### Certificate Transparency (RFC 6962) & Path Validation
- **Root Trust Anchor**: Checks if the chain terminates in a trusted root certificate included in Mozilla's Common CA Database (CCADB).
- **Certificate Transparency**: Scans for embedded Signed Certificate Timestamps (SCTs) required by modern Web PKI browsers.
- **Revocation Status**: Displays OCSP/CRL checking state. Under strict UX rules, an unverified revocation state is displayed with a neutral slate pill (`not checked`), never green.

---

### Machine Learning Advisory Drawer
The **Machine Learning Advisory** section provides statistical classification against baseline Web PKI distributions:
- **Predicted Profile**: Identifies whether the certificate's structural metrics match standard commercial issuing practices (`POLICY_COMPLIANT`).
- **Anomaly Score**: An isolation forest algorithm detects unusual structural traits (e.g. non-standard key lengths or anomalous extension counts).
- **Advisory Rule**: The ML advisory is marked with a prominent `[ Advisory Signal Only ]` badge. It cannot override deterministic cryptographic validity.

---

## 4. Running Website Security Scans

### Submitting a New Target
1. Navigate to **New Scan** in the sidebar.
2. Enter the full URL (e.g. `https://example.com`).
3. (Optional) Check **Treat as sensitive** if you wish to skip third-party threat feed lookups for confidential endpoints.
4. Click **Start Investigation**.

### Navigating the Multi-Layer Security Report
- **Overview Card**: Displays final verdict, risk score, host, scheme, and scanning duration.
- **Threat Findings**: Filter findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Certificate Preview**: Shows the integrated Certificate Trust Score and links directly to the detailed inspector.
- **Network & Redirects**: Shows hop-by-hop HTTP status codes and TLS verification status.

---

## 5. Developer API Reference

### POST `/api/v1/certificates/analyze`
Directly evaluates an endpoint or PEM certificate payload.

**Request Body (JSON):**
```json
{
  "hostname": "api.trustlens.io",
  "port": 443,
  "pem": null,
  "include_ml_advisory": true
}
```

**Response (200 OK):**
```json
{
  "certificate_sha256": "3a1f8c4...",
  "subject_dn": "CN=api.trustlens.io",
  "issuer_dn": "CN=GTS CA 1P5,O=Google Trust Services LLC,C=US",
  "verdict": "TRUSTED",
  "trust_score": 95,
  "confidence": 1.0,
  "scoring_version": "cert_v1.0.0",
  "checks_completed": 6,
  "findings": [],
  "features": {
    "public_key_algorithm": "ECDSA",
    "key_size_bits": 256,
    "validity_duration_days": 90,
    "is_cabf_validity_compliant": true
  },
  "policy_evaluation": {
    "policy_name": "CABF_BASELINE_REQUIREMENTS",
    "validity_compliant": true,
    "max_validity_days_allowed": 200
  },
  "ml_advisory": {
    "predicted_class": "POLICY_COMPLIANT",
    "compliance_probability": 0.999,
    "is_anomaly": false,
    "is_advisory": true
  },
  "recommendations": [],
  "summary": "Certificate is trusted and compliant."
}
```

---

### GET `/api/v1/scans/{id}/certificate`
Retrieves full certificate intelligence recorded during a scan.

---

## 6. Operational Security & SSRF Safeguards

To prevent Server-Side Request Forgery (SSRF) and network reconnaissance:
1. **Pre-flight IP Verification**: Every target hostname is resolved using DNS before any TLS connection is attempted.
2. **Blocked Destinations**: Requests targeting private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), or AWS/GCP cloud metadata endpoints (`169.254.169.254`) are immediately rejected with HTTP 400 `TARGET_NOT_PUBLIC`.
3. **Payload Boundaries**: Direct PEM uploads are capped at 10 MB to prevent memory exhaustion.
4. **Timeouts**: Handshakes enforce a strict 5-second socket timeout.

---

## 7. Troubleshooting & FAQs

**Q: Why does the scanner mark a website as DISTRUSTED even if Chrome opens it?**  
A: TrustLens evaluates certificates against strict RFC 5280 standards. If the server omits an intermediate certificate in its TLS handshake and relies on browser AIA fetching or local cache, TrustLens flags the chain as incomplete.

**Q: Can I run TrustLens completely offline?**  
A: Yes. In offline environments, use the **Raw PEM Certificate** tab or supply SQLite database credentials. Root CA validation operates against the bundled Mozilla CCADB store without requiring external network connectivity.

**Q: How do I resolve `TARGET_NOT_PUBLIC` errors?**  
A: This error indicates that the provided hostname resolves to an internal or private network IP address. To prevent SSRF attacks, TrustLens only connects to globally routable public IP addresses.
