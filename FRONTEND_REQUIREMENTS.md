# TrustLens — Frontend Response & API Integration Requirements

**Document Version:** 2.1  
**Target Audience:** UI/UX Engineer, Frontend Engineering Team (React 19 / TypeScript)  
**Author:** Backend Architecture & Security Engineering Team  
**Scope:** Phases 1 through 7 + Certificate Analyzer Integration (Foundation, Authentication, Scanning Infrastructure, Background Workers, AI Integration, PKI / Certificate Intelligence, Dashboard & Analytics, Collaborative Threat Intelligence & Moderation)  
**Status:** Implemented, Tested, and Verified (68/68 Automated Tests Passing)

---

## 1. Architectural Overview & Responsibilities

TrustLens is a unified website security assessment platform delivering explainable security verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `INCONCLUSIVE`). 

### Three-Person Engineering Collaboration
1. **AI Engineer:** Develops the threat engine models, heuristic weights, and assessment logic (`shared/contracts/ai_contracts.py`).
2. **Backend Engineer (Provided):** Implements REST APIs, PostgreSQL ORM, Celery pipeline, strict SSRF/network validation, authentication, community threat intelligence, dashboard analytics, and integration bridges.
3. **UI/UX Engineer (You):** Builds the responsive React 19 / Vite / Tailwind CSS 4 frontend using Radix UI primitives, TanStack Query, and React Hook Form.

---

## 2. API Transport & Security Protocol

### 2.1 Base URLs
- **Local Development:** `http://localhost:8000/api/v1`
- **Docker Compose:** `http://api:8000/api/v1`
- **Health Check Root:** `http://localhost:8000/health`

### 2.2 Standard Request Headers
For every authenticated request, the frontend client must supply:
```http
Authorization: Bearer <access_token>
X-CSRF-Token: <csrf_token>
Content-Type: application/json
X-Request-ID: <client-generated-uuid-v4>
```
*Note: `X-Request-ID` is optional from the client. If omitted, the FastAPI backend generates a UUID v4 and returns it in the response header `X-Request-ID` and in error payloads.*

### 2.3 Token Lifecycle & Rotation
- **Access Token:** Short-lived JWT (15 minutes). Sent in `Authorization: Bearer <access_token>`.
- **Refresh Token:** Rotated 7-day token. Kept in memory or secure storage and sent via `POST /api/v1/auth/refresh`.
- **CSRF Token:** Sent upon login/registration in the response body (`tokens.csrf_token`). Must be held in auth memory state and passed via `X-CSRF-Token` on state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Token Invalidation:** On HTTP 401 (`AUTHENTICATION_REQUIRED`), purge auth state and redirect to `/login?returnUrl=...`.

---

## 3. Centralized Error Envelope

All error responses from the backend follow this exact JSON contract. The frontend must parse errors using this structure rather than attempting to read raw Python stack traces.

### 3.1 Error Response JSON Schema
```json
{
  "error": {
    "code": "TARGET_NOT_PUBLIC",
    "message": "The target hostname or IP address resolves to a private, loopback, or non-public network address.",
    "request_id": "8f889988-51ec-46ce-bd5e-9907f9c8caea",
    "details": {
      "host": "localhost",
      "resolved_ips": ["127.0.0.1"]
    }
  }
}
```

### 3.2 Canonical Error Codes & UI Action Matrix

| Error Code | HTTP Status | Meaning | Recommended UI Treatment |
|---|---|---|---|
| `VALIDATION_ERROR` | 422 / 400 | Malformed schema or invalid field syntax | Highlight invalid inputs using inline form field errors. |
| `AUTHENTICATION_REQUIRED` | 401 | Missing, malformed, or expired access token | Clear session state and route to `/login`. |
| `FORBIDDEN` | 403 | Insufficient role or attempt to view another user's scan/report | Render full-page `Access Denied` panel. |
| `OWN_REPORT_VOTE_NOT_ALLOWED` | 403 | User attempted to vote on their own submitted report | Toast warning: *"You cannot vote on your own community report."* |
| `RESOURCE_NOT_FOUND` | 404 | Scan, report, finding, or user not found | Render `Not Found` empty state with return CTA. |
| `STATE_CONFLICT` | 409 | Duplicate resource conflict or re-moderating non-pending report | Inline collision notice or *"Report was already moderated by another user."* |
| `REPORT_NOT_VOTABLE` | 409 | Attempting to vote on unconfirmed report | Disable vote buttons; show *"Only confirmed reports can receive votes."* |
| `RATE_LIMIT_EXCEEDED` | 429 | Sliding window rate limit exceeded | Toast warning with `Retry-After` seconds countdown. |
| `TARGET_NOT_PUBLIC` | 400 | SSRF Defense: loopback, private, or cloud metadata IP | Show security notice: *"Private, loopback, and internal addresses cannot be scanned."* |
| `UNSUPPORTED_URL_SCHEME` | 400 | Non-HTTP/HTTPS protocol (e.g. `ftp://`, `file://`) | Inline error: *"Only HTTP and HTTPS URLs are supported."* |
| `CREDENTIALS_IN_URL_REJECTED` | 400 | URL contains `user:pass@host` | Inline error: *"URLs containing credentials are not permitted."* |
| `PORT_NOT_ALLOWED` | 400 | Port other than 80 or 443 submitted | Inline error: *"Only standard web ports (80 and 443) are supported."* |
| `REDIRECT_LOOP_DETECTED` | 400 | Target entered an infinite HTTP redirect loop | Scan failure badge: *"Target has an infinite redirect loop."* |
| `INTERNAL_ERROR` | 500 | Unhandled server exception | Display generic `ErrorState` card with `request_id` for support. |

---

## 4. Endpoints & Response Payloads (Phases 1–7)

### 4.1 Health Check Probes

#### `GET /health`
Returns top-level platform health.
- **Status:** 200 OK (or 503 if critical dependencies are down)
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "environment": "production",
  "timestamp": "2026-11-07T13:30:00Z"
}
```

#### `GET /health/database` & `GET /health/redis`
- **Status:** 200 OK / 503 Service Unavailable

---

### 4.2 Authentication Endpoints (`/api/v1/auth`)

- `POST /api/v1/auth/register` (HTTP 201 Created)
- `POST /api/v1/auth/login` (HTTP 200 OK)
- `POST /api/v1/auth/refresh` (HTTP 200 OK)
- `POST /api/v1/auth/logout` (HTTP 200 OK)
- `GET /api/v1/auth/me` & `GET /api/v1/users/me` (HTTP 200 OK)

---

### 4.3 Website Scan & Assessment Endpoints (`/api/v1/scans`)

- `POST /api/v1/scans` (HTTP 202 Accepted for new scan, HTTP 200 OK if deduplicated within 60s)
- `GET /api/v1/scans` (HTTP 200 OK, paginated user scans)
- `GET /api/v1/scans/{scan_id}` (HTTP 200 OK, full report)
- `GET /api/v1/scans/{scan_id}/findings` (HTTP 200 OK)
- `GET /api/v1/scans/{scan_id}/certificate` (HTTP 200 OK — Enriched with Certificate Intelligence Trust Score, Verdict, Policy Evaluation, ML Advisory, and Findings)
- `DELETE /api/v1/scans/{scan_id}` (HTTP 204 No Content)

---

### 4.4 Dedicated Certificate Intelligence Endpoints (`/api/v1/certificates`)

#### `POST /api/v1/certificates/analyze` (Direct Certificate Analysis)
Evaluates an X.509 certificate supplied as raw DER (`certificate_der_base64`), PEM bundle string (`certificate_pem`), or live TLS server probe (`target_hostname`).

- **Request Schema (`CertificateAnalyzeRequest`):**
```json
{
  "target_hostname": "api.trustlens.io",
  "port": 443,
  "tls_protocol_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "reference_observation_timestamp": "2026-11-08T12:00:00Z",
  "certificate_der_base64": "MIIB/DCCAY6gAwIBAgIUQzB4S...",
  "presented_intermediates_base64": [
    "MIIChzCCAi6gAwIBAgIQB1r3P..."
  ],
  "certificate_pem": null,
  "revocation_observation": {
    "source_url": "http://ocsp.pki.goog/gts1p5",
    "observation_timestamp": "2026-11-08T11:58:30Z",
    "status": "GOOD",
    "responder_type": "OCSP",
    "evidence_freshness_seconds": 90
  },
  "include_ml_advisory": true
}
```

- **Response (HTTP 200 OK — `CertificateAssessmentResponse`):**
```json
{
  "id": "c86e04bb-3031-419b-a3da-166fbbfbece6",
  "target_hostname": "api.trustlens.io",
  "certificate_sha256": "0a7976204137da6b50dbcff396ad5102a27b68d1820b29449dff352706782275",
  "subject_dn": "CN=api.trustlens.io,O=TrustLens Security",
  "issuer_dn": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
  "verdict": "TRUSTED",
  "trust_score": 95,
  "confidence": 0.95,
  "scoring_version": "cert_v1.0.0",
  "checks_completed": 8,
  "findings": [
    {
      "code": "RULE_TRUSTED_PATH_VERIFIED",
      "title": "Certification Path Validated to Root Anchor",
      "severity": "INFO",
      "description": "Certification path successfully chains to trusted Mozilla root store.",
      "evidence": null,
      "recommendation": null,
      "score_deduction": 0
    },
    {
      "code": "RULE_HOSTNAME_MATCHED",
      "title": "Service Identity Authenticated per RFC 9525",
      "severity": "INFO",
      "description": "Certificate matches target hostname via SAN extension.",
      "evidence": null,
      "recommendation": null,
      "score_deduction": 0
    }
  ],
  "features": {
    "public_key_algorithm": "RSA",
    "key_size_bits": 2048,
    "validity_duration_days": 90.0,
    "days_until_expiry": 45,
    "is_expired": false
  },
  "policy_evaluation": {
    "cabf_br_version": "2.3.1",
    "compliant": true
  },
  "ml_advisory": {
    "predicted_class": "COMPLIANT",
    "compliance_probability": 0.98,
    "is_anomaly": false,
    "anomaly_score": 0.12,
    "confidence": 0.96,
    "advisory_notes": "Certificate profile aligns with authentic Web PKI distribution."
  },
  "recommendations": [],
  "summary": "Valid and trusted Web PKI certificate chaining cleanly to Mozilla Root Store.",
  "evaluated_at": "2026-11-08T13:45:00Z"
}
```

#### `GET /api/v1/certificates/{id}` (Get Certificate Assessment)
Retrieves a stored certificate assessment by ID.
- **Status:** 200 OK
- **Response:** `CertificateAssessmentResponse`

#### `GET /api/v1/certificates` (List Certificate Assessments)
Returns paginated certificate analyses evaluated by the authenticated user.
- **Query Parameters:** `limit` (default 20, max 100), `offset` (default 0)
- **Status:** 200 OK
- **Response:**
```json
{
  "items": [
    {
      "id": "c86e04bb-3031-419b-a3da-166fbbfbece6",
      "target_hostname": "api.trustlens.io",
      "certificate_sha256": "0a7976204137da6b50dbcff396ad5102a27b68d1820b29449dff352706782275",
      "trust_score": 95,
      "verdict": "TRUSTED",
      "confidence": 0.95,
      "checks_completed": 8,
      "scanned_at": "2026-11-08T13:45:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

### 4.5 Dedicated Web Security Posture Analysis Endpoints (`/api/v1/web-security` & `/api/v1/analyze/web-security`)

#### `POST /api/v1/web-security/analyze` and `POST /api/v1/analyze/web-security` (Handoff Alias)
Executes safe passive telemetry extraction, evaluates 22 deterministic security rules, runs calibrated ML posture classification with abstention, aggregates risk, and produces evidence-backed remediation guidance.
- **Access:** Public or Authenticated (if authenticated, binds to user history)
- **Request:**
```json
{
  "url": "https://example.com",
  "force_fresh": false
}
```
- **Response (HTTP 200 OK):**
```json
{
  "id": "e96b7834-8c03-4f98-9008-011242bbcc44",
  "target_url": "https://example.com",
  "normalized_domain": "example.com",
  "registrable_domain": "example.com",
  "scan_timestamp": "2026-11-08T22:30:00Z",
  "scanner_version": "1.0.0",
  "posture": "GOOD",
  "security_score": 88.5,
  "deterministic_posture": "GOOD",
  "ml_prediction": {
    "available": true,
    "predicted_posture": "GOOD",
    "probabilities": {
      "GOOD": 0.88,
      "MODERATE": 0.10,
      "POOR": 0.02
    },
    "confidence": 0.88,
    "margin": 0.78,
    "abstained": false,
    "model_name": "HistGradientBoosting",
    "model_version": "1.0.0"
  },
  "consensus": {
    "status": "CONSENSUS",
    "discrepancy_explanation": null
  },
  "findings_summary": {
    "total_findings": 6,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 1,
    "low_count": 2,
    "pass_count": 3,
    "affected_categories": ["HTTP_HEADERS", "TLS_SECURITY"]
  },
  "findings": [
    {
      "finding_id": "HDR-HSTS-PASS",
      "category": "HTTP_HEADERS",
      "name": "Strict-Transport-Security Configured",
      "severity": "PASS",
      "status": "COMPLIANT",
      "evidence": "max-age=31536000; includeSubDomains; preload",
      "detection_method": "DETERMINISTIC_RULE_INSPECTION",
      "confidence": 1.0,
      "guidance": "RFC 6797",
      "recommendation": null
    }
  ],
  "remediations": [
    {
      "finding_id": "HDR-CSP-LOW",
      "severity": "LOW",
      "category": "HTTP_HEADERS",
      "recommendation": "Configure a restrictive Content-Security-Policy header."
    }
  ],
  "telemetry": {
    "status_code": 200,
    "hsts_present": true
  },
  "summary_text": "Executive assessment summary text...",
  "scanned_at": "2026-11-08T22:30:00Z"
}
```

#### `GET /api/v1/web-security/{id}`
Retrieves a stored web security posture assessment by ID.
- **Status:** 200 OK
- **Response:** `WebSecurityAssessmentResponse`

#### `GET /api/v1/web-security`
Returns paginated web security assessments with optional domain and posture filtering.
- **Query Parameters:** `domain` (string), `posture` (GOOD, MODERATE, POOR), `page` (default 1), `limit` (default 20)
- **Status:** 200 OK
- **Response:** `WebSecurityScanListResponse`

---

### 4.6 Dashboard Endpoints (`/api/v1/dashboard`)

#### `GET /api/v1/dashboard/summary`
Returns user-scoped security scan statistics, verdict distributions, and the 10 most recent scans.
- **Status:** 200 OK
- **Response:**
```json
{
  "summary": {
    "total_scans": 18,
    "scans_last_30_days": 12,
    "verdict_counts": {
      "SAFE": 9,
      "SUSPICIOUS": 5,
      "MALICIOUS": 2,
      "INCONCLUSIVE": 2
    },
    "active_scans": 1,
    "pending_community_reports": 2
  },
  "recent_scans": [
    {
      "id": "c1f7b029-4556-41bf-bb44-ec853c8b4ad1",
      "canonical_url": "https://example.com/login",
      "host": "example.com",
      "status": "succeeded",
      "verdict": "SAFE",
      "risk_score": 12,
      "created_at": "2026-11-07T13:32:00Z",
      "completed_at": "2026-11-07T13:32:04Z"
    }
  ]
}
```

---

### 4.5 Collaborative Threat Reporting Endpoints (`/api/v1/community/reports`)

#### `POST /api/v1/community/reports` (Submit Report)
Submits a suspicious URL with observed technical evidence for moderator review.
- **Request:**
```json
{
  "url": "https://payments-example.test/secure/login",
  "scan_id": null,
  "category": "phishing",
  "claimed_verdict": "MALICIOUS",
  "evidence_text": "The page impersonates a corporate payment portal and harvests account credentials on an unassociated domain."
}
```
- **Response A: Fresh Submission (HTTP 201 Created):**
```json
{
  "report": {
    "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
    "canonical_url": "https://payments-example.test/secure/login",
    "host": "payments-example.test",
    "category": "phishing",
    "claimed_verdict": "MALICIOUS",
    "status": "pending",
    "evidence_text": "The page impersonates a corporate payment portal and harvests account credentials on an unassociated domain.",
    "created_at": "2026-11-07T14:00:00Z",
    "moderated_at": null
  },
  "duplicate_submission": false
}
```
- **Response B: Deduplicated Submission within 30 Days (HTTP 200 OK):**
Returns the existing report with `duplicate_submission: true`.

#### `GET /api/v1/community/reports` (Public Confirmed Feed)
Public endpoint. Returns only `confirmed` reports with confirmation and false-positive vote counts.
- **Query Parameters:** `category`, `host`, `page`, `page_size`
- **Response (HTTP 200 OK):**
```json
{
  "items": [
    {
      "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
      "canonical_url": "https://payments-example.test/secure/login",
      "host": "payments-example.test",
      "category": "phishing",
      "claimed_verdict": "MALICIOUS",
      "status": "confirmed",
      "evidence_summary": "The page impersonates a corporate payment portal...",
      "confirmation_count": 8,
      "false_positive_count": 1,
      "created_at": "2026-11-07T14:00:00Z",
      "moderated_at": "2026-11-07T14:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

#### `GET /api/v1/community/reports/mine` (My Submissions)
Returns private history of reports submitted by the authenticated user across all moderation states (`pending`, `confirmed`, `rejected`, `duplicate`).
- **Response (HTTP 200 OK):** Paginated array of `UserCommunityReportItem`.

#### `GET /api/v1/community/reports/{report_id}` (Report Detail)
- Public users can view only `confirmed` reports.
- Report owner and moderators can view report in any state.
- **Response (HTTP 200 OK):** Detailed report data with vote counts and moderation explanation.

#### `POST /api/v1/community/reports/{report_id}/votes` (Cast/Update Vote)
Endorses or disputes a confirmed report.
- **Request:**
```json
{
  "vote": "confirm"
}
```
- **Response (HTTP 200 OK):**
```json
{
  "report_id": "d78f341b-82a7-42e8-ae75-8d5000124001",
  "vote": "confirm",
  "updated": false,
  "counts": {
    "confirm": 9,
    "false_positive": 1
  }
}
```

---

### 4.6 Moderation & Administration Endpoints (`/api/v1/admin`)

#### `GET /api/v1/admin/reports` (Moderator Queue)
Returns pending reports for triage. Restricted to `moderator` and `admin` roles.
- **Query Parameters:** `status` (default: `pending`), `page`, `page_size`
- **Response (HTTP 200 OK):** Paginated array of `AdminReportItem`.

#### `POST /api/v1/admin/reports/{report_id}/moderation` (Record Decision)
Atomically commits a moderation decision and appends an auditable record in `audit_events`.
- **Request:**
```json
{
  "decision": "confirmed",
  "reason": "Independently verified phishing page replicating brand assets on an unassociated domain."
}
```
- **Response (HTTP 200 OK):**
```json
{
  "report": {
    "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
    "status": "confirmed",
    "moderator_user_id": "9f3f0ae8-21e3-5d0f-b3b3-5f1ef6e8a202",
    "moderation_reason": "Independently verified phishing page replicating brand assets on an unassociated domain.",
    "moderated_at": "2026-11-07T14:30:00Z"
  },
  "audit_event_id": "e89a452c-93b8-53f9-bf86-9e6112345001"
}
```

#### `GET /api/v1/admin/providers` (Feed Telemetry)
Returns operational status and freshness of OpenPhish and URLhaus feeds.

---

## 5. Polling & State Transition Rules

### 5.1 Scan State Machine
`queued` -> `running` -> (`succeeded` | `partial` | `failed`)

### 5.2 Polling Algorithm
1. Poll `GET /api/v1/scans/:scanId` every **2 seconds** for initial 30 seconds.
2. Back off to **5 seconds** if active beyond 30 seconds.
3. Terminate polling on `succeeded`, `partial`, or `failed`.
4. Pause on document visibility hidden; resume immediately on visible.

---

## 6. Verdict Semantics & UI Copy Rules

| Verdict | Meaning | Token | Mandatory Canonical Copy |
|---|---|---|---|
| `SAFE` | Bounded checks found no known threats or high-severity vulnerabilities. | `--color-safe` (`#15803D`) | *"No material risk was found by the checks performed. This is not a guarantee that the website is safe."* |
| `SUSPICIOUS` | Indicators requiring caution (e.g. self-signed TLS, unconfirmed reports, missing security controls). | `--color-suspicious` (`#B45309`) | *"Some signals require caution. Review the findings before sharing information."* |
| `MALICIOUS` | Direct match in threat feed or confirmed community intelligence. | `--color-malicious` (`#B91C1C`) | *"This URL matched a trusted threat indicator or independently confirmed community intelligence. Do not visit or enter information."* |
| `INCONCLUSIVE` | DNS/HTTP lookup failed, worker timeout, or sensitive URL prevented full scan. | `--color-inconclusive` (`#475569`) | *"TrustLens could not collect enough reliable evidence. Do not interpret this result as safe."* |

---

## 7. Ready-to-Use TypeScript Definitions (`api.ts`)

```typescript
// ==========================================
// TrustLens API TypeScript Type Definitions
// ==========================================

export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'partial' | 'failed';
export type ScanVerdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'INCONCLUSIVE';
export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingCategory = 'threat_intel' | 'web_security' | 'certificate' | 'community';
export type LayerCoverageStatus = 'complete' | 'partial' | 'unavailable' | 'not_applicable';
export type ProviderResultStatus = 
  | 'match' 
  | 'no_match' 
  | 'unavailable' 
  | 'not_configured' 
  | 'skipped_sensitive_url' 
  | 'stale_cache';

export type ReportCategory = 
  | 'phishing' 
  | 'malware' 
  | 'scam' 
  | 'credential_harvesting' 
  | 'unsolicited_bulk' 
  | 'other';
export type ClaimedVerdict = 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';
export type ReportStatus = 'pending' | 'confirmed' | 'rejected' | 'duplicate';
export type VoteType = 'confirm' | 'false_positive';
export type ModerationDecision = 'confirmed' | 'rejected' | 'duplicate';

// Error Envelope
export interface ApiErrorPayload {
  error: {
    code: string;
    message: string;
    request_id: string;
    details?: Record<string, unknown> | null;
  };
}

// User & Auth
export interface UserRecord {
  id: string;
  email: string;
  display_name: string;
  role: 'user' | 'admin' | 'moderator';
  is_active: boolean;
  created_at: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  csrf_token: string;
}

export interface AuthResponse {
  user: UserRecord;
  tokens: AuthTokens;
}

// Dashboard
export interface DashboardVerdictCounts {
  SAFE: number;
  SUSPICIOUS: number;
  MALICIOUS: number;
  INCONCLUSIVE: number;
}

export interface DashboardSummaryMetrics {
  total_scans: number;
  scans_last_30_days: number;
  verdict_counts: DashboardVerdictCounts;
  active_scans: number;
  pending_community_reports: number;
}

export interface DashboardRecentScanItem {
  id: string;
  canonical_url: string;
  host: string;
  status: ScanStatus;
  verdict: ScanVerdict;
  risk_score: number | null;
  created_at: string;
  completed_at: string | null;
}

export interface DashboardSummaryResponse {
  summary: DashboardSummaryMetrics;
  recent_scans: DashboardRecentScanItem[];
}

// Community Reports & Voting
export interface CommunityReportCreateRequest {
  url: string;
  scan_id?: string | null;
  category: ReportCategory;
  claimed_verdict: ClaimedVerdict;
  evidence_text: string;
}

export interface CommunityReportResponse {
  id: string;
  canonical_url: string;
  host: string;
  category: string;
  claimed_verdict: string;
  status: ReportStatus;
  evidence_text: string;
  created_at: string;
  moderated_at: string | null;
}

export interface CommunityReportSubmitResponse {
  report: CommunityReportResponse;
  duplicate_submission: boolean;
}

export interface PublicCommunityReportItem {
  id: string;
  canonical_url: string;
  host: string;
  category: string;
  claimed_verdict: string;
  status: ReportStatus;
  evidence_summary: string;
  confirmation_count: number;
  false_positive_count: number;
  created_at: string;
  moderated_at: string | null;
}

export interface UserCommunityReportItem {
  id: string;
  canonical_url: string;
  category: string;
  claimed_verdict: string;
  status: ReportStatus;
  evidence_text: string;
  moderation_reason: string | null;
  created_at: string;
  moderated_at: string | null;
}

export interface CommunityReportDetailData {
  id: string;
  canonical_url: string;
  host: string;
  category: string;
  claimed_verdict: string;
  status: ReportStatus;
  evidence_summary: string;
  confirmation_count: number;
  false_positive_count: number;
  moderation_reason: string | null;
  created_at: string;
  moderated_at: string | null;
}

export interface CommunityReportDetailResponse {
  report: CommunityReportDetailData;
}

export interface CommunityVoteRequest {
  vote: VoteType;
}

export interface CommunityVoteCounts {
  confirm: number;
  false_positive: number;
}

export interface CommunityVoteResponse {
  report_id: string;
  vote: VoteType;
  updated: boolean;
  counts: CommunityVoteCounts;
}

// Moderation & Admin
export interface AdminReportItem {
  id: string;
  canonical_url: string;
  host: string;
  category: string;
  claimed_verdict: string;
  status: ReportStatus;
  evidence_text: string;
  reporter_id: string;
  confirmation_count: number;
  false_positive_count: number;
  created_at: string;
}

export interface ModerationDecisionRequest {
  decision: ModerationDecision;
  reason: string;
}

export interface ModeratedReportData {
  id: string;
  status: ReportStatus;
  moderator_user_id: string;
  moderation_reason: string;
  moderated_at: string;
}

export interface ModerationDecisionResponse {
  report: ModeratedReportData;
  audit_event_id: string;
}

export interface ProviderHealthItem {
  provider: string;
  enabled: boolean;
  status: string;
  last_success_at: string | null;
  freshness_seconds: number | null;
  freshness_limit_seconds: number | null;
  records_active: number | null;
}

export interface ProviderHealthResponse {
  providers: ProviderHealthItem[];
}

// Scans & Reports
export interface ScanCreateRequest {
  url: string;
  treat_as_sensitive?: boolean;
}

export interface ScanRecord {
  id: string;
  original_url: string;
  canonical_url: string;
  host: string;
  scheme: string;
  is_sensitive: boolean;
  status: ScanStatus;
  verdict: ScanVerdict;
  risk_score: number | null;
  scoring_version: string;
  checks_completed: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  failure_code: string | null;
  failure_message: string | null;
}

export interface ScanSubmitResponse {
  scan: ScanRecord;
  deduplicated: boolean;
}

export interface ScanSummaryItem {
  id: string;
  canonical_url: string;
  host: string;
  status: ScanStatus;
  verdict: ScanVerdict;
  risk_score: number | null;
  created_at: string;
  completed_at: string | null;
}

export interface LayerCoverage {
  threat_intel: LayerCoverageStatus;
  web_security: LayerCoverageStatus;
  certificate: LayerCoverageStatus;
  community: LayerCoverageStatus;
}

export interface ProviderCheckItem {
  provider: string;
  result_status: ProviderResultStatus;
  matched: boolean;
  checked_at: string;
  details: Record<string, unknown>;
}

export interface RedirectHopItem {
  hop: number;
  source_url: string;
  destination_url: string;
  status_code: number;
  host: string;
  ip: string;
  tls_verified: boolean;
}

export interface ScanDetailResponse {
  scan: ScanRecord;
  coverage: LayerCoverage;
  provider_checks: ProviderCheckItem[];
  redirects: RedirectHopItem[];
}

export interface FindingItem {
  code: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  category: FindingCategory;
  points: number;
  evidence: Record<string, unknown>;
  remediation: string;
  source: string;
}

export interface CertificateDetails {
  host: string;
  valid: boolean;
  subject: string;
  issuer: string;
  valid_from: string | null;
  valid_to: string | null;
  days_until_expiration: number | null;
  sans: string[];
  serial_number: string | null;
  sha256_fingerprint: string | null;
  signature_algorithm: string | null;
  key_algorithm: string | null;
  chain_valid: boolean;
  hostname_match: boolean;
  reasons: string[];
}

// Paginated Container
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}
```

---

## 8. Summary Checklist for UI/UX Engineer

- [x] **Backend Ready:** All Phase 1–7 APIs implemented with Async SQLAlchemy and FastAPI.
- [x] **Automated Tests:** 57/57 passing unit and integration tests.
- [x] **SSRF Defense:** Hardened against loopback, cloud metadata (169.254.169.254), carrier-grade NAT, and private IPs.
- [x] **Deduplication:** Automatic 60-second window on scans and 30-day window on community reports.
- [x] **AI Contract Guardrails:** Typed Pydantic and JSON schema contracts integrated without fabricating ML scores.
- [x] **Dashboard:** User-scoped analytics, 30-day velocity, verdict breakdowns, and recent scan logs.
- [x] **Community Intelligence:** Confirmed reports public feed, crowd voting, and auditable moderator triage.
