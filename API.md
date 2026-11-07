# TrustLens — Database and API Contract

**Document version:** 1.0  
**API base path:** `/api/v1`  
**Transport:** HTTPS, JSON request/response bodies  
**Authentication:** Opaque server-side session cookie  
**API style:** REST, snake_case fields, UUID identifiers  

## 1. Global API conventions

### 1.1 Common headers

All production requests use HTTPS.

| Header | Requirement | Purpose |
|---|---|---|
| `Accept: application/json` | Required | Response representation |
| `Content-Type: application/json` | Required for JSON bodies | Request representation |
| `Cookie: __Host-trustlens_session=<opaque-token>` | Required for authenticated routes | Session authentication; cookie is Secure, HttpOnly, SameSite=Lax, Path=/, no Domain attribute |
| `X-CSRF-Token: <token>` | Required for authenticated state-changing routes | Per-session CSRF protection |
| `Origin: https://app.trustlens.example` | Required for browser state-changing routes | Exact allowlist check; the production origin is deployment configuration |
| `X-Request-ID: <client-generated-id>` | Optional | Correlation; server generates one when absent and validates length/characters |

The raw session cookie is never returned in JSON. Registration/login responses return `csrf_token` in JSON. Store it in memory in the SPA and send it in `X-CSRF-Token`; do not persist it to localStorage.

### 1.2 Content and pagination

- JSON encoding is UTF-8.
- All timestamps are ISO 8601 UTC strings with a trailing `Z`.
- IDs are UUID v4 strings.
- List endpoints use `page` (default `1`) and `page_size` (default `20`, maximum `100`).
- List results include `items`, `page`, `page_size`, and `total`.
- All user-private endpoints enforce owner scoping in SQL queries. UUID secrecy is not authorization.
- Unknown JSON fields are rejected with HTTP 400.
- Request validation errors are mapped to the standard `VALIDATION_ERROR` response, not FastAPI's default validation payload.

### 1.3 Common enum values

```json
{
  "scan_status": ["queued", "running", "succeeded", "partial", "failed"],
  "verdict": ["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"],
  "finding_category": ["threat_intel", "web_security", "certificate", "community"],
  "finding_severity": ["info", "low", "medium", "high", "critical"],
  "provider_result_status": ["match", "no_match", "unavailable", "not_configured", "skipped_sensitive_url", "stale_cache"],
  "community_report_status": ["pending", "confirmed", "rejected", "duplicate"],
  "community_vote": ["confirm", "false_positive"],
  "community_category": ["phishing", "malware", "impersonation", "fraudulent_payment", "scam", "suspicious_redirect", "other"],
  "claimed_verdict": ["SUSPICIOUS", "MALICIOUS"]
}
```

### 1.4 Standard error envelope

Every API error uses this structure. `details` is an array and may be empty. `request_id` must match the response correlation ID.

**400 Bad Request example**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request could not be processed because one or more fields are invalid.",
    "request_id": "req_01J9TRUSTLENS000000000001",
    "details": [
      {
        "field": "url",
        "issue": "A valid absolute HTTP or HTTPS URL is required."
      }
    ]
  }
}
```

**401 Unauthorized example**

```json
{
  "error": {
    "code": "AUTHENTICATION_REQUIRED",
    "message": "A valid authenticated session is required.",
    "request_id": "req_01J9TRUSTLENS000000000002",
    "details": []
  }
}
```

**403 Forbidden example**

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to perform this action.",
    "request_id": "req_01J9TRUSTLENS000000000003",
    "details": []
  }
}
```

**404 Not Found example**

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found.",
    "request_id": "req_01J9TRUSTLENS000000000004",
    "details": []
  }
}
```

**409 Conflict example**

```json
{
  "error": {
    "code": "STATE_CONFLICT",
    "message": "The requested operation conflicts with the current resource state.",
    "request_id": "req_01J9TRUSTLENS000000000005",
    "details": [
      {
        "field": "status",
        "issue": "Only a pending report can be moderated."
      }
    ]
  }
}
```

**429 Too Many Requests example**

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "The request limit has been reached. Try again after the indicated interval.",
    "request_id": "req_01J9TRUSTLENS000000000006",
    "details": [
      {
        "field": "retry_after_seconds",
        "issue": "600"
      }
    ]
  }
}
```

**500 Internal Server Error example**

```json
{
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "TrustLens could not complete the request. Use the request ID when contacting support.",
    "request_id": "req_01J9TRUSTLENS000000000007",
    "details": []
  }
}
```

Error codes are stable identifiers; human-readable messages may be refined. Never return stack traces, SQL errors, provider credentials, internal IP addresses, or raw exception messages.

## 2. Database schema

### 2.1 PostgreSQL ER diagram

```mermaid
erDiagram
    USERS {
        UUID id PK
        VARCHAR_320 email UK
        TEXT password_hash
        VARCHAR_80 display_name
        VARCHAR_20 role
        VARCHAR_20 account_status
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
        TIMESTAMPTZ last_login_at
    }

    SESSIONS {
        UUID id PK
        UUID user_id FK
        CHAR_64 token_hash UK
        CHAR_64 csrf_token_hash
        TIMESTAMPTZ created_at
        TIMESTAMPTZ last_seen_at
        TIMESTAMPTZ expires_at
        TIMESTAMPTZ revoked_at
        VARCHAR_64 revoke_reason
    }

    SCANS {
        UUID id PK
        UUID user_id FK
        VARCHAR_2048 original_url
        VARCHAR_2048 canonical_url
        VARCHAR_253 host
        VARCHAR_5 scheme
        BOOLEAN is_sensitive
        VARCHAR_20 status
        VARCHAR_20 verdict
        SMALLINT risk_score
        VARCHAR_32 scoring_version
        SMALLINT checks_completed
        TIMESTAMPTZ created_at
        TIMESTAMPTZ started_at
        TIMESTAMPTZ completed_at
        VARCHAR_64 failure_code
        VARCHAR_500 failure_message
    }

    FINDINGS {
        UUID id PK
        UUID scan_id FK
        VARCHAR_30 category
        VARCHAR_80 code
        VARCHAR_160 title
        TEXT description
        VARCHAR_12 severity
        SMALLINT points
        JSONB evidence
        TEXT remediation
        VARCHAR_80 source
        TIMESTAMPTZ created_at
    }

    SCAN_REDIRECTS {
        UUID id PK
        UUID scan_id FK
        SMALLINT hop_index
        VARCHAR_2048 source_url
        VARCHAR_2048 destination_url
        SMALLINT http_status
        VARCHAR_253 resolved_host
        JSONB resolved_ips
        BOOLEAN tls_verified
        TIMESTAMPTZ created_at
    }

    CERTIFICATES {
        UUID id PK
        UUID scan_id FK_UK
        VARCHAR_253 host
        SMALLINT port
        CHAR_64 leaf_fingerprint_sha256
        VARCHAR_255 subject_cn
        JSONB san_dns
        VARCHAR_255 issuer
        VARCHAR_128 serial_number
        TIMESTAMPTZ not_before
        TIMESTAMPTZ not_after
        VARCHAR_100 signature_algorithm
        VARCHAR_80 public_key_algorithm
        SMALLINT public_key_bits
        BOOLEAN chain_valid
        BOOLEAN hostname_match
        BOOLEAN sct_present
        TIMESTAMPTZ fetched_at
    }

    PROVIDER_CHECKS {
        UUID id PK
        UUID scan_id FK
        VARCHAR_40 provider
        VARCHAR_32 result_status
        BOOLEAN matched
        JSONB details
        TIMESTAMPTZ checked_at
    }

    THREAT_INDICATORS {
        UUID id PK
        VARCHAR_16 indicator_type
        VARCHAR_2048 normalized_value
        VARCHAR_40 source
        SMALLINT confidence
        VARCHAR_128 source_record_id
        TIMESTAMPTZ first_seen
        TIMESTAMPTZ last_seen
        BOOLEAN active
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    COMMUNITY_REPORTS {
        UUID id PK
        UUID reporter_user_id FK
        UUID scan_id FK
        VARCHAR_2048 original_url
        VARCHAR_2048 canonical_url
        VARCHAR_253 host
        VARCHAR_40 category
        VARCHAR_20 claimed_verdict
        TEXT evidence_text
        VARCHAR_20 status
        UUID moderator_user_id FK
        TEXT moderation_reason
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
        TIMESTAMPTZ moderated_at
    }

    COMMUNITY_VOTES {
        UUID id PK
        UUID report_id FK
        UUID user_id FK
        VARCHAR_20 vote
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    FEED_SYNC_RUNS {
        UUID id PK
        VARCHAR_40 provider
        VARCHAR_20 status
        INTEGER records_seen
        INTEGER records_upserted
        TEXT error_summary
        TIMESTAMPTZ started_at
        TIMESTAMPTZ completed_at
    }

    AUDIT_EVENTS {
        UUID id PK
        UUID actor_user_id FK
        VARCHAR_64 action
        VARCHAR_40 target_type
        UUID target_id
        TEXT reason
        JSONB metadata
        TIMESTAMPTZ created_at
    }

    USERS ||--o{ SESSIONS : owns
    USERS ||--o{ SCANS : creates
    SCANS ||--o{ FINDINGS : contains
    SCANS ||--o{ SCAN_REDIRECTS : follows
    SCANS ||--o| CERTIFICATES : records
    SCANS ||--o{ PROVIDER_CHECKS : queries
    USERS ||--o{ COMMUNITY_REPORTS : submits
    SCANS o|--o{ COMMUNITY_REPORTS : referenced_by
    USERS ||--o{ COMMUNITY_VOTES : casts
    COMMUNITY_REPORTS ||--o{ COMMUNITY_VOTES : receives
    USERS o|--o{ COMMUNITY_REPORTS : moderates
    USERS ||--o{ AUDIT_EVENTS : performs
```

Mermaid identifiers use underscores for SQL types that contain parentheses. The authoritative SQL types are specified below; `VARCHAR_320` means `VARCHAR(320)`, `CHAR_64` means `CHAR(64)`, and likewise for the other encoded lengths.

### 2.2 Table constraints and indexes

**`users`**

- `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`.
- `email VARCHAR(320) NOT NULL UNIQUE`; normalize before insert.
- `password_hash TEXT NOT NULL` contains an Argon2id encoded hash.
- `display_name VARCHAR(80) NOT NULL`.
- `role VARCHAR(20) NOT NULL CHECK (role IN ('user','moderator','admin'))`.
- `account_status VARCHAR(20) NOT NULL CHECK (account_status IN ('active','suspended','deleted'))`.
- `created_at`, `updated_at` required; `last_login_at` nullable.

**`sessions`**

- `id UUID PRIMARY KEY`.
- `user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`.
- `token_hash CHAR(64) NOT NULL UNIQUE`; SHA-256 hex digest of the opaque cookie value.
- `csrf_token_hash CHAR(64) NOT NULL`; SHA-256 hex digest of the CSRF token.
- `created_at`, `last_seen_at`, `expires_at` required; `revoked_at`, `revoke_reason` nullable.
- Index `(user_id, expires_at)`; index on `token_hash` is unique.

**`scans`**

- `id UUID PRIMARY KEY`; `user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`.
- `original_url VARCHAR(2048) NOT NULL`; `canonical_url VARCHAR(2048) NOT NULL`; `host VARCHAR(253) NOT NULL`; `scheme VARCHAR(5) NOT NULL CHECK (scheme IN ('http','https'))`.
- `is_sensitive BOOLEAN NOT NULL DEFAULT FALSE`; true when the user selected the sensitive-URL option or an automatic secret detector flags the URL.
- `status VARCHAR(20) NOT NULL CHECK (status IN ('queued','running','succeeded','partial','failed'))`.
- `verdict VARCHAR(20) NOT NULL CHECK (verdict IN ('SAFE','SUSPICIOUS','MALICIOUS','INCONCLUSIVE'))`.
- `risk_score SMALLINT NULL CHECK (risk_score BETWEEN 0 AND 100)`; null only for failed scans without a reliable assessment.
- `scoring_version VARCHAR(32) NOT NULL`; `checks_completed SMALLINT NOT NULL DEFAULT 0`.
- `created_at` required; `started_at`, `completed_at`, `failure_code`, and `failure_message` nullable.
- Index `(user_id, created_at DESC)`, `(user_id, status, created_at DESC)`, `(canonical_url, created_at DESC)`, and `(status, created_at)`.
- Index `(user_id, canonical_url, created_at DESC)` supports active-scan deduplication.

**`findings`**

- `id UUID PRIMARY KEY`; `scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE`.
- `category VARCHAR(30) NOT NULL CHECK (category IN ('threat_intel','web_security','certificate','community'))`.
- `code VARCHAR(80) NOT NULL`; stable code identifies a rule.
- `title VARCHAR(160) NOT NULL`; `description TEXT NOT NULL`.
- `severity VARCHAR(12) NOT NULL CHECK (severity IN ('info','low','medium','high','critical'))`.
- `points SMALLINT NOT NULL CHECK (points BETWEEN 0 AND 100)`.
- `evidence JSONB NOT NULL DEFAULT '{}'`; `remediation TEXT NOT NULL`; `source VARCHAR(80) NOT NULL`.
- `created_at TIMESTAMPTZ NOT NULL`.
- Index `(scan_id, severity)` and unique `(scan_id, code)` to prevent duplicate findings in a scan.

**`scan_redirects`**

- `id UUID PRIMARY KEY`; `scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE`.
- `hop_index SMALLINT NOT NULL CHECK (hop_index BETWEEN 0 AND 5)`.
- `source_url`, `destination_url` are `VARCHAR(2048) NOT NULL`.
- `http_status SMALLINT NOT NULL`; `resolved_host VARCHAR(253) NOT NULL`.
- `resolved_ips JSONB NOT NULL DEFAULT '[]'`; `tls_verified BOOLEAN NOT NULL DEFAULT FALSE`.
- `created_at TIMESTAMPTZ NOT NULL`; unique `(scan_id, hop_index)`.

**`certificates`**

- `id UUID PRIMARY KEY`; `scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE`.
- Exactly one final-target leaf certificate snapshot is stored for a scan when an HTTPS handshake supplies a parseable certificate.
- `host VARCHAR(253) NOT NULL`; `port SMALLINT NOT NULL CHECK (port = 443)`.
- `leaf_fingerprint_sha256 CHAR(64) NOT NULL`; subject, SAN, issuer, serial and algorithm metadata are persisted as shown in the ER diagram.
- `not_before`, `not_after`, and `fetched_at` are `TIMESTAMPTZ NOT NULL`.
- `chain_valid`, `hostname_match`, and `sct_present` are `BOOLEAN NOT NULL`.
- `san_dns JSONB NOT NULL DEFAULT '[]'`.

**`provider_checks`**

- `id UUID PRIMARY KEY`; `scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE`.
- `provider VARCHAR(40) NOT NULL CHECK (provider IN ('openphish','urlhaus','community'))`.
- `result_status VARCHAR(32) NOT NULL CHECK (result_status IN ('match','no_match','unavailable','not_configured','skipped_sensitive_url','stale_cache'))`.
- `matched BOOLEAN NOT NULL`; false for all statuses other than `match`.
- `details JSONB NOT NULL DEFAULT '{}'`; `checked_at TIMESTAMPTZ NOT NULL`.
- Index `(scan_id, provider, checked_at DESC)`.

**`threat_indicators`**

- `id UUID PRIMARY KEY`.
- `indicator_type VARCHAR(16) NOT NULL CHECK (indicator_type IN ('url','domain','ip','sha256'))`.
- `normalized_value VARCHAR(2048) NOT NULL`.
- `source VARCHAR(40) NOT NULL CHECK (source IN ('openphish','urlhaus','community','manual'))`.
- `confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100)`.
- `source_record_id VARCHAR(128) NULL`; `first_seen`, `last_seen` required; `active BOOLEAN NOT NULL DEFAULT TRUE`.
- `created_at`, `updated_at` required.
- Unique `(indicator_type, normalized_value, source)`; index `(indicator_type, normalized_value, active)`.

**`community_reports`**

- `id UUID PRIMARY KEY`; `reporter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT`.
- `scan_id UUID NULL REFERENCES scans(id) ON DELETE SET NULL`.
- URL fields, category, claimed verdict, and evidence are required.
- `category VARCHAR(40) CHECK (category IN ('phishing','malware','impersonation','fraudulent_payment','scam','suspicious_redirect','other'))`.
- `claimed_verdict VARCHAR(20) CHECK (claimed_verdict IN ('SUSPICIOUS','MALICIOUS'))`.
- `status VARCHAR(20) CHECK (status IN ('pending','confirmed','rejected','duplicate'))`.
- `moderator_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL`; `moderation_reason TEXT NULL`; `moderated_at TIMESTAMPTZ NULL`.
- `created_at`, `updated_at` required.
- Index `(status, created_at DESC)`, `(canonical_url, status)`, and `(reporter_user_id, created_at DESC)`.
- Application-level deduplication checks same reporter + canonical URL + pending/confirmed status within 30 days in a transaction.

**`community_votes`**

- `id UUID PRIMARY KEY`; `report_id UUID NOT NULL REFERENCES community_reports(id) ON DELETE CASCADE`.
- `user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`.
- `vote VARCHAR(20) NOT NULL CHECK (vote IN ('confirm','false_positive'))`.
- `created_at`, `updated_at` required.
- Unique `(report_id, user_id)` ensures one vote per person per report.

**`feed_sync_runs`**

- `id UUID PRIMARY KEY`; `provider VARCHAR(40) NOT NULL`.
- `status VARCHAR(20) NOT NULL CHECK (status IN ('running','succeeded','failed'))`.
- `records_seen`, `records_upserted` are non-negative integers; `error_summary` nullable.
- `started_at TIMESTAMPTZ NOT NULL`; `completed_at TIMESTAMPTZ NULL`.
- Index `(provider, started_at DESC)`.

**`audit_events`**

- `id UUID PRIMARY KEY`; `actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT`.
- `action VARCHAR(64) NOT NULL`; `target_type VARCHAR(40) NOT NULL`; `target_id UUID NOT NULL`.
- `reason TEXT NOT NULL`; `metadata JSONB NOT NULL DEFAULT '{}'`; `created_at TIMESTAMPTZ NOT NULL`.
- Index `(target_type, target_id, created_at DESC)` and `(actor_user_id, created_at DESC)`.
- Application role receives `INSERT` and `SELECT` access; ordinary product routes must not update or delete audit events.

### 2.3 Database ownership rules

- `users` own `sessions` and `scans`.
- Deleting a user deletes their sessions and private scans; reporter identity on community reports is retained through `ON DELETE RESTRICT` until an account-deletion workflow anonymizes the report while preserving the audit chain.
- `findings`, `scan_redirects`, `certificates`, and `provider_checks` cascade with scan deletion.
- Community votes cascade when their report is deleted.
- Moderation history is preserved in `audit_events`.
- All scan responses are assembled from these relations; no second JSON report blob is authoritative.

## 3. REST endpoints

### 3.1 Endpoint index

| Method | Path | Auth | Success |
|---|---|---|---:|
| GET | `/health/live` | No | 200 |
| GET | `/health/ready` | Internal network only | 200 |
| POST | `/auth/register` | No | 201 |
| POST | `/auth/login` | No | 200 |
| POST | `/auth/logout` | Yes + CSRF | 200 |
| GET | `/users/me` | Yes | 200 |
| POST | `/scans` | Yes + CSRF | 202 or 200 deduplicated |
| GET | `/scans` | Yes | 200 |
| GET | `/scans/{scan_id}` | Yes, owner | 200 |
| GET | `/scans/{scan_id}/findings` | Yes, owner | 200 |
| GET | `/scans/{scan_id}/certificate` | Yes, owner | 200 |
| GET | `/dashboard/summary` | Yes | 200 |
| POST | `/community/reports` | Yes + CSRF | 201 or 200 duplicate |
| GET | `/community/reports` | Public | 200 |
| GET | `/community/reports/mine` | Yes | 200 |
| GET | `/community/reports/{report_id}` | Public confirmed; owner/moderator otherwise | 200 |
| POST | `/community/reports/{report_id}/votes` | Yes + CSRF | 200 |
| GET | `/admin/reports` | Moderator/admin | 200 |
| POST | `/admin/reports/{report_id}/moderation` | Moderator/admin + CSRF | 200 |
| GET | `/admin/providers` | Moderator/admin | 200 |

All paths above are relative to `/api/v1`.

### 3.2 Health endpoints

#### GET `/health/live`

No authentication. Used by container liveness probes. Does not perform database or provider checks.

**200 response**

```json
{
  "status": "alive",
  "service": "trustlens-api",
  "version": "1.0.0"
}
```

Possible errors: `500` with the standard `INTERNAL_ERROR` envelope only if the process cannot serialize a response.

#### GET `/health/ready`

Internal network only; not routed through the public frontend. Performs bounded PostgreSQL and Redis connectivity checks.

**200 response**

```json
{
  "status": "ready",
  "checks": {
    "postgres": "ok",
    "redis": "ok"
  }
}
```

**503 response**

```json
{
  "error": {
    "code": "DEPENDENCY_UNAVAILABLE",
    "message": "One or more required dependencies are unavailable.",
    "request_id": "req_01J9TRUSTLENS000000000008",
    "details": [
      {
        "field": "postgres",
        "issue": "unavailable"
      }
    ]
  }
}
```

### 3.3 Authentication endpoints

#### POST `/auth/register`

Creates an account and starts a session. The request body is validated strictly. The origin must be in the configured frontend-origin allowlist.

**Request headers:** `Content-Type`, `Accept`, `Origin`.  
**Request body**

```json
{
  "email": "alex@example.com",
  "password": "Correct-Horse-Battery-2026!",
  "display_name": "Alex Morgan"
}
```

**201 response**

`Set-Cookie` is also returned with `__Host-trustlens_session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and a 7-day absolute expiry.

```json
{
  "user": {
    "id": "8e2e9df7-10d2-4c9e-a2a2-4e0de5d7f001",
    "email": "alex@example.com",
    "display_name": "Alex Morgan",
    "role": "user",
    "account_status": "active",
    "created_at": "2026-11-07T05:45:00Z"
  },
  "csrf_token": "4k7l6nQZbNf7oRzM3n4hL7yC0b9aV1xW8p2dS6tK5mE",
  "session_expires_at": "2026-11-14T05:45:00Z"
}
```

Applicable errors: `400 VALIDATION_ERROR`, `400 EMAIL_ALREADY_REGISTERED`, `429 RATE_LIMIT_EXCEEDED`, `500 INTERNAL_ERROR`. A duplicate email response uses the common error envelope with code `EMAIL_ALREADY_REGISTERED`; do not reveal account existence through login responses.

#### POST `/auth/login`

**Request headers:** `Content-Type`, `Accept`, `Origin`.  
**Request body**

```json
{
  "email": "alex@example.com",
  "password": "Correct-Horse-Battery-2026!"
}
```

**200 response**

```json
{
  "user": {
    "id": "8e2e9df7-10d2-4c9e-a2a2-4e0de5d7f001",
    "email": "alex@example.com",
    "display_name": "Alex Morgan",
    "role": "user",
    "account_status": "active",
    "created_at": "2026-11-07T05:45:00Z"
  },
  "csrf_token": "aP8mV7kT3nR2xW6qL9zC4bH1sD5fG0jE8uY6iO2pQ1A",
  "session_expires_at": "2026-11-14T06:00:00Z"
}
```

Applicable errors: `400 VALIDATION_ERROR`, `401 INVALID_CREDENTIALS` using generic text, `403 ACCOUNT_SUSPENDED`, `429 RATE_LIMIT_EXCEEDED`, `500 INTERNAL_ERROR`.

#### POST `/auth/logout`

Requires session cookie, `X-CSRF-Token`, and allowed `Origin`.

**Request body:** none.  
**200 response**

```json
{
  "logged_out": true
}
```

Response expires the session cookie. Applicable errors: `401 AUTHENTICATION_REQUIRED`, `403 CSRF_VALIDATION_FAILED`, `500 INTERNAL_ERROR`.

#### GET `/users/me`

**200 response**

```json
{
  "user": {
    "id": "8e2e9df7-10d2-4c9e-a2a2-4e0de5d7f001",
    "email": "alex@example.com",
    "display_name": "Alex Morgan",
    "role": "user",
    "account_status": "active",
    "created_at": "2026-11-07T05:45:00Z",
    "last_login_at": "2026-11-07T06:00:00Z"
  }
}
```

Applicable errors: `401 AUTHENTICATION_REQUIRED`, `500 INTERNAL_ERROR`.

### 3.4 Scan endpoints

#### POST `/scans`

Creates an asynchronous scan. The API validates URL syntax and the initial DNS/IP policy; the worker repeats all checks at connection time. The initial check must not perform an HTTP fetch. If `treat_as_sensitive` is true, no full URL is sent to third-party threat providers. The same is true when automatic secret detection flags the URL.

**Request headers:** session cookie, `X-CSRF-Token`, `Origin`, `Content-Type`.  
**Request body**

```json
{
  "url": "https://www.example.org/security?source=mail",
  "treat_as_sensitive": false
}
```

**202 response**

```json
{
  "scan": {
    "id": "a45c01e8-59d4-4eb8-99b2-5a2dd79e1001",
    "original_url": "https://www.example.org/security?source=mail",
    "canonical_url": "https://www.example.org/security?source=mail",
    "host": "www.example.org",
    "scheme": "https",
    "is_sensitive": false,
    "status": "queued",
    "verdict": "INCONCLUSIVE",
    "risk_score": null,
    "scoring_version": "trustlens-1.0",
    "checks_completed": 0,
    "created_at": "2026-11-07T06:10:00Z",
    "started_at": null,
    "completed_at": null
  },
  "deduplicated": false
}
```

If an identical active scan owned by the same user exists within the previous 60 seconds, return `200` with its existing scan object and `deduplicated: true`.

Applicable errors: `400 VALIDATION_ERROR`, `400 TARGET_NOT_PUBLIC`, `400 UNSUPPORTED_URL_SCHEME`, `401 AUTHENTICATION_REQUIRED`, `403 CSRF_VALIDATION_FAILED`, `429 RATE_LIMIT_EXCEEDED`, `500 INTERNAL_ERROR`.

**400 target policy response**

```json
{
  "error": {
    "code": "TARGET_NOT_PUBLIC",
    "message": "The submitted hostname does not resolve exclusively to publicly routable IP addresses.",
    "request_id": "req_01J9TRUSTLENS000000000009",
    "details": [
      {
        "field": "url",
        "issue": "Private, loopback, link-local, reserved, and metadata destinations are not scanned."
      }
    ]
  }
}
```

#### GET `/scans`

Lists only scans owned by the current user.

**Query parameters:** `page=1`, `page_size=20`, optional `status=queued|running|succeeded|partial|failed`, optional `verdict=SAFE|SUSPICIOUS|MALICIOUS|INCONCLUSIVE`.

**200 response**

```json
{
  "items": [
    {
      "id": "a45c01e8-59d4-4eb8-99b2-5a2dd79e1001",
      "canonical_url": "https://www.example.org/security?source=mail",
      "host": "www.example.org",
      "status": "succeeded",
      "verdict": "SAFE",
      "risk_score": 4,
      "scoring_version": "trustlens-1.0",
      "created_at": "2026-11-07T06:10:00Z",
      "completed_at": "2026-11-07T06:10:08Z"
    },
    {
      "id": "b56d12f9-60e5-4fc9-8ac3-6b3ee80f2002",
      "canonical_url": "https://payments-example.invalid/secure/login",
      "host": "payments-example.invalid",
      "status": "partial",
      "verdict": "SUSPICIOUS",
      "risk_score": 42,
      "scoring_version": "trustlens-1.0",
      "created_at": "2026-11-07T05:55:00Z",
      "completed_at": "2026-11-07T05:55:14Z"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 2
}
```

Applicable errors: `400 VALIDATION_ERROR`, `401 AUTHENTICATION_REQUIRED`, `500 INTERNAL_ERROR`.

#### GET `/scans/{scan_id}`

Returns the owner-scoped scan report summary and layer coverage.

**200 response**

```json
{
  "scan": {
    "id": "a45c01e8-59d4-4eb8-99b2-5a2dd79e1001",
    "original_url": "https://www.example.org/security?source=mail",
    "canonical_url": "https://www.example.org/security?source=mail",
    "host": "www.example.org",
    "scheme": "https",
    "is_sensitive": false,
    "status": "succeeded",
    "verdict": "SAFE",
    "risk_score": 4,
    "scoring_version": "trustlens-1.0",
    "checks_completed": 4,
    "created_at": "2026-11-07T06:10:00Z",
    "started_at": "2026-11-07T06:10:01Z",
    "completed_at": "2026-11-07T06:10:08Z",
    "failure_code": null,
    "failure_message": null
  },
  "coverage": {
    "threat_intel": "complete",
    "web_security": "complete",
    "certificate": "complete",
    "community": "complete"
  },
  "provider_checks": [
    {
      "provider": "openphish",
      "result_status": "no_match",
      "matched": false,
      "checked_at": "2026-11-07T06:10:02Z"
    },
    {
      "provider": "urlhaus",
      "result_status": "no_match",
      "matched": false,
      "checked_at": "2026-11-07T06:10:03Z"
    },
    {
      "provider": "community",
      "result_status": "no_match",
      "matched": false,
      "checked_at": "2026-11-07T06:10:03Z"
    }
  ],
  "redirects": [
    {
      "hop_index": 0,
      "source_url": "https://www.example.org/security?source=mail",
      "destination_url": "https://www.example.org/security?source=mail",
      "http_status": 200,
      "resolved_host": "www.example.org",
      "resolved_ips": ["93.184.216.34"],
      "tls_verified": true
    }
  ]
}
```

Coverage values are `complete`, `partial`, `unavailable`, or `not_applicable`. Applicable errors: `401 AUTHENTICATION_REQUIRED`, `404 RESOURCE_NOT_FOUND` (including scans owned by another user), `500 INTERNAL_ERROR`.

#### GET `/scans/{scan_id}/findings`

**200 response**

```json
{
  "scan_id": "a45c01e8-59d4-4eb8-99b2-5a2dd79e1001",
  "items": [
    {
      "id": "c67e230a-71f6-40da-9bd4-7c4ff9013001",
      "category": "web_security",
      "code": "CSP_MISSING",
      "title": "Content Security Policy is not configured",
      "description": "The response did not include a Content-Security-Policy header.",
      "severity": "low",
      "points": 4,
      "evidence": {
        "header": "content-security-policy",
        "observed": false,
        "final_url": "https://www.example.org/security?source=mail"
      },
      "remediation": "Define a Content Security Policy that restricts script, object, frame, and other resource sources to the minimum required origins.",
      "source": "trustlens_web_security_rules_v1",
      "created_at": "2026-11-07T06:10:07Z"
    }
  ],
  "total": 1
}
```

Applicable errors: `401 AUTHENTICATION_REQUIRED`, `404 RESOURCE_NOT_FOUND`, `500 INTERNAL_ERROR`.

#### GET `/scans/{scan_id}/certificate`

Returns a certificate object when an HTTPS handshake returned a parseable leaf certificate. For HTTP targets or failed handshakes without a parseable certificate, returns `available: false` with a reason rather than a 404.

**200 response when available**

```json
{
  "scan_id": "a45c01e8-59d4-4eb8-99b2-5a2dd79e1001",
  "available": true,
  "certificate": {
    "host": "www.example.org",
    "port": 443,
    "leaf_fingerprint_sha256": "6f1ed002ab5595859014ebf0951522d9a6f9b5d7a3f0a8d45d6c2b8e3c3f1234",
    "subject_cn": "www.example.org",
    "san_dns": ["www.example.org", "example.org"],
    "issuer": "Example Public TLS CA",
    "serial_number": "04A91F12C8",
    "not_before": "2026-10-01T00:00:00Z",
    "not_after": "2027-01-01T23:59:59Z",
    "signature_algorithm": "sha256WithRSAEncryption",
    "public_key_algorithm": "RSA",
    "public_key_bits": 2048,
    "chain_valid": true,
    "hostname_match": true,
    "sct_present": true,
    "revocation_status": "not_checked",
    "fetched_at": "2026-11-07T06:10:06Z"
  }
}
```

**200 response when unavailable**

```json
{
  "scan_id": "b56d12f9-60e5-4fc9-8ac3-6b3ee80f2002",
  "available": false,
  "reason": "target_not_https"
}
```

Allowed `reason` values: `target_not_https`, `tls_handshake_failed`, `no_parseable_leaf_certificate`, `target_fetch_blocked`. Applicable errors: `401 AUTHENTICATION_REQUIRED`, `404 RESOURCE_NOT_FOUND`, `500 INTERNAL_ERROR`.

### 3.5 Dashboard endpoint

#### GET `/dashboard/summary`

All counts are scoped to the current user.

**200 response**

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
      "id": "a45c01e8-59d4-4eb8-99b2-5a2dd79e1001",
      "canonical_url": "https://www.example.org/security?source=mail",
      "host": "www.example.org",
      "status": "succeeded",
      "verdict": "SAFE",
      "risk_score": 4,
      "created_at": "2026-11-07T06:10:00Z",
      "completed_at": "2026-11-07T06:10:08Z"
    }
  ]
}
```

Applicable errors: `401 AUTHENTICATION_REQUIRED`, `500 INTERNAL_ERROR`.

### 3.6 Community endpoints

#### POST `/community/reports`

Creates a pending report. `scan_id` is optional and must refer to a scan owned by the reporter if provided.

**Request body**

```json
{
  "url": "https://payments-example.invalid/secure/login",
  "scan_id": null,
  "category": "phishing",
  "claimed_verdict": "MALICIOUS",
  "evidence_text": "The page impersonates a payment provider and asks visitors to enter account credentials on an unrelated domain."
}
```

**201 response**

```json
{
  "report": {
    "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
    "canonical_url": "https://payments-example.invalid/secure/login",
    "host": "payments-example.invalid",
    "category": "phishing",
    "claimed_verdict": "MALICIOUS",
    "status": "pending",
    "evidence_text": "The page impersonates a payment provider and asks visitors to enter account credentials on an unrelated domain.",
    "created_at": "2026-11-07T06:20:00Z",
    "moderated_at": null
  },
  "duplicate_submission": false
}
```

**200 response for an existing duplicate**

```json
{
  "report": {
    "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
    "canonical_url": "https://payments-example.invalid/secure/login",
    "host": "payments-example.invalid",
    "category": "phishing",
    "claimed_verdict": "MALICIOUS",
    "status": "pending",
    "evidence_text": "The page impersonates a payment provider and asks visitors to enter account credentials on an unrelated domain.",
    "created_at": "2026-11-07T06:20:00Z",
    "moderated_at": null
  },
  "duplicate_submission": true
}
```

Applicable errors: `400 VALIDATION_ERROR`, `400 TARGET_NOT_PUBLIC`, `401 AUTHENTICATION_REQUIRED`, `403 CSRF_VALIDATION_FAILED`, `429 RATE_LIMIT_EXCEEDED`, `500 INTERNAL_ERROR`.

#### GET `/community/reports`

Public listing. Only `confirmed` reports are returned. Optional filters: `category`, `host`, `page`, `page_size`. Do not expose evidence that contains raw credentials, personal information, or untrusted HTML.

**200 response**

```json
{
  "items": [
    {
      "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
      "canonical_url": "https://payments-example.invalid/secure/login",
      "host": "payments-example.invalid",
      "category": "phishing",
      "claimed_verdict": "MALICIOUS",
      "status": "confirmed",
      "evidence_summary": "The page impersonates a payment provider and requests credentials on an unrelated domain.",
      "confirmation_count": 8,
      "false_positive_count": 1,
      "created_at": "2026-11-07T06:20:00Z",
      "moderated_at": "2026-11-07T08:00:00Z"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 1
}
```

Applicable errors: `400 VALIDATION_ERROR`, `500 INTERNAL_ERROR`.

#### GET `/community/reports/mine`

Authenticated private list containing only reports submitted by the current user. Optional `status`, `page`, and `page_size` filters.

**200 response**

```json
{
  "items": [
    {
      "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
      "canonical_url": "https://payments-example.invalid/secure/login",
      "category": "phishing",
      "claimed_verdict": "MALICIOUS",
      "status": "pending",
      "evidence_text": "The page impersonates a payment provider and asks visitors to enter account credentials on an unrelated domain.",
      "moderation_reason": null,
      "created_at": "2026-11-07T06:20:00Z",
      "moderated_at": null
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 1
}
```

Applicable errors: `400 VALIDATION_ERROR`, `401 AUTHENTICATION_REQUIRED`, `500 INTERNAL_ERROR`.

#### GET `/community/reports/{report_id}`

- Anonymous users may view only confirmed reports.
- The report owner may view their own report in any moderation state.
- Moderators/admins may view any report.

**200 response**

```json
{
  "report": {
    "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
    "canonical_url": "https://payments-example.invalid/secure/login",
    "host": "payments-example.invalid",
    "category": "phishing",
    "claimed_verdict": "MALICIOUS",
    "status": "confirmed",
    "evidence_summary": "The page impersonates a payment provider and requests credentials on an unrelated domain.",
    "confirmation_count": 8,
    "false_positive_count": 1,
    "moderation_reason": "Evidence and independent corroboration support the report.",
    "created_at": "2026-11-07T06:20:00Z",
    "moderated_at": "2026-11-07T08:00:00Z"
  }
}
```

Applicable errors: `401 AUTHENTICATION_REQUIRED` when authentication is required for a private report, `404 RESOURCE_NOT_FOUND`, `500 INTERNAL_ERROR`.

#### POST `/community/reports/{report_id}/votes`

A user cannot vote on their own report. Repeated votes update the existing vote.

**Request body**

```json
{
  "vote": "confirm"
}
```

**200 response**

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

Applicable errors: `400 VALIDATION_ERROR`, `401 AUTHENTICATION_REQUIRED`, `403 CSRF_VALIDATION_FAILED`, `403 OWN_REPORT_VOTE_NOT_ALLOWED`, `404 RESOURCE_NOT_FOUND`, `409 REPORT_NOT_VOTABLE`, `500 INTERNAL_ERROR`.

### 3.7 Moderator/admin endpoints

#### GET `/admin/reports`

Moderator/admin only. Defaults to `status=pending`; allowed statuses are `pending`, `confirmed`, `rejected`, and `duplicate`.

**200 response**

```json
{
  "items": [
    {
      "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
      "canonical_url": "https://payments-example.invalid/secure/login",
      "host": "payments-example.invalid",
      "category": "phishing",
      "claimed_verdict": "MALICIOUS",
      "status": "pending",
      "evidence_text": "The page impersonates a payment provider and asks visitors to enter account credentials on an unrelated domain.",
      "reporter_id": "8e2e9df7-10d2-4c9e-a2a2-4e0de5d7f001",
      "confirmation_count": 3,
      "false_positive_count": 0,
      "created_at": "2026-11-07T06:20:00Z"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 1
}
```

Applicable errors: `400 VALIDATION_ERROR`, `401 AUTHENTICATION_REQUIRED`, `403 FORBIDDEN`, `500 INTERNAL_ERROR`.

#### POST `/admin/reports/{report_id}/moderation`

Moderator/admin only. A reason of 10–1,000 characters is mandatory. Only a `pending` report can be moderated. A repeated identical moderation request returns `409 STATE_CONFLICT`; the moderator must inspect the current state first.

**Request body**

```json
{
  "decision": "confirmed",
  "reason": "The submitted page uses the provider's branding and requests credentials on a domain unrelated to the claimed organisation."
}
```

Allowed `decision`: `confirmed`, `rejected`, `duplicate`.

**200 response**

```json
{
  "report": {
    "id": "d78f341b-82a7-42e8-ae75-8d5000124001",
    "status": "confirmed",
    "moderator_user_id": "9f3f0ae8-21e3-5d0f-b3b3-5f1ef6e8a202",
    "moderation_reason": "The submitted page uses the provider's branding and requests credentials on a domain unrelated to the claimed organisation.",
    "moderated_at": "2026-11-07T08:00:00Z"
  },
  "audit_event_id": "e89a452c-93b8-53f9-bf86-9e6112345001"
}
```

Applicable errors: `400 VALIDATION_ERROR`, `401 AUTHENTICATION_REQUIRED`, `403 FORBIDDEN`, `403 CSRF_VALIDATION_FAILED`, `404 RESOURCE_NOT_FOUND`, `409 STATE_CONFLICT`, `500 INTERNAL_ERROR`.

#### GET `/admin/providers`

Moderator/admin only. Exposes operational freshness, not API credentials.

**200 response**

```json
{
  "providers": [
    {
      "provider": "openphish",
      "enabled": true,
      "status": "healthy",
      "last_success_at": "2026-11-07T00:00:00Z",
      "freshness_seconds": 23100,
      "freshness_limit_seconds": 46800,
      "records_active": 14500
    },
    {
      "provider": "urlhaus",
      "enabled": true,
      "status": "healthy",
      "last_success_at": "2026-11-07T06:10:03Z",
      "freshness_seconds": 0,
      "freshness_limit_seconds": null,
      "records_active": null
    }
  ]
}
```

Applicable errors: `401 AUTHENTICATION_REQUIRED`, `403 FORBIDDEN`, `500 INTERNAL_ERROR`.

## 4. Finding code contract

Finding codes are stable and must map to exactly one category and one score rule. The API may add fields to evidence, but it must not rename existing codes without a new scoring version.

| Code | Category | Default severity | Points | Description |
|---|---|---|---:|---|
| `OPENPHISH_EXACT_URL_MATCH` | `threat_intel` | critical | 100 | Exact URL appears in OpenPhish community feed |
| `URLHAUS_EXACT_URL_MATCH` | `threat_intel` | critical | 100 | Exact URL appears in URLhaus with `url_status=online` |
| `URLHAUS_HISTORICAL_URL_MATCH` | `threat_intel` | high | 25 | Exact URL appears in URLhaus with `url_status=offline` or `unknown`; historical warning only |
| `COMMUNITY_CONFIRMED_INDICATOR` | `community` | critical | 90 | At least two independent moderator-confirmed reports exist for canonical URL |
| `CERT_CHAIN_INVALID` | `certificate` | high | 25 | TLS chain failed trust-store validation |
| `CERT_HOSTNAME_MISMATCH` | `certificate` | high | 25 | Certificate identity does not match scanned hostname |
| `CERT_EXPIRED` | `certificate` | high | 20 | Leaf certificate has expired |
| `TLS_LEGACY_PROTOCOL` | `web_security` | medium | 10 | Negotiated protocol is older than TLS 1.2 |
| `HSTS_MISSING` | `web_security` | low | 5 | HTTPS response did not include HSTS |
| `CSP_MISSING` | `web_security` | low | 4 | Response did not include Content-Security-Policy |
| `X_CONTENT_TYPE_OPTIONS_MISSING` | `web_security` | low | 2 | Response did not include X-Content-Type-Options: nosniff |
| `REFERRER_POLICY_MISSING` | `web_security` | info | 1 | Response did not include Referrer-Policy |
| `PERMISSIONS_POLICY_MISSING` | `web_security` | info | 1 | Response did not include Permissions-Policy |
| `COOKIE_SECURE_MISSING` | `web_security` | medium | 3 | Cookie lacks Secure attribute |
| `COOKIE_HTTPONLY_MISSING` | `web_security` | low | 2 | Cookie lacks HttpOnly attribute |
| `COOKIE_SAMESITE_MISSING` | `web_security` | low | 2 | Cookie lacks SameSite attribute |
| `HTTP_NO_HTTPS_REDIRECT` | `web_security` | medium | 5 | HTTP URL did not redirect to HTTPS |

The score and verdict rules are defined in PRD.md section 5 / FR-09 and implemented in `rules_v1.py`. A provider match is decisive; additive score alone cannot create `MALICIOUS`.

## 5. Third-party integrations

### 5.1 OpenPhish community phishing feed

**Purpose:** Phishing URL intelligence. It is not a malware payload feed.  
**Source:** <https://www.openphish.com/phishing_feeds.html>  
**Feed URL currently linked by the official Community row:** `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`  
**Method:** HTTPS GET; response is plain text with one URL per line.  
**Cadence:** Every 12 hours; do not poll more frequently.  
**Authentication:** Community feed is listed as free; access is subject to its terms of use.  
**Data handling:** Store normalized URL indicators locally. Preserve source attribution. Do not redistribute the full feed through TrustLens API/UI. Record `OPENPHISH_TERMS_ACCEPTED_AT` before enabling the adapter. The feed has limited metadata; do not invent targeted-brand, first-seen, or confidence fields that the source does not provide.

**Example request**

```http
GET /refs/heads/main/feed.txt HTTP/1.1
Host: raw.githubusercontent.com
Accept: text/plain
User-Agent: TrustLens-Feed-Sync/1.0
```

**Example response body**

```text
https://phishing-example.invalid/verify
http://account-check-example.invalid/login
https://payment-alert-example.invalid/session
```

**Internal normalized indicator example**

```json
{
  "indicator_type": "url",
  "normalized_value": "https://phishing-example.invalid/verify",
  "source": "openphish",
  "confidence": 95,
  "source_record_id": null,
  "active": true
}
```

The `confidence: 95` value is TrustLens's fixed source-reliability mapping, not a confidence value supplied by OpenPhish. The UI labels it as TrustLens source weighting.

### 5.2 URLhaus Community API

**Purpose:** Exact URL lookup for URLs associated with malware distribution. URLhaus explicitly states that phishing alone is not a URLhaus submission category; do not treat it as the phishing provider.  
**Documentation:** <https://urlhaus-api.abuse.ch/> and <https://urlhaus.abuse.ch/api/>.  
**Endpoint:** `POST https://urlhaus-api.abuse.ch/v1/url/`  
**Authentication:** `Auth-Key` HTTP header. Obtain a key from the abuse.ch authentication portal. Community API use is subject to fair-use terms; commercial use may require an enhanced paid API.

**Example request**

```http
POST /v1/url/ HTTP/1.1
Host: urlhaus-api.abuse.ch
Auth-Key: REPLACED_BY_SECRET_MANAGER
Content-Type: application/x-www-form-urlencoded
Accept: application/json

url=https%3A%2F%2Fmalware-example.invalid%2Fpayload
```

The literal `REPLACED_BY_SECRET_MANAGER` is a documentation marker only; production requests must load the real key from AWS Secrets Manager. It must never be committed or sent to the browser.

**Example match response**

```json
{
  "query_status": "ok",
  "id": "105821",
  "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
  "url": "https://malware-example.invalid/payload",
  "url_status": "online",
  "host": "malware-example.invalid",
  "date_added": "2026-11-07 05:00:00 UTC",
  "last_online": null,
  "threat": "malware_download",
  "blacklists": {
    "spamhaus_dbl": "not listed",
    "surbl": "listed"
  },
  "reporter": "anonymous",
  "larted": "false",
  "takedown_time_seconds": null,
  "tags": ["exe"]
}
```

**Example no-match response**

```json
{
  "query_status": "no_results"
}
```

**Internal normalized check example**

```json
{
  "provider": "urlhaus",
  "result_status": "match",
  "matched": true,
  "details": {
    "urlhaus_id": "105821",
    "url_status": "online",
    "threat": "malware_download",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
    "tags": ["exe"]
  }
}
```

Only an exact requested URL match with `url_status=online` creates `URLHAUS_EXACT_URL_MATCH` and triggers the decisive malicious rule. An exact match with `url_status=offline` or `unknown` creates `URLHAUS_HISTORICAL_URL_MATCH` (25 points) and cannot alone create a `MALICIOUS` verdict. Do not fetch any payload URL returned by URLhaus. Do not use URLhaus's sample-download endpoints in any TrustLens worker.

### 5.3 TrustLens community indicator store

No external HTTP service is called. `CommunityIntelService` queries `community_reports` with `status='confirmed'` and the exact canonical URL. It emits a `provider_checks` row with provider `community` and status `match` or `no_match`. Two distinct reporter accounts with moderator-confirmed reports trigger the decisive community rule. Votes do not make a report confirmed.

### 5.4 Optional commercial reputation provider (not MVP)

Google Safe Browsing API documentation specifies non-commercial use; a revenue-generating service should evaluate Google Web Risk rather than using Safe Browsing outside its terms. A future `WebRiskProvider` adapter may be implemented only after commercial licensing, billing, retention, and privacy reviews. It is not required for the MVP and is not part of the current scan coverage calculation.

- Safe Browsing reference: <https://developers.google.com/safe-browsing/reference/rest>.
- VirusTotal is also not an MVP dependency. Its documentation warns that queried/submitted indicators may be scanned and added to its dataset, so TrustLens must not send confidential or personally identifiable URLs to it without an explicit privacy/legal review. See <https://docs.virustotal.com/reference/api-search>.

### 5.5 Webhooks

TrustLens MVP does not expose inbound provider webhooks and does not send customer-configurable outbound webhooks. OpenPhish is polled by a scheduled feed worker; URLhaus is queried synchronously from a worker using an HTTPS POST. The API must reject unrecognized webhook routes rather than accepting unsigned external events.

## 6. API implementation rules

- Generate OpenAPI from FastAPI and save the reviewed contract to `openapi/trustlens-v1.json`.
- The frontend client is generated from that OpenAPI document; hand-maintained response duplicates are not allowed.
- Use `response_model` for every endpoint and exclude secrets/session token hashes by construction.
- Use one global error handler to map validation, auth, authorization, not-found, conflict, provider, and internal exceptions to the common envelope.
- Use database transactions for report moderation and audit event insertion.
- Use `SELECT ... FOR UPDATE` when moderating a report to prevent concurrent state transitions.
- Use parameterized ORM queries; no user-provided SQL fragments or dynamic table names.
- Use idempotency/uniqueness constraints to avoid duplicate findings, votes, redirect hops, and feed indicators.
- Never let a browser-supplied field set `user_id`, `role`, `status`, `risk_score`, `verdict`, `moderator_user_id`, `source`, or `scoring_version`.
- Provider check `no_match` is valid only after a successful provider response or valid fresh cache. A timeout, 401, 429, malformed JSON, or invalid feed is `unavailable` or `stale_cache`.
