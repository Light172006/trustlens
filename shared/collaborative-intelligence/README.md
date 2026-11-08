# TrustLens Collaborative Threat Intelligence — Integration Architecture & Backend Specification

> **Audience:** Backend Engineers, System Architects, Security Operations Engineers  
> **Component Ownership:** AI/ML & Threat Intelligence Engineering  
> **Status:** Proposed Integration Interface (Milestone 6 Finalized)

---

## 1. Architecture Overview

The **Collaborative Threat Intelligence Engine** is TrustLens's fourth core security pillar, complementing the *URL & Threat Analyzer*, *Web Security Analyzer*, and *Certificate Analyzer*.

Its objective is to allow community threat reporters, security analysts, and end users to submit suspicious URLs and supporting observations, and to reliably extract high-confidence threat signals without allowing malicious actors, coordinated smear campaigns, spam, or Sybil rings to poison TrustLens's intelligence repository.

### Conceptual Pipeline

```text
┌─────────────────────────┐
│ Community Report Input  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   URL Normalization     │  (RFC 3986, Punycode/IDNA, port stripping, query sorting)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│    Input Validation     │  (Length limits, schema validation, DoS boundaries)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Deduplication Engine   │  (Exact canonical vs. path-variants vs. host-variants)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Evidence Evaluator    │  (Cryptographic fingerprinting, stance, diversity, quality)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Corroboration & Abuse   │  (Independent cluster analysis, Sybil & burst detection)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Moderation Advisory     │  (Queue prioritization, explainable recommendations)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Human Moderation Queue  │  (Backend-owned authorization: ACCEPT / REJECT / REVOKE)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Confirmed Threat Store  │  (EXACT_URL, HOST, DOMAIN scoped indicators)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Scan Enrichment Query   │  (Read-only telemetry for future TrustLens scans)
└─────────────────────────┘
```

---

## 2. Component Responsibilities & Ownership Boundaries

| Responsibility Domain | AI/ML & Intelligence Engine (This Module) | Backend Engineering (`apps/api`, `app/*`) |
|:---|:---|:---|
| **URL Canonicalization** | Strict RFC 3986, IDNA Punycode, hash generation. | Ingests raw input, passes to normalizer. |
| **Input Validation** | Defensive bounds checking, syntax parsing. | HTTP request validation, auth header extraction. |
| **Deduplication** | Computes match strength, explanation, groupings. | PostgreSQL indexing on `canonical_hash`, `host_hash`. |
| **Evidence Processing** | Fingerprinting, stance accounting, quality weights. | Storage of evidence artifacts / references in DB. |
| **Corroboration** | Independent cluster sizing, temporal decay, diversity. | Provides historical reports and votes for URL cluster. |
| **Abuse & Sybil Defense** | Coordinated campaign signals, burst pattern analysis. | Rate limiting, CAPTCHA, IP tracking, auth revocation. |
| **Reporter Reliability** | Anti-farming reliability score & tier calculation. | Account credentials, session auth, user restrictions. |
| **Moderation** | Explainable recommendation & review queue priority. | Authorized moderator RBAC, decisions, DB persistence. |
| **Threat Enrichment** | Scoped indicator matching (URL/HOST/DOMAIN). | Querying confirmed indicator store during scan jobs. |

---

## 3. Separation of Entities

The engine strictly separates these six concepts:

1. **Report (`CommunityReportInput`):** An individual submission from an individual user.
2. **Evidence (`EvidenceItem`):** An observation supporting, contradicting, or inconclusive regarding a report.
3. **Indicator (`NormalizedURL` / `ConfirmedIndicator`):** The underlying threat entity (canonical URL, hostname, or domain).
4. **Corroboration (`CorroborationAssessment`):** An independent evaluation of multiple reports and observations.
5. **Moderation Decision:** An authorized human action transitioning a report (`ACCEPTED`, `REJECTED`) or indicator (`CONFIRMED`, `DISPUTED`, `REVOKED`).
6. **Threat Intelligence Signal (`ConfirmedIndicatorMatch`):** A verified result consumed by scan jobs.

> **CRITICAL RULE:** A user submitting a suspicious URL **never** automatically marks that URL or domain as malicious. Only authorized human moderation decisions can promote an indicator to `CONFIRMED`.

---

## 4. Report and Indicator Lifecycle

### 4.1 Report Lifecycle (`ReportStatus`)

```text
[Submitted] ──▶ PENDING ──▶ UNDER_REVIEW ──┬──▶ ACCEPTED
                   │                       ├──▶ REJECTED
                   ▼                       └──▶ DUPLICATE
               WITHDRAWN
```

### 4.2 Indicator Lifecycle (`IndicatorStatus`)

```text
[Aggregated] ──▶ UNCONFIRMED ──▶ (Moderation Approval) ──▶ CONFIRMED
                                                               │
                    ┌─────────────────┬────────────────────────┤
                    ▼                 ▼                        ▼
                DISPUTED           EXPIRED                  REVOKED
            (Under Review)       (TTL Elapsed)         (False Positive)
```

- **UNCONFIRMED:** Indicator is under review. Excluded from scan threat matching.
- **CONFIRMED:** Approved by an authorized moderator. Active for matching.
- **DISPUTED:** Endorsed or disputed by counter-evidence. Temporarily suspended from active scan matching until re-evaluated.
- **EXPIRED:** Indicator past its configurable TTL (default 90 days). Excluded from active matches.
- **REVOKED:** Retracted due to false positive identification. Permanently excluded from active matches.

---

## 5. Indicator Scope Architecture

The engine implements three explicit scopes:

| Scope | Matching Semantics | Justification Requirement |
|:---|:---|:---|
| `EXACT_URL` | Exact canonical URL (`scheme + host + path + sorted_query`). | Default for single-path compromise, malicious query targets, or phishing directories on shared platforms (e.g. `sites.google.com/site/phish`). |
| `HOST` | Entire hostname (e.g. `phish.target.com`). | Requires 3+ distinct confirmed malicious paths on host OR root compromise evidence. |
| `DOMAIN` | Entire apex domain and all subdomains (e.g. `malicious-campaign.top`). | Requires verified domain-wide compromise (e.g. DNS wildcarding, registrar seizure, dedicated malicious bulletproof domain). |

> **Security Guardrail:** Reporting `https://github.com/malicious/repo` matches **ONLY** `EXACT_URL`. It will never mark `github.com` or `raw.githubusercontent.com` malicious!

---

## 6. Proposed Python Integration API

### 6.1 Evaluating a Report Submission (Celery Worker / FastAPI Service)

```python
from collaborative_intelligence import (
    CollaborativeIntelligenceEngine,
    CommunityReportInput,
    EvidenceItem,
    EvidenceType,
    EvidenceStance,
    ReporterMetadata,
    ThreatCategory,
)

engine = CollaborativeIntelligenceEngine()

# Construct report input from request data
report = CommunityReportInput(
    submission_id=str(db_report.id),
    original_url=db_report.original_url,
    category=ThreatCategory.from_string(db_report.category),
    description=db_report.evidence_text,
    evidence_items=[
        EvidenceItem(
            evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
            stance=EvidenceStance.SUPPORTS,
            source="community_upload",
            description="HTML form post to credential drop.",
            is_verified=False,
        )
    ],
    submitted_at=db_report.created_at,
    reporter=ReporterMetadata(
        reporter_id=str(user.id),
        account_age_days=(now - user.created_at).days,
        previous_accepted_reports=user.accepted_count,
        previous_rejected_reports=user.rejected_count,
        is_trusted=user.is_trusted,
        is_restricted=user.is_restricted,
    ),
)

# Fetch historical candidate reports with same host_hash or canonical_hash
candidates = await fetch_candidate_reports(db, host_hash=norm.host_hash)

# Evaluate report
result = engine.evaluate_report(report, existing_reports=candidates)

# Persist intelligence metadata in PostgreSQL
db_report.canonical_url = result.canonical_url
db_report.is_duplicate = result.deduplication.is_duplicate
db_report.moderation_priority = result.moderation_recommendation.review_priority.value
db_report.recommended_action = result.moderation_recommendation.recommended_action.value
db_report.corroboration_level = result.corroboration.corroboration_level.value
await db.commit()
```

### 6.2 Scan Enrichment Integration (URL Scan Pipeline)

```python
from collaborative_intelligence import (
    CollaborativeIntelligenceEngine,
    ConfirmedIndicator,
)

engine = CollaborativeIntelligenceEngine()

# Query active confirmed indicators from Redis or DB
active_indicators: list[ConfirmedIndicator] = await load_active_indicators(db)

# Match incoming URL scan target
match_result = engine.match_confirmed_indicator(
    target_url="https://phish.target.com/login",
    indicators=active_indicators,
)

if match_result.matched and match_result.is_active:
    # Append community threat finding as additive evidence
    scan_findings.append({
        "category": "community",
        "severity": "high",
        "scope": match_result.matched_scope.value,
        "indicator_id": match_result.indicator.indicator_id,
        "threat_category": match_result.indicator.threat_category.value,
        "explanation": match_result.explanation,
    })
```

---

## 7. PostgreSQL Database Schema Recommendations for Backend

To support the intelligence engine efficiently, the backend engineer should add the following indexed columns to `community_reports` and a dedicated `confirmed_indicators` table:

```sql
-- Enhancements to community_reports table
ALTER TABLE community_reports
    ADD COLUMN IF NOT EXISTS canonical_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS host_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS domain_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS is_duplicate BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS primary_report_id UUID REFERENCES community_reports(id),
    ADD COLUMN IF NOT EXISTS corroboration_level VARCHAR(20) DEFAULT 'NONE',
    ADD COLUMN IF NOT EXISTS recommended_priority VARCHAR(20) DEFAULT 'NORMAL',
    ADD COLUMN IF NOT EXISTS evidence_fingerprints JSONB DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS ix_community_reports_canonical_hash ON community_reports(canonical_hash);
CREATE INDEX IF NOT EXISTS ix_community_reports_host_hash ON community_reports(host_hash);

-- Dedicated confirmed_indicators table
CREATE TABLE IF NOT EXISTS confirmed_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_value VARCHAR(2048) NOT NULL,
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('EXACT_URL', 'HOST', 'DOMAIN')),
    threat_category VARCHAR(40) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'CONFIRMED' CHECK (status IN ('UNCONFIRMED', 'CONFIRMED', 'DISPUTED', 'EXPIRED', 'REVOKED')),
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    disputed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    corroboration_level VARCHAR(20) NOT NULL,
    moderator_user_id UUID REFERENCES users(id),
    evidence_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_confirmed_indicators_lookup ON confirmed_indicators(indicator_value, status, expires_at);
```

---

## 8. Security Controls & Threat Model

| Attack Vector | Defense Mechanism Implemented in Engine |
|:---|:---|
| **Report Spam / Flooding** | Burst detection window (`burst_window_seconds`), O(1) hash indexing, safe duplicate grouping. |
| **Sybil Attack Rings** | Connected component graph analysis on shared evidence & payload similarity; collapses correlated accounts to a single source. |
| **Coordinated Smear Campaigns** | High corroboration requires diverse independent evidence types; report count alone never determines verdict; human moderation mandatory. |
| **Threat Intelligence Poisoning** | Indicators cannot be confirmed automatically by score; requires human moderation; full audit trail with revocation capability. |
| **Duplicate Evidence Inflation** | Cryptographic fingerprinting (`SHA-256`) strips duplicate evidence from diversity and quality weighting. |
| **Malicious URL Input / ReDoS** | RFC 3986 normalization, strict character validation (disallows null bytes, control characters), no regex backtrack. |
| **Domain Scope Overreach** | Strict scope enforcement (`EXACT_URL` vs. `HOST` vs. `DOMAIN`); single path never marks entire host or domain malicious. |
| **Stale Threat Data** | Exponential temporal decay with 14-day half-life; 90-day hard TTL; indicators expire automatically. |
| **SSRF / Malicious Network Calling** | Intelligence engine runs **completely offline**; strictly prohibited from performing HTTP fetches or resolving DNS. |
| **User Privacy Leakage** | Anonymized `reporter_id` and calculated score; sensitive account metadata isolated from public scan outputs. |

---

## 9. Known Limitations & Future Extension Points

1. **PSL Domain Granularity:** Currently handles common national multi-part TLDs (e.g. `co.uk`, `com.au`). When full Public Suffix List parsing is needed, the backend or unified package can install `tldextract` without modifying engine interfaces.
2. **Cluster Persistence:** In-memory connected components are evaluated per evaluation batch. When database persistence scales to millions of reports, cluster IDs should be pre-computed by background Celery tasks.
3. **Machine Learning Classifier:** Initial release prioritizes deterministic, explainable rules. When representative, independently labeled community datasets accumulate, a calibrated classification advisor can be introduced via the `interfaces.py` protocol.

