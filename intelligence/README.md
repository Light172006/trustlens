# TrustLens Intelligence Engine (`trustlens-intelligence`)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Scoring Version](https://img.shields.io/badge/scoring-trustlens--1.0-green.svg)](https://github.com/trustlens)
[![Test Coverage](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

The **TrustLens Intelligence Engine** is a modular, deterministic, explainable website threat intelligence and risk evaluation package. It interprets normalized website scan evidence collected by the TrustLens backend and produces audit-ready threat assessments with structured findings, deterministic risk scores (0–100), calibrated confidence metrics, and clear plain-language explanations.

---

## 1. Architectural Boundary & Separation

This package is strictly self-contained within `intelligence/` and adheres to architectural boundaries:

* **Backend Responsibility:** Safe HTTP crawling, DNS resolution, connection pinning, SSRF mitigation, leaf certificate extraction, Celery queue orchestration, and database persistence.
* **Frontend Responsibility:** React components, dashboard UI, scan visualizations, report rendering, and styling.
* **Intelligence Responsibility (This Package):**
  * Threat intelligence feed normalization and matching (OpenPhish, URLhaus, Community).
  * Deterministic lexical, structural, web security, and TLS feature extraction.
  * Rule-based threat detection and point attribution.
  * Deterministic, versioned risk scoring (`trustlens-1.0`) and verdict mapping (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `INCONCLUSIVE`).
  * Explainability engine and verdict-to-finding invariant enforcement.
  * Machine learning classification, model evaluation, and inference pipeline.

---

## 2. Directory Structure

```text
intelligence/
├── trustlens_intelligence/
│   ├── __init__.py                # Package exports and version metadata
│   ├── api.py                     # Public API entrypoints (analyze_website, etc.)
│   ├── common/                    # Low-level primitives & shared utilities
│   │   ├── __init__.py
│   │   └── url_utils.py           # Strict canonicalization, userinfo, adversarial IP
│   ├── config/
│   │   ├── __init__.py
│   │   ├── constants.py           # Enums, rule codes, and system constants
│   │   └── settings.py            # Typed Pydantic settings and thresholds
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── evidence.py            # Normalized scan input schemas (ScanEvidence)
│   │   ├── findings.py            # Finding and rule match schemas
│   │   ├── providers.py           # ProviderCheckResult schema
│   │   ├── features.py            # ExtractedFeatures vector schema
│   │   └── assessment.py          # ThreatAssessment and MLPrediction schemas
│   ├── features/
│   │   ├── __init__.py
│   │   ├── lexical.py             # URL lengths, Shannon entropy, keyword analysis
│   │   ├── structural.py          # Subdomains, IP hosts, Punycode, homoglyphs
│   │   ├── security.py            # Headers, cookie flags, TLS protocol, redirects
│   │   ├── provenance.py          # Observation source audit tracking
│   │   └── extractor.py           # Unified FeatureExtractor
│   ├── threat_feeds/
│   │   ├── __init__.py
│   │   ├── base.py                # ThreatIntelProvider abstract base class
│   │   ├── openphish.py           # OpenPhish community feed cache adapter
│   │   ├── urlhaus.py             # URLhaus malware API adapter (online vs offline)
│   │   ├── community.py           # Moderator-confirmed community intelligence
│   │   ├── mock_provider.py       # Configurable offline mock provider
│   │   └── manager.py             # ThreatIntelManager (TTL caching, coverage)
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── base_rule.py           # DetectionRule abstract class
│   │   ├── rules.py               # PRD FR-09 decisive & additive detection rules
│   │   ├── registry.py            # Rule registry and toggle management
│   │   └── engine.py              # DetectionEngine
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── weights.py             # ScoringWeights dataclass
│   │   ├── calculator.py          # Deterministic RiskCalculator
│   │   └── engine.py              # RiskScoringEngine (trustlens-1.0)
│   ├── explainability/
│   │   ├── __init__.py
│   │   ├── findings_builder.py    # Standardized finding constructor
│   │   └── explainer.py           # Narrative summary & invariant auditor
│   └── evaluation/
│       ├── __init__.py
│       ├── artifacts/             # Bundled pre-trained baseline model artifacts
│       │   └── baseline_classifier.joblib
│       ├── dataset.py             # Domain-aware benchmark dataset generator
│       ├── metrics.py             # Precision, recall, PR-AUC, ROC-AUC, FPR/FNR
│       ├── models.py              # Logistic Regression, Random Forest, Boosted Trees
│       ├── trainer.py             # ModelTrainer benchmark & artifact serialization
│       └── inference.py           # ThreatClassifier runtime inference interface
├── tests/
│   ├── conftest.py                # Offline fixtures (clean, phishing, malware)
│   ├── test_schemas.py            # Input/output validation and DTO contracts
│   ├── test_features.py           # Feature extraction & missing data tests
│   ├── test_threat_feeds.py       # Adapters, caching, stale cache, sensitive skip
│   ├── test_detection_rules.py    # Decisive, additive, and heuristic rules
│   ├── test_scoring.py            # Score boundaries, capping, and verdict thresholds
│   ├── test_explainability.py     # Findings invariants and narrative text
│   ├── test_ml_pipeline.py        # Domain-aware splits, training, inference
│   └── test_end_to_end.py         # Full pipeline integration tests
├── pyproject.toml                 # Package dependencies and configuration
└── README.md                      # Comprehensive engineering documentation
```

---

## 3. Public API & Interfaces

### Primary Entrypoints (`trustlens_intelligence.api`)

#### 1. `analyze_website(evidence: ScanEvidence, query_providers: bool = False, is_scan_failed: bool = False) -> ThreatAssessment`
Executes full intelligence evaluation on normalized evidence.

```python
from trustlens_intelligence import ScanEvidence, HttpEvidence, TlsCertificateEvidence, analyze_website

evidence = ScanEvidence(
    scan_id="scan_01J9...",
    original_url="https://example.com/login",
    http=HttpEvidence(
        status_code=200,
        security_headers={"strict-transport-security": "max-age=31536000"},
    ),
    tls=TlsCertificateEvidence(chain_valid=True, hostname_match=True, days_until_expiry=90),
)

assessment = analyze_website(evidence)

print(assessment.verdict)        # Verdict.SAFE, SUSPICIOUS, MALICIOUS, or INCONCLUSIVE
print(assessment.risk_score)     # Integer 0-100 (or None if failed)
print(assessment.confidence)     # Float 0.0 - 1.0
print(assessment.summary)        # Human-readable summary
print(assessment.to_api_dict())  # Format strictly aligned with FastAPI API.md
```

#### 2. `extract_features(evidence: ScanEvidence) -> ExtractedFeatures`
Extracts normalized feature vector for analytics or external ML pipelines.

```python
from trustlens_intelligence import extract_features

features = extract_features(evidence)
print(features.url_entropy)       # Shannon entropy (bits/char)
print(features.is_ip_host)        # True if host is raw IP address
print(features.to_ml_dict())      # Tabular dictionary ready for ML models
```

#### 3. `evaluate_threat_feeds(url: str, is_sensitive: bool = False) -> list[ProviderCheckResult]`
Queries OpenPhish, URLhaus, and Community providers directly with rate-limiting and TTL caching.

---

## 4. Input & Output Contracts

> [!NOTE]
> The formal, machine-readable JSON Schema (Draft 2020-12) specifications and validated fixtures are maintained in `shared/contracts/`. See [`shared/contracts/BACKEND_INTEGRATION.md`](../shared/contracts/BACKEND_INTEGRATION.md) for backend scanner and Celery worker integration details.

### Input Contract: `ScanEvidence`

Normalized observations supplied by the backend scan worker:

```json
{
  "scan_id": "scan_123",
  "original_url": "https://example.com/login",
  "canonical_url": "https://example.com/login",
  "host": "example.com",
  "scheme": "https",
  "is_sensitive": false,
  "http": {
    "status_code": 200,
    "final_url": "https://example.com/login",
    "redirect_count": 0,
    "security_headers": {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'"
    },
    "cookies": [
      { "name": "session_id", "secure": true, "httponly": true, "samesite": "Lax" }
    ]
  },
  "tls": {
    "valid": true,
    "chain_valid": true,
    "hostname_match": true,
    "days_until_expiry": 85,
    "is_expired": false,
    "protocol_version": "TLSv1.3"
  },
  "domain_intelligence": {
    "domain_age_days": 1420
  },
  "threat_intelligence": {
    "openphish_match": false,
    "openphish_status": "no_match",
    "urlhaus_match": false,
    "urlhaus_status": "no_match"
  },
  "community_intelligence": {
    "confirmed_report_count": 0,
    "distinct_reporter_count": 0
  }
}
```

### Output Contract: `ThreatAssessment` (`to_api_dict()`)

Directly matches the backend REST API response model:

```json
{
  "verdict": "SUSPICIOUS",
  "risk_score": 42,
  "confidence": 0.86,
  "scoring_version": "trustlens-1.0",
  "checks_completed": 4,
  "coverage": {
    "threat_intel": "complete",
    "web_security": "complete",
    "certificate": "complete",
    "community": "complete"
  },
  "findings": [
    {
      "code": "CERT_HOSTNAME_MISMATCH",
      "category": "certificate",
      "title": "TLS certificate hostname mismatch",
      "description": "The hostname in the certificate subject alternative names does not match the target domain.",
      "severity": "high",
      "points": 25,
      "evidence": {
        "hostname_match": false,
        "target_host": "example.com"
      },
      "remediation": "Ensure the domain requested matches the certificate Subject Alternative Names (SAN).",
      "source": "trustlens_detection_rules_v1"
    }
  ],
  "provider_checks": [
    {
      "provider": "openphish",
      "result_status": "no_match",
      "matched": false,
      "checked_at": "2026-11-07T06:10:02Z"
    }
  ],
  "summary": "Use caution; multiple security risks or anomalous configurations were detected. Notable findings: TLS certificate hostname mismatch (Risk Score: 42/100).",
  "evaluated_at": "2026-11-07T06:10:07Z"
}
```

---

## 5. Detection & Risk Scoring Methodology (`trustlens-1.0`)

The scoring engine implements the rules strictly as defined in **PRD.md FR-09**:

### A. Decisive Malicious Rules (Evaluated First)
1. **`OPENPHISH_URL_MATCH`**: Exact canonical URL match in OpenPhish feed $\rightarrow$ `MALICIOUS`, score **100**.
2. **`URLHAUS_ONLINE_URL_MATCH`**: URLhaus match with `url_status == 'online'` $\rightarrow$ `MALICIOUS`, score **100**.
3. **`COMMUNITY_CONFIRMED_MALICIOUS`**: $\ge 2$ moderator-confirmed reports from distinct accounts $\rightarrow$ `MALICIOUS`, score $\ge$ **90**.

### B. Additive Rules (Summed & Capped at 100)
| Finding Code | Points | Caps & Constraints |
|---|---:|---|
| `CERT_CHAIN_INVALID` | 25 | Untrusted TLS certificate chain |
| `CERT_HOSTNAME_MISMATCH` | 25 | SAN / CN mismatch |
| `CERT_EXPIRED` | 20 | notAfter date in the past |
| `TLS_LEGACY_PROTOCOL` | 10 | Obsolete TLS (TLS 1.0, 1.1, SSL 3.0) |
| `HSTS_MISSING` | 5 | Strict-Transport-Security missing |
| `CSP_MISSING` | 4 | Content-Security-Policy missing |
| `X_CONTENT_TYPE_OPTIONS_MISSING` | 2 | nosniff missing or invalid |
| `REFERRER_POLICY_MISSING` | 1 | Referrer-Policy missing |
| `PERMISSIONS_POLICY_MISSING` | 1 | Permissions-Policy missing |
| `COOKIE_SECURE_MISSING` | 3 per cookie | Capped at **6** total |
| `COOKIE_HTTPONLY_MISSING` | 2 per cookie | Capped at **4** total |
| `COOKIE_SAMESITE_MISSING` | 2 per cookie | Capped at **4** total |
| `HTTP_NO_HTTPS_REDIRECT` | 5 | Plain HTTP target does not redirect to HTTPS |
| `URLHAUS_HISTORICAL_URL_MATCH` | 25 | Historical malware URL (`offline` or `unknown`) |
| `DOMAIN_RECENTLY_REGISTERED` | 15 | Domain age $\le$ 30 days |
| `SUSPICIOUS_IP_HOST` | 20 | Host is raw IP address (standard, octal, hex, dword, or short) |
| `SUSPICIOUS_USERINFO` | 15 | Embedded credentials or userinfo in URL (`user:pass@host`) |
| `SUSPICIOUS_HOMOGLYPH_PUNYCODE` | 20 | Punycode or confusable characters |
| `SUSPICIOUS_EXCESSIVE_REDIRECTS` | 15 | $\ge 3$ redirect hops |
| `URL_HIGH_ENTROPY` | 10 | Shannon entropy $\ge 4.5$ and length $\ge 50$ |

### C. Verdict Mapping Rules
* **Decisive Triggered:** `MALICIOUS` (Score 90–100).
* **Score 25–74:** `SUSPICIOUS`.
* **Score 75–100 (without decisive rule):** `SUSPICIOUS` *(High score alone cannot prove malicious intent without decisive threat-intel match)*.
* **Score 0–24:**
  * If threat intelligence, HTTP, certificate, and community coverage are **complete** $\rightarrow$ `SAFE`.
  * If any required feed is **unavailable**, **stale**, or **skipped** $\rightarrow$ `INCONCLUSIVE`!
* **Failed scan:** `INCONCLUSIVE` with `risk_score = None`.

### D. Explainability Invariant
* **100% of non-`SAFE` verdicts have at least one finding.**
* When an assessment is `INCONCLUSIVE` due to missing provider coverage (even with 0 security flaws), `COVERAGE_INSUFFICIENT` is automatically attached.

---

## 6. Threat Provider Integrations

### 1. OpenPhish Provider (`OpenPhishProvider`)
* Ingests OpenPhish community plain-text feed.
* Evaluates exact canonical URLs in an in-memory `O(1)` set.
* Enforces maximum feed age (13 hours per PRD). Feeds older than 13h return `stale_cache`.
* Because matching occurs against a local cache, checking sensitive URLs does not transmit the URL across the network.

### 2. URLhaus Provider (`URLhausProvider`)
* Queries `https://urlhaus-api.abuse.ch/v1/url/`.
* Distinguishes `online` (decisive MALICIOUS) from `offline`/`unknown` (additive 25 points historical warning).
* **Privacy Guard:** When `is_sensitive=True`, skips external transmission and returns `skipped_sensitive_url` (preventing an unwarranted `SAFE` verdict).
* Bounded timeouts (default 4s) with exponential backoff on transient errors.

### 3. Community Intelligence Provider (`CommunityIntelProvider`)
* Evaluates moderator-reviewed reports.
* Single reports or unmoderated pending reports remain non-authoritative.
* Requires $\ge 2$ independent confirmed reports from distinct user IDs for a decisive match.

### 4. Mock Provider (`MockThreatProvider`)
* Fully offline, zero-network mock provider for deterministic testing, unit test fixtures, and simulating timeouts/outages.

---

## 7. Machine Learning Layer

The ML pipeline operates as an additional evidence signal and **never arbitrarily overrides confirmed threat intelligence**:

1. **Dataset Preparation (`trustlens_intelligence.evaluation.dataset`):**
   * Curated benchmark dataset covering legitimate, phishing, malware, and suspicious URLs.
   * **Domain-aware splitting:** Ensures domains in the training set never leak into the test set.
2. **Baseline Models (`trustlens_intelligence.evaluation.models`):**
   * Scaled Logistic Regression (`StandardScaler` + `LogisticRegression`).
   * Random Forest (`RandomForestClassifier` with balanced class weights).
   * Gradient Boosted Trees (`HistGradientBoostingClassifier`).
3. **Evaluation Metrics (`trustlens_intelligence.evaluation.metrics`):**
   * Precision, Recall, F1, PR-AUC, ROC-AUC, FPR, FNR, Brier calibration score, and Confusion Matrix.
4. **Runtime Inference (`trustlens_intelligence.evaluation.inference.ThreatClassifier`):**
   * Validates model artifact integrity and feature schema version (`1.0.0`).
   * Provides calibrated probability, predicted label (`legitimate`, `suspicious`, `malicious`), and top contributing features.
   * Graceful failure handling: Corrupted or missing artifacts return `None` and do not disrupt scan execution.

---

## 8. Installation & Testing

### Installation

Inside the project environment:

```bash
cd intelligence
pip install -e .
```

### Running the Offline Test Suite

All tests run completely offline without paid APIs, network access, or external secrets:

```bash
pytest tests -v
```

---

## 9. Backend Integration Instructions

For the **Backend Engineer** integrating the intelligence engine into the Celery scan worker (`apps/worker/trustlens_worker/tasks/scan_tasks.py`):

```python
# 1. Import the engine and evidence schemas
from trustlens_intelligence import (
    ScanEvidence,
    HttpEvidence,
    TlsCertificateEvidence,
    ThreatIntelEvidence,
    analyze_website,
)

# 2. Assemble normalized ScanEvidence from PostgreSQL scan facts
evidence = ScanEvidence(
    scan_id=str(scan.id),
    original_url=scan.original_url,
    canonical_url=scan.canonical_url,
    host=scan.host,
    scheme=scan.scheme,
    is_sensitive=scan.is_sensitive,
    http=HttpEvidence(
        status_code=http_result.status,
        final_url=http_result.final_url,
        redirect_count=len(redirect_hops),
        security_headers=http_result.headers,
        cookies=http_result.cookies,
    ),
    tls=TlsCertificateEvidence(
        valid=cert_result.valid,
        chain_valid=cert_result.chain_valid,
        hostname_match=cert_result.hostname_match,
        days_until_expiry=cert_result.days_until_expiry,
        is_expired=cert_result.is_expired,
        protocol_version=cert_result.protocol_version,
    ) if cert_result else None,
)

# 3. Analyze the evidence (set query_providers=True to query OpenPhish & URLhaus)
assessment = analyze_website(evidence, query_providers=True)

# 4. Update the Scan in PostgreSQL
scan.verdict = assessment.verdict.value          # e.g. "SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"
scan.risk_score = assessment.risk_score          # e.g. 42 (or None if failed)
scan.scoring_version = assessment.scoring_version  # "trustlens-1.0"
scan.checks_completed = assessment.checks_completed

# 5. Persist Findings to findings table
for f in assessment.findings:
    finding_repo.create(
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
    )

# 6. Persist Provider Checks
for pc in assessment.provider_checks:
    provider_repo.create(
        scan_id=scan.id,
        provider=pc.provider,
        result_status=pc.result_status.value,
        matched=pc.matched,
        details=pc.details,
    )
```

